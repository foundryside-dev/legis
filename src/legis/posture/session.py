"""Persisted operator-elevation session (design §6, plan Task 3.1).

An *elevation session* is ``sudo`` for governance signing: a short, time-boxed,
attributable window opened by ``legis operator enable``. v1 models it as a
**persisted session file**, not an in-memory daemon — ``legis`` is a fresh
process per CLI invocation, so the long-lived signing daemon is deferred (design
§6).

``.weft/legis/operator_session.json`` holds ONLY window metadata + a
backend-specific unlock reference:

  ``session_id, operator_id, opened_at, ttl, expires_at, backend_id, unlock_ref``

It never holds key plaintext, a passphrase, or a raw age blob. Per D5 the
``unlock_ref`` is the keychain item id for the keychain backend and ``None`` for
age-file / env (re-prompt is the unlock; the session file holds only metadata).

Invariants:
  * **Single active session** — a second :func:`open_session` atomically replaces
    the prior file (D-resolution: there is exactly one authoritative session).
  * **Fail-closed expiry** — :func:`load_session` past the TTL deletes the stale
    file and returns ``None``; a double-expire is safe (the self-delete catches
    :class:`FileNotFoundError`).
  * **Required for every ``posture set``** (D3) — there is no direct-sign path;
    the session id rides into every ``TRANSITION``.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from legis.config import operator_session_path

# The exact metadata key set persisted to operator_session.json. Pinned so a
# test can assert NO key/passphrase/blob ever leaks into the file.
_SESSION_KEYS = (
    "session_id",
    "operator_id",
    "opened_at",
    "ttl",
    "expires_at",
    "backend_id",
    "unlock_ref",
)


@dataclass(frozen=True)
class Session:
    """The in-memory view of a loaded ``operator_session.json``."""

    session_id: str
    operator_id: str
    opened_at: float
    ttl: int
    expires_at: float
    backend_id: str
    unlock_ref: str | None

    def is_active(self, *, now: float | None = None) -> bool:
        """True iff the window has not yet lapsed (``now <= expires_at``)."""
        current = time.time() if now is None else now
        return current <= self.expires_at


def _atomic_write_json(path: Path, obj: dict[str, Any]) -> None:
    """Write ``obj`` as JSON to ``path`` atomically (temp file + ``os.replace``).

    Local to this module by design — the plan forbids reusing install.py's
    text-writer for the session file (its refuse-to-empty / symlink-reject
    semantics are tuned for CLAUDE.md/.gitignore, not ephemeral state). The
    temp file is created in the destination directory so ``os.replace`` is a
    same-filesystem atomic rename.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp", prefix=path.name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, sort_keys=True)
        os.replace(tmp, path)
    except BaseException:
        # Never leave a dangling temp file on failure.
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def open_session(
    *,
    ttl: int,
    operator_id: str,
    backend_id: str,
    unlock_ref: str | None,
    now: float | None = None,
) -> Session:
    """Open (or atomically replace) the single active elevation session.

    Generates a fresh ``session_id`` and writes the metadata file. A second
    call overwrites the prior file (single authoritative session). The key,
    passphrase, and any wrapped blob are deliberately NOT arguments — only the
    ``unlock_ref`` (keychain item id, or ``None`` for age-file/env, per D5).
    """
    opened_at = time.time() if now is None else now
    session = Session(
        session_id=secrets.token_hex(16),
        operator_id=operator_id,
        opened_at=opened_at,
        ttl=ttl,
        expires_at=opened_at + ttl,
        backend_id=backend_id,
        unlock_ref=unlock_ref,
    )
    payload = {key: getattr(session, key) for key in _SESSION_KEYS}
    _atomic_write_json(operator_session_path(), payload)
    return session


def load_session(*, now: float | None = None) -> Session | None:
    """Load the active session, or ``None`` if absent / lapsed.

    Fail-closed: a file past its ``expires_at`` is deleted (catching
    :class:`FileNotFoundError` so a concurrent / double-expire is safe) and
    ``None`` is returned. A malformed file also reads as ``None``.
    """
    path = operator_session_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    try:
        session = Session(
            session_id=data["session_id"],
            operator_id=data["operator_id"],
            opened_at=data["opened_at"],
            ttl=data["ttl"],
            expires_at=data["expires_at"],
            backend_id=data["backend_id"],
            unlock_ref=data.get("unlock_ref"),
        )
    except (KeyError, TypeError):
        return None
    if not session.is_active(now=now):
        _delete(path)
        return None
    return session


def end_session() -> None:
    """Delete the session file (idempotent — ``disable`` may run twice)."""
    _delete(operator_session_path())


def is_active(*, now: float | None = None) -> bool:
    """True iff there is a currently-active (non-lapsed) session on disk."""
    return load_session(now=now) is not None


def _delete(path: Path) -> None:
    """Remove ``path``, tolerating an already-absent file (double-expire safe)."""
    try:
        path.unlink()
    except FileNotFoundError:
        pass
