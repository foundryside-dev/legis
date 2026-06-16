"""The posture-floor ledger (design §4).

A thin *domain* wrapper over :class:`~legis.store.audit_store.AuditStore`: it
holds an ``AuditStore`` and exposes posture-domain methods (``read_floor``,
``genesis``, ``transition``, and the Phase 3/11 signatures ``session_opened`` /
``rekey``). It is deliberately NOT an ``AppendOnlyStore`` — it is a wrapper, not
a drop-in store, so it implements no store protocol.

Fail-closed contract (design §4/§5):
  * **Absent ledger** (no DB file, or an empty store) -> ``read_floor()`` returns
    ``None``; callers map that to the fail-closed ``structured`` default, NEVER
    ``chill``. Only an explicit ``GENESIS`` record makes ``chill`` the floor.
  * The current floor is the *last* record's ``floor`` field, read via an O(1)
    tail read (``get_latest_sequence_and_hash`` + ``read_by_seq``), never the
    O(N) ``read_all`` loop — ``read_floor`` is on the per-request hot path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlparse

from legis.posture.records import (
    KIND_GENESIS,
    KIND_TRANSITION,
    PostureRecord,
)

if TYPE_CHECKING:
    from pathlib import Path


class _Signer(Protocol):
    """The custody-backend signer seam (full type lands in Phase 2 signing.py).

    The key is held by the backend and never passed by the caller; the caller
    hands canonical record fields (including ``chain_seq``) and receives a v3
    HMAC. ``fingerprint()`` is the ``sha256`` of the held key.
    """

    def fingerprint(self) -> str: ...

    def sign(self, fields: dict[str, Any]) -> str: ...


def _sqlite_file(url: str) -> Path | None:
    """The on-disk path backing a SQLite URL, or ``None`` for non-file URLs.

    Used to detect a genuinely-absent ledger before opening a connection (so a
    missing store reads as ``None`` rather than lazily creating an empty file).
    """
    from pathlib import Path

    if not url.startswith("sqlite"):
        return None
    parsed = urlparse(url)
    # sqlite:///relative/x.db -> path "/relative/x.db" (relative form);
    # sqlite:////abs/x.db    -> path "//abs/x.db".
    raw = parsed.path
    if raw.startswith("//"):
        return Path(raw[1:])
    if raw.startswith("/"):
        return Path(raw[1:])
    return Path(raw)


class PostureLedger:
    """Domain wrapper over an ``AuditStore`` for the posture-floor ledger."""

    def __init__(self, url: str, *, initialize: bool = True) -> None:
        from legis.store.audit_store import AuditStore

        self._url = url
        self.store = AuditStore(url, initialize=initialize)

    # -- reads ---------------------------------------------------------------

    def read_floor(self) -> str | None:
        """The current floor (last record's ``floor``), or ``None`` if no ledger.

        O(1) tail read: two indexed SQLite queries, no JSON-decode loop. A
        missing DB file or an empty store both report ``None`` (fail-closed:
        callers map ``None`` -> ``structured``).
        """
        path = _sqlite_file(self._url)
        if path is not None and not path.exists():
            return None
        seq, _ = self.store.get_latest_sequence_and_hash()
        if seq == 0:
            return None
        rec = self.store.read_by_seq(seq)
        if rec is None:
            return None
        return rec.payload.get("floor")

    # -- writes --------------------------------------------------------------

    def genesis(
        self, *, key_fingerprint: str, agent_id: str, recorded_at: str
    ) -> None:
        """Write the keyless ``GENESIS`` record (``floor=chill``), once.

        Idempotent / re-key-safe: if the store already has ANY record (an
        existing GENESIS, or a KEY_RESET tail), this is a no-op — a second
        install must never append a second GENESIS, and a rekey'd ledger must
        not be re-genesised.
        """
        if self.store.get_latest_sequence_and_hash()[0] != 0:
            return
        record = PostureRecord(
            kind=KIND_GENESIS,
            floor="chill",
            key_fingerprint=key_fingerprint,
            agent_id=agent_id,
            recorded_at=recorded_at,
            rationale="genesis",
            operator_sig=None,
            session_id=None,
        )
        self.store.append(record.to_payload())

    def transition(
        self,
        new_cell: str,
        *,
        signer: _Signer,
        session_id: str,
        key_fingerprint: str,
        agent_id: str,
        rationale: str,
        recorded_at: str,
    ) -> None:
        """Append a signed ``TRANSITION`` record moving the floor to ``new_cell``.

        Fail-closed: the signer's fingerprint must equal the current-epoch
        ``key_fingerprint`` and the signer must not raise; either failure raises
        BEFORE any row is committed (``append_signed`` runs build-then-insert
        under one lock, so a raise in ``build`` leaves no half-write).

        The signed field set folds ``chain_seq=seq`` (v3 position binding). The
        build callback does NO fresh-connection read — it would contend with the
        held ``BEGIN IMMEDIATE`` batch lock (Q-M5); the only inputs it needs
        (``key_fingerprint``, ``new_cell``, ...) are resolved by the caller
        before ``append_signed`` is entered.
        """

        def build(seq: int, prev_hash: str) -> dict[str, Any]:
            record = PostureRecord(
                kind=KIND_TRANSITION,
                floor=new_cell,
                key_fingerprint=key_fingerprint,
                agent_id=agent_id,
                recorded_at=recorded_at,
                rationale=rationale,
                operator_sig=None,
                session_id=session_id,
            )
            payload = record.to_payload()
            # Verify the held key matches this epoch BEFORE signing — fail-closed.
            if signer.fingerprint() != key_fingerprint:
                raise ValueError(
                    "posture transition refused: signer key fingerprint does not "
                    "match the current epoch fingerprint"
                )
            # Sign the content (sans signature) bound to its chain position.
            fields = {k: v for k, v in payload.items() if k != "operator_sig"}
            fields["chain_seq"] = seq
            payload["operator_sig"] = signer.sign(fields)
            return payload

        self.store.append_signed(build)

    # -- Phase 3.2 / Phase 11 signatures (implemented later) -----------------

    def session_opened(self, *args: Any, **kwargs: Any) -> None:
        """Append an ``OPERATOR_SESSION_OPENED`` record (Phase 3.2)."""
        raise NotImplementedError("session_opened lands in Phase 3.2")

    def rekey(self, *args: Any, **kwargs: Any) -> None:
        """Write a ``KEY_RESET`` genesis chained onto history (Phase 11)."""
        raise NotImplementedError("rekey lands in Phase 11")
