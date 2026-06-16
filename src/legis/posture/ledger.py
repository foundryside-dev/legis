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

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlparse

from legis.posture.records import (
    KIND_GENESIS,
    KIND_KEY_RESET,
    KIND_SESSION_OPENED,
    KIND_TRANSITION,
    PostureRecord,
)

if TYPE_CHECKING:
    from pathlib import Path

    from legis.clock import Clock


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

    def current_epoch_fingerprint(self) -> str | None:
        """The ``key_fingerprint`` of the current key epoch, or ``None``.

        The epoch is established by the latest ``GENESIS`` / ``KEY_RESET``
        record (a ``rekey`` mints a new key and chains a ``KEY_RESET`` carrying
        its fingerprint). A ``TRANSITION`` does NOT open an epoch — it is signed
        *under* the standing epoch — so we scan for the most recent
        epoch-opening record and return its fingerprint. ``None`` means no
        ledger / no epoch yet (fail-closed: the change gate refuses).

        This is a full scan (``read_all``); the change gate resolves it ONCE up
        front, BEFORE entering ``append_signed`` (Q-M5), never inside the build
        callback.
        """
        records = self.store.read_all()
        for rec in reversed(records):
            if rec.payload.get("kind") in (KIND_GENESIS, KIND_KEY_RESET):
                return rec.payload.get("key_fingerprint")
        return None

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

    def session_opened(
        self,
        *,
        operator_id: str,
        enabled_at: str,
        ttl: int,
        keychain_auth_ref: str | None,
        session_id: str,
    ) -> None:
        """Append a keyless ``OPERATOR_SESSION_OPENED`` record (design §6).

        The enable IS the operator's countersignature on the whole window
        (design §6), so the record carries no ``operator_sig``. It records who
        opened the window, when, for how long, and the backend unlock reference
        (``keychain_auth_ref`` — the keychain item id, or ``None`` for
        age-file/env, per D5). Every ``TRANSITION`` produced in the window then
        carries this ``session_id``, so the trail reads back as "operator X
        opened a window at T; within it the floor moved A->B".
        """
        self.store.append(
            {
                "kind": KIND_SESSION_OPENED,
                "operator_id": operator_id,
                "enabled_at": enabled_at,
                "ttl": ttl,
                "keychain_auth_ref": keychain_auth_ref,
                "session_id": session_id,
                "operator_sig": None,
            }
        )

    def rekey(self, *args: Any, **kwargs: Any) -> None:
        """Write a ``KEY_RESET`` genesis chained onto history (Phase 11)."""
        raise NotImplementedError("rekey lands in Phase 11")


# -- the change gate (Phase 5, Task 5.1) -------------------------------------

# Refusal reasons (stable discriminants so callers can branch / report).
REFUSED_NO_SESSION = "no_open_session"
REFUSED_NO_EPOCH = "no_key_epoch"
REFUSED_FINGERPRINT_MISMATCH = "fingerprint_mismatch"
REFUSED_SIGNER_ERROR = "signer_error"


@dataclass(frozen=True)
class PostureSetResult:
    """The single outcome of a :func:`set_floor` call (design §7).

    Exactly one of ``accepted`` is True (one ``TRANSITION`` appended) or False
    (no record written, floor unchanged). ``reason`` carries a refusal
    discriminant when refused, or ``None`` on success; ``floor`` is the new
    floor on success.
    """

    accepted: bool
    reason: str | None = None
    floor: str | None = None
    session_id: str | None = None
    detail: str | None = None


def set_floor(
    new_cell: str,
    *,
    ledger: PostureLedger,
    signer: _Signer,
    agent_id: str,
    rationale: str,
    clock: Clock | None = None,
) -> PostureSetResult:
    """The posture change gate: append a signed ``TRANSITION`` or refuse.

    Per D3 an open elevation session is REQUIRED — there is no direct-sign path.
    Fail-closed (design §7): no open session, no key epoch, fingerprint
    mismatch, or signer failure each yields a refusal with ZERO records written
    and the floor unchanged. A success writes exactly one ``TRANSITION``. Every
    outcome is exactly one ``PostureSetResult`` — no silent pass.

    Sequence (all reads resolved BEFORE entering ``append_signed``, Q-M5):
      1. ``session = load_session()``; absent / lapsed -> refuse.
      2. Resolve the current-epoch ``key_fingerprint`` from the last
         GENESIS/KEY_RESET record; if the signer's fingerprint does not match
         the LEDGER epoch -> refuse (the epoch is the source of truth, not the
         session's recorded field — closes the concurrent-session race).
      3. ``ledger.transition(...)`` under the session id. A signer raise inside
         ``append_signed``'s build -> refusal, no half-write.
    """
    from legis.clock import SystemClock
    from legis.posture import session as _session

    used_clock = clock if clock is not None else SystemClock()

    # 1. An open elevation session is mandatory (D3).
    sess = _session.load_session()
    if sess is None:
        return PostureSetResult(accepted=False, reason=REFUSED_NO_SESSION)

    # 2. Resolve the current-epoch fingerprint up front (tail read before batch).
    epoch_fp = ledger.current_epoch_fingerprint()
    if epoch_fp is None:
        return PostureSetResult(
            accepted=False,
            reason=REFUSED_NO_EPOCH,
            session_id=sess.session_id,
        )
    # The signer must hold the current epoch's key. Checking against the LEDGER
    # epoch (not the session's recorded field) closes the concurrent-session /
    # rekey race: a signer for a superseded epoch is refused even with a live
    # session. ``signer.fingerprint()`` may itself fault for a custody backend
    # (e.g. age-file wrong passphrase) — treat that as a signer-error refusal.
    try:
        signer_fp = signer.fingerprint()
    except Exception as exc:  # noqa: BLE001 — fail-closed: any custody fault refuses
        return PostureSetResult(
            accepted=False,
            reason=REFUSED_SIGNER_ERROR,
            session_id=sess.session_id,
            detail=str(exc),
        )
    if signer_fp != epoch_fp:
        return PostureSetResult(
            accepted=False,
            reason=REFUSED_FINGERPRINT_MISMATCH,
            session_id=sess.session_id,
        )

    # 3. Append exactly one signed TRANSITION. A signer raise inside the build
    # callback (or a re-checked fingerprint mismatch) propagates out of
    # append_signed before any row is committed — fail-closed, no half-write.
    try:
        ledger.transition(
            new_cell,
            signer=signer,
            session_id=sess.session_id,
            key_fingerprint=epoch_fp,
            agent_id=agent_id,
            rationale=rationale,
            recorded_at=used_clock.now_iso(),
        )
    except Exception as exc:  # noqa: BLE001 — fail-closed: any signer fault refuses
        return PostureSetResult(
            accepted=False,
            reason=REFUSED_SIGNER_ERROR,
            session_id=sess.session_id,
            detail=str(exc),
        )

    return PostureSetResult(
        accepted=True,
        floor=new_cell,
        session_id=sess.session_id,
    )
