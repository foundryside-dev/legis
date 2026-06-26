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
  * The current floor is the latest authoritative floor record's ``floor`` field
    (``GENESIS`` / ``TRANSITION`` / ``KEY_RESET``). An O(N) keyless
    ``verify_integrity`` walk GATES the read (fail-closed: a chain that does not
    verify yields ``None`` -> ``structured``); the floor itself is then found by
    one descending payload scan from the tail, never a repeated point-read loop
    over metadata. Metadata records such as ``OPERATOR_SESSION_OPENED`` must not
    lower the effective floor, even if they carry a stale ``floor`` field.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlparse

from sqlalchemy import select

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

    _FLOOR_RECORD_KINDS = frozenset({KIND_GENESIS, KIND_TRANSITION, KIND_KEY_RESET})

    def __init__(self, url: str, *, initialize: bool = True) -> None:
        from legis.store.audit_store import AuditStore

        self._url = url
        self.store = AuditStore(url, initialize=initialize)

    # -- reads ---------------------------------------------------------------

    def read_floor(self) -> str | None:
        """The current floor (latest authoritative floor record), or ``None``.

        Fail-closed: the floor sets routing, so the ledger must first PROVE its
        own integrity. ``verify_integrity()`` (an O(N) keyless chain re-hash)
        gates the read; a chain that does not verify — a raw-write in-place edit,
        reorder, or seq gap — yields ``None`` (callers map ``None`` -> the
        fail-closed ``structured`` default), never the tampered floor. A missing
        DB file or an empty store also report ``None`` (``verify_integrity`` is
        True on an empty store; the table-absence check returns ``None`` below).

        The O(N) integrity walk runs on EVERY resolution (the floor is never
        cached, design D2) and is deliberate: it is bounded by operator-action
        volume (genesis/transition/rekey are operator-gated; session-open churn
        is bounded by TTL expiry + human-in-the-loop enabling), immaterial at
        posture-ledger scale on local SQLite, and an *unverified* hot read was
        the whole bug. The two failure modes are both fail-closed but
        asymmetric: a DETECTED tamper (a clean walk that does not verify)
        resolves to ``None`` -> ``structured``; an I/O fault (locked/corrupt DB
        raising ``OperationalError``) propagates as an exception and aborts the
        read — neither is a pass. Do NOT wrap the gate in a try/except that
        downgrades that raise to a permissive default.

        SCOPE (honesty): the chain is keyless SHA, so this proves integrity +
        tail-kind but NOT operator authorization. A file-write attacker who
        *recomputes* the keyless chain on a forged floor-lowering ``TRANSITION``
        passes this gate; on a non-rekeyed ledger that forgery is caught by
        NEITHER this keyless hot read NOR ``doctor`` today — it is a PURE
        conceded raw-file-write residual (README "Known security limitations",
        README.md:137). ``doctor``'s keyed ``operator_sig`` verification
        (``_transition_acknowledges``, doctor.py:649) covers ONLY the
        ``KEY_RESET``-acknowledgment path (D6), not a ``TRANSITION`` on a ledger
        with no reset to acknowledge. A general per-transition ``operator_sig``
        audit in ``doctor`` would close the residual operator-side, but that is
        separate follow-up, not this change. See
        ``test_read_floor_fails_closed_on_integrity_break`` and
        ``test_read_floor_recomputed_chain_forgery_is_conceded_residual``.
        """
        path = _sqlite_file(self._url)
        if path is not None and not path.exists():
            return None
        # Fail closed if the chain cannot prove integrity: a tampered/forged
        # ledger must not be trusted to set the routing floor. verify_integrity()
        # returns True on an empty store, so an absent/empty ledger still reads
        # as None via the table-absence check below, not a spurious failure.
        if not self.store.verify_integrity():
            return None
        self.store._assert_no_batch_in_progress("read_floor")
        with self.store._engine.begin() as conn:
            if not self.store._has_log_table(conn):
                return None
            rows = conn.execute(
                select(self.store._log.c.payload)
                .order_by(self.store._log.c.seq.desc())
            )
            for row in rows:
                payload = json.loads(row.payload)
                kind = payload.get("kind")
                floor = payload.get("floor")
                if kind in self._FLOOR_RECORD_KINDS and floor is not None:
                    return floor
        return None

    def epoch_reset_unacknowledged(self) -> bool:
        """True iff the current key epoch was opened by a ``KEY_RESET`` that no
        later ``TRANSITION`` has acknowledged (design §8/§10).

        A ``rekey`` preserves the standing floor and chains a ``KEY_RESET``
        carrying a fresh epoch fingerprint. Until an operator signs a follow-on
        ``TRANSITION`` under that new epoch, the reset is *unacknowledged* — a
        pending operator action the agent should surface (the same signal the
        doctor exits non-zero on). This is the structural, agent-visible check:
        the latest epoch-opening record is a ``KEY_RESET`` AND no ``TRANSITION``
        record follows it. The doctor's deeper acknowledgment check (Phase 10.2)
        additionally *verifies* that follow-on signature against the new epoch
        fingerprint (D6); that verification needs the key and is operator-side,
        so the agent-visible read reports the unacknowledged window structurally.

        A missing/empty ledger, or an epoch opened by ``GENESIS`` (the normal
        install path), reports ``False``.
        """
        records = self.store.read_all()
        for rec in reversed(records):
            kind = rec.payload.get("kind")
            if kind == KIND_TRANSITION:
                # A transition after the latest epoch opener -> acknowledged.
                return False
            if kind == KIND_KEY_RESET:
                return True
            if kind == KIND_GENESIS:
                # Genesis epoch (install) is not a reset to acknowledge.
                return False
        return False

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

        Idempotent / re-key-safe: if the store already has an epoch-opening
        record (an existing GENESIS, or a KEY_RESET tail), this is a no-op — a
        second install must never append a second GENESIS, and a rekey'd ledger
        must not be re-genesised. Metadata-only ledgers from an interrupted old
        operator-enable path have no epoch and remain recoverable by appending
        GENESIS.
        """
        if self.current_epoch_fingerprint() is not None:
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
            # Sign the content (sans signature) bound to its chain position, then
            # verify the produced signature against the actual held key material.
            # A self-attested fingerprint plus arbitrary signature is not enough.
            fields = {k: v for k, v in payload.items() if k != "operator_sig"}
            fields["chain_seq"] = seq
            payload["operator_sig"] = signer.sign(fields)
            from legis.posture.signing import verify_signer_signature

            if not verify_signer_signature(
                signer,
                fields,
                payload["operator_sig"],
                expected_fingerprint=key_fingerprint,
            ):
                raise ValueError(
                    "posture transition refused: signer did not prove custody of "
                    "the current epoch key"
                )
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
        opened a window at T; within it the floor moved A->B". The record does
        not carry ``floor``; :meth:`read_floor` ignores metadata records so a
        session-open tail cannot change the effective floor.
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

    def session_opened_recorded(self, session_id: str) -> bool:
        """True iff a matching session-open audit record exists in the ledger."""
        for rec in self.store.read_all():
            if (
                rec.payload.get("kind") == KIND_SESSION_OPENED
                and rec.payload.get("session_id") == session_id
            ):
                return True
        return False

    def rekey(
        self,
        *,
        agent_id: str,
        recorded_at: str,
        key_sink: Callable[[str, str], None] | None = None,
        backend: str = "env",
    ) -> str:
        """Mint a fresh key epoch and chain a loud ``KEY_RESET`` onto history.

        The lost-key / recovery path (design §8). Fail-closed/loud invariants:

          * **Preserves the standing floor.** The ``KEY_RESET`` carries the
            current floor because runtime routing reads the floor from the tail
            record. A missing/empty ledger falls back to the fail-closed
            ``structured`` floor, never the self-clearable ``chill`` default.
          * **Needs no old key and no open session.** Rekey is the recovery
            mechanism for a lost custody key, so it deliberately mints a new key
            without proving possession of the old one (a lost key cannot sign)
            and without an elevation session — its accountability is the
            indelible, doctor-flagged ``KEY_RESET`` record, not a countersignature.
          * **Preserves history.** The reset is ``append``\\ed onto the existing
            chain (NOT a fresh DB) — every prior record stays present and
            ``verify_integrity`` holds across the whole ledger.
          * **Loud.** Exactly one ``KEY_RESET`` is written; doctor then exits
            non-zero until a signed ``TRANSITION`` verifies under the NEW epoch
            (Task 10.2 / D6).

        The freshly-minted key bytes reach ONLY the required custody ``key_sink``
        (handed off BEFORE the record is written, mirroring ``install_posture`` —
        if custody fails we have written no fingerprint we cannot later sign
        against); the ledger stores the new fingerprint alone. Returns the new
        epoch ``key_fingerprint``.
        """
        if key_sink is None:
            from legis.install import OperatorKeyCustodyError

            raise OperatorKeyCustodyError(
                "posture rekey requires an explicit operator-key custody sink"
            )

        from legis.posture.signing import key_fingerprint, mint_key

        floor = self.read_floor() or "structured"
        key_hex = mint_key()
        new_fp = key_fingerprint(key_hex)
        # Hand the key to custody BEFORE appending the reset: a custody failure
        # must leave the ledger untouched (no fingerprint we cannot sign against).
        key_sink(key_hex, backend)
        record = PostureRecord(
            kind=KIND_KEY_RESET,
            floor=floor,
            key_fingerprint=new_fp,
            agent_id=agent_id,
            recorded_at=recorded_at,
            rationale="key epoch reset (rekey)",
            operator_sig=None,
            session_id=None,
        )
        self.store.append(record.to_payload())
        return new_fp


# -- the change gate (Phase 5, Task 5.1) -------------------------------------

# Refusal reasons (stable discriminants so callers can branch / report).
REFUSED_NO_SESSION = "no_open_session"
REFUSED_NO_EPOCH = "no_key_epoch"
REFUSED_SESSION_NOT_RECORDED = "session_not_recorded"
REFUSED_SESSION_AUTH_FAILED = "session_auth_failed"
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
    if not ledger.session_opened_recorded(sess.session_id):
        return PostureSetResult(
            accepted=False,
            reason=REFUSED_SESSION_NOT_RECORDED,
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
    if not _session.verify_session_signature(
        sess,
        signer,
        expected_fingerprint=epoch_fp,
    ):
        return PostureSetResult(
            accepted=False,
            reason=REFUSED_SESSION_AUTH_FAILED,
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
