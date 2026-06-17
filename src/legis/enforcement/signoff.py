"""Structured / protected sign-off — block + escalate, no LLM in the path.

``request`` records a PENDING_SIGNOFF and does NOT clear the gate; a designated
operator's ``sign_off`` records SIGNED_OFF (referencing the request) and clears
it. An optional ``signer`` makes protected-cell sign-offs tamper-bound;
structured sign-offs are procedural (unsigned). Human-in-the-loop by exception.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from legis.canonical import content_hash
from legis.clock import Clock
from legis.enforcement.signing import sign
from legis.enforcement.verdict import SignoffState
from legis.identity.entity_key import EntityKey
from legis.records.override_record import OverrideRecord
from legis.store.head_anchor import HeadAnchor
from legis.store.protocol import AppendOnlyStore


@dataclass(frozen=True)
class SignoffResult:
    seq: int
    cleared: bool


def signoff_signing_fields(
    payload: dict[str, Any], *, seq: int | None = None
) -> dict[str, Any]:
    ext = payload.get("extensions") or {}
    clar = ext.get("loomweave") or {}
    snap = clar.get("lineage_snapshot") or {}
    fields = {
        "policy": payload.get("policy"),
        "entity": payload.get("entity_key"),
        "recorded_at": payload.get("recorded_at"),
        "rationale": payload.get("rationale"),
        "actor": payload.get("agent_id"),
        "signoff_state": ext.get("signoff_state"),
        "request_seq": ext.get("request_seq"),
        "request_payload_hash": ext.get("request_payload_hash"),
        "loomweave_content_hash": clar.get("content_hash"),
        "loomweave_lineage_hash": snap.get("hash"),
        "loomweave_lineage_len": snap.get("length"),
    }
    # AUD-1 / v3: bind the record's chain position. Sign-offs share the
    # governance trail with protected verdicts, so they must close the same
    # delete-and-rechain hole. At verify time seq comes from the column.
    if seq is not None:
        fields["chain_seq"] = seq
    return fields


class SignoffGate:
    def __init__(
        self,
        store: AppendOnlyStore,
        clock: Clock,
        signer: bool | None = None,
        key: bytes | None = None,
        anchor: HeadAnchor | None = None,
    ) -> None:
        self._store = store
        self._clock = clock
        # `signer` truthy → protected sign-off (sign the SIGNED_OFF record).
        self._sign = bool(signer)
        self._key = key
        # Opt-in (AUD-1): advance the shared trail's head anchor after each
        # append so a later tail-truncation is detectable. None → not anchored.
        self._anchor = anchor

    def _append(
        self,
        *,
        policy: str,
        entity_key: EntityKey,
        rationale: str,
        actor_id: str,
        ext: dict[str, Any],
    ) -> int:
        rec = OverrideRecord(
            policy=policy,
            entity_key=entity_key,
            rationale=rationale,
            agent_id=actor_id,
            recorded_at=self._clock.now_iso(),
            extensions=ext,
        )
        if self._sign and self._key is not None:
            key = self._key

            def build(seq: int, _prev_hash: str) -> dict[str, Any]:
                payload = rec.to_payload()
                payload["extensions"]["signoff_signature"] = sign(
                    signoff_signing_fields(payload, seq=seq), key, version="v3"
                )
                return payload

            seq = self._store.append_signed(build)
        else:
            seq = self._store.append(rec.to_payload())
        # Advance the anchor after the commit (AUD-1) — but never mid-batch: the
        # head read is a fresh-connection read the batch forbids (Q-M5), and a
        # per-append advance inside a batch is wasted anyway since only the final
        # head matters. ``transaction()`` advances it once when the batch commits.
        if self._anchor is not None and not self._store.in_batch():
            self._anchor.update(*self._store.get_latest_sequence_and_hash())
        return seq

    def request(
        self,
        *,
        policy: str,
        entity_key: EntityKey,
        rationale: str,
        agent_id: str,
        extensions: dict[str, Any] | None = None,
    ) -> SignoffResult:
        seq = self._append(
            policy=policy,
            entity_key=entity_key,
            rationale=rationale,
            actor_id=agent_id,
            ext={**(extensions or {}), "signoff_state": SignoffState.PENDING.value},
        )
        return SignoffResult(seq=seq, cleared=False)

    def sign_off(
        self, *, request_seq: int, operator_id: str, rationale: str = ""
    ) -> SignoffResult:
        req = self.request_record(request_seq)
        if req is None:
            raise ValueError(f"No pending sign-off request found at sequence {request_seq}")
        if self.is_cleared(request_seq):
            raise ValueError(f"Request at sequence {request_seq} has already been signed off")
        seq = self._append(
            policy=req["policy"],
            entity_key=EntityKey.from_dict(req["entity_key"]),
            rationale=rationale,
            actor_id=operator_id,
            ext={
                "signoff_state": SignoffState.SIGNED_OFF.value,
                "request_seq": request_seq,
                "request_payload_hash": content_hash(req),
            },
        )
        return SignoffResult(seq=seq, cleared=True)

    def request_record(self, request_seq: int) -> dict | None:
        """The recorded PENDING_SIGNOFF request payload at this seq, or None."""
        rec = self._store.read_by_seq(request_seq)
        if rec is None:
            return None
        payload = rec.payload
        if payload.get("extensions", {}).get("signoff_state") != SignoffState.PENDING.value:
            return None
        return payload

    def is_cleared(self, request_seq: int) -> bool:
        for rec in self._store.read_all():
            ext = rec.payload.get("extensions", {})
            if (
                ext.get("signoff_state") == SignoffState.SIGNED_OFF.value
                and ext.get("request_seq") == request_seq
            ):
                return True
        return False

    def records(self):
        """The sign-off trail this gate writes to — for verified consumers."""
        return self._store.read_all()

    @contextmanager
    def transaction(self):
        """Group this gate's appends into one all-or-nothing transaction (Q-M5).

        The per-append anchor advance is deferred inside a batch (the head read
        is batch-forbidden, Q-M5); advance it once here after the batch commits
        and the write lock is released. An exception inside the batch rolls back
        and propagates before this runs, so the anchor never advances past a
        rolled-back head (AUD-1: the anchor only ever lags, never overshoots)."""
        with self._store.transaction():
            yield
        if self._anchor is not None:
            self._anchor.update(*self._store.get_latest_sequence_and_hash())

    def verify_integrity(self) -> bool:
        """Verify the underlying append-only hash chain before HMAC checks."""
        return self._store.verify_integrity()
