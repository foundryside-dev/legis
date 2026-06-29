"""Tamper-bound ledger of sign-off → issue bindings (legis-side, WP-A3).

A governed sign-off bound to a Filigree issue is recorded here as a signed,
append-only ``BindingRecord`` — the legis-side tamper-bound attestation. The row
legis posts to Filigree is an opaque pointer that also carries ``signoff_seq`` and
the binding HMAC so the sibling can persist the attestation leg when it supports
the extended shape. This ledger remains the local tamper-bound source of truth,
using the same HMAC scheme as protected verdicts. A forged or mutated binding
record is rejected at read time (``BindingError``). The ledger is a DEDICATED
append-only store, isolated from the override/gap governance trail, so binding
records never pollute those reads.
"""

from __future__ import annotations

from typing import Any

from legis.clock import Clock
from legis.crypto.signing import sign, verify
from legis.identity.entity_key import EntityKey
from legis.store.protocol import AppendOnlyStore

BINDING_KIND = "issue_binding"


class BindingError(RuntimeError):
    """A binding record failed load-time signature verification."""


def binding_signing_fields(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "signoff_seq": payload["signoff_seq"],
        "issue_id": payload["issue_id"],
        "entity_key": payload["entity_key"],  # full dict: value + identity_stable
        "content_hash": payload["content_hash"],
        "recorded_at": payload["recorded_at"],
    }


class BindingLedger:
    def __init__(self, store: AppendOnlyStore, clock: Clock, key: bytes) -> None:
        self._store = store
        self._clock = clock
        self._key = key

    def record(self, *, signoff_seq: int, issue_id: str,
               entity_key: EntityKey, content_hash: str) -> int:
        payload: dict[str, Any] = {
            "kind": BINDING_KIND,
            "signoff_seq": signoff_seq,
            "issue_id": issue_id,
            "entity_key": entity_key.to_dict(),
            "content_hash": content_hash,
            "recorded_at": self._clock.now_iso(),
        }
        payload["binding_signature"] = sign(binding_signing_fields(payload), self._key)
        return self._store.append(payload)

    def verify(self) -> None:
        if not self._store.verify_integrity():
            raise BindingError("binding ledger hash chain integrity check failed")
        for rec in self._store.read_all():
            payload = rec.payload
            if payload.get("kind") != BINDING_KIND:
                continue
            sig = payload.get("binding_signature")
            if not sig:
                raise BindingError(f"binding record seq={rec.seq} is missing its signature")
            try:
                fields = binding_signing_fields(payload)
            except KeyError as exc:
                raise BindingError(
                    f"binding record seq={rec.seq} is structurally malformed: missing {exc}"
                ) from exc
            if not verify(fields, sig, self._key):
                raise BindingError(f"binding record seq={rec.seq} signature does not verify")

    def get(self, signoff_seq: int) -> dict[str, Any] | None:
        self.verify()  # fail-closed: never return data from a tampered ledger
        for rec in self._store.read_all():
            p = rec.payload
            if p.get("kind") == BINDING_KIND and p.get("signoff_seq") == signoff_seq:
                return p
        return None

    def get_by_issue_id(self, issue_id: str) -> dict[str, Any] | None:
        self.verify()  # fail-closed: never return data from a tampered ledger
        match: dict[str, Any] | None = None
        for rec in self._store.read_all():
            p = rec.payload
            if p.get("kind") == BINDING_KIND and p.get("issue_id") == issue_id:
                match = p  # last verified binding for this issue wins
        return match
