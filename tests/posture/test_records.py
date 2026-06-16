"""Phase 1 / Task 1.1 — PostureRecord dataclass + kind constants.

The record serializes to a flat payload that the record-agnostic AuditStore
chains; the store adds seq/prev_hash/chain_hash, so those must NOT be in the
payload (including them would shift the content hash and break verify_integrity).
"""

from __future__ import annotations

from legis.canonical import canonical_json, content_hash
from legis.posture.records import (
    KIND_GENESIS,
    KIND_KEY_RESET,
    KIND_SESSION_OPENED,
    KIND_TRANSITION,
    PostureRecord,
)


def _record(**overrides):
    base = dict(
        kind=KIND_GENESIS,
        floor="chill",
        key_fingerprint="ff" * 32,
        operator_sig=None,
        session_id=None,
        agent_id="agent-1",
        recorded_at="2026-06-16T00:00:00Z",
        rationale="genesis",
    )
    base.update(overrides)
    return PostureRecord(**base)


def test_to_payload_keys():
    payload = _record().to_payload()
    assert set(payload.keys()) == {
        "kind",
        "floor",
        "key_fingerprint",
        "operator_sig",
        "session_id",
        "agent_id",
        "recorded_at",
        "rationale",
    }


def test_to_payload_excludes_chain_fields():
    payload = _record().to_payload()
    # Negative assertion: the store owns these; including them would shift the
    # content hash and fail verify_integrity.
    assert "seq" not in payload
    assert "prev_hash" not in payload
    assert "chain_hash" not in payload
    assert "this_hash" not in payload


def test_kind_constants():
    assert KIND_GENESIS == "GENESIS"
    assert KIND_TRANSITION == "TRANSITION"
    assert KIND_KEY_RESET == "KEY_RESET"
    assert KIND_SESSION_OPENED == "OPERATOR_SESSION_OPENED"


def test_canonical_roundtrip():
    rec = _record(
        kind=KIND_TRANSITION,
        floor="structured",
        operator_sig="hmac-sha256:v3:abc",
        session_id="sess-1",
    )
    payload = rec.to_payload()
    # canonical_json is sorted/stable regardless of key-insertion order.
    assert canonical_json(payload) == canonical_json(dict(reversed(list(payload.items()))))
    # content_hash deterministic across key-insertion order.
    assert content_hash(payload) == content_hash(dict(reversed(list(payload.items()))))
