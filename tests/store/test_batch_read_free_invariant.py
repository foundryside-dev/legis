"""The transaction() read-free invariant is enforced and gate-path-proven (Q-M5).

`AuditStore.transaction()` groups appends into one all-or-nothing batch behind a
held `BEGIN IMMEDIATE` write lock. Its contract is appends-only: a fresh-
connection read inside the batch would miss the uncommitted appends and contend
with the lock (`SQLITE_BUSY`). These tests pin that the store now *enforces* the
invariant (turning silent contention into a loud error), that the real gate
append paths driven through `route_findings` honour it, and that the batch is
genuinely all-or-nothing on a real on-disk SQLite file.
"""

from __future__ import annotations

import pytest

from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.signoff import SignoffGate
from legis.identity.entity_key import EntityKey
from legis.store.audit_store import AuditStore
from legis.wardline.governor import WardlineCellPolicy, route_findings
from legis.wardline.ingest import active_defects

_CLOCK = "2026-06-02T12:00:00+00:00"


def _on_disk_store(tmp_path, name="g.db") -> AuditStore:
    # A real file, NOT sqlite:///:memory: and NOT shared-cache — so the held
    # BEGIN IMMEDIATE genuinely locks a second connection out (the condition the
    # invariant protects against).
    return AuditStore(f"sqlite:///{tmp_path / name}")


def _scan(n: int) -> dict:
    return {
        "findings": [
            {
                "rule_id": f"PY-WL-{100 + i}",
                "message": f"untrusted reaches trusted #{i}",
                "severity": "ERROR",
                "kind": "defect",
                "fingerprint": f"fp{i}",
                "qualname": f"m.f{i}",
                "properties": {"actual_return": "UNKNOWN_RAW"},
                "suppression_state": "active",
            }
            for i in range(n)
        ]
    }


# --- the guard itself: a read inside a held batch raises, not contends ---

@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.read_all(),
        lambda s: s.read_by_seq(1),
        lambda s: s.verify_integrity(),
        lambda s: s.get_latest_sequence_and_hash(),
    ],
)
def test_read_inside_batch_raises_runtime_error(tmp_path, call):
    store = _on_disk_store(tmp_path)
    store.append({"event": "before"})
    with pytest.raises(RuntimeError, match="active transaction"):
        with store.transaction():
            store.append({"event": "in-batch"})
            call(store)


def test_reads_work_again_after_batch_exits(tmp_path):
    store = _on_disk_store(tmp_path)
    with store.transaction():
        store.append({"event": "a"})
        store.append({"event": "b"})
    # Once the batch commits and the thread-local clears, reads are fine again.
    assert len(store.read_all()) == 2
    assert store.verify_integrity() is True


# --- the real gate append paths, driven through route_findings' batch ---

def test_surface_override_batch_is_read_free_on_disk(tmp_path):
    # EnforcementEngine.submit_override is the append path here. If it (or
    # anything it calls) issued a fresh-connection read inside the batch, the
    # guard would raise; a clean completion proves the path is read-free.
    engine = EnforcementEngine(_on_disk_store(tmp_path), FixedClock(_CLOCK))
    results = route_findings(
        active_defects(_scan(3)),
        policy=WardlineCellPolicy.SURFACE_OVERRIDE,
        agent_id="agent-1",
        resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
        engine=engine,
    )
    assert len(results) == 3
    # All three landed atomically and the chain is intact (reads outside batch).
    assert len(engine.records()) == 3
    assert engine._store.verify_integrity() is True


def test_block_escalate_batch_is_read_free_on_disk(tmp_path):
    # SignoffGate.request is the append path here.
    gate = SignoffGate(_on_disk_store(tmp_path), FixedClock(_CLOCK))
    results = route_findings(
        active_defects(_scan(3)),
        policy=WardlineCellPolicy.BLOCK_ESCALATE,
        agent_id="agent-1",
        resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
        signoff=gate,
    )
    assert len(results) == 3
    assert len(gate.records()) == 3
    assert gate._store.verify_integrity() is True


# --- all-or-nothing on a real file: a mid-batch failure rolls everything back ---

def test_batch_rolls_back_atomically_on_disk(tmp_path):
    store = _on_disk_store(tmp_path)
    store.append({"event": "committed-before-batch"})

    with pytest.raises(RuntimeError, match="boom"):
        with store.transaction():
            store.append({"event": "batch-1"})
            store.append({"event": "batch-2"})
            raise RuntimeError("boom")  # mid-loop failure

    # The two in-batch appends rolled back; only the pre-batch record survives,
    # and the hash chain is unbroken — proving real on-disk atomicity, not a
    # half-written batch.
    records = store.read_all()
    assert [r.payload["event"] for r in records] == ["committed-before-batch"]
    assert store.verify_integrity() is True
