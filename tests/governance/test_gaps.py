from legis.canonical import content_hash
from legis.governance.gaps import (
    LineageDivergence,
    LineageUnavailable,
    find_lineage_integrity,
    find_lineage_divergence,
    find_orphan_gaps,
)
from legis.store.audit_store import AuditStore


def _store(tmp_path, *payloads):
    s = AuditStore(f"sqlite:///{tmp_path / 'g.db'}")
    for p in payloads:
        s.append(p)
    return s


def _rec(sei, *, identity_stable=True, snapshot=None):
    ext = {"loomweave": {"lineage_snapshot": snapshot}} if snapshot else {}
    return {"policy": "p", "entity_key": {"value": sei, "identity_stable": identity_stable},
            "rationale": "r", "agent_id": "a", "recorded_at": "t",
            "identity_stable": identity_stable, "extensions": ext}


class FakeClient:
    def __init__(self, sei_status, lineages=None):
        self._status = sei_status          # {sei: {"alive": bool, "lineage": [...]}}
        self._lineages = lineages or {}    # {sei: [events]}

    def resolve_sei(self, sei):
        return {"sei": sei, **self._status.get(sei, {"alive": True})}

    def lineage(self, sei):
        return self._lineages.get(sei, [])


class BrokenLineageClient(FakeClient):
    def lineage(self, sei):
        raise RuntimeError("loomweave down")


class ResolveFailsClient(FakeClient):
    def resolve_sei(self, sei):
        from legis.identity.loomweave_client import LoomweaveError

        raise LoomweaveError("GET /identity/sei timed out")


def test_orphaned_sei_surfaces_a_gap(tmp_path):
    store = _store(tmp_path, _rec("loomweave:eid:alive"), _rec("loomweave:eid:dead"))
    client = FakeClient({
        "loomweave:eid:alive": {"alive": True},
        "loomweave:eid:dead": {"alive": False, "lineage": [{"event": "orphaned"}]},
    })
    gaps = find_orphan_gaps(store.read_all(), client)
    assert [g.sei for g in gaps] == ["loomweave:eid:dead"]
    assert gaps[0].lineage == [{"event": "orphaned"}]


def test_locator_keyed_records_are_not_probed(tmp_path):
    store = _store(tmp_path, _rec("python:function:x", identity_stable=False))
    gaps = find_orphan_gaps(store.read_all(), FakeClient({}))
    assert gaps == []   # nothing stable to probe → no gap, no crash


def test_appended_lineage_is_not_divergence(tmp_path):
    born = [{"event": "born"}]
    snap = {"length": 1, "hash": content_hash(born)}
    store = _store(tmp_path, _rec("loomweave:eid:s", snapshot=snap))
    grown = born + [{"event": "locator_changed"}]   # legitimate append
    div = find_lineage_divergence(store.read_all(), FakeClient({}, {"loomweave:eid:s": grown}))
    assert div == []


def test_truncated_or_mutated_prefix_is_divergence(tmp_path):
    born = [{"event": "born"}, {"event": "moved"}]
    snap = {"length": 2, "hash": content_hash(born)}
    store = _store(tmp_path, _rec("loomweave:eid:s", snapshot=snap))
    tampered = [{"event": "born"}]   # the 'moved' event vanished — prefix broken
    div = find_lineage_divergence(store.read_all(), FakeClient({}, {"loomweave:eid:s": tampered}))
    assert div == [LineageDivergence(sei="loomweave:eid:s", recorded_length=2, current_length=1)]


def test_lineage_integrity_reports_unavailable_fetches(tmp_path):
    born = [{"event": "born"}]
    snap = {"length": 1, "hash": content_hash(born)}
    store = _store(tmp_path, _rec("loomweave:eid:s", snapshot=snap))
    integrity = find_lineage_integrity(store.read_all(), BrokenLineageClient({}))
    assert integrity.divergences == []
    assert integrity.unavailable == [
        LineageUnavailable(sei="loomweave:eid:s", reason="lineage_fetch_failed")
    ]


def test_lineage_integrity_reports_missing_snapshot_as_unverified(tmp_path):
    store = _store(tmp_path, _rec("loomweave:eid:s"))
    integrity = find_lineage_integrity(store.read_all(), FakeClient({}))
    assert integrity.divergences == []
    assert integrity.unavailable == [
        LineageUnavailable(sei="loomweave:eid:s", reason="missing_snapshot")
    ]


def test_explicit_null_entity_key_does_not_crash_stable_seis(tmp_path):
    # A directly-written record with `entity_key: null` must not raise
    # AttributeError out of the read path (Q-L1).
    store = _store(
        tmp_path,
        {"policy": "p", "entity_key": None, "rationale": "r",
         "agent_id": "a", "recorded_at": "t", "extensions": {}},
        _rec("loomweave:eid:alive"),
    )
    gaps = find_orphan_gaps(store.read_all(), FakeClient({"loomweave:eid:alive": {"alive": True}}))
    assert gaps == []  # null row ignored, alive row probed → no crash


def test_explicit_null_entity_key_does_not_crash_lineage_integrity(tmp_path):
    store = _store(
        tmp_path,
        {"policy": "p", "entity_key": None, "rationale": "r",
         "agent_id": "a", "recorded_at": "t", "extensions": {}},
    )
    result = find_lineage_integrity(store.read_all(), FakeClient({}))
    assert result.divergences == []
    assert result.unavailable == []


def test_identity_gap_read_degrades_to_unavailable_on_loomweave_error(tmp_path):
    # GOV-2: a transient Loomweave failure during the check must surface as
    # status "unavailable", not escape as INTERNAL_ERROR — the read exists to
    # distinguish "could not check" from a checked-empty gap list.
    from types import SimpleNamespace

    from legis.service.governance import read_identity_gaps

    store = _store(tmp_path, _rec("loomweave:eid:s"))
    identity = SimpleNamespace(client=ResolveFailsClient({}))
    result = read_identity_gaps(identity, store.read_all)
    assert result["status"] == "unavailable"
    assert result["gaps"] == []
    assert "loomweave check failed" in result["unavailable"][0]["reason"]
