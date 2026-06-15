from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.signoff import SignoffGate
from legis.enforcement.verdict import SignoffState
from legis.identity.entity_key import EntityKey
from legis.store.audit_store import AuditStore
from legis.wardline.governor import WardlineCellPolicy, route_findings
from legis.wardline.ingest import WardlinePayloadError, WardlineSeverity, active_defects


def _scan():
    return {"findings": [
        {"rule_id": "PY-WL-101", "message": "untrusted reaches trusted",
         "severity": "ERROR", "kind": "defect", "fingerprint": "fp1",
         "qualname": "m.f", "properties": {"actual_return": "UNKNOWN_RAW"},
         "suppression_state": "active"},
    ]}


def _engine(tmp_path):
    return EnforcementEngine(AuditStore(f"sqlite:///{tmp_path / 'g.db'}"),
                             FixedClock("2026-06-02T12:00:00+00:00"))


def test_surface_override_cell_records_an_override(tmp_path):
    eng = _engine(tmp_path)
    results = route_findings(
        active_defects(_scan()),
        policy=WardlineCellPolicy.SURFACE_OVERRIDE,
        agent_id="agent-1",
        resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
        engine=eng,
    )
    assert len(results) == 1 and results[0]["mode"] == "surface_override"
    trail = eng.trail()
    assert trail[0]["policy"] == "PY-WL-101"             # Wardline rule_id is the policy
    assert trail[0]["entity_key"]["value"] == "m.f"      # routed on the finding's qualname
    assert "untrusted reaches trusted" in trail[0]["rationale"]


def test_non_tier_diagnostic_properties_are_accepted_and_carried(tmp_path):
    # Properties are write-only evidence (legis never acts on the values), so a
    # non-tier diagnostic is carried verbatim, not rejected — and it lands in the
    # record under "properties" (NOT mislabelled as "tiers").
    eng = _engine(tmp_path)
    scan = _scan()
    scan["findings"][0]["properties"] = {"actual_return": "ROOT", "sink": "os.system"}
    route_findings(
        active_defects(scan),
        policy=WardlineCellPolicy.SURFACE_OVERRIDE,
        agent_id="agent-1",
        resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
        engine=eng,
    )
    ward = eng.trail()[0]["extensions"]["wardline"]
    assert ward["properties"] == {"actual_return": "ROOT", "sink": "os.system"}
    assert "tiers" not in ward


def test_suppressed_defect_without_proof_is_rejected():
    import pytest

    scan = _scan()
    scan["findings"][0]["suppression_state"] = "waived"
    with pytest.raises(WardlinePayloadError, match="suppression proof"):
        active_defects(scan)


def test_surface_override_captures_loomweave_lineage_alongside_wardline(tmp_path):
    # A SEI-keyed wardline-routed override must carry the REQ-L-01 loomweave
    # lineage snapshot (alive/content_hash/lineage_snapshot) merged ALONGSIDE the
    # wardline ext — same as the same override taken via /overrides.
    eng = _engine(tmp_path)
    loomweave_ext = {"loomweave": {"alive": True, "content_hash": "h",
                               "lineage_snapshot": {"length": 1, "hash": "z"}}}
    results = route_findings(
        active_defects(_scan()),
        policy=WardlineCellPolicy.SURFACE_OVERRIDE,
        agent_id="agent-1",
        resolve=lambda q: (EntityKey.from_sei("loomweave:eid:x"), loomweave_ext),
        engine=eng,
    )
    assert results[0]["mode"] == "surface_override"
    ext = eng.trail()[0]["extensions"]
    assert ext["loomweave"] == loomweave_ext["loomweave"]      # lineage snapshot captured
    assert ext["wardline"]["fingerprint"] == "fp1"       # wardline ext still present


def test_route_records_batch_provenance(tmp_path):
    eng = _engine(tmp_path)
    provenance = {"scan_digest": "sha256:abc", "finding_count": 3, "active_count": 1}
    route_findings(
        active_defects(_scan()),
        policy=WardlineCellPolicy.SURFACE_OVERRIDE,
        agent_id="agent-1",
        resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
        engine=eng,
        batch_provenance=provenance,
    )
    wardline = eng.trail()[0]["extensions"]["wardline"]
    assert wardline["scan_digest"] == "sha256:abc"
    assert wardline["finding_count"] == 3
    assert wardline["active_count"] == 1


def test_block_escalate_cell_opens_a_signoff_request(tmp_path):
    store = AuditStore(f"sqlite:///{tmp_path / 'g.db'}")
    gate = SignoffGate(store, FixedClock("2026-06-02T12:00:00+00:00"))
    results = route_findings(
        active_defects(_scan()),
        policy=WardlineCellPolicy.BLOCK_ESCALATE,
        agent_id="agent-1",
        resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
        signoff=gate,
    )
    assert results[0]["mode"] == "block_escalate"
    assert results[0]["cleared"] is False                # a human must sign off

    # The stored side-effect: a PENDING_SIGNOFF request was written, not cleared.
    req_seq = results[0]["seq"]
    assert gate.is_cleared(req_seq) is False
    record = store.read_all()[req_seq - 1].payload
    assert record["policy"] == "PY-WL-101"
    assert record["entity_key"]["value"] == "m.f"
    assert (
        record["extensions"]["signoff_state"] == SignoffState.PENDING.value
    )


def test_block_escalate_captures_loomweave_and_wardline_metadata(tmp_path):
    store = AuditStore(f"sqlite:///{tmp_path / 'g.db'}")
    gate = SignoffGate(store, FixedClock("2026-06-02T12:00:00+00:00"))
    loomweave_ext = {"loomweave": {"alive": True, "content_hash": "h",
                               "lineage_snapshot": {"length": 1, "hash": "z"}}}
    results = route_findings(
        active_defects(_scan()),
        policy=WardlineCellPolicy.BLOCK_ESCALATE,
        agent_id="agent-1",
        resolve=lambda q: (EntityKey.from_sei("loomweave:eid:x"), loomweave_ext),
        signoff=gate,
    )
    record = store.read_all()[results[0]["seq"] - 1].payload
    assert record["extensions"]["loomweave"] == loomweave_ext["loomweave"]
    assert record["extensions"]["wardline"]["fingerprint"] == "fp1"
    assert record["extensions"]["wardline"]["severity"] == "ERROR"


def test_anchored_block_escalate_batch_advances_anchor_after_commit(tmp_path):
    # AUD-1 regression: an anchored SignoffGate routing a block_escalate batch
    # opens signoff.transaction(). The per-append anchor read used to call
    # get_latest_sequence_and_hash() INSIDE the held batch — a batch-forbidden
    # fresh-connection read (Q-M5) that raised, rolling back valid sign-offs.
    # The anchor must instead advance once, after the batch commits.
    from legis.store.head_anchor import HeadAnchor

    key = b"anchor-key-0123456789abcdef01234"
    store = AuditStore(f"sqlite:///{tmp_path / 'g.db'}")
    anchor = HeadAnchor(str(tmp_path / "g.anchor"), key)
    gate = SignoffGate(
        store, FixedClock("2026-06-02T12:00:00+00:00"),
        signer=True, key=key, anchor=anchor,
    )
    results = route_findings(
        active_defects(_multi_scan("fp1", "fp2")),
        policy=WardlineCellPolicy.BLOCK_ESCALATE,
        agent_id="agent-1",
        resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
        signoff=gate,
    )
    assert [r["mode"] for r in results] == ["block_escalate", "block_escalate"]
    # Both requests committed — nothing rolled back.
    records = store.read_all()
    assert len(records) == 2
    # The anchor advanced to the final committed head and verifies against it.
    head_seq, _ = store.get_latest_sequence_and_hash()
    assert head_seq == 2
    anchor.check(records)  # no AnchorError → anchor tracks the committed head


def test_surface_only_records_a_non_gating_event(tmp_path):
    eng = _engine(tmp_path)
    results = route_findings(
        active_defects(_scan()),
        policy=WardlineCellPolicy.SURFACE_ONLY,
        agent_id="agent-1",
        resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
        engine=eng,
    )
    assert results[0]["mode"] == "surface_only"
    assert results[0]["surfaced"] is True
    assert "accepted" not in results[0] and "cleared" not in results[0]
    trail = eng.trail()
    assert trail[0]["kind"] == "wardline_surfaced"
    assert trail[0]["policy"] == "PY-WL-101"
    assert trail[0]["extensions"]["wardline"]["fingerprint"] == "fp1"


def test_surface_only_needs_no_signoff_gate(tmp_path):
    eng = _engine(tmp_path)
    results = route_findings(
        active_defects(_scan()), policy=WardlineCellPolicy.SURFACE_ONLY,
        agent_id="a", resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
        engine=eng, signoff=None)
    assert results[0]["mode"] == "surface_only"


def _mixed_scan():
    def fnd(rule, sev, fp):
        return {"rule_id": rule, "message": "m", "severity": sev, "kind": "defect",
                "fingerprint": fp, "qualname": "m.f", "properties": {}, "suppression_state": "active"}
    return {"findings": [fnd("R-CRIT", "CRITICAL", "c"),
                         fnd("R-WARN", "WARN", "w"),
                         fnd("R-INFO", "INFO", "i")]}


def test_cell_map_routes_each_finding_by_severity(tmp_path):
    eng = _engine(tmp_path)
    cell_map = {
        WardlineSeverity.CRITICAL: WardlineCellPolicy.SURFACE_ONLY,
        WardlineSeverity.WARN: WardlineCellPolicy.SURFACE_OVERRIDE,
        WardlineSeverity.INFO: WardlineCellPolicy.SURFACE_ONLY,
    }
    results = route_findings(
        active_defects(_mixed_scan()), cell_map=cell_map, agent_id="a",
        resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
        engine=eng)
    by_fp = {r["fingerprint"]: r["mode"] for r in results}
    assert by_fp == {"c": "surface_only", "w": "surface_override", "i": "surface_only"}


def test_cross_store_cell_map_is_rejected_before_writes(tmp_path):
    import pytest
    eng = _engine(tmp_path)
    gate_store = AuditStore(f"sqlite:///{tmp_path / 's.db'}")
    gate = SignoffGate(gate_store, FixedClock("2026-06-02T12:00:00+00:00"))
    cell_map = {
        WardlineSeverity.CRITICAL: WardlineCellPolicy.BLOCK_ESCALATE,
        WardlineSeverity.WARN: WardlineCellPolicy.SURFACE_OVERRIDE,
        WardlineSeverity.INFO: WardlineCellPolicy.SURFACE_ONLY,
    }

    with pytest.raises(ValueError, match="split cross-store Wardline batches"):
        route_findings(
            active_defects(_mixed_scan()), cell_map=cell_map, agent_id="a",
            resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
            engine=eng, signoff=gate)

    assert eng.trail() == []
    assert gate_store.read_all() == []


def test_unmapped_severity_in_cell_map_is_rejected_before_writes(tmp_path):
    import pytest
    eng = _engine(tmp_path)
    cell_map = {WardlineSeverity.CRITICAL: WardlineCellPolicy.SURFACE_ONLY}
    with pytest.raises(ValueError, match="unmapped severity"):
        route_findings(
            active_defects(_scan()), cell_map=cell_map, agent_id="a",
            resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}), engine=eng)
    assert eng.trail() == []


def test_exactly_one_of_policy_or_cell_map(tmp_path):
    import pytest
    eng = _engine(tmp_path)
    # neither given → raises
    with pytest.raises(ValueError, match="exactly one"):
        route_findings(active_defects(_scan()), agent_id="a",
                       resolve=lambda q: (EntityKey.from_locator("x"), {}), engine=eng)
    # both given → raises
    with pytest.raises(ValueError, match="exactly one"):
        route_findings(active_defects(_scan()), policy=WardlineCellPolicy.SURFACE_OVERRIDE,
                       cell_map={WardlineSeverity.CRITICAL: WardlineCellPolicy.SURFACE_ONLY},
                       agent_id="a",
                       resolve=lambda q: (EntityKey.from_locator("x"), {}), engine=eng)


def test_surface_only_record_is_orphan_detectable(tmp_path):
    from legis.governance.gaps import find_orphan_gaps
    eng = _engine(tmp_path)
    route_findings(
        active_defects(_scan()), policy=WardlineCellPolicy.SURFACE_ONLY, agent_id="a",
        resolve=lambda q: (EntityKey.from_sei("loomweave:eid:s"),
                           {"loomweave": {"alive": True, "content_hash": "h", "lineage_snapshot": None}}),
        engine=eng)

    class DeadClient:
        def resolve_sei(self, sei):
            return {"sei": sei, "alive": False, "lineage": [{"event": "orphaned"}]}
        def lineage(self, sei):
            return []

    gaps = find_orphan_gaps(eng.records(), DeadClient())
    assert [g.sei for g in gaps] == ["loomweave:eid:s"]  # surfaced record IS orphan-detectable


def test_pre_loop_guard_prevents_partial_application(tmp_path):
    # A heterogeneous cell_map needing block_escalate with no signoff gate must
    # raise BEFORE any finding is written — no partial batch in the ledger.
    import pytest
    eng = _engine(tmp_path)
    cell_map = {
        WardlineSeverity.WARN: WardlineCellPolicy.SURFACE_OVERRIDE,
        WardlineSeverity.CRITICAL: WardlineCellPolicy.BLOCK_ESCALATE,
        WardlineSeverity.INFO: WardlineCellPolicy.SURFACE_ONLY,
    }
    with pytest.raises(ValueError, match="block_escalate cell requires a signoff gate"):
        route_findings(active_defects(_mixed_scan()), cell_map=cell_map, agent_id="a",
                       resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
                       engine=eng, signoff=None)
    assert eng.trail() == []  # nothing written


def _multi_scan(*fingerprints):
    return {"findings": [
        {"rule_id": "PY-WL-101", "message": f"finding {fp}",
         "severity": "ERROR", "kind": "defect", "fingerprint": fp,
         "qualname": f"m.{fp}", "properties": {}, "suppression_state": "active"}
        for fp in fingerprints
    ]}


def test_same_cell_batch_is_atomic_finding_two_failure_rolls_back_finding_one(tmp_path):
    # A mid-batch runtime failure must not leave earlier findings persisted —
    # the whole same-cell batch is one transaction (Q-M5 / audit M3).
    import pytest

    class FailOnSecond(EnforcementEngine):
        def __init__(self, store, clock):
            super().__init__(store, clock)
            self._calls = 0

        def submit_override(self, **kwargs):
            self._calls += 1
            if self._calls == 2:
                raise RuntimeError("simulated mid-batch failure")
            return super().submit_override(**kwargs)

    store = AuditStore(f"sqlite:///{tmp_path / 'g.db'}")
    eng = FailOnSecond(store, FixedClock("2026-06-02T12:00:00+00:00"))

    with pytest.raises(RuntimeError, match="simulated mid-batch failure"):
        route_findings(
            active_defects(_multi_scan("fp1", "fp2", "fp3")),
            policy=WardlineCellPolicy.SURFACE_OVERRIDE,
            agent_id="agent-1",
            resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
            engine=eng,
        )

    # Finding 1's append must have been rolled back: the trail is empty.
    assert store.read_all() == []


def test_same_cell_batch_commits_all_on_success(tmp_path):
    store = AuditStore(f"sqlite:///{tmp_path / 'g.db'}")
    eng = EnforcementEngine(store, FixedClock("2026-06-02T12:00:00+00:00"))
    results = route_findings(
        active_defects(_multi_scan("fp1", "fp2", "fp3")),
        policy=WardlineCellPolicy.SURFACE_OVERRIDE,
        agent_id="agent-1",
        resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
        engine=eng,
    )
    assert [r["fingerprint"] for r in results] == ["fp1", "fp2", "fp3"]
    assert len(store.read_all()) == 3
