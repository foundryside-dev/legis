import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from legis.api.app import create_app
from legis.canonical import canonical_json, content_hash
from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.protected import TrailVerifier
from legis.enforcement.signoff import SignoffGate
from legis.crypto.signing import sign
from legis.identity.entity_key import EntityKey
from legis.store.audit_store import GENESIS, AuditStore, _chain
from legis.wardline.ingest import wardline_artifact_fields

pytestmark = pytest.mark.usefixtures("unsafe_dev_defaults")


def _client(tmp_path, **kw):
    eng = EnforcementEngine(AuditStore(f"sqlite:///{tmp_path / 'g.db'}"),
                            FixedClock("2026-06-02T12:00:00+00:00"))
    return TestClient(create_app(enforcement=eng, **kw))


class _FakeFiligree:
    def __init__(self):
        self.attached = []

    def attach(self, issue_id, entity_id, content_hash, *, actor,
               signoff_seq=None, signature=None):
        self.attached.append(
            (issue_id, entity_id, content_hash, actor, signoff_seq, signature)
        )
        return {"issue_id": issue_id, "loomweave_entity_id": entity_id,
                "content_hash_at_attach": content_hash, "attached_at": "t",
                "attached_by": actor}

    def associations_for_entity(self, entity_id):
        return []


def _tamper_first_record(db, mutate):
    con = sqlite3.connect(db)
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    seq, payload = con.execute(
        "SELECT seq, payload FROM audit_log ORDER BY seq ASC LIMIT 1"
    ).fetchone()
    p = json.loads(payload)
    mutate(p)
    con.execute("UPDATE audit_log SET payload=? WHERE seq=?", (canonical_json(p), seq))
    prev = GENESIS
    for s, pl in con.execute(
        "SELECT seq, payload FROM audit_log ORDER BY seq ASC"
    ).fetchall():
        ch = content_hash(json.loads(pl))
        con.execute(
            "UPDATE audit_log SET content_hash=?, prev_hash=?, chain_hash=? WHERE seq=?",
            (ch, prev, _chain(prev, ch), s),
        )
        prev = _chain(prev, ch)
    con.commit()
    con.close()


def test_scan_results_route_surface_override(tmp_path):
    c = _client(tmp_path)
    body = {"cell": "surface_override", "agent_id": "agent-1", "scan": {"findings": [
        {"rule_id": "PY-WL-101", "message": "untrusted reaches trusted",
         "severity": "ERROR", "kind": "defect", "fingerprint": "fp1",
         "qualname": "m.f", "properties": {}, "suppression_state": "active"}]}}
    resp = c.post("/wardline/scan-results", json=body)
    assert resp.status_code == 200
    assert resp.json()["routed"][0]["mode"] == "surface_override"
    assert c.get("/overrides").json()[0]["policy"] == "PY-WL-101"


def test_bind_issue_endpoint_attaches_sei_from_cleared_record(tmp_path):
    # Binding is governed: the SEI and content_hash come from the recorded,
    # CLEARED sign-off — never from the caller. The caller supplies only issue_id.
    fil = _FakeFiligree()
    gate = SignoffGate(AuditStore(f"sqlite:///{tmp_path / 'sg.db'}"),
                       FixedClock("2026-06-02T12:00:00+00:00"))
    req = gate.request(
        policy="PY-WL-101",
        entity_key=EntityKey.from_sei("loomweave:eid:abc"),
        rationale="needs a human",
        agent_id="agent-1",
    )
    gate.sign_off(request_seq=req.seq, operator_id="operator-1")

    c = _client(tmp_path, filigree=fil, signoff_gate=gate)
    resp = c.post(f"/signoff/{req.seq}/bind-issue", json={"issue_id": "ISSUE-1"})

    assert resp.status_code == 201
    assert resp.json()["loomweave_entity_id"] == "loomweave:eid:abc"
    # SEI sourced from the trail; content_hash is "" because request() records no
    # loomweave ext — the honest behaviour of the real record.
    assert fil.attached == [("ISSUE-1", "loomweave:eid:abc", "", "legis", req.seq, None)]


def test_bind_issue_endpoint_maps_filigree_failure_to_502(tmp_path):
    # Filigree wired but down/redirecting/malformed: nothing bound, recoverable.
    # The route must surface a typed 502 (parity with the MCP adapter's
    # FILIGREE_UNAVAILABLE), not let FiligreeError escape as an untyped 500.
    from legis.filigree.client import FiligreeError

    class _DownFiligree(_FakeFiligree):
        def attach(self, *a, **k):
            raise FiligreeError("POST /attach connection refused")

    gate = SignoffGate(AuditStore(f"sqlite:///{tmp_path / 'sg.db'}"),
                       FixedClock("2026-06-02T12:00:00+00:00"))
    req = gate.request(
        policy="PY-WL-101",
        entity_key=EntityKey.from_sei("loomweave:eid:abc"),
        rationale="needs a human",
        agent_id="agent-1",
    )
    gate.sign_off(request_seq=req.seq, operator_id="operator-1")

    c = _client(tmp_path, filigree=_DownFiligree(), signoff_gate=gate)
    resp = c.post(f"/signoff/{req.seq}/bind-issue", json={"issue_id": "ISSUE-1"})

    assert resp.status_code == 502
    assert "filigree unavailable" in resp.json()["detail"]


def test_bind_issue_endpoint_uses_resolved_backfill_for_locator_keyed_request(tmp_path):
    fil = _FakeFiligree()
    store = AuditStore(f"sqlite:///{tmp_path / 'sg.db'}")
    gate = SignoffGate(store, FixedClock("2026-06-02T12:00:00+00:00"))
    req = gate.request(
        policy="PY-WL-101",
        entity_key=EntityKey.from_locator("python:function:m.f"),
        rationale="needs a human",
        agent_id="agent-1",
    )
    gate.sign_off(request_seq=req.seq, operator_id="operator-1")
    store.append(
        {
            "event": "SEI_BACKFILL",
            "original_seq": req.seq,
            "entity_key": EntityKey.from_sei("loomweave:eid:abc").to_dict(),
            "identity_stable": True,
            "agent_id": "legis-sei-backfill",
            "recorded_at": "2026-06-04T12:00:00+00:00",
            "extensions": {
                "loomweave": {
                    "alive": True,
                    "content_hash": "hash-abc",
                    "lineage_snapshot": {"length": 1, "hash": "lineage"},
                    "identity_resolution_status": "resolved",
                    "lineage_snapshot_status": "verified",
                },
                "backfill": {
                    "source": "pre_sei_locator",
                    "original_seq": req.seq,
                    "original_entity_key": EntityKey.from_locator("python:function:m.f").to_dict(),
                },
            },
        }
    )

    c = _client(tmp_path, filigree=fil, signoff_gate=gate)
    resp = c.post(f"/signoff/{req.seq}/bind-issue", json={"issue_id": "ISSUE-1"})

    assert resp.status_code == 201
    assert resp.json()["loomweave_entity_id"] == "loomweave:eid:abc"
    assert fil.attached == [
        ("ISSUE-1", "loomweave:eid:abc", "hash-abc", "legis", req.seq, None)
    ]


def test_bind_issue_endpoint_transmits_hmac_binding_signature(tmp_path):
    from legis.crypto.signing import verify

    key = b"k" * 32
    fil = _FakeFiligree()
    gate = SignoffGate(AuditStore(f"sqlite:///{tmp_path / 'sg.db'}"),
                       FixedClock("2026-06-02T12:00:00+00:00"))
    req = gate.request(
        policy="PY-WL-101",
        entity_key=EntityKey.from_sei("loomweave:eid:abc"),
        rationale="needs a human",
        agent_id="agent-1",
        extensions={"loomweave": {"content_hash": "blake3"}},
    )
    gate.sign_off(request_seq=req.seq, operator_id="operator-1")

    c = _client(tmp_path, filigree=fil, signoff_gate=gate, binding_key=key)
    resp = c.post(f"/signoff/{req.seq}/bind-issue", json={"issue_id": "ISSUE-1"})

    assert resp.status_code == 201
    sig = resp.json()["binding_signature"]
    assert verify(
        {
            "issue_id": "ISSUE-1",
            "entity_id": "loomweave:eid:abc",
            "content_hash": "blake3",
            "signoff_seq": req.seq,
        },
        sig,
        key,
    )
    assert fil.attached == [
        ("ISSUE-1", "loomweave:eid:abc", "blake3", "legis", req.seq, sig)
    ]


def test_bind_issue_endpoint_rejects_uncleared_request(tmp_path):
    fil = _FakeFiligree()
    gate = SignoffGate(AuditStore(f"sqlite:///{tmp_path / 'sg.db'}"),
                       FixedClock("2026-06-02T12:00:00+00:00"))
    req = gate.request(
        policy="PY-WL-101",
        entity_key=EntityKey.from_sei("loomweave:eid:abc"),
        rationale="needs a human",
        agent_id="agent-1",
    )
    # Not signed off → not cleared.
    c = _client(tmp_path, filigree=fil, signoff_gate=gate)
    resp = c.post(f"/signoff/{req.seq}/bind-issue", json={"issue_id": "ISSUE-1"})

    assert resp.status_code == 409
    assert "not cleared" in resp.json()["detail"]
    assert fil.attached == []


def test_bind_issue_endpoint_404_for_missing_request(tmp_path):
    fil = _FakeFiligree()
    gate = SignoffGate(AuditStore(f"sqlite:///{tmp_path / 'sg.db'}"),
                       FixedClock("2026-06-02T12:00:00+00:00"))
    c = _client(tmp_path, filigree=fil, signoff_gate=gate)
    resp = c.post("/signoff/99/bind-issue", json={"issue_id": "ISSUE-1"})

    assert resp.status_code == 404
    assert fil.attached == []


def test_bind_issue_records_to_ledger_and_binding_is_verifiable(tmp_path):
    from legis.governance.binding_ledger import BindingLedger

    clock = FixedClock("2026-06-02T12:00:00+00:00")
    sg = SignoffGate(AuditStore(f"sqlite:///{tmp_path / 'gov.db'}"), clock)
    ledger = BindingLedger(AuditStore(f"sqlite:///{tmp_path / 'bind.db'}"), clock, key=b"k")
    fil = _FakeFiligree()
    c = _client(tmp_path, signoff_gate=sg, filigree=fil, binding_ledger=ledger)

    sg.request(policy="prod-deploy", entity_key=EntityKey.from_sei("loomweave:eid:abc"),
               rationale="r", agent_id="a",
               extensions={"loomweave": {"content_hash": "blake3", "alive": True,
                                       "lineage_snapshot": None}})
    sg.sign_off(request_seq=1, operator_id="op-1")

    # The body's content_hash is attacker-supplied and must NOT win: the SEI and
    # content_hash come from the CLEARED sign-off record ("blake3"), never the body.
    resp = c.post("/signoff/1/bind-issue",
                  json={"issue_id": "ISSUE-1", "sei": "loomweave:eid:abc",
                        "content_hash": "ATTACKER-SUPPLIED"})
    assert resp.status_code == 201
    assert resp.json()["binding_seq"] == 1
    # Full tuple: the cleared "blake3" wins at index [2], NOT "ATTACKER-SUPPLIED".
    assert fil.attached[0] == ("ISSUE-1", "loomweave:eid:abc", "blake3", "legis", 1, None)

    got = c.get("/signoff/1/binding")
    assert got.status_code == 200
    assert got.json()["issue_id"] == "ISSUE-1"
    assert got.json()["entity_key"]["value"] == "loomweave:eid:abc"
    # The recorded binding reflects the cleared content_hash, not the body's.
    assert got.json()["content_hash"] == "blake3"


def test_bind_issue_fails_closed_on_tampered_signed_signoff_request(tmp_path):
    fil = _FakeFiligree()
    db = tmp_path / "sg.db"
    gate = SignoffGate(
        AuditStore(f"sqlite:///{db}"),
        FixedClock("2026-06-02T12:00:00+00:00"),
        signer=True,
        key=b"k",
    )
    req = gate.request(
        policy="prod-deploy",
        entity_key=EntityKey.from_sei("loomweave:eid:abc"),
        rationale="r",
        agent_id="a",
        extensions={"loomweave": {"content_hash": "blake3", "alive": True,
                                "lineage_snapshot": {"length": 1, "hash": "lh"}}},
    )
    gate.sign_off(request_seq=req.seq, operator_id="op-1")
    _tamper_first_record(
        db,
        lambda p: p["extensions"]["loomweave"].update({"content_hash": "forged"}),
    )
    c = _client(
        tmp_path,
        signoff_gate=gate,
        filigree=fil,
        trail_verifier=TrailVerifier(b"k", frozenset()),
    )

    resp = c.post(f"/signoff/{req.seq}/bind-issue", json={"issue_id": "ISSUE-1"})

    assert resp.status_code == 500
    assert fil.attached == []


def test_binding_read_404_when_no_ledger(tmp_path):
    c = _client(tmp_path)
    assert c.get("/signoff/1/binding").status_code == 404


def test_binding_read_500_on_forged_record(tmp_path):
    # Fail-closed at read time: a forged binding row whose HMAC does not verify
    # is an honest integrity 500, never silently returned (WP-A3 exit criterion).
    from legis.governance.binding_ledger import BindingLedger

    store = AuditStore(f"sqlite:///{tmp_path / 'bind.db'}")
    ledger = BindingLedger(store, FixedClock("2026-06-02T12:00:00+00:00"), key=b"k")
    store.append({"kind": "issue_binding", "signoff_seq": 1, "issue_id": "I",
                  "entity_key": {"value": "loomweave:eid:x", "identity_stable": True},
                  "content_hash": "h", "recorded_at": "t",
                  "binding_signature": "hmac-sha256:v1:deadbeef"})
    c = _client(tmp_path, binding_ledger=ledger)
    assert c.get("/signoff/1/binding").status_code == 500


def test_scan_results_surface_only_records_non_gating(tmp_path):
    c = _client(tmp_path)
    body = {"cell": "surface_only", "agent_id": "agent-1", "scan": {"findings": [
        {"rule_id": "PY-WL-101", "message": "m", "severity": "INFO", "kind": "defect",
         "fingerprint": "fp1", "qualname": "m.f", "properties": {}, "suppression_state": "active"}]}}
    resp = c.post("/wardline/scan-results", json=body)
    assert resp.status_code == 200
    assert resp.json()["routed"][0]["mode"] == "surface_only"
    trail = c.get("/overrides").json()
    assert trail[0]["kind"] == "wardline_surfaced"
    assert trail[0]["extensions"]["wardline"]["finding_count"] == 1
    assert trail[0]["extensions"]["wardline"]["active_count"] == 1
    assert trail[0]["extensions"]["wardline"]["scan_digest"].startswith("sha256:")


def test_scan_results_cell_by_severity_routes_per_finding(tmp_path):
    c = _client(tmp_path)
    body = {"agent_id": "a",
            "cell_by_severity": {"CRITICAL": "surface_override", "INFO": "surface_only"},
            "scan": {"findings": [
                {"rule_id": "R-C", "message": "m", "severity": "CRITICAL", "kind": "defect",
                 "fingerprint": "c", "qualname": "m.f", "properties": {}, "suppression_state": "active"},
                {"rule_id": "R-I", "message": "m", "severity": "INFO", "kind": "defect",
                 "fingerprint": "i", "qualname": "m.g", "properties": {}, "suppression_state": "active"}]}}
    resp = c.post("/wardline/scan-results", json=body)
    assert resp.status_code == 200
    modes = {r["fingerprint"]: r["mode"] for r in resp.json()["routed"]}
    assert modes == {"c": "surface_override", "i": "surface_only"}


def test_scan_results_fail_on_routes_threshold_per_finding(tmp_path):
    c = _client(tmp_path)
    body = {"agent_id": "a", "cell": "surface_override", "fail_on": "ERROR",
            "scan": {"findings": [
                {"rule_id": "R-E", "message": "m", "severity": "ERROR", "kind": "defect",
                 "fingerprint": "e", "qualname": "m.f", "properties": {}, "suppression_state": "active"},
                {"rule_id": "R-W", "message": "m", "severity": "WARN", "kind": "defect",
                 "fingerprint": "w", "qualname": "m.g", "properties": {}, "suppression_state": "active"}]}}
    resp = c.post("/wardline/scan-results", json=body)
    assert resp.status_code == 200
    routed = {r["fingerprint"]: r for r in resp.json()["routed"]}
    assert {fp: r["mode"] for fp, r in routed.items()} == {
        "e": "surface_override",
        "w": "surface_only",
    }
    trail = c.get("/overrides").json()
    assert len(trail) == 2
    by_policy = {row["policy"]: row for row in trail}
    assert by_policy["R-E"]["extensions"]["wardline"]["fingerprint"] == "e"
    assert by_policy["R-W"]["kind"] == "wardline_surfaced"


def test_scan_results_unknown_fail_on_is_422(tmp_path):
    c = _client(tmp_path)
    body = {"agent_id": "a", "cell": "surface_only", "fail_on": "SEVERE",
            "scan": {"findings": [
                {"rule_id": "R-W", "message": "m", "severity": "WARN", "kind": "defect",
                 "fingerprint": "w", "qualname": "m.g", "properties": {}, "suppression_state": "active"}]}}

    resp = c.post("/wardline/scan-results", json=body)

    assert resp.status_code == 422
    assert "SEVERE" in resp.json()["detail"]


def test_scan_results_block_escalate_without_gate_is_409(tmp_path):
    # cell_by_severity needing block_escalate but no signoff_gate wired → pre-loop guard → 409
    c = _client(tmp_path)  # no signoff_gate
    body = {"agent_id": "a", "cell_by_severity": {"CRITICAL": "block_escalate"},
            "scan": {"findings": [
                {"rule_id": "R-C", "message": "m", "severity": "CRITICAL", "kind": "defect",
                 "fingerprint": "c", "qualname": "m.f", "properties": {}, "suppression_state": "active"}]}}
    assert c.post("/wardline/scan-results", json=body).status_code == 409


def test_scan_results_rejects_both_or_neither_cell_form(tmp_path):
    c = _client(tmp_path)
    base = {"agent_id": "a", "scan": {"findings": []}}
    assert c.post("/wardline/scan-results", json=base).status_code == 422  # neither
    assert c.post("/wardline/scan-results",
                  json={**base, "cell": "surface_only",
                        "cell_by_severity": {"INFO": "surface_only"}}).status_code == 422  # both


def test_scan_results_block_escalate_only_needs_no_engine(tmp_path):
    # A pure block_escalate scan must route with only a signoff gate wired — no
    # enforcement engine, so engine()'s lazy .weft/legis/legis-governance.db is never created.
    sg = SignoffGate(AuditStore(f"sqlite:///{tmp_path / 's.db'}"),
                     FixedClock("2026-06-02T12:00:00+00:00"))
    c = TestClient(create_app(signoff_gate=sg))  # NOT _client: no enforcement injected
    body = {"cell": "block_escalate", "agent_id": "a", "scan": {"findings": [
        {"rule_id": "R-C", "message": "m", "severity": "CRITICAL", "kind": "defect",
         "fingerprint": "c", "qualname": "m.f", "properties": {}, "suppression_state": "active"}]}}
    resp = c.post("/wardline/scan-results", json=body)
    assert resp.status_code == 200
    assert resp.json()["routed"][0]["mode"] == "block_escalate"


def test_scan_results_empty_cell_by_severity_is_422(tmp_path):
    c = _client(tmp_path)
    body = {"agent_id": "a", "cell_by_severity": {}, "scan": {"findings": []}}
    assert c.post("/wardline/scan-results", json=body).status_code == 422


def test_scan_results_rejects_malformed_findings_without_writing(tmp_path):
    c = _client(tmp_path)
    for scan in (
        {"findings": "not-a-list"},
        {"findings": [{"message": "missing rule", "severity": "ERROR", "kind": "defect",
                       "fingerprint": "fp", "qualname": "m.f"}]},
        {"findings": [{"rule_id": "R", "message": "bad severity", "severity": "BOGUS",
                       "kind": "defect", "fingerprint": "fp", "qualname": "m.f"}]},
    ):
        resp = c.post("/wardline/scan-results",
                      json={"cell": "surface_override", "agent_id": "agent-1", "scan": scan})
        assert resp.status_code == 422
    assert c.get("/overrides").json() == []


def test_scan_results_rejects_suppressed_defect_without_proof(tmp_path):
    c = _client(tmp_path)
    scan = {"findings": [
        {"rule_id": "R-C", "message": "m", "severity": "CRITICAL", "kind": "defect",
         "fingerprint": "c", "qualname": "m.f", "properties": {}, "suppression_state": "waived"}
    ]}
    resp = c.post("/wardline/scan-results",
                  json={"cell": "surface_only", "agent_id": "a", "scan": scan})
    assert resp.status_code == 422
    assert c.get("/overrides").json() == []


def test_scan_results_accepts_diagnostic_properties(tmp_path):
    # Realistic Wardline findings carry diagnostics (sink, callee, markers) in
    # properties alongside trust tiers. legis accepts them at the wire — it
    # records properties verbatim and never constrains the values to the tier
    # vocabulary (which would 422 every real scan).
    c = _client(tmp_path)
    scan = {"findings": [
        {"rule_id": "R-C", "message": "m", "severity": "CRITICAL", "kind": "defect",
         "fingerprint": "c", "qualname": "m.f",
         "properties": {"sink": "os.system", "actual_return": "UNKNOWN_RAW"},
         "suppression_state": "active"}
    ]}
    resp = c.post("/wardline/scan-results",
                  json={"cell": "surface_override", "agent_id": "a", "scan": scan})
    assert resp.status_code == 200
    assert resp.json()["routed"][0]["mode"] == "surface_override"
    assert len(c.get("/overrides").json()) == 1     # accepted + written, not 422'd


def test_scan_results_rejects_oversized_finding_batch_without_writing(tmp_path):
    c = _client(tmp_path)
    finding = {"rule_id": "R", "message": "m", "severity": "INFO", "kind": "defect",
               "fingerprint": "fp", "qualname": "m.f", "properties": {},
               "suppression_state": "active"}
    scan = {"findings": [{**finding, "fingerprint": f"fp-{i}"} for i in range(501)]}
    resp = c.post("/wardline/scan-results",
                  json={"cell": "surface_only", "agent_id": "a", "scan": scan})
    assert resp.status_code == 422
    assert c.get("/overrides").json() == []


def test_scan_results_server_owned_routing_rejects_request_routing(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    c = _client(tmp_path)
    body = {"cell": "surface_override", "agent_id": "a", "scan": {"findings": [
        {"rule_id": "R", "message": "m", "severity": "INFO", "kind": "defect",
         "fingerprint": "fp", "qualname": "m.f", "properties": {}, "suppression_state": "active"}
    ]}}
    resp = c.post("/wardline/scan-results", json=body)
    assert resp.status_code == 403
    assert "server-owned" in resp.json()["detail"]


def test_scan_results_default_rejects_request_owned_routing(tmp_path, monkeypatch):
    monkeypatch.delenv("LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING", raising=False)
    c = _client(tmp_path)
    body = {"cell": "surface_only", "agent_id": "a", "scan": {"findings": [
        {"rule_id": "R", "message": "m", "severity": "INFO", "kind": "defect",
         "fingerprint": "fp", "qualname": "m.f", "properties": {}, "suppression_state": "active"}
    ]}}

    resp = c.post("/wardline/scan-results", json=body)

    assert resp.status_code == 403
    assert "server-owned" in resp.json()["detail"]


def test_scan_results_can_use_server_owned_single_cell(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    c = _client(tmp_path)
    body = {"agent_id": "a", "scan": {"findings": [
        {"rule_id": "R", "message": "m", "severity": "INFO", "kind": "defect",
         "fingerprint": "fp", "qualname": "m.f", "properties": {}, "suppression_state": "active"}
    ]}}
    resp = c.post("/wardline/scan-results", json=body)
    assert resp.status_code == 200
    assert resp.json()["routed"][0]["mode"] == "surface_only"


def _signed_wardline_scan(scan, key=b"wardline-key"):
    return {
        **scan,
        "artifact_signature": sign(wardline_artifact_fields(scan), key),
    }


def test_scan_results_requires_signed_artifact_when_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_WARDLINE_ARTIFACT_KEY", "wardline-key")
    c = _client(tmp_path)
    scan = {
        "scanner_identity": "wardline@1",
        "rule_set_version": "rules@abc123",
        "commit_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "findings": [
            {"rule_id": "R", "message": "m", "severity": "INFO", "kind": "defect",
             "fingerprint": "fp", "qualname": "m.f", "properties": {}, "suppression_state": "active"}
        ],
    }

    resp = c.post("/wardline/scan-results",
                  json={"cell": "surface_only", "agent_id": "a", "scan": scan})

    assert resp.status_code == 422
    assert "artifact signature" in resp.json()["detail"]
    assert c.get("/overrides").json() == []


def test_scan_results_records_verified_artifact_provenance(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_WARDLINE_ARTIFACT_KEY", "wardline-key")
    c = _client(tmp_path)
    scan = _signed_wardline_scan({
        "scanner_identity": "wardline@1",
        "rule_set_version": "rules@abc123",
        "commit_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "findings": [
            {"rule_id": "R", "message": "m", "severity": "INFO", "kind": "defect",
             "fingerprint": "fp", "qualname": "m.f", "properties": {}, "suppression_state": "active"}
        ],
    })

    resp = c.post("/wardline/scan-results",
                  json={"cell": "surface_only", "agent_id": "a", "scan": scan})

    assert resp.status_code == 200
    wardline = c.get("/overrides").json()[0]["extensions"]["wardline"]
    assert wardline["artifact_status"] == "verified"
    assert wardline["scanner_identity"] == "wardline@1"
    assert wardline["rule_set_version"] == "rules@abc123"
    assert wardline["commit_sha"] == "a" * 40
    assert wardline["tree_sha"] == "b" * 40
    assert wardline["artifact_signature"].startswith("hmac-sha256:v2:")


def _dirty_wardline_scan():
    return {
        "scanner_identity": "wardline@1.0.0rc1",
        "rule_set_version": "rules@abc123",
        "commit_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "dirty": True,
        "findings": [
            {"rule_id": "R", "message": "m", "severity": "INFO", "kind": "defect",
             "fingerprint": "fp", "qualname": "m.f", "properties": {}, "suppression_state": "active"}
        ],
    }


def test_scan_results_dirty_tree_is_error_skip_not_success(tmp_path, monkeypatch):
    # P1: key configured, dirty + unsigned, no dev-mode -> typed
    # SKIPPED_DIRTY_TREE, but as a non-2xx result because nothing was governed.
    monkeypatch.setenv("LEGIS_WARDLINE_ARTIFACT_KEY", "wardline-key")
    monkeypatch.delenv("LEGIS_WARDLINE_ALLOW_DIRTY", raising=False)
    c = _client(tmp_path)

    resp = c.post("/wardline/scan-results",
                  json={"cell": "surface_only", "agent_id": "a",
                        "scan": _dirty_wardline_scan()})

    assert resp.status_code == 409
    body = resp.json()
    assert body["outcome"] == "SKIPPED_DIRTY_TREE"
    assert body["routed"] == []
    assert c.get("/overrides").json() == []
    # N4: HTTP body carries the same structured, actionable fields as MCP
    # (both single-sourced on WardlineDirtyTreeError.to_payload()).
    assert body["reason"] == "SKIPPED_DIRTY_TREE"
    assert body["posture"] == "ci_artifact_key_configured"
    assert body["cause"] == "dirty_unsigned_artifact"
    assert "LEGIS_WARDLINE_ALLOW_DIRTY" in " ".join(body["remediation"])


def test_scan_results_dirty_tree_governs_under_devmode_optin(tmp_path, monkeypatch):
    # P0: the explicit dev-mode opt-in governs the unsigned dirty artifact,
    # recorded honestly as artifact_status="dirty".
    monkeypatch.setenv("LEGIS_WARDLINE_ARTIFACT_KEY", "wardline-key")
    monkeypatch.setenv("LEGIS_WARDLINE_ALLOW_DIRTY", "1")
    c = _client(tmp_path)

    resp = c.post("/wardline/scan-results",
                  json={"cell": "surface_only", "agent_id": "a",
                        "scan": _dirty_wardline_scan()})

    assert resp.status_code == 200
    assert resp.json()["outcome"] == "ROUTED"
    wardline = c.get("/overrides").json()[0]["extensions"]["wardline"]
    assert wardline["artifact_status"] == "dirty"
    assert "artifact_signature" not in wardline


def test_scan_results_devmode_optin_is_strict_and_fails_safe(tmp_path, monkeypatch):
    # The dev-mode opt-in is `LEGIS_WARDLINE_ALLOW_DIRTY == "1"` exactly. A
    # governing knob that gates UNSIGNED artifacts must fail safe: any value other
    # than "1" (truthy-looking "true", "0", "yes") must NOT govern — it stays a
    # typed recoverable failure. Pins the strict parse against a future drift to truthiness.
    monkeypatch.setenv("LEGIS_WARDLINE_ARTIFACT_KEY", "wardline-key")
    for value in ("0", "true", "True", "yes", "2", ""):
        monkeypatch.setenv("LEGIS_WARDLINE_ALLOW_DIRTY", value)
        c = _client(tmp_path)
        resp = c.post("/wardline/scan-results",
                      json={"cell": "surface_only", "agent_id": "a",
                            "scan": _dirty_wardline_scan()})
        assert resp.status_code == 409, value
        assert resp.json()["outcome"] == "SKIPPED_DIRTY_TREE", value
        assert resp.json()["routed"] == [], value


def test_scan_results_single_cell_still_works(tmp_path):
    c = _client(tmp_path)
    body = {"cell": "surface_override", "agent_id": "agent-1", "scan": {"findings": [
        {"rule_id": "PY-WL-101", "message": "m", "severity": "ERROR", "kind": "defect",
         "fingerprint": "fp1", "qualname": "m.f", "properties": {}, "suppression_state": "active"}]}}
    resp = c.post("/wardline/scan-results", json=body)
    assert resp.status_code == 200
    assert resp.json()["routed"][0]["mode"] == "surface_override"


# --- Filigree closure-gate endpoint tests ---


def test_closure_gate_404_when_ledger_disabled(monkeypatch):
    # create_app auto-builds a ledger from LEGIS_HMAC_KEY when binding_ledger is
    # None — clear it so "disabled" really means disabled (W1: else CI with the
    # key set returns 409, not 404).
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)
    client = TestClient(create_app(binding_ledger=None))
    resp = client.get("/filigree/issues/ISSUE-7/closure-gate")
    assert resp.status_code == 404


def test_closure_gate_409_when_no_binding(tmp_path):
    from legis.governance.binding_ledger import BindingLedger

    # Empty-but-enabled ledger → no binding → blocked.
    ledger = BindingLedger(
        AuditStore(f"sqlite:///{tmp_path / 'bind.db'}"),
        FixedClock("2026-06-02T12:00:00+00:00"),
        key=b"k",
    )
    client = TestClient(create_app(binding_ledger=ledger))
    resp = client.get("/filigree/issues/ISSUE-UNBOUND/closure-gate")
    assert resp.status_code == 409
    assert resp.json()["allowed"] is False


def test_closure_gate_200_on_real_verified_binding(tmp_path):
    from legis.governance.binding_ledger import BindingLedger

    # ALLOW path against a REAL recorded binding (not a fake).
    ledger = BindingLedger(
        AuditStore(f"sqlite:///{tmp_path / 'bind.db'}"),
        FixedClock("2026-06-02T12:00:00+00:00"),
        key=b"k",
    )
    ledger.record(
        signoff_seq=7,
        issue_id="ISSUE-7",
        entity_key=EntityKey.from_sei("loomweave:eid:abc"),
        content_hash="h7",
    )
    client = TestClient(create_app(binding_ledger=ledger))
    resp = client.get("/filigree/issues/ISSUE-7/closure-gate")
    assert resp.status_code == 200
    assert resp.json()["allowed"] is True
    # Pin the evidence body end-to-end: a regression that silently nulls
    # evidence must not pass just because allowed stays True.
    body = resp.json()
    assert body["evidence"]["signoff_seq"] == 7
    assert body["evidence"]["content_hash"] == "h7"
    assert body["evidence"]["recorded_at"] == "2026-06-02T12:00:00+00:00"


def test_closure_gate_500_on_integrity_failure(tmp_path):
    from legis.governance.binding_ledger import BindingLedger

    # Tampered ledger → BindingError → 500 (fail-closed).
    store = AuditStore(f"sqlite:///{tmp_path / 'bind.db'}")
    ledger = BindingLedger(
        store,
        FixedClock("2026-06-02T12:00:00+00:00"),
        key=b"k",
    )
    ledger.record(
        signoff_seq=7,
        issue_id="ISSUE-7",
        entity_key=EntityKey.from_sei("loomweave:eid:abc"),
        content_hash="h7",
    )
    # Append a forged binding record (bad signature) — poisons the whole ledger.
    store.append({
        "kind": "issue_binding",
        "signoff_seq": 8,
        "issue_id": "ISSUE-7",
        "entity_key": {"value": "loomweave:eid:abc", "identity_stable": True},
        "content_hash": "h7",
        "recorded_at": "t",
        "binding_signature": "hmac-sha256:v1:deadbeef",
    })
    client = TestClient(create_app(binding_ledger=ledger))
    resp = client.get("/filigree/issues/ISSUE-7/closure-gate")
    assert resp.status_code == 500
