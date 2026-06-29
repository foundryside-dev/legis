"""MCP tool ``governance_read`` handler tests.

Mirrors the attestation_get test structure (tests/mcp/test_server.py Task 5 section):
  (a) verifiable trail with a clearance -> {status:checked, records:[…]}
  (b) protected_gate is None or trail_verifier is None -> {status:unavailable, …}
  (c) tampered trail -> AuditIntegrityError -> AUDIT_INTEGRITY_FAILURE error envelope

The BOTH-objects fail-closed pre-gate (must-fix) is the key invariant: the tool
must gate on *both* runtime.protected_gate AND runtime.trail_verifier, not just one.
"""
from __future__ import annotations

from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.protected import ProtectedGate, TrailVerifier
from legis.enforcement.signoff import SignoffGate
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.identity.entity_key import EntityKey
from legis.mcp import McpRuntime, call_tool
from legis.store.audit_store import AuditStore

_CLOCK_ISO = "2026-06-02T12:00:00+00:00"
_KEY = b"gov-read-key"
_POLICY = "protected.governance"
_SEI = "loomweave:eid:governance-read-test"


class _AdvisoryJudge:
    def evaluate(self, record):  # noqa: ANN001
        return JudgeOpinion(Verdict.BLOCKED, "judge@1", "advisory only")


def _runtime(tmp_path):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    engine = EnforcementEngine(store, FixedClock(_CLOCK_ISO))
    return McpRuntime(agent_id="agent-launch", initialized=True, engine=engine), store


def _wired_runtime_with_clearance(tmp_path):
    """Build a runtime with BOTH objects wired and a genuine clearance (signoff_cleared +
    operator_override) for _SEI."""
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock(_CLOCK_ISO)

    # Write a signoff_cleared record
    gate = SignoffGate(store, clock, signer=True, key=_KEY)
    req = gate.request(
        policy=_POLICY,
        entity_key=EntityKey(value=_SEI, identity_stable=True),
        rationale="review",
        agent_id="agent-1",
        extensions={"loomweave": {"content_hash": "blake3:clearance-signoff"}},
    )
    gate.sign_off(request_seq=req.seq, operator_id="op-1", rationale="ok")

    # Write an operator_override record
    protected = ProtectedGate(
        store,
        clock,
        judge=_AdvisoryJudge(),
        key=_KEY,
        protected_policies=frozenset({_POLICY}),
    )
    protected.operator_override(
        policy=_POLICY,
        entity_key=EntityKey(value=_SEI, identity_stable=True),
        rationale="approved",
        operator_id="op-sec",
        file_fingerprint="sha256:abc",
        ast_path="Module/Call",
        extensions={"loomweave": {"content_hash": "blake3:clearance-override"}},
    )

    engine = EnforcementEngine(store, clock)
    pg = ProtectedGate(
        store, clock, judge=_AdvisoryJudge(), key=_KEY,
        protected_policies=frozenset({_POLICY}),
    )
    runtime = McpRuntime(
        agent_id="agent-launch",
        initialized=True,
        engine=engine,
        protected_gate=pg,
        trail_verifier=TrailVerifier(_KEY, frozenset({_POLICY})),
    )
    return runtime, store


# --- (a) verifiable trail with clearance -> checked with records ---

def test_governance_read_checked_with_clearances(tmp_path):
    runtime, _store = _wired_runtime_with_clearance(tmp_path)
    result = call_tool(runtime, "governance_read", {"sei": _SEI})
    assert not result.get("isError"), result
    sc = result["structuredContent"]
    assert sc["status"] == "checked"
    assert sc["sei"] == _SEI
    assert len(sc["records"]) == 2
    # Both clearance kinds must appear
    postures = {r["posture"] for r in sc["records"]}
    assert postures == {"operator_signoff", "protected_override"}
    # Every record must have the required v1 clearance_record fields
    for rec in sc["records"]:
        assert rec["disposition"] == "cleared"
        assert rec["authority"] == "operator"
        assert rec["sei"] == _SEI
        assert isinstance(rec["reasons"], list) and len(rec["reasons"]) == 1
        assert rec["content_hash"].startswith("blake3:")
        assert rec["as_of"] == _CLOCK_ISO


def test_governance_read_empty_verified_trail_is_checked_empty(tmp_path):
    """A wired runtime with no clearances returns status=checked, records=[]
    (honest absence, NOT unavailable — trail was checked)."""
    runtime, _store = _runtime(tmp_path)

    class _OkVerifier:
        def verify(self, records):
            return None

    class _FakeProtectedGate:
        def records(self):
            return []

    runtime.protected_gate = _FakeProtectedGate()
    runtime.trail_verifier = _OkVerifier()
    result = call_tool(runtime, "governance_read", {"sei": _SEI})
    assert not result.get("isError"), result
    sc = result["structuredContent"]
    assert sc["status"] == "checked"
    assert sc["records"] == []
    assert "unavailable" not in sc


# --- (b) both-objects fail-closed pre-gate ---

def test_governance_read_unavailable_when_no_protected_gate(tmp_path):
    """No protected_gate (engine-only deployment) -> unavailable, NEVER checked/[]."""
    runtime, _store = _runtime(tmp_path)
    assert runtime.protected_gate is None
    result = call_tool(runtime, "governance_read", {"sei": _SEI})
    assert not result.get("isError"), result
    sc = result["structuredContent"]
    assert sc["status"] == "unavailable"
    assert sc["sei"] == _SEI
    assert sc["records"] == []
    assert sc["unavailable"] and "reason" in sc["unavailable"][0]


def test_governance_read_unavailable_when_no_trail_verifier(tmp_path):
    """protected_gate present but trail_verifier absent -> unavailable.
    The BOTH-objects gate must reject on either missing half."""
    runtime, _store = _runtime(tmp_path)

    class _FakeProtectedGate:
        def records(self):
            return []

    runtime.protected_gate = _FakeProtectedGate()
    # trail_verifier deliberately left None
    assert runtime.trail_verifier is None
    result = call_tool(runtime, "governance_read", {"sei": _SEI})
    assert not result.get("isError"), result
    sc = result["structuredContent"]
    assert sc["status"] == "unavailable"
    assert sc["records"] == []
    assert sc["unavailable"] and "reason" in sc["unavailable"][0]


# --- (c) tampered trail -> AUDIT_INTEGRITY_FAILURE ---

def test_governance_read_tamper_yields_audit_integrity_failure(tmp_path):
    """A tampered trail -> AuditIntegrityError -> AUDIT_INTEGRITY_FAILURE error envelope."""
    runtime, _store = _runtime(tmp_path)

    class _TamperVerifier:
        def verify(self, records):
            from legis.enforcement.protected import TamperError
            raise TamperError("record 2 hash mismatch")

    class _FakeProtectedGate:
        def records(self):
            return ["bad-record"]

    runtime.protected_gate = _FakeProtectedGate()
    runtime.trail_verifier = _TamperVerifier()
    result = call_tool(runtime, "governance_read", {"sei": _SEI})
    assert result.get("isError")
    assert result["structuredContent"]["error_code"] == "AUDIT_INTEGRITY_FAILURE"
