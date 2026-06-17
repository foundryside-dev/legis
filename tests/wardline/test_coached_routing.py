"""WP-A6: a Wardline finding routed surface_override through a JUDGE-enabled engine
records a coached verdict — the coached cell is reachable from the Wardline seam."""
from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.identity.entity_key import EntityKey
from legis.store.audit_store import AuditStore
from legis.wardline.governor import WardlineCellPolicy, route_findings
from legis.wardline.ingest import active_defects


class BlockingJudge:
    def evaluate(self, record):
        return JudgeOpinion(Verdict.BLOCKED, "judge@1", "untrusted reaches trusted")


def _scan():
    return {"findings": [
        {"rule_id": "PY-WL-101", "message": "untrusted reaches trusted",
         "severity": "ERROR", "kind": "defect", "fingerprint": "fp1",
         "qualname": "m.f", "properties": {"actual_return": "UNKNOWN_RAW"},
         "suppression_state": "active"}]}


def test_coached_wardline_path_records_a_judge_verdict(tmp_path):
    eng = EnforcementEngine(AuditStore(f"sqlite:///{tmp_path / 'g.db'}"),
                            FixedClock("2026-06-02T12:00:00+00:00"),
                            judge=BlockingJudge())
    results = route_findings(
        active_defects(_scan()), policy=WardlineCellPolicy.SURFACE_OVERRIDE,
        agent_id="agent-1", resolve=lambda q: (EntityKey.from_locator(q or "unknown"), {}),
        engine=eng)
    assert results[0]["accepted"] is False
    rec = eng.trail()[0]
    assert rec["extensions"]["judge_verdict"] == "BLOCKED"
    assert rec["extensions"]["wardline"]["fingerprint"] == "fp1"
