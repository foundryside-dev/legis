from legis.clock import FixedClock
from legis.enforcement.protected import ProtectedGate
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.identity.entity_key import EntityKey
from legis.store.audit_store import AuditStore


class ScriptedJudge:
    def __init__(self, opinion):
        self.opinion = opinion

    def evaluate(self, record):
        return self.opinion


def gate(tmp_path):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    g = ProtectedGate(
        store,
        FixedClock("2026-06-02T12:00:00+00:00"),
        judge=ScriptedJudge(JudgeOpinion(Verdict.BLOCKED, "judge@1", "no")),
        key=b"k",
    )
    return g, store


def test_operator_override_is_distinct_signed_and_accepted(tmp_path):
    g, store = gate(tmp_path)
    result = g.operator_override(
        policy="no-eval",
        entity_key=EntityKey.from_locator("src/x.py:f"),
        rationale="release exception approved by security lead",
        operator_id="op-sec-lead",
        file_fingerprint="sha256:abc",
        ast_path="Module/Call[eval]",
    )
    assert result.verdict is Verdict.OVERRIDDEN_BY_OPERATOR
    assert result.accepted is True
    payload = store.read_all()[0].payload
    ext = payload["extensions"]
    assert ext["judge_verdict"] == "OVERRIDDEN_BY_OPERATOR"   # distinct from ACCEPTED
    assert ext["judge_metadata_signature"].startswith("hmac-sha256:v3:")
    assert payload["agent_id"] == "op-sec-lead"
