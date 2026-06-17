from legis.clock import SystemClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.policy.cells import PolicyCellRegistry, PolicyCellRule
from legis.service.explain import explain_cell, explain_policy
from legis.store.audit_store import AuditStore


class _AcceptingJudge:
    def evaluate(self, record):
        return JudgeOpinion(
            verdict=Verdict.ACCEPTED,
            model="stub-judge",
            rationale="accepted for explain wiring test",
        )


def _engine(tmp_path, *, judge=None):
    return EnforcementEngine(
        AuditStore(f"sqlite:///{tmp_path / 'gov.db'}"),
        SystemClock(),
        judge=judge,
    )


def test_explain_chill_policy_reports_enabled_self_clearable_cell(tmp_path):
    registry = PolicyCellRegistry(default_cell="chill")

    result = explain_policy(
        registry,
        policy="ordinary.policy",
        entity="src/x.py:f",
        engine=_engine(tmp_path),
        protected_gate=None,
        signoff_gate=None,
    )

    assert result.to_payload() == {
        "cell": "chill",
        "judge_inline": False,
        "self_clearable": True,
        "human_in_loop": False,
        "enabled": True,
        "available_moves": ["override_submit"],
        "required_inputs": [],
        "matched_rule": None,
        "policy_known": False,
    }


def test_explain_coached_policy_reports_disabled_without_judge_and_enabled_with_judge(
    tmp_path,
):
    registry = PolicyCellRegistry(
        default_cell="chill",
        rules=(PolicyCellRule(pattern="review.*", cell="coached"),),
    )

    disabled = explain_policy(
        registry,
        policy="review.rationale",
        entity="src/x.py:f",
        engine=_engine(tmp_path),
        protected_gate=None,
        signoff_gate=None,
    )

    assert disabled.to_payload() == {
        "cell": "coached",
        "judge_inline": True,
        "self_clearable": False,
        "human_in_loop": False,
        "enabled": False,
        "available_moves": [],
        "required_inputs": [],
        "matched_rule": "review.*",
        "policy_known": True,
    }

    enabled = explain_policy(
        registry,
        policy="review.rationale",
        entity="src/x.py:f",
        engine=_engine(tmp_path, judge=_AcceptingJudge()),
        protected_gate=None,
        signoff_gate=None,
    )

    assert enabled.enabled is True
    assert enabled.available_moves == ("override_submit",)


def test_explain_protected_policy_reports_required_inputs_even_when_gate_disabled(
    tmp_path,
):
    registry = PolicyCellRegistry(
        default_cell="chill",
        rules=(PolicyCellRule(pattern="protected.*", cell="protected"),),
    )

    result = explain_policy(
        registry,
        policy="protected.source-integrity",
        entity="src/x.py:f",
        engine=_engine(tmp_path),
        protected_gate=None,
        signoff_gate=None,
    )

    assert result.to_payload() == {
        "cell": "protected",
        "judge_inline": True,
        "self_clearable": False,
        "human_in_loop": False,
        "enabled": False,
        "available_moves": [],
        "required_inputs": [
            {
                "field": "file_fingerprint",
                "how": "sha256 of the target file contents",
            },
            {
                "field": "ast_path",
                "how": "dotted path to the AST node",
            },
        ],
        "matched_rule": "protected.*",
        "policy_known": True,
    }


def test_explain_structured_policy_reports_human_loop_when_signoff_gate_wired(
    tmp_path,
):
    registry = PolicyCellRegistry(
        default_cell="chill",
        rules=(PolicyCellRule(pattern="human.*", cell="structured"),),
    )

    result = explain_policy(
        registry,
        policy="human.release-signoff",
        entity="src/x.py:f",
        engine=_engine(tmp_path),
        protected_gate=None,
        signoff_gate=object(),
    )

    assert result.to_payload() == {
        "cell": "structured",
        "judge_inline": False,
        "self_clearable": False,
        "human_in_loop": True,
        "enabled": True,
        "available_moves": ["override_submit", "signoff_status_get"],
        "required_inputs": [],
        "matched_rule": "human.*",
        "policy_known": True,
    }


def test_explain_policy_marks_unmatched_name_policy_unknown(tmp_path):
    # N-9: policy_known:false is the explicit "no routing rule matched — the
    # name may be hallucinated" signal; matched_rule:null alone was too easy
    # to miss. Unmatched names still legitimately route to default_cell.
    registry = PolicyCellRegistry(
        default_cell="chill",
        rules=(PolicyCellRule(pattern="human.*", cell="structured"),),
    )

    unmatched = explain_policy(
        registry,
        policy="completely-made-up-policy-xyz",
        entity="src/x.py:f",
        engine=_engine(tmp_path),
        protected_gate=None,
        signoff_gate=None,
    )

    assert unmatched.policy_known is False
    assert unmatched.to_payload()["policy_known"] is False
    assert unmatched.to_payload()["cell"] == "chill"

    matched = explain_policy(
        registry,
        policy="human.release-signoff",
        entity="src/x.py:f",
        engine=_engine(tmp_path),
        protected_gate=None,
        signoff_gate=None,
    )

    assert matched.policy_known is True
    assert matched.to_payload()["policy_known"] is True


def test_explain_cell_payload_omits_policy_known(tmp_path):
    # explain_cell backs policy_list's per-cell rows, where "policy_known" has
    # no policy referent — the key must be absent, never a misleading false.
    explanation = explain_cell(
        "chill",
        engine=_engine(tmp_path),
        protected_gate=None,
        signoff_gate=None,
    )

    assert explanation.policy_known is None
    assert "policy_known" not in explanation.to_payload()
