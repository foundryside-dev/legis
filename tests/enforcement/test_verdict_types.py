from legis.enforcement.verdict import JudgeOpinion, Verdict


def test_verdict_values_are_stable_strings():
    assert Verdict.ACCEPTED.value == "ACCEPTED"
    assert Verdict.BLOCKED.value == "BLOCKED"


def test_judge_opinion_carries_verdict_model_rationale():
    op = JudgeOpinion(verdict=Verdict.BLOCKED, model="m-1", rationale="too vague")
    assert op.verdict is Verdict.BLOCKED
    assert op.model == "m-1"
    assert op.rationale == "too vague"


def test_model_emittable_excludes_operator_authority_verdict():
    # legis-3d16dd0132 / JUDGE-3: a model must never be able to emit
    # OVERRIDDEN_BY_OPERATOR (it would clear a protected gate as accepted).
    assert Verdict.model_emittable() == frozenset({Verdict.ACCEPTED, Verdict.BLOCKED})
    assert Verdict.OVERRIDDEN_BY_OPERATOR not in Verdict.model_emittable()


def test_accepting_set_is_the_clearing_verdicts():
    # legis-3d16dd0132: single source of truth for "this verdict cleared".
    assert Verdict.accepting() == frozenset(
        {Verdict.ACCEPTED, Verdict.OVERRIDDEN_BY_OPERATOR}
    )
    assert Verdict.BLOCKED not in Verdict.accepting()


def test_verdict_partitions_stay_in_sync_with_membership():
    # The two classifications are partitions of the SAME enum; if a new Verdict
    # member is added, at least one of these assertions forces the author to
    # classify it instead of silently leaving it out of both sets.
    assert Verdict.model_emittable() <= set(Verdict)
    assert Verdict.accepting() <= set(Verdict)
    # Every accepting verdict is final; BLOCKED is the only non-accepting verdict.
    assert set(Verdict) - Verdict.accepting() == {Verdict.BLOCKED}
