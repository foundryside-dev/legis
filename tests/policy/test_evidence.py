import ast

from legis.policy.evidence import EvidenceResult, evaluate_test_evidence


def _fn(src: str) -> ast.FunctionDef:
    mod = ast.parse(src)
    return next(n for n in mod.body if isinstance(n, ast.FunctionDef))


def test_ok_when_boundary_called_and_policy_asserted_together():
    fn = _fn(
        'def test_x():\n'
        '    result = guarded({"p": "PY-WL-101"})\n'
        '    assert result == "ok", "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res == EvidenceResult(True, "ok", "ok")


def test_not_exercised_when_subject_never_called():
    fn = _fn('def test_x():\n    assert "PY-WL-101"\n')
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "not_exercised"


def test_policy_not_asserted_when_mention_is_outside_the_assert():
    fn = _fn(
        'def test_x():\n'
        '    note = "see PY-WL-101 docs"\n'
        '    result = guarded(1)\n'
        '    assert result == "ok"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "policy_not_asserted"


def test_shadowed_when_boundary_name_redefined():
    fn = _fn(
        'def test_x():\n'
        '    def guarded(p):\n'
        '        return "ok"\n'
        '    assert guarded(1) == "ok", "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "shadowed"


def test_exercise_excludes_uninvoked_nested_helper():
    fn = _fn(
        'def test_x():\n'
        '    def helper():\n'
        '        return guarded(1)\n'
        '    assert True\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "not_exercised"


def test_shadowed_when_test_parameter_is_named_after_the_boundary():
    # A pytest fixture parameter named after the boundary shadows the import;
    # `guarded(...)` then refers to the fixture, not the real boundary. The
    # runtime gate flags this today, so the shared evaluator must too.
    fn = _fn(
        'def test_x(guarded):\n'
        '    assert guarded(1) == "ok", "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "shadowed"


# AnnAssign / AugAssign / For-target shadowing and attribute-form boundary calls
# round out the evaluator's coverage — it is now the single point of failure for
# both gates. Add one case per construct mirroring the patterns above.
def test_shadowed_via_for_target():
    fn = _fn(
        'def test_x():\n'
        '    for guarded in range(2):\n'
        '        pass\n'
        '    assert True, "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "shadowed"


def test_attribute_form_boundary_call_counts_as_exercise():
    fn = _fn(
        'def test_x():\n'
        '    result = obj.guarded(1)\n'
        '    assert result == "ok", "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.ok is True


def test_shadowed_via_assign():
    fn = _fn(
        'def test_x():\n'
        '    guarded = 1\n'
        '    assert True, "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "shadowed"


def test_shadowed_via_ann_assign():
    fn = _fn(
        'def test_x():\n'
        '    guarded: int = 1\n'
        '    assert True, "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "shadowed"


def test_shadowed_via_aug_assign():
    fn = _fn(
        'def test_x():\n'
        '    guarded = 1\n'
        '    guarded += 1\n'
        '    assert True, "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "shadowed"


def test_policy_not_asserted_when_boundary_result_is_only_in_the_message():
    # The boundary result must be the assertion SUBJECT (in the condition),
    # not merely mentioned in the assert message alongside the policy name
    # (Q-M8). Here the asserted condition is unrelated; result + policy appear
    # only in the f-string message.
    fn = _fn(
        'def test_x():\n'
        '    result = guarded(1)\n'
        '    unrelated = 5\n'
        '    assert unrelated == 5, f"{result} satisfies PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "policy_not_asserted"


def test_ok_when_boundary_result_is_the_condition_and_policy_in_message():
    # The established accepted pattern must keep passing: boundary result is
    # the asserted subject; policy name may live in the message.
    fn = _fn(
        'def test_x():\n'
        '    result = guarded(1)\n'
        '    assert result == "ok", "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "ok"


# --- POLICY-1: a disabled evidence test cannot stand as live proof ---
# Fingerprints now include decorators, but the evaluator still rejects a
# currently pinned skip/xfail marker so disabled evidence cannot stand even if
# someone deliberately records the decorated fingerprint.
# Each case carries a fully-valid body (exercises the boundary AND asserts the
# policy) so the ONLY reason it fails is the disabling marker — proving the
# disabled check pre-empts an otherwise-passing test.

def test_disabled_when_evidence_test_is_skip_marked():
    fn = _fn(
        'import pytest\n'
        '@pytest.mark.skip(reason="flaky")\n'
        'def test_x():\n'
        '    result = guarded({"p": "PY-WL-101"})\n'
        '    assert result == "ok", "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "disabled"
    assert "skip" in res.reason


def test_disabled_when_evidence_test_is_bare_xfail_marked():
    # The marker as a bare attribute (no call) must also be caught.
    fn = _fn(
        'import pytest\n'
        '@pytest.mark.xfail\n'
        'def test_x():\n'
        '    result = guarded({"p": "PY-WL-101"})\n'
        '    assert result == "ok", "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "disabled"
    assert "xfail" in res.reason


def test_disabled_when_evidence_test_is_skipif_marked():
    # skipif runs on some platforms but not others — a conditional disable is
    # still a disable for evidence purposes, and is the least obvious form.
    fn = _fn(
        'import sys, pytest\n'
        '@pytest.mark.skipif(sys.platform == "win32", reason="posix only")\n'
        'def test_x():\n'
        '    result = guarded({"p": "PY-WL-101"})\n'
        '    assert result == "ok", "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "disabled"


def test_disabled_detection_is_blind_to_marker_import_alias():
    # `from pytest import mark` then `@mark.skip` — the disabling form whose
    # only tell (the import) lives OUTSIDE the function source the fingerprint
    # sees. The terminal-name match catches it; an attribute-chain match
    # requiring a literal `pytest` would not.
    fn = _fn(
        'from pytest import mark\n'
        '@mark.skip\n'
        'def test_x():\n'
        '    result = guarded({"p": "PY-WL-101"})\n'
        '    assert result == "ok", "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "disabled"


def test_unrelated_markers_do_not_trip_the_disabled_check():
    # parametrize / usefixtures are not disabling markers; an otherwise-valid
    # evidence test carrying them must still pass.
    fn = _fn(
        'import pytest\n'
        '@pytest.mark.parametrize("n", [1, 2])\n'
        'def test_x(n):\n'
        '    result = guarded({"p": "PY-WL-101"})\n'
        '    assert result == "ok", "PY-WL-101"\n'
    )
    res = evaluate_test_evidence(fn, {"guarded"}, ("PY-WL-101",))
    assert res.code == "ok"
