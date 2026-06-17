import pytest

from legis.policy.decorator import (
    check_policy_boundary,
    fingerprint,
    fingerprint_source,
    policy_boundary,
)


# Fixture functions the gate fingerprints BY SOURCE — they are never executed,
# so the free `handler` name is intentional (it stands for the real boundary
# call the gate looks for); noqa keeps that deliberate undefined name.
def fake_boundary_test():
    result = handler("payload")  # noqa: F821
    assert result == "payload", "no-eval"


def string_only_boundary_test():
    # mentions the decorated function name and policy without exercising either
    handler_under_test = "handler exercises no-eval boundary"
    assert "no-eval" in handler_under_test


def weak_policy_boundary_test():
    assert handler("payload") == "payload"  # noqa: F821
    assert "no-eval" == "no-eval"


def shadowed_boundary_test():
    def handler(payload):
        return payload

    assert handler("payload") == "payload", "no-eval"


def resolver(ref):
    return {"tests::fake": fake_boundary_test}.get(ref)


def _decorate(test_fingerprint):
    @policy_boundary(
        source="src/legis/handlers.py:42",
        suppresses=("no-eval",),
        invariant="rejects bad input",
        test_ref="tests::fake",
        test_fingerprint=test_fingerprint,
    )
    def handler(payload):
        return payload

    return handler


def test_gate_passes_with_a_pinned_unmodified_test():
    good = fingerprint(fake_boundary_test)
    finding = check_policy_boundary(_decorate(good), resolver)
    assert finding.ok is True, finding.reason


def test_gate_parses_nested_test_sources_consistently():
    def nested_boundary_test():
        result = handler("payload")  # noqa: F821
        assert result == "payload", "no-eval"

    good = fingerprint(nested_boundary_test)
    finding = check_policy_boundary(
        _decorate(good),
        lambda ref: {"tests::fake": nested_boundary_test}.get(ref),
    )

    assert finding.ok is True, finding.reason


def test_gate_rejects_string_only_mentions_as_behavioural_evidence():
    def string_resolver(ref):
        return {"tests::fake": string_only_boundary_test}.get(ref)

    stale_proof = fingerprint(string_only_boundary_test)
    finding = check_policy_boundary(_decorate(stale_proof), string_resolver)
    assert finding.ok is False
    assert "exercise" in finding.reason


def test_gate_rejects_policy_mentions_not_bound_to_the_boundary_assertion():
    def weak_resolver(ref):
        return {"tests::fake": weak_policy_boundary_test}.get(ref)

    stale_proof = fingerprint(weak_policy_boundary_test)
    finding = check_policy_boundary(_decorate(stale_proof), weak_resolver)
    assert finding.ok is False
    assert "assert" in finding.reason


def test_gate_rejects_shadowed_boundary_calls():
    def shadowed_resolver(ref):
        return {"tests::fake": shadowed_boundary_test}.get(ref)

    stale_proof = fingerprint(shadowed_boundary_test)
    finding = check_policy_boundary(_decorate(stale_proof), shadowed_resolver)
    assert finding.ok is False
    assert "shadow" in finding.reason


# A pinned, running evidence test that is later disabled with @pytest.mark.skip.
# It is never collected as a test (name does not start with `test_`); the marker
# merely sets an attribute. The recomputed fingerprint must now include the
# @skip line, so a clean pre-skip fingerprint fails as drift before the evidence
# evaluator runs.
@pytest.mark.skip(reason="disabled after the human pinned it")
def skip_disabled_boundary_test():
    result = handler("payload")  # noqa: F821
    assert result == "payload", "no-eval"


def test_gate_rejects_evidence_test_disabled_by_skip_marker():
    # Pin the fingerprint of the same-named/body test BEFORE the @skip was added,
    # computed straight from source. The live recompute over the @skip-decorated
    # function must differ so semantic decorator changes cannot be laundered.
    clean_source = (
        "def skip_disabled_boundary_test():\n"
        "    result = handler('payload')\n"
        "    assert result == 'payload', 'no-eval'\n"
    )
    clean_fp = fingerprint_source(clean_source)
    decorated_fp = fingerprint(skip_disabled_boundary_test)
    assert decorated_fp != clean_fp

    finding = check_policy_boundary(
        _decorate(clean_fp), lambda ref: skip_disabled_boundary_test
    )
    assert finding.ok is False
    assert "fingerprint" in finding.reason.lower()

    finding = check_policy_boundary(
        _decorate(decorated_fp), lambda ref: skip_disabled_boundary_test
    )
    assert finding.ok is False
    assert "disabl" in finding.reason.lower()


def test_gate_fails_on_fingerprint_drift():
    # THE discriminating test: a stale fingerprint means the test changed after
    # review — behavioural evidence no longer pinned.
    finding = check_policy_boundary(_decorate("stale-old-hash"), resolver)
    assert finding.ok is False
    assert "drift" in finding.reason.lower()


def test_gate_rejects_missing_test_ref_as_vibe_justification():
    @policy_boundary(source="src/legis/x.py:1", suppresses=("no-eval",), invariant="rejects bad input")
    def handler(payload):
        return payload

    finding = check_policy_boundary(handler, resolver)
    assert finding.ok is False
    assert "test_ref" in finding.reason


def test_gate_fails_when_test_ref_resolves_to_nothing():
    good = fingerprint(fake_boundary_test)
    h = _decorate(good)
    finding = check_policy_boundary(h, lambda ref: None)
    assert finding.ok is False


def test_gate_fails_on_metadata_transplant():
    # qualname mismatch = metadata copied onto a different function.
    good = fingerprint(fake_boundary_test)
    h = _decorate(good)
    object.__setattr__(h.__policy_boundary__, "qualname", "some.other.func")
    finding = check_policy_boundary(h, resolver)
    assert finding.ok is False
    assert "scope" in finding.reason.lower() or "qualname" in finding.reason.lower()


def _decorate_src(source, invariant="rejects bad input"):
    good = fingerprint(fake_boundary_test)

    @policy_boundary(source=source, suppresses=("no-eval",), invariant=invariant,
                     test_ref="tests::fake", test_fingerprint=good)
    def handler(payload):
        return payload

    return handler


def test_decoration_rejects_empty_source():
    with pytest.raises(TypeError, match="source"):
        @policy_boundary(source="  ", suppresses=("no-eval",), invariant="rejects bad input")
        def handler(payload):
            return payload


def test_decoration_rejects_empty_invariant():
    with pytest.raises(TypeError, match="invariant"):
        @policy_boundary(source="src/legis/x.py:1", suppresses=("no-eval",), invariant="  ")
        def handler(payload):
            return payload


def test_gate_rejects_empty_source():
    h = _decorate_src("src/legis/x.py:1")
    object.__setattr__(h.__policy_boundary__, "source", "   ")
    finding = check_policy_boundary(h, resolver)
    assert finding.ok is False
    assert "source" in finding.reason.lower()


def test_gate_rejects_vibe_source_that_is_not_a_citation():
    finding = check_policy_boundary(_decorate_src("because I tested it"), resolver)
    assert finding.ok is False
    assert "citation" in finding.reason.lower()


def test_gate_accepts_url_sha_and_repo_path_citations():
    for src in ("https://github.com/o/r/pull/9",
                "https://github.com/o/r/blob/main/x.py?ts=1#L42",
                "a1b2c3d",
                "0123456789abcdef0123456789abcdef01234567",  # full 40-char SHA
                "src/legis/x.py:42", "README.md"):
        assert check_policy_boundary(_decorate_src(src), resolver).ok is True, src


def test_gate_rejects_empty_invariant():
    h = _decorate_src("src/legis/x.py:1", invariant="rejects bad input")
    object.__setattr__(h.__policy_boundary__, "invariant", "   ")
    finding = check_policy_boundary(h, resolver)
    assert finding.ok is False
    assert "invariant" in finding.reason.lower()


def test_passing_finding_surfaces_the_invariant():
    finding = check_policy_boundary(_decorate_src("src/legis/x.py:1", invariant="rejects bad input"), resolver)
    assert finding.ok is True
    assert "rejects bad input" in finding.reason
