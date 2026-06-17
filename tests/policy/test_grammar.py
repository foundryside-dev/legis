import pytest

from legis.policy.grammar import (
    AllowlistBoundary,
    PolicyConflictError,
    PolicyGrammar,
    PolicyResult,
    default_grammar,
)


def test_unregistered_policy_is_unknown_not_clear():
    ev = PolicyGrammar().evaluate("nonexistent", {})
    assert ev.result is PolicyResult.UNKNOWN
    assert ev.provenance_gap is True
    assert ev.result is not PolicyResult.CLEAR


def test_allowlist_builtin_clears_violates_and_unknowns():
    g = PolicyGrammar()
    g.register(AllowlistBoundary("imports", frozenset({"json", "os"})))
    assert g.evaluate("imports", {"value": "json"}).result is PolicyResult.CLEAR
    assert g.evaluate("imports", {"value": "socket"}).result is PolicyResult.VIOLATION
    # Missing provenance → cannot prove → UNKNOWN, not CLEAR.
    miss = g.evaluate("imports", {})
    assert miss.result is PolicyResult.UNKNOWN
    assert miss.provenance_gap is True


def test_agent_can_register_a_new_boundary_type_zero_config():
    g = PolicyGrammar()

    class NoTodoBoundary:
        name = "no-todo"

        def evaluate(self, target):
            text = target.get("text", "")
            if "TODO" in text:
                return (PolicyResult.VIOLATION, "contains TODO")
            return (PolicyResult.CLEAR, "clean")

    g.register(NoTodoBoundary())
    assert g.evaluate("no-todo", {"text": "x TODO y"}).result is PolicyResult.VIOLATION
    assert g.evaluate("no-todo", {"text": "clean"}).result is PolicyResult.CLEAR


def test_grammar_has_no_exemption_rescue_mechanism():
    # POLICY-2: an exemption-rescue path turns a proven VIOLATION into CLEAR — an
    # agent-writable bypass surface. It was removed entirely (no registry param, no
    # rescue branch), so the trap cannot be re-wired by accident. This pins the
    # removal: any future re-introduction of an exemptions seam must trip this test
    # and consciously own the human-governed-source requirement.
    g = default_grammar()
    assert not hasattr(g, "_exemptions")
    with pytest.raises(TypeError):
        PolicyGrammar(exemptions=object())  # type: ignore[call-arg]


def test_builtins_cannot_be_shadowed():
    g = default_grammar()
    name = next(iter(g.registered()))

    class Permissive:
        def evaluate(self, target):
            return (PolicyResult.CLEAR, "always ok")

    p = Permissive()
    p.name = name
    with pytest.raises(PolicyConflictError):
        g.register(p)


def test_a_boundary_that_raises_fails_closed_to_unknown():
    g = PolicyGrammar()

    class Exploding:
        name = "boom"

        def evaluate(self, target):
            raise RuntimeError("boundary blew up")

    g.register(Exploding())
    ev = g.evaluate("boom", {})
    assert ev.result is PolicyResult.UNKNOWN  # never propagates, never CLEAR
    assert ev.provenance_gap is True
    assert "boundary blew up" in ev.detail


def test_a_boundary_returning_garbage_fails_closed_to_unknown():
    g = PolicyGrammar()

    class Garbage:
        name = "garbage"

        def evaluate(self, target):
            return "definitely not a (PolicyResult, str)"

    g.register(Garbage())
    assert g.evaluate("garbage", {}).result is PolicyResult.UNKNOWN
