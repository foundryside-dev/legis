"""Single source of policy-boundary test-evidence judgement.

The static scanner (``boundary_scan``) and the runtime gate
(``decorator.check_policy_boundary``) both call this, so the two gates cannot
drift apart. Strictest-of-both semantics: the exercise check excludes calls that
appear only inside uninvoked nested helper definitions; policy evidence must
co-occur with boundary evidence inside a single ``assert``.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class EvidenceResult:
    ok: bool
    code: str  # "ok" | "disabled" | "shadowed" | "not_exercised" | "policy_not_asserted"
    reason: str


# pytest markers that mean "this test does not run, or is not expected to pass"
# — a test carrying one cannot stand as live behavioural evidence (POLICY-1).
_DISABLING_MARKERS = frozenset({"skip", "skipif", "xfail"})


def _disabling_marker(decorator: ast.expr) -> str | None:
    """Return the marker name if ``decorator`` is a pytest skip / skipif / xfail
    marker, else ``None``.

    Deliberately broad and fail-closed: it matches the terminal attribute or bare
    name (``pytest.mark.skip``, ``mark.xfail``, ``m.skipif(...)``, or a bare
    ``skip`` imported under that name), with or without a call. Fingerprints now
    include decorators, but the marker's import alias can still live outside the
    function source being pinned, so a chain match anchored on a literal
    ``pytest`` would leave the alias path open for a freshly pinned disabled
    test. The population of evidence tests is tiny and the only decorators
    legitimately placed on them are pytest markers, so over-matching merely
    (loudly) blocks a boundary a human then resolves, whereas
    under-matching would silently let a disabled test satisfy the gate — the exact
    false-green this closes.

    Residuals it does NOT catch, by design (POLICY-1 / 2026-06-09 review):
    - A module-level ``pytestmark = pytest.mark.skip`` or a class-level
      ``@pytest.mark.skip`` on the test's enclosing class. The runtime gate only
      has ``inspect.getsource`` of the test function/method — it structurally
      cannot see module globals or the class decorator — so flagging them would
      break the Q-L5 runtime/static parity contract.
    - An ALIASED disabling marker bound to a name, e.g. ``skipper =
      pytest.mark.skip`` then ``@skipper``: the decorator surfaces only as
      ``Name('skipper')`` and knowing it MEANS skip requires the out-of-function
      assignment, which the runtime gate cannot see (resolving it would break
      parity). It is catchable only by a name-heuristic that fails closed on any
      decorator whose terminal name is not an allow-listed safe marker — NOT
      adopted here because it would false-positive on legitimate markers
      (``parametrize``, ``usefixtures``, custom project markers) and there are
      currently zero shipped ``@policy_boundary`` decoration sites, so the live
      exposure is nil. Tracked as a post-1.0 hardening.
    - A fixture-mediated skip: a pinned evidence test whose conftest fixture is
      later edited to call ``pytest.skip()`` never runs, yet its fingerprint is
      unchanged (the fixture body lives in another file). Out-of-band signal,
      genuinely parity-bound.
    All are the same false-green class; they are documented here rather than
    silently absent so the gate's guarantee is stated honestly.
    """
    expr: ast.expr = decorator
    if isinstance(expr, ast.Call):
        expr = expr.func
    name: str | None = None
    if isinstance(expr, ast.Attribute):
        name = expr.attr
    elif isinstance(expr, ast.Name):
        name = expr.id
    return name if name in _DISABLING_MARKERS else None


def _name_targets(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for item in target.elts:
            names.update(_name_targets(item))
        return names
    return set()


def _is_boundary_call(node: ast.AST, boundary_names: set[str]) -> bool:
    return isinstance(node, ast.Call) and (
        (isinstance(node.func, ast.Name) and node.func.id in boundary_names)
        or (isinstance(node.func, ast.Attribute) and node.func.attr in boundary_names)
    )


def _contains_boundary_call(node: ast.AST, boundary_names: set[str]) -> bool:
    return any(_is_boundary_call(child, boundary_names) for child in ast.walk(node))


def _contains_policy_reference(node: ast.AST, suppresses: tuple[str, ...]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if any(re.search(r"\b" + re.escape(p) + r"\b", child.value) for p in suppresses):
                return True
        elif isinstance(child, ast.Name) and child.id in suppresses:
            return True
    return False


def _walk_without_nested_definitions(node: ast.AST):
    yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield from _walk_without_nested_definitions(child)


def evaluate_test_evidence(
    test_fn: ast.FunctionDef | ast.AsyncFunctionDef | None,
    boundary_names: set[str],
    suppresses: tuple[str, ...],
) -> EvidenceResult:
    # Disabled-evidence (highest priority, POLICY-1): a test carrying a pytest
    # skip / skipif / xfail marker does not run (or is not expected to pass), so
    # it cannot stand as live behavioural evidence — independent of whether it
    # otherwise exercises the boundary and asserts the policy. Fingerprints catch
    # post-review decorator drift; this evaluator catches the case where someone
    # pins the disabled decorated test itself. Both gate callers route through
    # here, so the detection lands on the runtime gate and the static scanner
    # identically.
    if test_fn is not None:
        for decorator in test_fn.decorator_list:
            marker = _disabling_marker(decorator)
            if marker is not None:
                return EvidenceResult(
                    False,
                    "disabled",
                    f"evidence test is disabled by a pytest @...{marker} marker "
                    "and cannot serve as running behavioural evidence",
                )

    # Exercise (stricter): a call inside an uninvoked nested helper does not count.
    func_called = False
    if test_fn is not None:
        for node in _walk_without_nested_definitions(test_fn):
            if _is_boundary_call(node, boundary_names):
                func_called = True
                break

    # Shadowing + call-result tracking (full walk, runtime semantics).
    shadowed = False
    call_result_names: set[str] = set()
    if test_fn is not None:
        for node in ast.walk(test_fn):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # NB: do NOT skip `node is test_fn`. The runtime gate checks the
                # test function's own parameters for boundary-name shadowing
                # (e.g. `def test_x(guarded):` where `guarded` is the boundary).
                # The name check below is harmless for the test fn (its name is
                # never a boundary name), and the arg check below must run on it.
                if node.name in boundary_names:
                    shadowed = True
                    break
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                        if arg.arg in boundary_names:
                            shadowed = True
                            break
                    if node.args.vararg and node.args.vararg.arg in boundary_names:
                        shadowed = True
                    if node.args.kwarg and node.args.kwarg.arg in boundary_names:
                        shadowed = True
                    if shadowed:
                        break
            elif isinstance(node, ast.Assign):
                targets = set().union(*(_name_targets(t) for t in node.targets))
                if targets & boundary_names:
                    shadowed = True
                    break
                if _contains_boundary_call(node.value, boundary_names):
                    call_result_names.update(targets)
            elif isinstance(node, ast.AnnAssign):
                targets = _name_targets(node.target)
                if targets & boundary_names:
                    shadowed = True
                    break
                if node.value is not None and _contains_boundary_call(node.value, boundary_names):
                    call_result_names.update(targets)
            elif isinstance(node, ast.AugAssign):
                if _name_targets(node.target) & boundary_names:
                    shadowed = True
                    break
            elif isinstance(node, ast.For):
                if _name_targets(node.target) & boundary_names:
                    shadowed = True
                    break

    if shadowed:
        return EvidenceResult(False, "shadowed", "test shadows the boundary function name")
    if not func_called:
        return EvidenceResult(False, "not_exercised", "test does not appear to exercise the boundary")

    # Policy co-occurrence (runtime semantics): a policy reference must co-occur
    # with boundary evidence inside the same assert, AND the boundary result
    # must be the assertion SUBJECT — it must appear in the assert's test
    # condition, not merely in the assert message. Otherwise a test asserting
    # something unrelated, with the boundary result and policy name dropped into
    # the message string, would falsely satisfy the gate (Q-M8). The policy
    # reference itself may still live in the message (the established honesty
    # pattern names the policy there). Reaching here implies func_called is
    # True, hence test_fn is not None.
    assert test_fn is not None
    policy_referenced = False
    for node in ast.walk(test_fn):
        if not isinstance(node, ast.Assert):
            continue
        boundary_in_subject = _contains_boundary_call(node.test, boundary_names) or any(
            isinstance(child, ast.Name) and child.id in call_result_names
            for child in ast.walk(node.test)
        )
        if boundary_in_subject and _contains_policy_reference(node, suppresses):
            policy_referenced = True
            break

    if not policy_referenced:
        return EvidenceResult(
            False,
            "policy_not_asserted",
            "test does not assert a suppressed policy against the boundary result",
        )
    return EvidenceResult(True, "ok", "ok")
