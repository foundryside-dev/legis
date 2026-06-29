"""Static scanner for @policy_boundary declarations."""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

from legis.policy.decorator import fingerprint_source
from legis.policy.evidence import evaluate_test_evidence


@dataclass(frozen=True)
class BoundaryFinding:
    rule_id: str
    file_path: str
    line: int
    qualname: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_EVIDENCE_RULE_IDS = {
    "disabled": "POLICY_BOUNDARY_TEST_DISABLED",
    "shadowed": "POLICY_BOUNDARY_TEST_SHADOWS_SUBJECT",
    "not_exercised": "POLICY_BOUNDARY_TEST_DOES_NOT_EXERCISE_SUBJECT",
    "policy_not_asserted": "POLICY_BOUNDARY_TEST_WEAK",
}


def scan_policy_boundaries(
    root: str | Path, *, repo_root: str | Path | None = None
) -> list[BoundaryFinding]:
    scan_root = Path(root)
    repo = Path(repo_root) if repo_root is not None else scan_root
    repo_resolved = repo.resolve()
    findings: list[BoundaryFinding] = []

    for file_path in sorted(scan_root.rglob("*.py")):
        display_path = _display_path(file_path, repo)
        # Fail-degraded, never fail-dead (dogfood-4 A2 / federation rec #3): one
        # hostile file (e.g. lacuna's nesting_bomb.py — a deep BinOp chain that
        # exhausts the parser stack, or a deep attribute/expression tree that
        # parses but exhausts the NodeVisitor walk) must not kill the whole run.
        # Skip it, flag it as a finding so the gate still sees it, and keep
        # scanning. Same posture as loomweave's LMWV-PY-TOO-COMPLEX. We guard the
        # whole resource-exhaustion class (RecursionError on the C stack,
        # MemoryError on a pathological literal) across read/parse/walk in one
        # place — _coerce_literal at line ~225 already catches MemoryError, so a
        # memory-bomb specimen must degrade here the same way rather than
        # fail-dead the gate.
        try:
            source = file_path.read_text(encoding="utf-8")
            module = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            findings.append(
                BoundaryFinding(
                    "POLICY_BOUNDARY_PARSE_ERROR",
                    display_path,
                    exc.lineno if isinstance(exc, SyntaxError) and exc.lineno else 1,
                    "",
                    str(exc),
                )
            )
            continue
        except (RecursionError, MemoryError):
            findings.append(_too_complex_finding(display_path))
            continue

        try:
            visitor = _BoundaryVisitor(source, file_path, display_path, repo, repo_resolved)
            visitor.visit(module)
        except (RecursionError, MemoryError):
            findings.append(_too_complex_finding(display_path))
            continue
        findings.extend(visitor.findings)

    return findings


def count_source_files(root: str | Path) -> int:
    """Count the analyzable Python files under *root*.

    The single source of truth for "did the scan actually look at anything".
    Counts exactly the set ``scan_policy_boundaries`` would walk (``*.py`` under
    *root*), so a surface can distinguish "scanned N>=1 files, 0 findings ->
    PASS" from "scanned 0 files / root missing -> NO_ROOT". A governance gate
    must never report PASS for a zero-file scan (weft-ef2e898642
    silent-clean-on-zero-scope). A missing root counts as zero.
    """
    scan_root = Path(root)
    if not scan_root.exists():
        return 0
    return sum(1 for _ in scan_root.rglob("*.py"))


def assert_within_boundary(anchor: str | Path, *candidates: str | Path) -> None:
    """Fail closed when any candidate path resolves outside *anchor*.

    The MCP ``policy_boundary_check`` surface accepts caller-supplied scan roots
    (``root``, ``repo_root``). An absolute root — or a relative root with ``..``
    segments — would otherwise let an MCP caller make Legis walk and parse
    arbitrary Python trees visible to the server process, leaking paths and parse
    results and inviting expensive traversal (legis-0186c23a2c).

    ``resolve()`` collapses ``..`` and symlinks, so ``relative_to`` is a true
    containment test: a symlink inside the anchor that points outside resolves
    outside and is rejected. Raises ``InvalidArgumentError`` — the MCP adapter
    maps that to an ``INVALID_ARGUMENT`` error envelope (``isError``), never a
    result, so a rejected scan can never be misread as a clean PASS.
    """
    # Deferred import: policy/ does not import service/ at module load, and
    # service/__init__ pulls in modules that import policy/ — importing at module
    # level would risk a cycle. Importing here (call time) is cycle-safe.
    from legis.service.errors import InvalidArgumentError

    anchor_resolved = Path(anchor).resolve()
    for candidate in candidates:
        candidate_resolved = Path(candidate).resolve()
        try:
            candidate_resolved.relative_to(anchor_resolved)
        except ValueError as exc:
            raise InvalidArgumentError(
                f"scan root {candidate_resolved} is outside the configured source "
                f"boundary {anchor_resolved}; pass a root within the server's "
                "source root (set via LEGIS_SOURCE_ROOT)."
            ) from exc


def _too_complex_finding(display_path: str) -> BoundaryFinding:
    return BoundaryFinding(
        "POLICY_BOUNDARY_FILE_TOO_COMPLEX",
        display_path,
        1,
        "",
        "nesting too deep to analyze; file skipped, scan continued (per-file degrade)",
    )


class _BoundaryVisitor(ast.NodeVisitor):
    def __init__(
        self,
        source: str,
        file_path: Path,
        display_path: str,
        repo_root: Path,
        repo_root_resolved: Path,
    ) -> None:
        self.source = source
        self.file_path = file_path
        self.display_path = display_path
        self.repo_root = repo_root
        self.repo_root_resolved = repo_root_resolved
        self.findings: list[BoundaryFinding] = []
        self._qualname_stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._qualname_stack.append(node.name)
        self.generic_visit(node)
        self._qualname_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualname = ".".join([*self._qualname_stack, node.name])
        for decorator in node.decorator_list:
            if not _is_policy_boundary_call(decorator):
                continue

            values = self._literal_keywords(decorator, node, qualname)
            if values is None:
                return

            suppresses = values.get("suppresses")
            if not _valid_suppresses(suppresses):
                self._add(
                    "POLICY_BOUNDARY_SUPPRESSES_INVALID",
                    node,
                    qualname,
                    "suppresses must be a non-empty tuple of strings",
                )
                return
            suppresses = cast(tuple[str, ...], suppresses)

            test_ref = values.get("test_ref")
            if not isinstance(test_ref, str) or not test_ref.strip():
                self._add(
                    "POLICY_BOUNDARY_TEST_REF_MISSING",
                    node,
                    qualname,
                    "test_ref is required",
                )
                return

            test_fingerprint = values.get("test_fingerprint")
            if not isinstance(test_fingerprint, str) or not test_fingerprint.strip():
                self._add(
                    "POLICY_BOUNDARY_TEST_FINGERPRINT_MISSING",
                    node,
                    qualname,
                    "test_fingerprint is required",
                )
                return

            test_result = _resolve_test_ref(
                test_ref,
                self.repo_root,
                self.repo_root_resolved,
            )
            if isinstance(test_result, BoundaryFinding):
                self.findings.append(
                    BoundaryFinding(
                        test_result.rule_id,
                        self.display_path,
                        node.lineno,
                        qualname,
                        test_result.reason,
                    )
                )
                return

            test_source, test_node = test_result
            test_segment = _source_segment_with_decorators(test_source, test_node)
            # Same canonicalization the runtime honesty gate uses — CRLF/dedent
            # normalization and a decorator-sensitive AST hash — so the two
            # paths cannot diverge for a decorated / class-method test_ref (Q-L5),
            # and decorators that change execution semantics are pinned.
            actual_fingerprint = fingerprint_source(test_segment)
            if actual_fingerprint != test_fingerprint:
                self._add(
                    "POLICY_BOUNDARY_TEST_FINGERPRINT_MISMATCH",
                    node,
                    qualname,
                    "test_fingerprint does not match referenced test",
                )
                return

            evidence = evaluate_test_evidence(test_node, {node.name}, suppresses)
            if not evidence.ok:
                self._add(
                    _EVIDENCE_RULE_IDS[evidence.code],
                    node,
                    qualname,
                    evidence.reason,
                )
                return

    def _literal_keywords(
        self,
        decorator: ast.expr,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        qualname: str,
    ) -> dict[str, Any] | None:
        if not isinstance(decorator, ast.Call):
            return None
        if decorator.args or any(keyword.arg is None for keyword in decorator.keywords):
            self._add(
                "POLICY_BOUNDARY_NONLITERAL",
                node,
                qualname,
                "policy_boundary arguments must be static literal keywords",
            )
            return None

        values: dict[str, Any] = {}
        for keyword in decorator.keywords:
            if keyword.arg is None:
                continue
            try:
                values[keyword.arg] = ast.literal_eval(keyword.value)
            except (ValueError, TypeError, SyntaxError, MemoryError):
                self._add(
                    "POLICY_BOUNDARY_NONLITERAL",
                    node,
                    qualname,
                    "policy_boundary arguments must be static literal keywords",
                )
                return None
        return values

    def _add(
        self,
        rule_id: str,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        qualname: str,
        reason: str,
    ) -> None:
        self.findings.append(
            BoundaryFinding(rule_id, self.display_path, node.lineno, qualname, reason)
        )


def _is_policy_boundary_call(node: ast.expr) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "policy_boundary"
    if isinstance(func, ast.Attribute):
        return func.attr == "policy_boundary"
    return False


def _valid_suppresses(value: object) -> bool:
    return (
        isinstance(value, tuple)
        and bool(value)
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
    )


def _resolve_test_ref(
    test_ref: str,
    repo_root: Path,
    repo_root_resolved: Path,
) -> tuple[str, ast.FunctionDef | ast.AsyncFunctionDef] | BoundaryFinding:
    parts = test_ref.split("::")
    if len(parts) not in (2, 3) or not parts[0] or not parts[1]:
        return _test_ref_finding(
            "POLICY_BOUNDARY_TEST_REF_MALFORMED",
            "test_ref must be tests/path.py::test_func or tests/path.py::Class::test_method",
        )
    if len(parts) == 3 and not parts[2]:
        return _test_ref_finding(
            "POLICY_BOUNDARY_TEST_REF_MALFORMED",
            "test_ref must include a test method name",
        )
    test_name = parts[-1]
    if not test_name.startswith("test_"):
        return _test_ref_finding(
            "POLICY_BOUNDARY_TEST_REF_MALFORMED",
            "test_ref function or method name must start with test_",
        )
    test_path = Path(parts[0])
    if test_path.is_absolute() or test_path.suffix != ".py" or not test_path.parts:
        return _test_ref_finding(
            "POLICY_BOUNDARY_TEST_REF_MALFORMED",
            "test_ref path must be a relative tests/*.py file",
        )
    if ".." in test_path.parts:
        return _test_ref_finding(
            "POLICY_BOUNDARY_TEST_REF_MALFORMED",
            "test_ref path must not contain traversal segments",
        )
    if test_path.parts[0] != "tests":
        return _test_ref_finding(
            "POLICY_BOUNDARY_TEST_REF_MALFORMED",
            "test_ref path must start with tests/",
        )

    candidate = repo_root / test_path

    candidate_resolved = candidate.resolve()
    try:
        candidate_resolved.relative_to(repo_root_resolved)
    except ValueError:
        return _test_ref_finding(
            "POLICY_BOUNDARY_TEST_REF_OUTSIDE_REPO",
            "test_ref must resolve under repo_root",
        )
    tests_root_resolved = (repo_root_resolved / "tests").resolve()
    try:
        candidate_resolved.relative_to(tests_root_resolved)
    except ValueError:
        return _test_ref_finding(
            "POLICY_BOUNDARY_TEST_REF_MALFORMED",
            "test_ref path must stay under tests/",
        )

    if not candidate_resolved.is_file():
        return _test_ref_finding(
            "POLICY_BOUNDARY_TEST_FILE_MISSING",
            f"test file not found: {parts[0]}",
        )

    try:
        test_source = candidate_resolved.read_text(encoding="utf-8")
        module = ast.parse(test_source, filename=str(candidate_resolved))
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        return _test_ref_finding(
            "POLICY_BOUNDARY_TEST_PARSE_ERROR",
            f"test file could not be parsed: {exc}",
        )

    test_node = _find_test_node(module, parts[1:])
    if test_node is None:
        return _test_ref_finding(
            "POLICY_BOUNDARY_TEST_FUNCTION_MISSING",
            f"test function not found: {test_ref}",
        )
    return test_source, test_node


def _test_ref_finding(rule_id: str, reason: str) -> BoundaryFinding:
    return BoundaryFinding(rule_id, "", 0, "", reason)


def _source_segment_with_decorators(
    source: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str:
    """Return source for *node* including decorator lines.

    ``ast.get_source_segment`` for a FunctionDef starts at the ``def`` line even
    when decorators are present. Runtime ``inspect.getsource`` includes
    decorators, and decorators can change test execution semantics, so the
    scanner must include them before hashing.
    """
    if node.end_lineno is None:
        return ast.get_source_segment(source, node) or ""
    start_lineno = node.lineno
    if node.decorator_list:
        start_lineno = min(decorator.lineno for decorator in node.decorator_list)
    lines = source.splitlines(keepends=True)
    return "".join(lines[start_lineno - 1 : node.end_lineno])


def _find_test_node(
    module: ast.Module,
    ref_parts: list[str],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    if len(ref_parts) == 1:
        return _find_function(module.body, ref_parts[0])

    class_name, method_name = ref_parts
    for node in module.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return _find_function(node.body, method_name)
    return None


def _find_function(
    nodes: list[ast.stmt],
    name: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _display_path(file_path: Path, repo_root: Path) -> str:
    try:
        return file_path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return file_path.as_posix()
