import ast
from pathlib import Path

from legis.policy.boundary_scan import scan_policy_boundaries
from legis.policy.decorator import fingerprint_source


def _test_fingerprint(source: str) -> str:
    # The canonical fingerprint both the gate and scanner compute (Q-L5).
    return fingerprint_source(source)


def _write_boundary_subject(
    src: Path,
    *,
    test_ref: str | None,
    test_fingerprint: str | None,
    suppresses: tuple[str, ...] = ("PY-WL-101",),
) -> None:
    test_ref_line = "" if test_ref is None else f'    test_ref="{test_ref}",\n'
    fingerprint_line = (
        "" if test_fingerprint is None else f'    test_fingerprint="{test_fingerprint}",\n'
    )
    src.mkdir(parents=True, exist_ok=True)
    (src / "subject.py").write_text(
        f'''
from legis.policy.decorator import policy_boundary

@policy_boundary(
    source="docs/spec.md:12",
    suppresses={suppresses!r},
    invariant="guarded input rejects malformed records",
{test_ref_line}{fingerprint_line})
def guarded(payload):
    return "ok"
''',
        encoding="utf-8",
    )


def test_scan_policy_boundaries_accepts_pinned_exercising_test(tmp_path: Path) -> None:
    test_source = '''
def test_policy_boundary_exercises_subject():
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    fp = _test_fingerprint(test_source)
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint=fp,
    )
    (tests / "test_subject.py").write_text(test_source, encoding="utf-8")

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert findings == []


def test_scan_policy_boundaries_reports_missing_test_ref(tmp_path: Path) -> None:
    src = tmp_path / "src" / "pkg"
    _write_boundary_subject(src, test_ref=None, test_fingerprint="pinned")

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_REF_MISSING"
    assert findings[0].reason == "test_ref is required"


def test_scan_policy_boundaries_reports_stale_fingerprint(tmp_path: Path) -> None:
    test_source = '''
def test_policy_boundary_exercises_subject():
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint="stale",
    )
    (tests / "test_subject.py").write_text(test_source, encoding="utf-8")

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_FINGERPRINT_MISMATCH"


def test_scan_policy_boundaries_rejects_skip_disabled_evidence_test(tmp_path: Path) -> None:
    # POLICY-1, end-to-end: a reviewer pins a real, running evidence test, then
    # the test is disabled with @pytest.mark.skip after the fact. Decorators are
    # semantic and now fingerprinted, so the clean pinned hash must drift before
    # the evidence evaluator runs.
    clean_test = '''
def test_policy_boundary_exercises_subject():
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    fp = _test_fingerprint(clean_test)
    disabled_function = '''
@pytest.mark.skip(reason="disabled after the human pinned it")
def test_policy_boundary_exercises_subject():
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    disabled_test = "import pytest\n\n" + disabled_function
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint=fp,
    )
    (tests / "test_subject.py").write_text(disabled_test, encoding="utf-8")

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_FINGERPRINT_MISMATCH"

    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint=_test_fingerprint(disabled_function),
    )
    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_DISABLED"


def test_scan_policy_boundaries_rejects_xfail_disabled_evidence_test(tmp_path: Path) -> None:
    clean_test = '''
def test_policy_boundary_exercises_subject():
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    fp = _test_fingerprint(clean_test)
    disabled_function = '''
@pytest.mark.xfail
def test_policy_boundary_exercises_subject():
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    disabled_test = "import pytest\n\n" + disabled_function
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint=fp,
    )
    (tests / "test_subject.py").write_text(disabled_test, encoding="utf-8")

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_FINGERPRINT_MISMATCH"

    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint=_test_fingerprint(disabled_function),
    )
    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_DISABLED"


def test_scan_policy_boundaries_reports_test_that_does_not_exercise_subject(
    tmp_path: Path,
) -> None:
    test_source = '''
def test_policy_boundary_mentions_policy_only():
    assert "PY-WL-101"
'''
    fp = _test_fingerprint(test_source)
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::test_policy_boundary_mentions_policy_only",
        test_fingerprint=fp,
    )
    (tests / "test_subject.py").write_text(test_source, encoding="utf-8")

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_DOES_NOT_EXERCISE_SUBJECT"


def test_scan_policy_boundaries_rejects_test_ref_outside_tests_directory(
    tmp_path: Path,
) -> None:
    test_source = '''
def test_policy_boundary_exercises_subject():
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    src = tmp_path / "src" / "pkg"
    other = tmp_path / "src" / "test_subject.py"
    other.parent.mkdir(parents=True)
    other.write_text(test_source, encoding="utf-8")
    _write_boundary_subject(
        src,
        test_ref="src/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint=_test_fingerprint(test_source),
    )

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_REF_MALFORMED"


def test_scan_policy_boundaries_rejects_non_python_test_ref_file(tmp_path: Path) -> None:
    test_source = '''
def test_policy_boundary_exercises_subject():
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_subject.txt").write_text(test_source, encoding="utf-8")
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.txt::test_policy_boundary_exercises_subject",
        test_fingerprint=_test_fingerprint(test_source),
    )

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_REF_MALFORMED"


def test_scan_policy_boundaries_rejects_tests_path_traversal(tmp_path: Path) -> None:
    test_source = '''
def test_policy_boundary_exercises_subject():
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    src = tmp_path / "src" / "pkg"
    other = tmp_path / "src" / "test_subject.py"
    other.parent.mkdir(parents=True)
    other.write_text(test_source, encoding="utf-8")
    _write_boundary_subject(
        src,
        test_ref="tests/../src/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint=_test_fingerprint(test_source),
    )

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_REF_MALFORMED"


def test_scan_policy_boundaries_rejects_traversal_syntax_even_inside_tests(
    tmp_path: Path,
) -> None:
    test_source = '''
def test_policy_boundary_exercises_subject():
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_subject.py").write_text(test_source, encoding="utf-8")
    _write_boundary_subject(
        src,
        test_ref="tests/../tests/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint=_test_fingerprint(test_source),
    )

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_REF_MALFORMED"


def test_scan_policy_boundaries_rejects_non_test_function_ref(tmp_path: Path) -> None:
    test_source = '''
def helper():
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_subject.py").write_text(test_source, encoding="utf-8")
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::helper",
        test_fingerprint=_test_fingerprint(test_source),
    )

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_REF_MALFORMED"


def test_scan_policy_boundaries_rejects_non_test_method_ref(tmp_path: Path) -> None:
    test_source = '''
class TestPolicyBoundary:
    def helper(self):
        assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    fp = _test_fingerprint(
        '''
def helper(self):
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    )
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_subject.py").write_text(test_source, encoding="utf-8")
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::TestPolicyBoundary::helper",
        test_fingerprint=fp,
    )

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_REF_MALFORMED"


def test_scan_policy_boundaries_rejects_subject_call_hidden_in_nested_helper(
    tmp_path: Path,
) -> None:
    test_source = '''
def test_policy_boundary_exercises_subject():
    def dead_helper():
        return guarded({"policy": "PY-WL-101"})
    assert "PY-WL-101"
'''
    fp = _test_fingerprint(test_source)
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint=fp,
    )
    (tests / "test_subject.py").write_text(test_source, encoding="utf-8")

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_DOES_NOT_EXERCISE_SUBJECT"


def test_scan_policy_boundaries_requires_exact_policy_token(tmp_path: Path) -> None:
    test_source = '''
def test_policy_boundary_exercises_subject():
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    fp = _test_fingerprint(test_source)
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint=fp,
        suppresses=("PY-WL-10",),
    )
    (tests / "test_subject.py").write_text(test_source, encoding="utf-8")

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_WEAK"


def test_scan_policy_boundaries_accepts_class_method_test_ref(tmp_path: Path) -> None:
    test_source = '''
class TestPolicyBoundary:
    def test_policy_boundary_exercises_subject(self):
        assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    fp = _test_fingerprint(
        '''
def test_policy_boundary_exercises_subject(self):
    assert guarded({"policy": "PY-WL-101"}) == "ok"
'''
    )
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::TestPolicyBoundary::test_policy_boundary_exercises_subject",
        test_fingerprint=fp,
    )
    (tests / "test_subject.py").write_text(test_source, encoding="utf-8")

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert findings == []


def test_scan_policy_boundaries_reports_nonliteral_decorator(tmp_path: Path) -> None:
    src = tmp_path / "src" / "pkg"
    src.mkdir(parents=True)
    (src / "subject.py").write_text(
        '''
from legis.policy.decorator import policy_boundary

POLICY = "PY-WL-101"

@policy_boundary(
    source="docs/spec.md:12",
    suppresses=(POLICY,),
    invariant="guarded input rejects malformed records",
    test_ref="tests/test_subject.py::test_policy_boundary_exercises_subject",
    test_fingerprint="pinned",
)
def guarded(payload):
    return "ok"
''',
        encoding="utf-8",
    )

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_NONLITERAL"


def test_scan_policy_boundaries_reports_source_decode_error(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "bad.py").write_bytes(b"\xff")

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_PARSE_ERROR"


def test_scan_policy_boundaries_reports_test_file_decode_error(tmp_path: Path) -> None:
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_subject.py").write_bytes(b"\xff")
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint="pinned",
    )

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_PARSE_ERROR"


def test_scan_rejects_policy_mention_outside_the_assert(tmp_path: Path) -> None:
    # Calls the subject and mentions the policy, but only in a throwaway string
    # not bound to the assert. The OLD scanner passed this; the new one must not.
    test_source = '''
def test_policy_boundary_exercises_subject():
    note = "see PY-WL-101 in the docs"
    result = guarded({"x": 1})
    assert result == "ok"
'''
    fp = _test_fingerprint(test_source)
    src = tmp_path / "src" / "pkg"
    tests = tmp_path / "tests"
    tests.mkdir()
    _write_boundary_subject(
        src,
        test_ref="tests/test_subject.py::test_policy_boundary_exercises_subject",
        test_fingerprint=fp,
    )
    (tests / "test_subject.py").write_text(test_source, encoding="utf-8")

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    assert len(findings) == 1
    assert findings[0].rule_id == "POLICY_BOUNDARY_TEST_WEAK"


def test_scan_and_runtime_gate_agree_on_a_shared_corpus(tmp_path: Path) -> None:
    """Convergence keystone: drive BOTH real public gates over the same corpus
    and assert their allow/block verdicts match. This invokes scan_policy_boundaries
    AND check_policy_boundary end-to-end (not the shared evaluator alone), so it
    verifies the WIRING of both callers: that each correctly resolves/extracts the
    test function node, constructs boundary_names, and that the scanner's on-disk
    fingerprint recompute aligns with the runtime's in-memory fingerprint. After
    the Task-2-Step-4 convergence both callers delegate to evaluate_test_evidence,
    so this test goes from RED (pre-convergence: the old _test_mentions_policy
    allows `test_weak` while the runtime blocks it) to GREEN. It is the regression
    guard that keeps the two callers wired to the single evaluator. (It does NOT
    test independent semantics — by design there is only one implementation now;
    `test_weak` is the case that proves the old token-anywhere scanner is gone.)
    """
    import inspect
    import textwrap

    from legis.policy.decorator import check_policy_boundary, fingerprint, policy_boundary

    # Corpus: each is a real test function; `guarded` is the boundary subject.
    # They are inspected, never executed, so the free `guarded`/`note` names are fine.
    def test_ok():
        result = guarded({"p": "PY-WL-101"})  # noqa: F821
        assert result == "ok", "PY-WL-101"

    def test_weak():
        note = "PY-WL-101"  # noqa: F841 — policy mentioned outside the assert
        result = guarded(1)  # noqa: F821
        assert result == "ok"

    def test_unexercised():
        assert "PY-WL-101"

    def test_shadowed():
        def guarded(payload):  # noqa: F811 — shadows the boundary name
            return "ok"
        assert guarded(1) == "ok", "PY-WL-101"

    for test_fn in (test_ok, test_weak, test_unexercised, test_shadowed):
        name = test_fn.__name__
        fp = fingerprint(test_fn)

        @policy_boundary(
            source="docs/spec.md:1",
            suppresses=("PY-WL-101",),
            invariant="boundary holds",
            test_ref=f"tests/test_case.py::{name}",
            test_fingerprint=fp,
        )
        def guarded(payload):
            return "ok"

        runtime_ok = check_policy_boundary(guarded, lambda ref, _fn=test_fn: _fn).ok

        src_dir = tmp_path / name / "src" / "pkg"
        tests_dir = tmp_path / name / "tests"
        tests_dir.mkdir(parents=True)
        _write_boundary_subject(
            src_dir, test_ref=f"tests/test_case.py::{name}", test_fingerprint=fp
        )
        # Same source on disk (dedented top-level) → matching fingerprint.
        (tests_dir / "test_case.py").write_text(
            textwrap.dedent(inspect.getsource(test_fn)), encoding="utf-8"
        )
        scanner_ok = scan_policy_boundaries(src_dir, repo_root=tmp_path / name) == []

        assert runtime_ok == scanner_ok, (
            f"gates disagree on {name!r}: runtime={runtime_ok}, scanner={scanner_ok}"
        )


def _write_sibling_boundary(src: Path) -> None:
    """A detectable sibling: a @policy_boundary with no test_ref yields a
    POLICY_BOUNDARY_TEST_REF_MISSING finding *iff* the file is actually scanned.
    Used to prove the scan continued past a hostile file (G4)."""
    _write_boundary_subject(src, test_ref=None, test_fingerprint="pinned")


def test_parse_bomb_degrades_per_file_and_scan_continues(tmp_path: Path) -> None:
    """Dogfood-4 A2 / federation rec #3 (fail-degraded, never fail-dead): a deep
    left-leaning BinOp chain exhausts the *parser* stack (ast.parse raises
    RecursionError). It must become a POLICY_BOUNDARY_FILE_TOO_COMPLEX finding,
    not kill the run — and the sibling @policy_boundary file is still scanned
    and reported (proves the scan continued past the bomb)."""
    src = tmp_path / "src" / "pkg"
    src.mkdir(parents=True)
    # A deep BinOp chain blows ast.parse at the default recursion limit.
    bomb = "BOMB = " + "+".join(["1"] * 20000) + "\n"
    (src / "nesting_bomb.py").write_text(bomb, encoding="utf-8")
    _write_sibling_boundary(src)

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    rule_ids = {f.rule_id for f in findings}
    too_complex = [f for f in findings if f.rule_id == "POLICY_BOUNDARY_FILE_TOO_COMPLEX"]
    assert len(too_complex) == 1, f"expected exactly one degrade finding, got {rule_ids}"
    assert too_complex[0].file_path.endswith("nesting_bomb.py")
    assert "skipped" in too_complex[0].reason
    # Scan must have continued: the sibling boundary was actually scanned.
    sibling = [f for f in findings if f.rule_id == "POLICY_BOUNDARY_TEST_REF_MISSING"]
    assert len(sibling) == 1, f"sibling file was not scanned; got {rule_ids}"
    assert sibling[0].file_path.endswith("subject.py")


def test_visitor_walk_bomb_degrades_per_file_and_scan_continues(tmp_path: Path) -> None:
    """Drives the *visitor-walk* degrade path (boundary_scan.py lines after the
    parse guard), distinct from the parse-stack path above. A deep attribute
    chain (a.b.b.b…) PARSES fine but blows the recursive NodeVisitor walk; the
    file must degrade to POLICY_BOUNDARY_FILE_TOO_COMPLEX and the sibling
    @policy_boundary is still scanned and reported."""
    src = tmp_path / "src" / "pkg"
    src.mkdir(parents=True)
    # Sanity-check the shape: this source parses but blows the visitor walk.
    walk_bomb = "BOMB = a" + ".b" * 5000 + "\n"
    ast.parse(walk_bomb)  # parses fine at the default recursion limit
    (src / "walk_bomb.py").write_text(walk_bomb, encoding="utf-8")
    _write_sibling_boundary(src)

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    rule_ids = {f.rule_id for f in findings}
    too_complex = [f for f in findings if f.rule_id == "POLICY_BOUNDARY_FILE_TOO_COMPLEX"]
    assert len(too_complex) == 1, f"expected exactly one degrade finding, got {rule_ids}"
    assert too_complex[0].file_path.endswith("walk_bomb.py")
    assert "skipped" in too_complex[0].reason
    # Scan must have continued past the walk-bomb: sibling boundary was scanned.
    sibling = [f for f in findings if f.rule_id == "POLICY_BOUNDARY_TEST_REF_MISSING"]
    assert len(sibling) == 1, f"sibling file was not scanned; got {rule_ids}"
    assert sibling[0].file_path.endswith("subject.py")


def test_memory_exhaustion_degrades_per_file_and_scan_continues(
    tmp_path: Path, monkeypatch
) -> None:
    """G2: a memory-exhausting specimen (MemoryError on read/parse/walk) must
    degrade the same way a RecursionError does, not fail-dead the whole gate
    (_coerce_literal already catches MemoryError; the per-file guard must too).
    We inject MemoryError at ast.parse for the bomb file only and assert the
    sibling is still scanned."""
    src = tmp_path / "src" / "pkg"
    src.mkdir(parents=True)
    (src / "mem_bomb.py").write_text("X = 1\n", encoding="utf-8")
    _write_sibling_boundary(src)

    import legis.policy.boundary_scan as bscan

    real_parse = bscan.ast.parse

    def fake_parse(source, *args, **kwargs):
        filename = kwargs.get("filename") or (args[0] if args else "")
        if "mem_bomb.py" in str(filename):
            raise MemoryError("simulated literal blowup")
        return real_parse(source, *args, **kwargs)

    monkeypatch.setattr(bscan.ast, "parse", fake_parse)

    findings = scan_policy_boundaries(src, repo_root=tmp_path)

    rule_ids = {f.rule_id for f in findings}
    too_complex = [f for f in findings if f.rule_id == "POLICY_BOUNDARY_FILE_TOO_COMPLEX"]
    assert len(too_complex) == 1, f"MemoryError should degrade, not fail-dead; got {rule_ids}"
    assert too_complex[0].file_path.endswith("mem_bomb.py")
    # Scan must have continued past the memory bomb.
    sibling = [f for f in findings if f.rule_id == "POLICY_BOUNDARY_TEST_REF_MISSING"]
    assert len(sibling) == 1, f"sibling file was not scanned; got {rule_ids}"


# --- fix/legis-policy-boundary-no-vacuous-pass: count_source_files ---
# A governance gate that PASSES on a zero-file scan is a vacuous green (the
# weft-ef2e898642 silent-clean-on-zero-scope failure class). The surfaces
# (MCP + CLI) need to distinguish "scanned N>=1 files, 0 findings -> PASS" from
# "scanned 0 files / root missing -> NO_ROOT". count_source_files is the single
# source of truth for "did we actually scan anything", counting exactly the set
# scan_policy_boundaries would walk.


def test_count_source_files_counts_python_files_recursively(tmp_path: Path) -> None:
    from legis.policy.boundary_scan import count_source_files

    pkg = tmp_path / "src" / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "a.py").write_text("x = 1\n", encoding="utf-8")
    (pkg / "b.py").write_text("y = 2\n", encoding="utf-8")
    (pkg / "notes.txt").write_text("not python\n", encoding="utf-8")

    assert count_source_files(tmp_path / "src") == 2


def test_count_source_files_zero_for_empty_dir(tmp_path: Path) -> None:
    from legis.policy.boundary_scan import count_source_files

    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "README.md").write_text("# no python here\n", encoding="utf-8")

    assert count_source_files(empty) == 0


def test_count_source_files_zero_for_missing_dir(tmp_path: Path) -> None:
    from legis.policy.boundary_scan import count_source_files

    assert count_source_files(tmp_path / "does-not-exist") == 0
