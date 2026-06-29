# Policy-Boundary Scan-Root Containment Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make MCP `policy_boundary_check` fail closed when a caller-supplied scan root (`root` or `repo_root`) resolves outside the server's configured source boundary, closing finding **legis-0186c23a2c** (the last open north-star governance-honesty P2).

**Architecture:** Add a single-responsibility containment primitive `assert_within_boundary(anchor, *candidates)` to the policy truth layer (`src/legis/policy/boundary_scan.py`). It resolves each candidate path (collapsing `..` and symlinks) and raises `InvalidArgumentError` if it escapes the resolved anchor. The MCP tool calls it with `anchor=source_root` **before** any filesystem walk. The MCP dispatcher already maps `InvalidArgumentError` → an `INVALID_ARGUMENT` error envelope (`isError`), never a result payload — so a rejected scan can never be misread as a clean PASS. The CLI (`legis policy-boundary-check`) is operator-invoked with local filesystem authority and is **deliberately out of scope** — containment there adds no security and would break the CI self-scan gate.

**Tech Stack:** Python 3.12, `uv`, pytest, mypy, ruff. No new dependencies.

**Prerequisites:**
- **Branch isolation (REQUIRED):** Execute on a fresh branch off `main`, e.g. `fix/policy-boundary-containment`. Do **NOT** add these commits to `release/1.3.0-federation-reads` — that branch backs open, owner-gated **PR #21** (the 1.3.0 release) and this security fix must ship as its own PR, not pile onto the release. Recommended: a dedicated git worktree (REQUIRED SUB-SKILL: superpowers:using-git-worktrees).
- `uv sync --dev` has been run; `uv run pytest` is green on the base commit.

> **Locate by symbol, not line number.** This plan was grounded on the `release/1.3.0-federation-reads` checkout. The target `_tool_policy_boundary_check` is **byte-identical on `main`** (verified) — only its offset differs (`main:2479` vs the `release:2660` cited below) because the governance_read work shifted ~181 lines earlier in `mcp.py`. `src/legis/policy/boundary_scan.py` is **identical on both branches**. So every code block below applies verbatim on `main`; find the insertion points by the surrounding code strings, treating line numbers as approximate.

---

## Background facts (verified against the tree, 2026-06-28)

- **Vuln site:** `src/legis/mcp.py:2660` `_tool_policy_boundary_check`. Lines 2664–2671 default + join `repo_root` and `root`, but an **absolute** `repo_root`/`root` is taken verbatim with no containment, and a **relative** `root` with `..` escapes after the join. The chosen root is then walked at 2683 (`count_source_files`) / 2707 (`scan_policy_boundaries`).
- **Error mapping (fail-closed path):** `src/legis/mcp.py:1614` maps `InvalidArgumentError` → `_tool_error("INVALID_ARGUMENT", …)`; `:1625` maps bare `ValueError` the same way. Both produce an error envelope (`isError: True`), not a result.
- **`InvalidArgumentError`** is defined in `src/legis/service/errors.py` ("Caller input is structurally valid for the transport but invalid for Legis") — the exact semantics for an out-of-bounds root.
- **Import-cycle risk:** `src/legis/policy/` does not import `legis.service` today, and `service/__init__.py` imports governance/wardline (which touch `policy`). A module-level `from legis.service.errors import …` in `boundary_scan.py` could cycle. Mitigation: **function-local deferred import** (the established codebase idiom; cf. the deferred `from legis.policy.boundary_scan import …` inside the MCP tool at `mcp.py:2661`).
- **Established containment idiom:** `boundary_scan.py:329-331` (`_resolve_test_ref`) already uses `candidate.resolve()` + `relative_to(...)`-raises-`ValueError`. We reuse that pattern.
- **No HTTP surface:** `grep` confirms `policy_boundary` has no route in `src/legis/api/app.py`. Surface = MCP + CLI only; the fix is MCP-only.
- **Result schema unchanged:** the rejection is an *error*, not a new outcome, so the result `outcome` enum stays `{PASS, FINDINGS, NO_ROOT}` — `test_policy_boundary_check_outcome_schema_includes_no_root` (test_server.py:3304) stays valid.
- **Test patterns:** MCP tests build `McpRuntime(agent_id="agent-1", initialized=True, source_root=str(tmp_path))` and call `call_tool(runtime, "policy_boundary_check", {...})` (test_server.py:3186-3247). Error-envelope assertion shape: `result["isError"] is True`, `result["structuredContent"]["error_code"] == "INVALID_ARGUMENT"` (test_server.py:953-954).

### Pre-verified: no existing test breaks (all 6 MCP call sites analyzed)

Every existing `policy_boundary_check` call site resolves *inside* its `source_root`, so the new check leaves them green:
- 3194/3218/3264/3282 — `{}` defaults under `source_root=tmp_path` → contained.
- 3241 — relative `{"root": "lib", "repo_root": "pkg"}` → `tmp_path/pkg/lib`, `tmp_path/pkg` → contained.
- **3289** (`{"root": str(tmp_path / "nope")}`, `source_root=tmp_path`) — **the acute case.** `tmp_path/nope` is *inside* `tmp_path`; `resolve()`/`relative_to` succeed on a non-existent path, so containment **passes** and the existing `NO_ROOT` outcome is preserved. **Decision pre-made: a nonexistent-but-in-bounds root stays `NO_ROOT`, NOT `INVALID_ARGUMENT`** — only an *out-of-bounds* root errors. Do not "fix" this test.
- `test_honesty_gate.py` / `test_regressions.py` use `check_policy_boundary` (the decorator-evidence checker) and the `@policy_boundary` decorator — different code, untouched. `test_cli.py` exercises the CLI path (out of scope) and monkeypatches `scan_policy_boundaries`.

---

## Task 1: Containment primitive `assert_within_boundary` in the policy layer

**Files:**
- Modify: `src/legis/policy/boundary_scan.py` (add new function near the other module-level helpers, e.g. after `count_source_files`, ~line 98)
- Test: `tests/policy/test_boundary_scan.py`

**Step 1: Write the failing tests**

Add to `tests/policy/test_boundary_scan.py`:

```python
def test_assert_within_boundary_allows_child_path(tmp_path):
    from legis.policy.boundary_scan import assert_within_boundary

    child = tmp_path / "src"
    child.mkdir()
    # Does not raise.
    assert_within_boundary(tmp_path, child)


def test_assert_within_boundary_allows_anchor_itself(tmp_path):
    from legis.policy.boundary_scan import assert_within_boundary

    assert_within_boundary(tmp_path, tmp_path)


def test_assert_within_boundary_rejects_absolute_sibling(tmp_path):
    from legis.policy.boundary_scan import assert_within_boundary
    from legis.service.errors import InvalidArgumentError

    anchor = tmp_path / "project"
    anchor.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()

    with pytest.raises(InvalidArgumentError):
        assert_within_boundary(anchor, outside)


def test_assert_within_boundary_rejects_dotdot_escape(tmp_path):
    from legis.policy.boundary_scan import assert_within_boundary
    from legis.service.errors import InvalidArgumentError

    anchor = tmp_path / "project"
    anchor.mkdir()

    with pytest.raises(InvalidArgumentError):
        assert_within_boundary(anchor, anchor / ".." / "etc")


def test_assert_within_boundary_rejects_symlink_escape(tmp_path):
    from legis.policy.boundary_scan import assert_within_boundary
    from legis.service.errors import InvalidArgumentError

    anchor = tmp_path / "project"
    anchor.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = anchor / "link"
    link.symlink_to(outside)  # a symlink inside the anchor that points out

    with pytest.raises(InvalidArgumentError):
        assert_within_boundary(anchor, link)


def test_assert_within_boundary_checks_every_candidate(tmp_path):
    from legis.policy.boundary_scan import assert_within_boundary
    from legis.service.errors import InvalidArgumentError

    anchor = tmp_path / "project"
    anchor.mkdir()
    good = anchor / "src"
    good.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()

    # The bad one is second — proves all candidates are checked, not just the first.
    with pytest.raises(InvalidArgumentError):
        assert_within_boundary(anchor, good, outside)
```

Confirm `import pytest` is present at the top of the test file (it is used elsewhere in the suite; add it if missing).

**Why these tests:** They pin the security contract directly — child/anchor allowed; absolute-sibling, `..`-traversal, and symlink-escape rejected (the three real bypass shapes); and that *every* candidate is checked (so a contained `root` with an uncontained `repo_root` still fails).

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/policy/test_boundary_scan.py -k assert_within_boundary -v`

Expected output:
```
ImportError / AttributeError: cannot import name 'assert_within_boundary' from 'legis.policy.boundary_scan'
... 6 failed / errors
```

**Step 3: Write minimal implementation**

In `src/legis/policy/boundary_scan.py`, add (after `count_source_files`):

```python
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
```

**Why minimal:** No defaulting/join logic here — that stays in the caller. This is a pure containment assertion so it is trivially unit-testable and reusable.

> **Scope note (symlink traversal):** This primitive rejects a symlink passed *as* a scan root (`resolve()` catches it). It does **not** address `rglob("*.py")` following a symlink discovered *inside* an already-contained tree during the walk — that vector requires filesystem-write access to the source root and is outside this finding's caller-supplied-args threat model. The green symlink test below proves root-rejection, not full traversal hardening.

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/policy/test_boundary_scan.py -k assert_within_boundary -v`

Expected output:
```
6 passed
```

**Step 5: Commit**

```bash
git add src/legis/policy/boundary_scan.py tests/policy/test_boundary_scan.py
git commit -m "feat(policy): add assert_within_boundary scan-root containment primitive

- Resolves candidate paths and fails closed (InvalidArgumentError) when any
  escapes the anchor; collapses .. and symlinks via resolve()
- Deferred service.errors import to avoid a policy<->service cycle
- Toward legis-0186c23a2c

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

**Definition of Done:**
- [ ] 6 tests written and failed for the right reason (missing symbol)
- [ ] `assert_within_boundary` implemented; all 6 pass
- [ ] No other tests in `tests/policy/test_boundary_scan.py` broke
- [ ] Committed

---

## Task 2: Enforce containment in the MCP `policy_boundary_check` tool

**Files:**
- Modify: `src/legis/mcp.py` — in `_tool_policy_boundary_check` (release:2660 / main:2479), extend the deferred `from legis.policy.boundary_scan import ...` and insert a containment call right after `root` is finalized, before the `count_source_files(...)` honesty block. Locate by those code strings, not line number.
- Test: `tests/mcp/test_server.py`

**Step 1: Write the failing tests**

Add to `tests/mcp/test_server.py` (near the existing policy_boundary tests, ~3247):

```python
def test_policy_boundary_check_rejects_absolute_root_outside_source_root(tmp_path):
    from legis.mcp import McpRuntime, call_tool

    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "secret.py").write_text("def s():\n    return 1\n", encoding="utf-8")
    runtime = McpRuntime(agent_id="agent-1", initialized=True, source_root=str(project))

    result = call_tool(runtime, "policy_boundary_check", {"root": str(outside)})

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "INVALID_ARGUMENT"
    # Fail closed: nothing about the out-of-bounds tree leaks as a scanned result.
    assert "scanned_root" not in result["structuredContent"]


def test_policy_boundary_check_rejects_absolute_repo_root_outside_source_root(tmp_path):
    from legis.mcp import McpRuntime, call_tool

    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    (outside / "src").mkdir(parents=True)
    runtime = McpRuntime(agent_id="agent-1", initialized=True, source_root=str(project))

    result = call_tool(runtime, "policy_boundary_check", {"repo_root": str(outside)})

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "INVALID_ARGUMENT"


def test_policy_boundary_check_rejects_relative_traversal_escape(tmp_path):
    from legis.mcp import McpRuntime, call_tool

    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    runtime = McpRuntime(agent_id="agent-1", initialized=True, source_root=str(project))

    result = call_tool(runtime, "policy_boundary_check", {"root": "../../etc"})

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "INVALID_ARGUMENT"


def test_policy_boundary_check_allows_absolute_root_inside_source_root(tmp_path):
    from legis.mcp import McpRuntime, call_tool

    src = tmp_path / "src"
    src.mkdir()
    (src / "clean.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    runtime = McpRuntime(agent_id="agent-1", initialized=True, source_root=str(tmp_path))

    # An ABSOLUTE root that IS inside the boundary must still scan normally.
    result = call_tool(runtime, "policy_boundary_check", {"root": str(src)})

    assert result.get("isError") is not True
    assert result["structuredContent"]["outcome"] == "PASS"
    assert result["structuredContent"]["scanned_root"] == str(src)
```

**Why these tests:** The first three reproduce the finding's three bypass shapes and assert the fail-closed envelope (no scan, no leaked `scanned_root`). The fourth is the regression guard proving in-bounds absolute roots still work — so the fix constrains the attack, not legitimate use.

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/mcp/test_server.py -k "policy_boundary_check_rejects or policy_boundary_check_allows_absolute" -v`

Expected output (pre-fix): the three `rejects` tests FAIL — the tool currently scans the out-of-bounds tree and returns a result (`isError` absent, `outcome` `PASS`/`FINDINGS`/`NO_ROOT`) instead of an error. The `allows_absolute` test passes already.
```
FAILED ... test_policy_boundary_check_rejects_absolute_root_outside_source_root - assert <KeyError 'isError' / outcome ...>
FAILED ... rejects_absolute_repo_root_outside_source_root
FAILED ... rejects_relative_traversal_escape
PASSED ... allows_absolute_root_inside_source_root
```

**Step 3: Write minimal implementation**

In `src/legis/mcp.py`, extend the deferred import at `:2661`:

```python
    from legis.policy.boundary_scan import (
        assert_within_boundary,
        count_source_files,
        scan_policy_boundaries,
    )
```

Then insert the containment call immediately after `root` is finalized (`:2671`) and before the `count_source_files` honesty block (`:2683`):

```python
    root_arg = _optional_string(args, "root")
    root = Path(root_arg) if root_arg else repo_root / "src"
    if not root.is_absolute():
        root = repo_root / root
    # Containment (legis-0186c23a2c): an MCP caller supplies these roots, so an
    # absolute or ..-bearing root must not let Legis walk arbitrary trees outside
    # the server's configured source boundary. Fail closed (INVALID_ARGUMENT)
    # BEFORE any filesystem walk; never scan-then-report an out-of-bounds tree.
    assert_within_boundary(source_root, repo_root, root)
```

**Why minimal:** Reuses the Task 1 primitive; one call, placed before the first filesystem touch (`count_source_files` at `:2683`). No change to defaulting, scanning, or the result schema.

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/mcp/test_server.py -k "policy_boundary" -v`

Expected output: all policy_boundary tests pass (the 3 new `rejects`, the new `allows_absolute`, and the 6 pre-existing ones at 3186-3309).
```
10 passed
```

**Step 5: Commit**

```bash
git add src/legis/mcp.py tests/mcp/test_server.py
git commit -m "fix(mcp): contain policy_boundary_check scan roots to the source boundary

Closes legis-0186c23a2c. An MCP caller could pass an absolute or ..-bearing
root/repo_root and make Legis walk/parse arbitrary Python trees visible to the
server process. The tool now calls assert_within_boundary(source_root, ...)
before any filesystem walk; an out-of-bounds root fails closed to an
INVALID_ARGUMENT error envelope (never a scanned result / PASS).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

**Definition of Done:**
- [ ] 3 reject-tests failed pre-fix for the right reason (scanned instead of erroring)
- [ ] Containment call added before the filesystem walk
- [ ] All 10 policy_boundary tests pass; no other MCP tests broke
- [ ] Committed

---

## Task 3: Full gate verification (CI parity) + self-scan

**Files:** none (verification only)

**Step 1: Run the governance-honesty self-scan gate**

This gate runs `policy_boundary_check` over Legis's own source — it must still PASS (proves the fix did not break the legitimate in-repo scan path).

Run: `uv run legis policy-boundary-check --root src --repo-root .`

Expected output:
```
policy-boundary-check: PASS
```

**Step 2: Run the full CI gate set (mirror `.github/workflows/ci.yml`)**

Run each; all must pass:

```bash
uv run ruff check src
uv run mypy src/legis
uv run pytest --cov=legis --cov-fail-under=88
uv run python scripts/check_coverage_floors.py
uv run pytest tests/conformance/test_sei_oracle.py
uv run legis policy-boundary-check --root src --repo-root .
uv run legis governance-gate
```

Expected output: ruff clean; mypy `Success`; pytest all-passed with coverage ≥ 88 (the new `policy/boundary_scan.py` lines are covered by Task 1); per-package floors hold; SEI oracle passes; self-scan PASS; governance-gate passes.

**Why this task:** CLAUDE.md names these as the gates that fail most often; a governance-honesty fix must not regress any of them. The `policy/` package has a per-package coverage floor — Task 1's six tests must keep it above floor.

**Definition of Done:**
- [ ] Self-scan gate PASS (twice — it appears in both steps intentionally)
- [ ] ruff / mypy / pytest+coverage / floors / SEI oracle / governance-gate all green
- [ ] No commit (verification only)

---

## Task 4: ACCEPT handoff (tracker + workspace) — owner/checkpoint step

**Not executed as code.** On a green Task 3, this fix satisfies **PRD-0005 criterion 3** and takes the north-star **1 → 0**. The acceptance bookkeeping belongs to the ownership loop, not plan execution:

- Close tracker issue **legis-0186c23a2c** with the close commit (the Task 2 commit), via the `/product-checkpoint` flow.
- Record a PDR accepting the governance-honesty bet's completion (the third finding) and update `metrics.md` north-star to 0 / `roadmap.md` Now → done.
- Open a PR for `fix/policy-boundary-containment` **against `main`**, separate from release PR #21. Merging it (and any publish) remains **owner-gated** per the authority grant.

**Definition of Done (for the owner / checkpoint):**
- [ ] CI green on the fix branch
- [ ] legis-0186c23a2c closed against the fix commit
- [ ] north-star recorded at 0; PDR written at checkpoint

---

## Validation before execution — done inline

This is a security fix on the governance-honesty surface, but it is **low-complexity** (~15 lines: one primitive + one call site + tests). The reality validation a `/review-plan` panel would perform has already been done inline and against the tree:

- **Reality:** every symbol, path, the error mapping (`mcp.py` `InvalidArgumentError`/`ValueError` → `INVALID_ARGUMENT` envelope), the import-cycle risk, and the test patterns were verified against the checkout. The function is byte-identical on `main`; `boundary_scan.py` is identical on both branches.
- **Test impact:** all 6 existing MCP call sites analyzed → none break (see "Pre-verified" above); the acute nonexistent-root case decided (`NO_ROOT`, not `INVALID_ARGUMENT`).
- **Design questions settled:** (a) `source_root` is the correct trust anchor (caller-supplied `repo_root` cannot be the boundary or it self-authorizes); (b) CLI is operator-trusted → out of scope, CI self-scan preserved; (c) error-envelope, not a new outcome → fail-closed, schema unchanged; (d) deferred import avoids the policy↔service cycle.

**Do NOT additionally run `/review-plan`** for this fix — a 4-agent panel is disproportionate to a 15-line change whose reality is already verified. Proceed to execution. (Reserve `/review-plan` only if execution surfaces a design change.)
