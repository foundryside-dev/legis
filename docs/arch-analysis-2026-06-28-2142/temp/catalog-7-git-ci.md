## Git/Change Surface

**Location:** `src/legis/git/`

**Responsibility:** Provides stateless, read-only access to the local git repository (branches, commits, rename evidence) and defines the injectable forge seam used by adapters that need PR context from an external forge.

**Key Components:**
- `surface.py` (208 lines) — `GitSurface`: shells out to `git -C <repo>` for all reads; exposes `branches()`, `commit()`, `commits()`, `merge_base()`, `renames()`, and `working_tree_renames()`; validates every ref/SHA against a strict allowlist regex before passing to the shell (`surface.py:81,117,124,127,137`) to prevent injection; raises `GitError` on bad exit codes or timeouts (10 s ceiling)
- `rename_feed.py` (48 lines) — `build_rename_feed()`: composes committed and optional worktree renames into the dict structure consumed by `GET /git/rename-feed` (HTTP) and `git_rename_feed_get` (MCP); emits `worktree_checked` flag to distinguish "checked and clean" from "not checked" (`rename_feed.py:14-16`)
- `models.py` (46 lines) — frozen dataclasses `BranchInfo`, `CommitInfo`, `RenameEvidence`; `RenameEvidence` docstring explicitly scopes the claim to path-level git detection only and defers symbol-level resolution to Loomweave (`models.py:33-38`)
- `pull_request.py` (28 lines) — `PullRequestContext` dataclass and `PullRequestSource` runtime-checkable Protocol; a deployment wires a provider (e.g. `gh`-backed); legis bakes in no forge HTTP (`pull_request.py:1-8`)
- `__init__.py` (1 line) — module docstring only; exports nothing (consumers import from submodules directly)

**Dependencies:**
- Inbound: `api/app.py` (imports `GitSurface`, `build_rename_feed`, `PullRequestSource`); `mcp.py` (imports `GitSurface`, `build_rename_feed`, `GitError`)
- Outbound: stdlib only (`subprocess`, `pathlib`, `re`); no Legis sibling packages

**Patterns Observed:**
- Strict ref/SHA allowlist validation at every entry point before shell invocation (`surface.py:81,117,124,127,137,178`) — injection defense is in the surface, not in each caller
- Stateless design: every method call reads directly from the real repository; no in-memory cache
- `_run_raw()` vs `_run()` split: error-tolerant reads (e.g. upstream ahead/behind, blob lookups) use `_run_raw` and check returncode; mandatory reads use `_run` and raise `GitError`
- Working-tree renames use the literal sentinel `"WORKTREE"` as `commit_sha` (`surface.py:194`), communicating uncommitted provenance to the consumer
- Forge seam (PR context) uses a `Protocol` injection pattern matching `identity/` and `filigree/` client seams

**Concerns:**
- None observed for governance honesty: rename evidence carries an explicit docstring boundary (path-level only, `models.py:33-38`); `PullRequestSource` is read-only and injects no forge writes; `working_tree_renames` emits `commit_sha="WORKTREE"` rather than a hash, preventing misinterpretation as a committed ref; `merge_base()` returns `None` (not an empty string that could collide with a ref) when there is no common ancestor (`surface.py:131-132`)
- `_blob()` silently returns `""` when a rev/path cannot be resolved (`surface.py:207`); a consumer receiving `old_blob=""` cannot distinguish "object missing" from "lookup failed" — documented as intentional for Loomweave's matcher, but the emptiness semantics are not explicit in `RenameEvidence`
- Test coverage: `test_git_surface.py` (156 lines), `test_rename_feed.py` (47 lines), `test_git_rename_feed_contract.py` (103 lines); ref-validation injection tests verified in `test_git_surface.py`

**Confidence:** High — read 100% of all 5 source files (surface.py 208 lines, rename_feed.py 48 lines, models.py 46 lines, pull_request.py 28 lines, __init__.py 1 line); cross-verified inbound callers in api/app.py and mcp.py; verified test coverage exists for rename feed and surface


---

## CI/Check Surface

**Location:** `src/legis/checks/`

**Responsibility:** Records CI check runs supplied by writers (agents, CI adapters) into an indexed SQLite store and serves them back queryable by commit SHA, branch name, or PR number, always tagging recorded runs as writer-supplied and unauthenticated.

**Key Components:**
- `surface.py` (133 lines) — `CheckSurface`: SQLAlchemy Core over SQLite (NullPool); `record()`, `for_commit()`, `for_branch()`, `for_pr()`, `latest_state()`; additive migration via `_ensure_schema()` for `recorded_by` and `provenance` columns (`surface.py:57-66`); `_to_run()` defaults missing `provenance` to `Provenance.UNAUTHENTICATED` for rows written before the column existed (`surface.py:115`)
- `models.py` (43 lines) — `CheckRun` frozen dataclass and `CheckOutcome` str-Enum; comment at `models.py:36-42` explicitly names the governance limit: "a recorded check is a writer-supplied claim, not a forge-verified fact"; `provenance` defaults to `Provenance.UNAUTHENTICATED`
- `__init__.py` (1 line) — module docstring only

**Dependencies:**
- Inbound: `api/app.py` (imports `CheckSurface`, `CheckRun`, `CheckOutcome`); `mcp.py` (imports `CheckSurface`, `CheckRun`, `CheckOutcome`); `pulls/surface.py` imports `Provenance` (via shared `legis.provenance`, not this package)
- Outbound: `legis.provenance` (shared vocabulary); `legis.config.ensure_sqlite_parent` (parent-dir creation for DB path); SQLAlchemy (storage)

**Patterns Observed:**
- Provenance honesty by construction: the `provenance` field is set to `UNAUTHENTICATED` at the model default (`models.py:42`) and is re-applied on read for pre-migration rows (`surface.py:115`), so no code path can return a check run without an explicit provenance claim
- `check_report` MCP tool echoes `recorded_by` and `provenance` back to the caller in its result (`mcp.py:2433-2440`), explicitly preventing a caller from believing its own report became forge-attested
- `latest_state()` uses last-write-wins by insert order (`surface.py:129-131`), matching a CI model where newer runs supersede older ones for the same check name
- Table is indexed (not append-only) to support dimensional queries, distinct from the HMAC-chained governance audit log (`surface.py:3-7`)
- Additive `ALTER TABLE` migration rather than versioned migrations — suitable for the single-writer, file-local SQLite model

**Concerns:**
- No deduplication guard: recording the same `(run_id, commit_sha, check_name)` twice produces two rows; `latest_state()` will return the second by insert order, but `for_commit()` / `for_branch()` / `for_pr()` return all rows. An agent that double-reports does not cause a false-green (both rows are unauthenticated claims), but check counts in API/MCP responses may mislead
- `check_report` (MCP write tool) accepts `commit_sha` as a free string with no validation against the actual repo — an agent can record a check against a SHA that does not exist in the repository; there is no proof-of-commit gate
- `provenance` column is `Text` in the DB and is never validated on read — a raw-DB write of an arbitrary string would survive round-trip; the `_to_run()` fallback only guards `NULL`, not arbitrary values (`surface.py:115`)
- No forge-verification path exists today (only `UNAUTHENTICATED`); the field is wired for a future authenticated path (e.g. signed webhook), but the extension point is in `provenance.py` only — there is no corresponding routing or validation logic yet

**Confidence:** High — read 100% of all 3 source files (surface.py 133 lines, models.py 43 lines, __init__.py 1 line); read the MCP check_report and check_list tool implementations (mcp.py:2396-2440); cross-verified provenance defaults in surface._to_run() and models.CheckRun; test coverage in tests/checks/test_check_surface.py (84 lines)


---

## Pull-Request Surface

**Location:** `src/legis/pulls/`

**Responsibility:** Records forge-reported pull-request metadata (writer-supplied, unauthenticated) into a per-PR upsert SQLite store and serves it back, always preserving a provenance label that prevents a consumer from treating a writer-asserted PR state as forge-authoritative.

**Key Components:**
- `surface.py` (78 lines) — `PullSurface`: SQLAlchemy Core over SQLite (NullPool); `record()` upserts via delete-then-insert keyed on PR number (`surface.py:46-58`); `get()` returns `None` for unknown PRs; `_ensure_schema()` adds `recorded_by` and `provenance` columns additively (`surface.py:34-43`); `get()` defaults `provenance` to `UNAUTHENTICATED` for pre-migration rows (`surface.py:76`)
- `models.py` (30 lines) — `PullRequest` frozen dataclass and `PullRequestState` str-Enum; comment at `models.py:26-29` mirrors the checks provenance honesty contract
- `__init__.py` (3 lines) — explicit `__all__` re-export of `PullRequest`, `PullRequestState`, `PullSurface`

**Dependencies:**
- Inbound: `api/app.py` (imports `PullRequest`, `PullRequestState`, `PullSurface`); `mcp.py` (imports `PullRequestState`, `PullSurface`); also `git/pull_request.py` defines a parallel `PullRequestContext` / `PullRequestSource` Protocol used by the live-forge injection path (the two are not merged)
- Outbound: `legis.provenance` (shared vocabulary); `legis.config.ensure_sqlite_parent`; SQLAlchemy

**Patterns Observed:**
- Upsert-by-number semantics: each `record()` call replaces any prior row for that PR number atomically within a transaction (`surface.py:46-48`), so the store always reflects the last-known state rather than accumulating history
- `pull_request_get` MCP tool lazily initialises `_checks()` unconditionally to prevent call-order-dependent gaps where a fresh runtime might report no checks for a PR (`mcp.py:2354-2359`) — an explicit governance-honesty fix noted in the comment
- Two parallel PR seams in the HTTP adapter: `GET /git/pull-requests/{number}` uses the injected `PullRequestSource` (live forge); `POST /git/pulls` + `GET /git/pulls/{number}` use `PullSurface` (recorded cache) — clearly separated and documented
- `pull_request_record` intentionally absent from MCP tool surface (per CLAUDE.md: "forge is source of truth, pinned in test") — the MCP surface is read-only for PRs; write is HTTP-only

**Concerns:**
- The two PR representations (`PullRequestContext` in `git/pull_request.py` and `PullRequest` in `pulls/models.py`) carry overlapping fields (`number`, `title`, `base`, `head`, `state`) but are structurally separate types with no shared base or adapter — a consumer receiving one cannot easily convert to the other without a manual mapping; this is intentional (live-forge vs recorded seam) but the distinction is undocumented at the type level
- `record()` silently overwrites an existing PR's data with whatever the writer provides; if a writer submits a stale state (e.g. `open` after a PR merged), the store will reflect the stale value with no conflict detection or warning
- No test exercises the `provenance` field being set to a non-default value (e.g. a hypothetical `"webhook_signed"`); the `UNAUTHENTICATED` default is tested implicitly but the upgrade path is only named in comments, not in any test fixture

**Confidence:** High — read 100% of all 3 source files (surface.py 78 lines, models.py 30 lines, __init__.py 3 lines); cross-verified both PR seams in api/app.py (lines 523-551); verified MCP pull_request_get implementation (mcp.py:2347-2360); test coverage verified via tests/pulls/test_pull_surface.py (30 lines) and tests/git/test_pull_request_api.py
