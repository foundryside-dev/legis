## Enforcement

**Location:** `src/legis/enforcement/`

**Responsibility:** Implements the governance 2x2 enforcement engine: routes overrides through the appropriate cell (chill, coached, structured, or protected), appends every decision to an HMAC-signed append-only audit trail, and provides lifecycle gates (decay sweep, override-rate check) for the protected cell.

**Key Components:**
- `engine.py` (120 lines) — Simple-tier engine (chill + coached cells). `EnforcementEngine.submit_override` is the single entry point; when `judge=None` the record appends unconditionally (chill), otherwise the `LLMJudge` evaluates before append (coached). Every submission appends exactly one record — no silent path.
- `judge.py` (186 lines) — Coached-cell judge. Defines `LLMJudge`, `parse_verdict` (fail-closed: anything not an explicit ACCEPTED is BLOCKED), and `_parse_structured_response` (JUDGE-3: rejects `OVERRIDDEN_BY_OPERATOR` from model output). Prompt injection defense: 8192-char serialized-request cap (JUDGE-1); JSON-serialized request prevents structural key injection (JUDGE-2).
- `protected.py` (422 lines) — Protected cell. `ProtectedGate.submit` routes through the LLM judge then requires a deterministic non-LLM `ProtectedValidator` to confirm ACCEPTED (JUDGE-3 / Q-H3); any validator exception is a veto. `_record_signed` computes an HMAC-SHA256 signature over a defined field set including `chain_seq` (v3 / AUD-1 position binding). `TrailVerifier` re-checks signatures on read and optionally checks `HeadAnchor` for tail-truncation detection.
- `signing.py` (62 lines) — HMAC-SHA256 signing primitive. v2 binds record content only; v3 additionally binds `chain_seq` to close delete-and-rechain forgery. `canonical_json` from `legis.canonical` is the serialization contract (ensure_ascii=False is intentional per the cross-tool HMAC contract with Wardline).
- `signoff.py` (194 lines) — Structured/protected sign-off gate. `SignoffGate.request` writes `PENDING_SIGNOFF` (does NOT clear the gate); `sign_off` writes `SIGNED_OFF` referencing the request by seq and payload hash. Protected sign-offs are HMAC-signed with v3 chain_seq binding. Anchor advance is batch-aware (Q-M5).
- `verdict.py` (51 lines) — Value types shared across the engine. `Verdict.model_emittable()` is the single source of truth for what an LLM may return (ACCEPTED or BLOCKED only); `Verdict.accepting()` is the single source of truth for what counts as cleared. Both are checked by name, not re-listed.
- `lifecycle.py` (135 lines) — Protected-cell lifecycle gates. `decay_sweep` re-judges each ACCEPTED suppression via the live judge (skips BLOCKED and OVERRIDDEN_BY_OPERATOR). `evaluate_override_rate` computes operator-override share over the most recent window; PASS_WITH_NOTICE when below `min_sample`.
- `judge_factory.py` (36 lines) — Runtime wiring. `FailClosedJudge` is the default when no LLM is configured (always returns BLOCKED). `build_judge_from_env` returns the real `LLMJudge` or `FailClosedJudge`, never None from the coached/protected wiring paths.
- `llm_client.py` (169 lines) — OpenRouter-backed LLM client. Validates HTTPS (loopback exception), blocks HTTP redirects, caps response size at 1 MB. API key read from `OPENROUTER_API_KEY` environment variable at config time.

**Dependencies:**
- Inbound: `service/` (wires the engine/gates into governance decisions), `api/`, `mcp.py`, `cli.py` (thin adapters that consume `service/`)
- Outbound: `legis.canonical` (signing serialization), `legis.clock` (timestamp injection), `legis.identity.entity_key` (SEI-keyed records), `legis.records.override_record` (record schema), `legis.store.protocol` / `legis.store.head_anchor` (append-only store + tail-truncation anchor)

**Patterns Observed:**
- Protocol-typed injection for all external seams (`AppendOnlyStore`, `Clock`, `Judge`, `LLMClient`, `ProtectedValidator`) — every dependency is testable without a network or real store.
- Every verdict path appends exactly one record (no silent governance path); the only way to not append is to raise, which is fail-closed.
- Single sources of truth: `Verdict.model_emittable()` for LLM-emittable verdicts, `Verdict.accepting()` for what counts as cleared, `signing_fields()` shared by write and verify paths so they cannot drift.
- v3 chain position binding: signature includes `chain_seq` from the database column (not a payload field), closing delete-and-rechain attacks.
- Validator exception handling in `ProtectedGate.submit` (protected.py:355-358): any exception from the user-supplied validator is caught and treated as a veto (fail-closed), preventing an unexpected record shape from surfacing as a fail-open 500.
- `FailClosedJudge` sentinel: the coached/protected paths never degrade to a nil judge on misconfiguration; absence of LLM config produces an always-BLOCKED fallback, not an open path.

**Concerns:**
- `TrailVerifier._requires_verification` (protected.py:133-142) derives verification requirement from in-record fields (`protected_cell`, `file_fingerprint`, etc.). An actor with raw DB write access can strip these markers and downgrade a protected record to unsigned — the verifier then skips it. This is a documented residual (protected.py:100-113) of the raw-file-write threat tier, mitigated only by the opt-in `HeadAnchor`. The `HeadAnchor` itself has a documented anchor-replay caveat (re-writing the anchor to match a truncated trail). Both are known, stated residuals, not silent gaps.
- `SignoffGate.is_cleared` (signoff.py:163-170) performs a full linear scan of all governance records for each is-cleared query. Not a correctness issue, but a potential performance concern on long-lived trails. No pagination or index is used.
- The `ProtectedValidator` callable type alias (`protected.py:203`) has no interface contract beyond `Callable[[OverrideRecord], bool]`. There is no documented precondition about what fields of `OverrideRecord` the validator may trust. The exception-as-veto guard mitigates unexpected inputs, but validator authors have no formal contract to code against.
- `llm_client.py` API key (`OPENROUTER_API_KEY`) is read from the environment at `llm_client_config_from_env()` call time (llm_client.py:44), which is at server startup. No rotation/reload mechanism is visible in this module; a key rotation requires a server restart.

**Confidence:** High — Read 100% of all 8 files in the subsystem. Cross-verified verdict-path claims by tracing `submit_override` (engine.py:52-97), `ProtectedGate.submit` (protected.py:303-387), and `TrailVerifier.verify` (protected.py:144-197). Cross-verified signing field set against both write path (`_record_signed`, protected.py:241-301) and verify path (`TrailVerifier.verify`, protected.py:144-197). Checked `Verdict.model_emittable()` usage in `_parse_structured_response` (judge.py:107) and in `TrailVerifier` comment context.

---

## Policy

**Location:** `src/legis/policy/`

**Responsibility:** Provides the agent-programmable policy grammar (boundary type registry, evaluation, and fail-closed UNKNOWN semantics), the policy-to-cell routing registry (loaded from `policy/cells.toml`), and the `@policy_boundary` self-honesty gate (decorator + static scanner + test-evidence evaluator) that enforces Legis's own governance honesty over its source.

**Key Components:**
- `grammar.py` (109 lines) — `PolicyGrammar` registry: `register` is conflict-safe (no shadowing), `evaluate` is fail-closed (unregistered policy, exception from boundary, or non-`PolicyResult` return all yield `UNKNOWN` with `provenance_gap=True` — never CLEAR). `AllowlistBoundary` is the builtin. `default_grammar()` preloads builtins.
- `cells.py` (138 lines) — `PolicyCellRegistry` for policy-to-cell routing. Glob-capable (`fnmatch`) with exact-pattern precedence. `default_policy_cells()` defaults to `chill` (dev/test only, explicitly documented as unsafe for production). `fail_closed_policy_cells()` defaults to `structured`. `load_policy_cells()` reads `policy/cells.toml` (committed default). Validation rejects unknown cell names at load time.
- `decorator.py` (254 lines) — `@policy_boundary` decorator (metadata-only passthrough), `fingerprint_source` (shared canonicalization for runtime and static scanner — Q-L5 parity), `check_policy_boundary` (runtime honesty gate: verifies citation, invariant, test_ref resolution, fingerprint match, and test evidence quality). `_stable_ast_repr` avoids `ast.dump` version instability across Python 3.12/3.13.
- `boundary_scan.py` (456 lines) — Static AST scanner. `scan_policy_boundaries` walks all `.py` files, parses each, runs `_BoundaryVisitor`. Fail-degraded-not-dead: parse errors and RecursionError/MemoryError on a per-file basis produce a finding and continue (per dogfood-4 A2). `count_source_files` is the single source of truth for scope — a gate must not report PASS on zero files scanned. `assert_within_boundary` blocks path-traversal attacks on caller-supplied scan roots (deferred import of `service.errors` to avoid load-time cycle).
- `evidence.py` (233 lines) — `evaluate_test_evidence`: shared logic for both the static scanner and runtime gate (Q-L5 parity). Checks in order: disabled marker detection (POLICY-1), exercise (excluding calls inside uninvoked nested helpers), shadowing, and policy co-occurrence inside the same `assert` condition (Q-M8). Documented honest residuals: module-level `pytestmark`, aliased skip markers, fixture-mediated skips.
- `__init__.py` (1 line) — Module docstring only; no public re-exports.

**Dependencies:**
- Inbound: `service/` (wires policy grammar and cell registry into governance decisions, calls `scan_policy_boundaries` and `count_source_files` for the honesty gate), `enforcement/` (consumes `PolicyCellRegistry.cell_for` to select the enforcement gate per policy)
- Outbound: `legis.canonical` (`content_hash` used in `decorator.fingerprint_source`); `legis.service.errors.InvalidArgumentError` via a deferred call-time import in `boundary_scan.assert_within_boundary` (to avoid a load-time cycle — `service/__init__` imports `policy/`)

**Patterns Observed:**
- Fail-closed by design at every ambiguous point: unregistered policy → UNKNOWN (not CLEAR), boundary exception → UNKNOWN, zero-file scan is explicitly distinguishable from a scan with zero findings.
- Deferred import pattern in `boundary_scan.assert_within_boundary` (boundary_scan.py:116-117) breaks a load-time cycle between `policy/` and `service/` without restructuring the dependency graph.
- Shared canonicalization (`fingerprint_source`) ensures the runtime gate and the static scanner compute identical fingerprints for the same source, preventing divergence (Q-L5).
- `evaluate_test_evidence` is the single evidence-judgement implementation used by both the static scanner and the runtime gate, so the two gates cannot have different evidence standards.
- `_stable_ast_repr` (decorator.py:104-126) is a forward-compatibility measure: `ast.dump` output changed between Python 3.12 and 3.13 (`show_empty` default), which would have invalidated pinned fingerprints on a Python bump. The stable serializer walks `_fields` explicitly.
- Cell routing precedence: exact patterns beat globs (cells.py:44-56); unlisted policies fall through to `default_cell`. The committed `policy/cells.toml` ships `default_cell = "structured"` (fail-closed for production).

**Concerns:**
- `default_policy_cells()` (cells.py:64-71) defaults to `chill` and is documented as "NOT a safe production default". The code relies on composition roots to choose `fail_closed_policy_cells()` or `load_policy_cells()` instead. If a composition root omits the production selection, governance silently self-clears. The comment and docstring warn against this but there is no runtime guard preventing it.
- The `policy/` → `service/` layering edge (boundary_scan.py:116-117, deferred import) is a structural inversion: `policy/` reaches into `service/` for `InvalidArgumentError`. This is mitigated by the call-time import (no load-time cycle), but it means `policy/` is not independently deployable from `service/`. A dedicated `errors.py` module shared by both layers would close this without restructuring.
- `count_source_files` (boundary_scan.py:84-97) is a separate filesystem walk from `scan_policy_boundaries`. A race between the two (a file appearing or disappearing between the count and the scan) could produce a count mismatch. The gate compares count > 0 vs. findings, not exact file-set equality. In practice this is a non-issue for a local source scan, but is a gap for a hostile or rapidly changing filesystem.
- `evidence.py` documents three residual false-green classes (module-level `pytestmark`, aliased skip markers, fixture-mediated skips) that the gate structurally cannot detect while maintaining Q-L5 runtime/static parity. These are stated honestly, not silently absent. The live exposure is noted as nil at current decoration-site count.

**Confidence:** High — Read 100% of all 6 files in the subsystem (grammar.py, cells.py, decorator.py, boundary_scan.py, evidence.py, __init__.py). Read the committed `policy/cells.toml`. Verified fail-closed path in `PolicyGrammar.evaluate` (grammar.py:62-85), the deferred import location (boundary_scan.py:116-117), the zero-scope guard (`count_source_files`, boundary_scan.py:84-97), and the shared `fingerprint_source` call in both decorator.py:144-162 and boundary_scan.py:237.
