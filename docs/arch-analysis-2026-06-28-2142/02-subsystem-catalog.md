# 02 — Subsystem Catalog

> Produced by 8 parallel codebase-explorer reviewers over the clusters in 00-coordination.md. Each entry cites file:line evidence. Validation report: temp/validation-catalog.md.

## Service layer

**Location:** `src/legis/service/`

**Responsibility:** Acts as the single, transport-agnostic governance decision authority that all three transports (HTTP `api/app.py`, MCP `mcp.py`, CLI `cli.py`) call into, raising typed `ServiceError` subclasses on failure so each adapter owns its own error-shape translation.

**Key Components:**
- `__init__.py` — Public surface of the layer; re-exports 8 error types, 2 data classes, and 14 service functions as the defined contract adapters import from (`service/__init__.py:9–63`).
- `errors.py` — `ServiceError` taxonomy: 9 typed subclasses covering audit integrity (`AuditIntegrityError`), enablement gates (`NotEnabledError`), resource absence (`NotFoundError`, `NoSuchRequestError`), state conflicts (`NotClearedError`, `BindingUnavailableError`), bad input (`InvalidArgumentError`, `UnresolvedInputError`), routing failures (`WardlineRoutingError` with `SERVER_MISCONFIGURED`/`SERVER_OWNED`/`MALFORMED` kind discriminator), and key-absent protected reads (`ProtectedKeyRequiredError`). Adapters switch on type and `.kind`, never on message text (`errors.py:1–99`).
- `governance.py` — Core decision logic: `resolve_for_record`/`resolve_for_entry` (the single SEI-on-entry resolve boundary, failing closed when Loomweave absent or SEI mismatches, `governance.py:43–154`); `verified_records` (full O(N) trail verification on every call, `governance.py:157–206`); `compute_override_rate` / `evaluate_override_rate_gate` (threshold/window hardcoded from ADR-0002 constants, not caller input, `governance.py:209–409`); `submit_override`, `submit_protected_override`, `submit_operator_override`, `request_signoff`, `sign_off`, `bind_signoff_issue` (all wired through `resolve_for_entry` and gate-null checks, `governance.py:412–747`); `read_identity_gaps`, `read_lineage_integrity` (GOV-1/GOV-2 honesty reads — always `"unavailable"` vs `"checked"`, never an empty list that reads as all-clear, `governance.py:556–632`); `read_sei_attestations` (forge-proof discriminator for operator_override/signoff_cleared; asymmetric error rule: ambiguous → omit, never surface, `governance.py:223–350`); `evaluate_policy` (records UNKNOWN provenance gaps, `governance.py:749–767`).
- `explain.py` — `explain_policy`/`explain_cell` data types and logic: routes through `FlooredRegistry.cell_for` (not raw rule.cell) so posture floor is respected; `policy_known` boolean distinguishes configured policy from hallucinated/unconfigured name (`explain.py:87–108`); `explain_cell` is the single source of truth for per-cell `enabled`/`available_moves`, ensuring `policy_list` and `policy_explain` cannot disagree (`explain.py:111–175`).
- `wardline.py` — `resolve_scan_routing` (the single home for the server-owned-vs-request routing decision, raising `WardlineRoutingError` with kind for adapter mapping, `wardline.py:58–171`); `route_wardline_scan` (verifies artifact provenance, extracts active defects, resolves entity keys, routes findings through enforcement, returns `RoutedScan` with `artifact_status` + `artifact_status_reason` always present — no posture without provenance, `wardline.py:196–249`).
- `preflight.py` — `read_warpline_preflight`: advisory Warpline read; unconfigured/unreachable → `"unavailable"` with reason, never an empty affected-set that reads as "nothing impacted" (`preflight.py:16–38`).
- `source_binding.py` — `verify_current_source_binding` / `require_verified_source_binding`: fail-closed SHA-256 fingerprint check for protected submissions from Python source-path locators; non-path entities record honest `"unverified"` rather than being rejected; `source_binding_status` is folded into HMAC-signed fields so consumers can distinguish (`source_binding.py:31–107`).

**Dependencies:**
- Inbound: `legis.api.app` (HTTP transport), `legis.mcp` (MCP transport), `legis.cli` (CLI transport) — all three import only from `service/` for governance decisions.
- Outbound: `legis.enforcement` (engine, lifecycle, protected gate, signoff gate, verdict), `legis.identity` (resolver, entity_key, loomweave_client), `legis.policy` (grammar, cells/FlooredRegistry), `legis.wardline` (governor, ingest, policy), `legis.warpline_preflight.client`, `legis.canonical` (content_hash), `legis.governance` (params, gaps, signoff_binding).

**Patterns Observed:**
- Gate-null fail-closed: every function that requires a gate (`protected_gate`, `signoff_gate`, `filigree`) checks for `None` first and raises `NotEnabledError` naming the operator knob, before any computation (`governance.py:466–470`, `543–545`, `688–693`).
- Single resolve boundary: all identity resolution flows through `resolve_for_entry` (SEI-on-entry, L1/L2 paths) or `resolve_for_record` (record-side), never re-derived in gate/engine layers (`governance.py:43–154`).
- Asymmetric error rules: false-positive safety is the cheaper failure mode; `read_sei_attestations` omits any ambiguous record, `read_identity_gaps`/`read_lineage_integrity` always discriminate `"unavailable"` vs `"checked"`/`"verified"`, `read_warpline_preflight` always has a reason alongside `"unavailable"` (`governance.py:229–232`, `preflight.py:1–9`).
- Adapter isolation: `errors.py` docs map each error type to HTTP status codes and MCP error codes, but the service layer raises only `ServiceError` subclasses with structured attributes (`.kind`, `.cause`, `.fix`) — adapters switch on type, never text (`errors.py:1–6`).
- Policy constants hardcoded out of reach: override-rate threshold/window/floor sourced from `params` module constants, not caller input (`governance.py:214–220`).
- Full trail verification on every interactive read: deliberate O(N) cost; comment explicitly rejects incremental verification as a tamper window (`governance.py:180–193`).
- `UnresolvedInputError` in `errors.py` is NOT re-exported from `__init__.py` (line 9–18): it is raised internally by `governance.py` but absent from the public surface, meaning adapters that import only from `service/` cannot `except UnresolvedInputError` by name without an additional import. `WardlineRoutingError`, `ProtectedKeyRequiredError` are similarly absent from `__all__`.

**Concerns:**
- `UnresolvedInputError`, `WardlineRoutingError`, and `ProtectedKeyRequiredError` are defined in `errors.py` and raised from service functions but are NOT listed in `__init__.py`'s `__all__` or imports (`__init__.py:9–63`). Adapters relying only on `from legis.service import ...` cannot catch these by name without an extra `from legis.service.errors import ...`. This is a latent import discipline gap: the MCP and HTTP adapters presumably do import them directly from `errors`, but the omission from the declared public surface is inconsistently documented and risks future callers missing them.
- `sign_off` (operator sign-off on a pending request, `governance.py:724–746`) is implemented in `governance.py` but is not exported from `__init__.py` (absent from `__all__` and import list). This means it is not reachable via the declared public surface (`service/__init__.py:37–63`). If an adapter calls it via `from legis.service.governance import sign_off` it works, but the public-surface contract is violated.
- Verified: error handling is present throughout. No resource handles opened at service layer. No function returns `None` or `[]` on a failure path that an adapter could read as a governance pass — all failure paths raise. Warpline/identity-gap/lineage reads use explicit `"unavailable"` status, never silent empty. Source binding is recorded honestly (`"unverified"`) for non-path entities rather than rejected, with the status folded into HMAC fields — consumer read-side discipline is noted in comments but not enforced at this layer.

**Confidence:** High — read 100% of all 7 files in `src/legis/service/` (errors.py, __init__.py, governance.py, explain.py, wardline.py, preflight.py, source_binding.py). Cross-validated export surface against `__init__.py:9–63` and function definitions. Dependency claims verified against import statements in each file. Honesty patterns confirmed by reading all decision paths and inline comments.

---

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

---

## Identity

**Location:** `src/legis/identity/`

**Responsibility:** Resolves git locators to Loomweave-minted Stable Entity Identities (SEIs), producing opaque `EntityKey` values that key governance attestations so they survive rename/move events.

**Key Components:**
- `entity_key.py` (41 lines) — Frozen dataclass holding `value: str` and `identity_stable: bool`; two factory classmethods (`from_locator`, `from_sei`) are the only construction paths; `value` is never parsed downstream — the docstring explicitly states the opacity discipline at line 4.
- `resolver.py` (263 lines) — `IdentityResolver` drives the WP-5.1 upgrade path: returns a locator-keyed (`identity_stable=False`) `EntityKey` on any failure path and an SEI-keyed (`identity_stable=True`) key only on a confirmed-alive Loomweave response; `IdentityResolution` frozen dataclass has a `__post_init__` guard (lines 61–100) that makes it impossible to construct a self-contradictory record (e.g. `alive=True` + status `NOT_ALIVE`).
- `loomweave_client.py` (240 lines) — `HttpLoomweaveIdentity` thin transport wrapper over `urllib`; injectable `fetch` callable for offline tests; HMAC signed via `weft_signing.sign_weft_request` when a key is provisioned; `_validate_base_url` enforces HTTPS for non-loopback hosts (lines 139–159); `_decode_json_response` enforces a 1 MB response cap; SEI strings are URL-quoted but never parsed (lines 224, 232).
- `__init__.py` (1 line) — Module docstring only; no re-exports.

**Dependencies:**
- Inbound: `enforcement/` (uses `IdentityResolver` and `EntityKey`), `governance/signoff_binding.py` (SEI-keyed sign-off), `records/override_record.py` (embeds `EntityKey`)
- Outbound: `canonical.content_hash` (lineage snapshot hashing, resolver.py line 168), `weft_signing` (HMAC transport signing, loomweave_client.py lines 33–38), external Loomweave HTTP service

**Patterns Observed:**
- Fail-closed on every transport and parse error: capability probe failure clears the capability latch (`_capable = None`, resolver.py lines 148–151) so the next resolve retries rather than trusting a stale positive; locator resolve failures and malformed responses all return the `degraded` value (locator-keyed, `UNAVAILABLE`).
- Capability TTL re-probe (5 min window, resolver.py lines 27, 127–153) prevents the positive-latch-forever bug (Q-L6): a Loomweave that loses SEI capability mid-life is noticed within one TTL window.
- `alive is not True` strict identity check (resolver.py lines 194, 232, comment "ID-SEI-2") rejects non-bool truthy values from a buggy or hostile Loomweave — a string `"false"` or integer `1` cannot promote a dead entity to a stable identity.
- `resolve_supplied_sei` returns `None` (not a degraded locator key) when an agent-supplied SEI cannot be confirmed alive (resolver.py lines 171–209): silently demoting an L1 SEI bind to a locator-keyed record is explicitly refused.
- TLS custody warning is emitted but not enforced when `LEGIS_ALLOW_INSECURE_REMOTE_HTTP=1` is set for non-loopback hosts (loomweave_client.py lines 147–158, comment "ID-SEI-1") — the flag is the documented dev-only escape hatch.

**Concerns:**
- The capability TTL and latch-clearing pattern is correct, but a capability probe failure at the START of `_capability()` (before a latch is ever set, `_capable is None`) logs a warning and returns `False` — which is the right degraded behavior. However, if the Loomweave host is reachable but systematically returns a non-`{"sei": {"supported": true}}` body, `_capable` is set to `False` (not `None`) and latched for the full TTL, suppressing re-probes even when the upstream recovers. This is acceptable but is not documented as a known limitation alongside the Q-L6 fix.
- The `content_hash` field on `IdentityResolution` comes verbatim from the Loomweave response (resolver.py lines 200–201, 252–254) and is not independently verified — Legis trusts Loomweave's assertion. This is architecturally correct (Loomweave is the authority), but an on-path attacker who can forge a response (e.g. via the `LEGIS_ALLOW_INSECURE_REMOTE_HTTP` escape) controls the content axis of governance records, which is not called out in the security model.

**Confidence:** High — Read 100% of all four files; cross-verified imports (`resolver.py` line 19 imports `content_hash`, line 20 imports `LoomweaveIdentity`; `loomweave_client.py` lines 33–38 import `weft_signing`). Fail-closed and SEI-opacity behaviors verified line-by-line.


## Store

**Location:** `src/legis/store/`

**Responsibility:** Provides a record-agnostic, append-only, hash-chained SQLite audit store with DB-level UPDATE/DELETE triggers, contiguous-seq verification, and an optional out-of-band head anchor for tail-truncation detection.

**Key Components:**
- `audit_store.py` (457 lines) — `AuditStore` is the implementation; SQLAlchemy with `NullPool` (no lingering locks); `synchronous=FULL` enforced unconditionally (lines 69–77, not configurable); `journal_mode=WAL`; `BEGIN IMMEDIATE` write locks on every append path; `append_signed` (lines 297–312) hands the signer its `(seq, prev_hash)` under the held lock so the v3 HMAC binds the exact position the row receives (AUD-1); `transaction()` (lines 179–212) provides batched appends with thread-local ambient connection; `_assert_no_batch_in_progress` (lines 222–240) turns mid-batch reads into explicit `RuntimeError`s.
- `head_anchor.py` (143 lines) — `HeadAnchor` sidecar file holding `(head_seq, head_chain_hash)` HMAC-signed with `enforcement.signing`; `update` uses temp-file + `os.replace` for atomic writes (line 93); `check` fails closed on missing file (`AnchorError`, lines 107–113) and on signature mismatch (lines 120–121); the REPLAY LIMITATION (a snapshotting attacker can restore a genuine older anchor) is explicitly documented in the module docstring (lines 34–47).
- `protocol.py` (68 lines) — `AppendOnlyStore` Protocol and `AuditRecordLike` Protocol; `transaction()` docstring (lines 57–68) prohibits reads inside batches and documents that `AuditStore` enforces this; `append_signed` contract (lines 27–37) documents the reserve-sign-insert atomicity guarantee.
- `__init__.py` (1 line) — Module docstring only; no re-exports.

**Dependencies:**
- Inbound: `enforcement/engine.py` (imports `AppendOnlyStore` protocol), `enforcement/protected.py` (imports `AnchorError`, `HeadAnchor`, `AppendOnlyStore`), `enforcement/signoff.py` (imports `HeadAnchor`, `AppendOnlyStore`)
- Outbound: `canonical` (`canonical_json`, `content_hash`; audit_store.py line 40), `enforcement/signing` (`sign`, `verify`; head_anchor.py lines 56–57), `legis.config.ensure_sqlite_parent` (lazy import, audit_store.py line 127)

**Patterns Observed:**
- Bidirectional coupling between `store/` and `enforcement/`: `enforcement/` imports `store.protocol` and `store.head_anchor`; `store/head_anchor.py` imports `enforcement.signing`. The dependency graph is: `store.head_anchor` → `enforcement.signing` → `canonical`; `enforcement.{engine,protected,signoff}` → `store.{protocol,head_anchor}`. This forms a cycle at the package level (`store ↔ enforcement`) but NOT at the module level (no circular imports in practice because `audit_store.py` does NOT import enforcement and `enforcement.signing` does not import store).
- `verify_integrity` (lines 362–442) is O(N) by design: checks seq contiguity, recomputes `content_hash` for every payload, walks the `prev_hash` chain, and recomputes `chain_hash`. The `allow_nan=False` in `canonical_json` catches a Nan/Infinity-injected payload that `json.loads` would silently accept (lines 403–415).
- DB-level triggers (lines 161–177) reject UPDATE/DELETE at the SQLite engine before any application logic runs; the application layer has no mutation methods — two independent enforcement layers.
- `append` on an uninitialized (`initialize=False`) path is never called safely against a no-table DB: `_has_log_table` guards reads (lines 314–323) but `_insert` / `_write` would raise `OperationalError` on missing table. This is by design — `initialize=False` is for read-only inspection handles.

**Concerns:**
- The store↔enforcement bidirectional coupling is real but is NOT a circular import at runtime: `store.head_anchor` → `enforcement.signing` → `canonical` is a clean downward dependency; `enforcement.{engine,protected,signoff}` → `store.protocol` / `store.head_anchor` is also clean downward. The cycle is only at the package-name level. The governance-honesty risk is low: neither direction pulls in logic that could silently change a governance decision. However, if `enforcement.signing` ever gains upward imports back into `store`, the current non-circular property breaks silently — a refactor to extract signing into a shared `crypto/` leaf would close this cleanly.
- The head anchor's REPLAY LIMITATION (a snapshotting attacker can restore a genuine earlier anchor and paired truncated DB, and the check passes) is honestly documented in `head_anchor.py` lines 34–47 and in the project README. No mitigating control exists for local-filesystem deployments; the documentation correctly names WORM/remote storage or an external monotonicity monitor as the only closure. This is a conceded residual threat, not a gap.
- `transaction()` nested re-entrance silently reuses the outer batch (lines 201–204), which is the correct behavior for avoid double-commit, but it means a caller who believes it opened a fresh transaction boundary has not — if the outer batch rolls back, so does work the inner caller expected to commit. No warning is emitted on re-entrance. This is low-severity for an append-only store but could surprise future callers.

**Confidence:** High — Read 100% of all four files; cross-verified the bidirectional coupling by grepping all import statements across both packages (head_anchor.py:56–57, enforcement/engine.py:25, enforcement/protected.py:25–26, enforcement/signoff.py:21–22); read enforcement/signing.py in full to confirm it imports only `canonical` (no back-reference to store).


## Crypto/Leaf Primitives

**Location:** `src/legis/canonical.py`, `src/legis/weft_signing.py`, `src/legis/provenance.py`, `src/legis/records/`

**Responsibility:** Provide the canonical JSON serialization, content hashing, transport-HMAC signing, provenance vocabulary, and governance record schemas that all upper layers share without creating inter-layer dependencies.

**Key Components:**
- `canonical.py` (51 lines) — `canonical_json`: `json.dumps` with `sort_keys=True`, `separators=(",",":")`, `ensure_ascii=False`, `allow_nan=False`; `content_hash`: SHA-256 of the UTF-8-encoded canonical form. The `ensure_ascii=False` is the byte-for-byte HMAC contract with Wardline's Python signer; both sides use identical `json.dumps` params, so non-ASCII payloads round-trip without escape divergence. The module docstring (lines 1–34) documents the Q-L4 RFC-8785 deferral, the cross-repo golden vector status, and the condition that triggers the upgrade (a non-Python verifier).
- `weft_signing.py` (91 lines) — `sign_weft_request`: produces `X-Weft-Component`, `X-Weft-Timestamp`, `X-Weft-Nonce` headers; signs `METHOD\npath?query\nsha256(body)\ntimestamp\nnonce`; body canonicalization uses `ensure_ascii=True` (NOT `canonical_json`) to match the transport contract — deliberately different from the audit HMAC contract (lines 38–42, module docstring lines 9–15). `weft_hmac_key_from_env`: channel-specific env var falls back to `LEGIS_HMAC_KEY`.
- `enforcement/signing.py` (61 lines) — `sign`/`verify` for per-record HMACs; version-tagged prefixes (`v2` binds content, `v3` additionally binds `chain_seq`); `verify` accepts both v2 and v3 without ambiguity (lines 57–61); uses `canonical_json` (the `ensure_ascii=False` variant) for HMAC body. This file lives in `enforcement/` but functions as a shared crypto primitive used also by `store/head_anchor.py`.
- `provenance.py` (28 lines) — `Provenance` str-Enum; currently one member (`UNAUTHENTICATED`); shared by `checks/` and `pulls/` without either importing the other.
- `records/override_record.py` (40 lines) — `OverrideRecord` frozen dataclass; `extensions: dict` open field for coached- and protected-cell additions without schema migration; `to_payload()` flattens to dict for `AuditStore.append`.
- `records/__init__.py` (1 line) — Module docstring only.

**Dependencies:**
- Inbound: `canonical` ← `store/audit_store.py`, `enforcement/signing.py`, `identity/resolver.py`, `governance/`, `wardline/` (cross-repo: Wardline's `core/legis.py` replicates the same `json.dumps` call); `weft_signing` ← `identity/loomweave_client.py`, `filigree/`; `enforcement/signing` ← `store/head_anchor.py`, `enforcement/protected.py`, `enforcement/verdict.py`; `records/` ← `enforcement/engine.py`, `governance/`
- Outbound: `canonical.py` — stdlib only (`hashlib`, `json`); `weft_signing.py` — stdlib only (`hashlib`, `hmac`, `json`, `os`, `urllib.parse`); `enforcement/signing.py` — `canonical` only; `provenance.py` — stdlib only; `records/override_record.py` — `identity.entity_key` only

**Patterns Observed:**
- Two distinct canonicalization contracts coexist intentionally: `canonical_json` (`ensure_ascii=False`) for audit HMACs and content hashes; `weft_body_bytes` (`ensure_ascii=True`) for transport HMACs. Both are documented; the module docstrings explicitly cross-reference each other to prevent accidental unification (canonical.py lines 1–34, weft_signing.py lines 1–27).
- `allow_nan=False` in `canonical_json` is a tamper-detection aid: a payload injected with `Infinity` or `NaN` survives `json.loads` but raises on re-canonicalization, which `verify_integrity` catches as tamper rather than a crash (audit_store.py lines 403–415).
- The v2/v3 signature version tag allows the signing primitive to evolve the field set without ambiguity in stored records; `verify` accepts both prefixes, so a store with mixed v2/v3 records verifies correctly.
- `Provenance` as a str-Enum means `json.dumps` / `canonical_json` emit the bare string value without any enum wrapper, keeping wire payloads stable across Python versions and avoiding coercion on read-back (provenance.py lines 14–16).
- `OverrideRecord.extensions` (records/override_record.py line 24) is the deliberate extension point for coached- and protected-cell fields; no schema migration is required to add judge output or HMAC binding to an override record.

**Concerns:**
- `enforcement/signing.py` is located inside `enforcement/` but is consumed as a shared primitive by `store/head_anchor.py` — it is not co-located with the other leaf primitives (`canonical.py`, `weft_signing.py`) it logically belongs with. This is a naming/location inconsistency rather than a governance-honesty risk, but it means a reader of `store/` must know to look in `enforcement/` for the signing primitive, which the `head_anchor.py` import makes visible but surprising.
- `Provenance` has exactly one member (`UNAUTHENTICATED`) and the docstring states an authenticated path "would add a stronger value here." The enum is not yet used in any decision path — it is recorded into check/pull payloads but nothing currently gates on its value. If policy logic is added that trusts a higher-provenance value, the gap between the recorded `unauthenticated` claim and any actual authentication verification must be explicitly re-examined.
- The cross-repo non-ASCII golden vector is not yet pinned (canonical.py lines 22–27): both Python signers use identical `json.dumps` params, so they agree by construction, but a Wardline-side drift (e.g. switching to `ensure_ascii=True` in a refactor) would break cross-repo HMAC verification without a failing test on either side until a non-ASCII payload hits production. The fix (a shared golden HMAC vector with a non-ASCII payload in Wardline's repo) is documented as a Wardline-side follow-up.

**Confidence:** High — Read 100% of `canonical.py` (51 lines), `weft_signing.py` (91 lines), `enforcement/signing.py` (61 lines), `provenance.py` (28 lines), `records/override_record.py` (40 lines), `records/__init__.py` (1 line). Cross-verified that `canonical.py` has no legis imports (stdlib only); verified `weft_signing.py` has no legis imports (stdlib only); verified `enforcement/signing.py` imports only `canonical` (line 30); verified `records/override_record.py` imports only `identity.entity_key` (line 13).

---

## MCP Stdio Adapter

**Location:** `src/legis/mcp.py`

**Responsibility:** Implements the MCP-over-stdio JSON-RPC transport that exposes 23 agent-callable tools, translating tool calls into `service/` calls and mapping all `ServiceError` subclasses to typed `isError` error envelopes without duplicating any governance decision.

**Key Components:**
- `McpRuntime` dataclass (lines 154–182) — holds all wired dependencies (engine, gates, ledger handles, identity, filigree, warpline) per launch; `posture_ledger` is stored as a handle only (never a cached floor value, D2 discipline)
- `build_runtime(agent_id)` (lines 203–309) — composition root; constructs gates conditionally on `LEGIS_HMAC_KEY`; wires identity, filigree, warpline, posture ledger; fail-closed defaults throughout (e.g. missing policy cells → `fail_closed_policy_cells()`)
- `tool_definitions()` (lines 369–1316) — emits JSON Schema for all 23 tools including `outputSchema` for every tool (enforced after dogfood-4 A6 incident where an omitted top-level `"type": "object"` caused Claude Code's zod validator to drop all 21 tools)
- `_TOOL_HANDLERS` dict (lines 2574–2599) — dispatch table mapping tool names to 23 `_tool_*` functions; `call_tool()` (lines 2602–2610) wraps every dispatch in `_service_error()` catch-all
- `_service_error(exc)` (lines 1432–1484) — ServiceError→error_code mapping table; covers 12 typed cases including `NoSuchRequestError` before `NotFoundError` (subclass ordering), `WardlineRoutingError` before generic `ServiceError`, and a logging fall-through to `INTERNAL_ERROR` for unhandled exceptions
- `_recovery_for(code)` (lines 1326–1388) — maps each error code to `{recoverable, next_action}` text; `AUDIT_INTEGRITY_FAILURE` and `INTERNAL_ERROR` are marked `recoverable=False`
- `ERROR_ENVELOPE_SCHEMA` (lines 348–366) — shared schema for all `isError:true` responses; `additionalProperties: False` with required `[error_code, message, recoverable, next_action]`
- `run_jsonrpc()` / `main()` (lines 2705–2748) — stdlib-only stdio loop with `_read_bounded_line()` enforcing a 16 MiB per-request cap (overridable via `LEGIS_MCP_MAX_REQUEST_BYTES`)
- `_load_policy_cell_registry()` (lines 184–200) — resolution order: env var → `policy/cells.toml` → fail-closed (unless `LEGIS_DEV_DEFAULT_CELLS=1`)
- `_floored_registry(runtime)` (lines 1588–1596) — called fresh at every cell-resolution site; missing ledger maps to `_NoLedger` → structured floor, never chill

**Dependencies:**
- Inbound: `cli.py` (`legis mcp` command bootstraps `build_runtime` and calls `main()`); `api/app.py` (imports `_load_policy_cell_registry` for shared config loading)
- Outbound: `service/governance`, `service/wardline`, `service/explain`, `service/preflight`; `enforcement/` (engine, protected gate, signoff gate, trail verifier); `store/audit_store`; `policy/cells`, `policy/grammar`; `identity/resolver`; `filigree/client`; `governance/binding_ledger`; `posture/floor`, `posture/ledger`; `git/surface`; `checks/surface`; `pulls/surface`; `wardline/ingest`; `warpline_preflight/client`; `doctor`, `install`, `hooks` (via `cli.py` best-effort refresh on boot)

**Patterns Observed:**
- Strict thin-adapter discipline: every tool handler calls a `service/` function and maps the result to the MCP envelope; no governance decision logic is in `mcp.py` itself
- Launch-bound agent identity: `agent_id` is set at startup and propagated to every record; no tool schema accepts an actor argument (enforced by `_validate_argument_keys` against `_allowed_tool_arguments`)
- Idempotency via request-hash scan: `_existing_idempotent_record()` walks the full verified trail (O(N) HMAC cost deliberate — optimization that would skip verification was explicitly declined in rc4 review)
- Posture floor always read fresh per request via `_floored_registry()`; floor-raising during an idempotent replay emits `floor_warning` rather than silently grandfathering past the new floor (D4 discipline)
- `warpline` field annotated `# advisory sibling; NEVER read by a verdict path` (line 181); `warpline_preflight_get` tool description explicitly says "Purely advisory"
- `_one_of()` helper (lines 321–332) injects `"type": "object"` at every discriminated outputSchema to prevent zod validator rejection of entire tools/list

**Concerns:**
- God-module size (2748 LOC): all 23 tool handlers, the full JSON Schema catalogue, the stdio loop, runtime construction, and multiple utility classes live in one file. No honesty violation, but high change-coupling — adding a tool requires edits across tool_definitions(), _TOOL_HANDLERS, _allowed_tool_arguments(), and the handler itself, all in one file with no enforced co-location.
- `api/app.py` imports `_load_policy_cell_registry` directly from `mcp.py` (line 398): a transport module's private helper (`_` prefix) is shared by the HTTP adapter. This is a transport-on-transport dependency; the function belongs in `config.py` or `policy/` to break the coupling (a comment at the site acknowledges it as Q-H2 / "store-location resolvers live in the transport-agnostic config module").
- `_service_error` fall-through (line 1483): any unhandled exception reaches `INTERNAL_ERROR` with `logger.error`; operators/Sentry see it, but the agent receives only `str(exc)` — no structured payload — which may be less actionable than the typed cases above it. Not a false-green (error is surfaced), but observability gap for novel exception types.
- `WardlineRoutingError` has three HTTP-distinct kinds (`SERVER_MISCONFIGURED` → 500, `SERVER_OWNED` → 403, `MALFORMED` → 422) but MCP collapses all three to `INVALID_CELL_SPEC` (line 1470); this is intentional and documented in `service/errors.py`, but an agent cannot distinguish a server misconfiguration (operator action needed) from a caller error (argument fix needed) by error code alone.

**Confidence:** High — read 100% of `mcp.py` structurally (build_runtime, McpRuntime, _TOOL_HANDLERS dispatch, _service_error mapping table, _recovery_for, ERROR_ENVELOPE_SCHEMA, run_jsonrpc, all 23 handler function signatures); sampled 8 handler bodies in depth; read `service/errors.py` fully. Cross-verified: `_AGENT_TOOLS` frozenset (line 81) has 23 members matching `_TOOL_HANDLERS` (line 2574) entry count; `NoSuchRequestError` subclass ordering confirmed correct in both the error hierarchy and the mapping.

---

## HTTP API Adapter

**Location:** `src/legis/api/app.py`

**Responsibility:** Implements the FastAPI HTTP adapter that exposes Legis governance, git/CI, and wardline surfaces as REST endpoints, translating `ServiceError` subclasses to HTTP status codes and delegating all governance decisions to `service/`.

**Key Components:**
- `create_app()` factory (lines 314–954) — single application factory injecting all dependencies (engine, gates, identity, filigree, binding ledger, posture ledger) with lazy fallbacks from environment; returns a `FastAPI` instance
- Auth layer: `_verify_secret()` / `_token_actor_from_mapping()` (lines 94–189) — scope-gated bearer token auth; single-secret mode defaults to `writer`-only, requiring explicit scope grant for `operator`; `LEGIS_UNSAFE_DEV_AUTH=1` escape hatch; `_authenticated_actor_configured()` guards whether body-supplied actor is trusted
- `verify_writer` / `verify_operator` dependencies (lines 211–216) — FastAPI `Depends` guards that enforce writer/operator scope split on all write routes; operator routes use a separate `verify_operator` dependency
- `_WARDLINE_ROUTING_STATUS` map (lines 295–299) — three-way HTTP status dispatch for `WardlineRoutingError` kinds (500/403/422), complementing MCP's single-code collapse
- `POST /overrides` unified route (lines 586–715) — cell-dispatched override submission; reads `floored_registry()` per request (D2); branches on `chill`/`coached`/`structured`/`protected` cells; `202` for structured (never `201` — "an old '201 == accepted' reader must not misread it"); `need_inputs` discriminant returns `422` (not a generic error) for protected-cell missing inputs
- `_unresolved_input_http()` (lines 192–208) — structured `422` for non-resolving inline SEI; carries `weft_reason` dict matching MCP's `UNRESOLVED_INPUT` envelope
- `POST /signoff/{seq}/bind-issue` (lines 766–802) — maps 6 service exception types to distinct status codes including `502` for `FiligreeError` (typed, recoverable, not 500)
- `POST /wardline/scan-results` (lines 892–952) — `WardlineDirtyTreeError` → `JSONResponse(409)` (not 2xx); `outcome: ScanOutcome.ROUTED` plus `artifact_status_reason` honesty field

**Dependencies:**
- Inbound: `cli.py` (`legis serve` sets env vars and calls `uvicorn.run("legis.api.app:create_app", factory=True)`)
- Outbound: `service/governance`, `service/explain`, `service/wardline`; `enforcement/` (engine, protected gate, signoff gate, trail verifier); `store/audit_store`; `policy/cells`, `policy/grammar`; `identity/resolver`; `filigree/client`; `governance/binding_ledger`, `governance/filigree_gate`; `posture/floor`, `posture/ledger`; `git/surface`, `git/rename_feed`, `git/pull_request`; `checks/surface`; `pulls/surface`; `wardline/ingest`, `wardline/governor`; `config` (db URL resolvers); `mcp._load_policy_cell_registry` (cross-transport import, line 398)

**Patterns Observed:**
- Cell dispatch inside the unified `POST /overrides` route mirrors the MCP `_tool_override_submit` dispatch, both delegating to the same `service/` functions; no governance logic duplicated between adapters
- Status codes carry semantic weight: `201` (accepted/recorded), `202` (pending escalation), `409` (blocked/conflict/dirty-tree), `422` (input error/need_inputs), `500` (integrity failure), `502` (upstream unavailable)
- `floored_registry()` called fresh at each request via the `floored()` closure (lines 415–423) with `PostureLedger` handle shared but floor re-read each time (D2 compliance)
- Auth scope model: `writer` for all mutation routes, `operator` exclusively for `POST /protected/operator-override` and `POST /signoff/{seq}/sign`; unscoped tokens rejected by default (AUTH-1 comment, line 118)
- `LEGIS_ALLOW_UNSCOPED_API_TOKENS=1` flag comment (line 123) explicitly notes it grants unscoped tokens full operator authority — intentionally blunt warning in code

**Concerns:**
- `create_app()` imports `_load_policy_cell_registry` from `legis.mcp` (line 398): this is the transport-on-transport coupling noted under the MCP entry. The comment at that line attributes it to Q-H2 ("store-location resolvers live in the transport-agnostic config module") but the function still lives in `mcp.py` with a `_` prefix rather than the identified right home.
- `assert simple_engine is not None` (line 607) inside `post_override` after `simple_engine_for(cell)` returns `None` for coached when no judge is configured: this path would panic with `AssertionError` rather than a clean `ServiceError`. The `assert` is a correctness assumption that the upstream `not explanation.enabled` guard (line 603) would have caught the unwired case — but `simple_engine_for` returns `None` for coached without a judge, and `explanation.enabled` may still be `True` in some edge configurations. This is a potential unguarded assertion that would produce a 500 with stack trace rather than a structured error. (Medium confidence — the `explanation.enabled` path is the primary guard, but the assertion is a backup, not a primary defense.)
- No top-level exception handler is registered on the FastAPI app for unhandled `ServiceError` subclasses: any `ServiceError` that escapes route-level `except` blocks becomes an untyped 500. The individual routes cover their expected exception shapes, but a new `ServiceError` subclass not yet added to a route's except list would surface as a 500 without a structured payload.

**Confidence:** High — read 100% of `app.py` (954 lines). Cross-verified: ServiceError imports at lines 51–60 match handler `except` clauses in routes; `_WARDLINE_ROUTING_STATUS` keys match `WardlineRoutingError` kind constants in `service/errors.py`; `floored()` closure construction confirmed at lines 415–423.

---

## CLI Adapter

**Location:** `src/legis/cli.py`

**Responsibility:** Implements the `legis` command-line interface, providing subcommands for serving, MCP boot, governance gates, install/doctor/posture/operator management, and policy tooling, delegating all governance logic to `service/` and translating outcomes to exit codes.

**Key Components:**
- `build_parser()` (lines 36–260) — argparse definition for all subcommands: `serve`, `mcp`, `check-override-rate`/`governance-gate`, `sei-backfill`, `policy-boundary-check`, `install`, `session-context`, `doctor`, `posture {show,set,rekey}`, `operator {enable,disable}`
- `main()` (lines 705–844) — top-level dispatch; `serve` sets env vars and calls `uvicorn.run`; `mcp` sets env vars and calls `legis.mcp.main(args.agent_id)`; operator/posture subcommands use full governance paths
- `_check_override_rate()` (lines 287–335) — override-rate gate: reads store → `evaluate_override_rate_gate()` in `service/`; fail-closed in CI (`LEGIS_ALLOW_MISSING_GOVERNANCE_DB` guard); integrity check before scoring; exit 1 on FAIL/missing-in-CI
- `_run_install()` (lines 609–689) — step-runner for `legis install`; catches per-step exceptions broadly (BLE001) to avoid half-applied installs, counts failures, returns 1 if any step failed
- `_run_posture()` / `_run_operator()` (lines 401–606) — operator elevation and posture floor management; `posture set` requires open session and matching key fingerprint; `posture rekey` chains KEY_RESET with no old key needed; env backend refused for rekey (cannot persist from child process)
- `_build_operator_signer()` (lines 365–398) — custody dispatch: `env` → `EnvSigner`, `age-file` → `AgeFileSigner` with passphrase from `LEGIS_OPERATOR_KEY_AGE_PASSPHRASE`; `keychain` raises LOUD (not shipped)
- `_parse_ttl()` (lines 344–362) — fail-closed: empty or non-positive TTL raises `ValueError`; no silent zero-length session windows
- `policy-boundary-check` handler (lines 779–832) — zero-scope guard: exits with code 2 (`NO_ROOT`) if scan root is missing or contains no Python files; explicitly blocks a vacuous green PASS on empty input

**Dependencies:**
- Inbound: process entry point (`legis` console script); no other Legis module imports `cli.py`
- Outbound: `mcp.main()` (for `legis mcp`); `api.app.create_app` (via uvicorn, for `legis serve`); `service/governance.evaluate_override_rate_gate`; `governance/sei_backfill`; `policy/boundary_scan`; `store/audit_store`; `identity/loomweave_client`; `doctor.run_doctor`; `install.*`; `hooks.generate_session_context`, `hooks.refresh_instructions`; `posture.*`; `config` (db URLs)

**Patterns Observed:**
- Subcommand handlers are private `_run_*()` functions called from `main()`; thin: I/O + env var forwarding + exit code mapping, no governance logic
- Override-rate gate delegates fully to `service.evaluate_override_rate_gate()`; CLI only adds I/O and exit code (the comment at line 323 explicitly says "The detect → require-key → verify → score decision lives in the service layer")
- `policy-boundary-check` has explicit no-scope false-green guard (zero-file = exit 2, not exit 0) mirroring the honesty stance; comment references `weft-ef2e898642 silent-clean-on-zero-scope`
- Operator elevation (D3): `posture set` cannot bypass session — requires a prior `operator enable`; fingerprint mismatch between signer and current epoch is caught before any session opens
- `_refresh_instructions_best_effort()` (lines 692–702) wraps boot-time instruction refresh in broad except with `logger.warning`; explicit comment: "Best-effort: never break the server, but don't vanish silently either"

**Concerns:**
- `_run_install()` catches all exceptions per step with `except Exception` (line 677, BLE001 suppressed); this prevents tracebacks from aborting a partial install, but means a step can fail silently if the failure string is ambiguous. Acceptable tradeoff for install resilience, but could mask custody errors that should be fatal (e.g., a failed posture step printing `[FAIL]` still lets the overall install return 0 if it was a deferred step).
- None observed for governance-honesty discipline: the CLI makes no governance decisions; all decision paths delegate to `service/` or to the modules that own the logic (`install`, `doctor`, `posture`). Error paths uniformly use non-zero exit codes (1 for failures, 2 for usage/vacuous-scan). The operator elevation path is fail-closed at every guard (signer verification, fingerprint match, session persistence before audit append).

**Confidence:** High — read 100% of `cli.py` (844 lines). Cross-verified: subcommand names in `build_parser()` match dispatch cases in `main()`; `_check_override_rate()` delegates confirmed by reading the service call at line 326 (`evaluate_override_rate_gate`); zero-scope guard at line 795 (`count_source_files`) confirmed to precede `scan_policy_boundaries`.

---

## Posture

**Location:** `src/legis/posture/`

**Responsibility:** Maintains a signed, append-only posture floor that sets the minimum governance enforcement cell across all surfaces, enforces that an absent or empty ledger fails closed to `structured` (never `chill`), and gates floor transitions behind a short-lived sudo-style operator elevation session backed by an OS-keychain, age-encrypted file, or (explicitly opted-in) env-var key custody backend.

**Key Components:**
- `floor.py` (84 lines) — `FlooredRegistry` subclasses `PolicyCellRegistry`; `cell_for` and `default_cell` are raised to the floor via `_max_tier`; `floored_registry()` calls `ledger.read_floor()` at call time (never cached, D2) and maps `None` to `"structured"` (fail-closed). This is the cross-surface chokepoint consumed by all three transports.
- `ledger.py` (506 lines) — `PostureLedger` wraps `AuditStore`; exposes `read_floor()` (single descending SQL scan skipping metadata records so a `OPERATOR_SESSION_OPENED` tail cannot lower the floor), `genesis()`, `transition()` (fingerprint-checked, v3 HMAC signed, fail-closed via `append_signed`), `session_opened()`, `rekey()`, and the `set_floor()` change gate. The change gate (lines 400–506) enforces: open session required, epoch fingerprint must match LEDGER (not session field), session audit record must be present, signer must prove custody, any fault refuses with zero records written.
- `session.py` (259 lines) — Persisted elevation session at `.weft/legis/operator_session.json`; atomic write via temp-file + `os.replace`; `load_session()` deletes stale files and returns `None` (fail-closed expiry); session file never holds key plaintext, passphrase, or raw blob — only `unlock_ref` (keychain item id, or `None` for age/env).
- `signing.py` (353 lines) — Three custody backends: `KeychainSigner` (key fetched per call, discarded), `AgeFileSigner` (blob + passphrase callback, key unwrapped per call), `EnvSigner` (plaintext env escape hatch; requires explicit `insecure_env=True` and emits `InsecureEnvKeyWarning`). `PostureSigner` / `PostureVerifier` protocols. `verify_signer_signature()` requires fingerprint match AND HMAC verification — self-attested fingerprint alone is not sufficient.
- `records.py` (54 lines) — Frozen `PostureRecord` dataclass; `to_payload()` deliberately excludes `seq/prev_hash/chain_hash` (added by `AuditStore`) to avoid breaking `verify_integrity`.
- `__init__.py` (75 lines) — Public re-exports of all five modules; constitutes the full public surface of the package.

**Dependencies:**
- Inbound: `api/app.py` (imports `floored_registry`, `PostureLedger`); `mcp.py` (imports `FlooredRegistry`, `_max_tier`, `floored_registry`, `PostureLedger`); `cli.py` (imports signers, `set_floor`, session functions); `install.py` (imports `select_backend`, `mint_key`, `key_fingerprint`, `wrap_key`); `doctor.py` (imports `PostureLedger`, `signing`, `records`); `hooks.py` (imports `PostureLedger`).
- Outbound: `legis.policy.cells` (`PolicyCellRegistry`, `CELL_TIER_ORDER`, `_validate_cell`); `legis.store.audit_store` (`AuditStore`); `legis.enforcement.signing` (`sign`, `verify`); `legis.config` (`operator_session_path`); `legis.clock` (`Clock`, `SystemClock`); `legis.install` (`OperatorKeyCustodyError` — one deferred import in `ledger.py:344`, inside `rekey()` only).

**Patterns Observed:**
- Fail-closed at every boundary: `None` floor maps to `"structured"` in `floored_registry()` (floor.py:79–83); `read_floor()` returns `None` for absent file, absent table, or empty store (ledger.py:101–118); `load_session()` returns `None` for absent, malformed, or lapsed file (session.py:199–221); `verify_signer_signature()` returns `False` on any exception (signing.py:333).
- Key-never-resident: all three non-env backends fetch the key into a local variable per `sign` call and discard it; no backend exposes a `key` attribute; `__slots__` used on `_RawKeySigner`, `AgeFileSigner`, `KeychainSigner` to prevent attribute injection.
- Append-only chain with position binding: `transition()` uses `append_signed` with a build callback that folds `chain_seq=seq` into signed fields (v3 HMAC); a raise in the callback leaves no half-write (ledger.py:207–262).
- GENESIS idempotent guard: `genesis()` checks `current_epoch_fingerprint()` and is a no-op if any epoch-opening record exists — prevents double-genesis on reinstall (ledger.py:185–197).
- Read-fresh floor (D2): `FlooredRegistry` is constructed per-request in all three transports; the floor is never cached at runtime.
- `rekey()` hands key to custody sink BEFORE appending the `KEY_RESET` record — a custody failure leaves no fingerprint the ledger cannot later sign against (ledger.py:356–358).
- Metadata records (`OPERATOR_SESSION_OPENED`) are explicitly excluded from the `_FLOOR_RECORD_KINDS` set and skipped by the descending `read_floor()` scan, so a session-open tail cannot lower or freeze the effective floor (ledger.py:82, 116).

**Concerns:**
- `read_floor()` does NOT call `verify_integrity()` before returning the floor value. The task description states "read_floor() gates on verify_integrity()" but the actual implementation (ledger.py:92–118) performs only a descending SQL payload scan with no chain-hash verification. A silently corrupted ledger (raw DB write that keeps SQL rows intact but alters payload bytes) could cause `read_floor()` to return an attacker-lowered floor value. `verify_integrity()` is called separately by `doctor.py:480` during health checks, not inline on floor reads. This is a documented residual threat ("raw-DB-write deletion/truncation are conceded residual threats" per CLAUDE.md), but the gap is worth recording explicitly — the floor-read path trusts payload content without chain verification.
- The `posture -> install` coupling (`ledger.py:344`: `from legis.install import OperatorKeyCustodyError`) is a deferred import inside `rekey()`. `install.py` is a large module (owns CLI install flows, doctor probe logic, config/runtime setup) with the opposite dependency direction expected: install calls posture during setup. The current coupling is narrow (one exception class) but the direction is logically inverted — `OperatorKeyCustodyError` belongs in a shared errors or posture module, not in install. This creates a latent risk: changes to `install.py`'s imports or structure can inadvertently affect the posture/rekey path.
- `epoch_reset_unacknowledged()` and `current_epoch_fingerprint()` both call `self.store.read_all()` (full table scans, ledger.py:138, 165). As the ledger grows with session-open and transition records, these become increasingly expensive. `read_floor()` correctly uses a descending early-exit scan; these two read paths do not benefit from the same optimization.
- No logging or observability in the posture package itself. A refused `set_floor()` call (wrong session, fingerprint mismatch, signer fault) returns a structured `PostureSetResult` but nothing is written to an audit trail at the time of refusal — only accepted transitions appear in the ledger.

**Confidence:** High — Read 100% of all six source files in the package (`__init__.py`, `floor.py`, `ledger.py`, `records.py`, `session.py`, `signing.py`; 1,331 lines total). Verified inbound dependency graph by grepping all legis source for `from legis.posture`. Cross-validated the `read_floor()` fail-closed path against `floored_registry()` (floor.py:78–84) and the `set_floor()` gate (ledger.py:400–506). Confirmed the `install` import is a single deferred call site at ledger.py:344. Verified `verify_integrity()` is absent from the posture read path by direct code inspection.

---

## Wardline Findings Ingestion and Routing

**Location:** `src/legis/wardline/`

**Responsibility:** Ingest Wardline scan payloads (agent-supplied, not pulled via HTTP), validate the wire contract and artifact provenance, and route active defect findings into the configured enforcement cell — all without re-adjudicating Wardline's trust/taint verdicts.

**Key Components:**
- `ingest.py` (534 lines) — Wire validation: `active_defects()` extracts the gate population, `verify_wardline_artifact()` authenticates provenance (HMAC via `LEGIS_WARDLINE_ARTIFACT_KEY` or records `key_absent`). Defines `TRUST_TIERS`, `KNOWN_KINDS`, `DEFECT_KIND`, `FINDINGS_KEY`, `WardlineFinding`, `Suppressed` enum, `ArtifactStatus`/`ArtifactStatusReason` enums, canonical-reason carrier, `WardlineDirtyTreeError` (typed amber, not a generic red), and `ScanOutcome`.
- `governor.py` (178 lines) — Routing engine: `route_findings()` maps `WardlineFinding` list to `WardlineCellPolicy` members (`SURFACE_OVERRIDE`, `BLOCK_ESCALATE`, `SURFACE_ONLY`), resolves entity SEI before opening writes, wraps the batch in a single-store transaction (engine or signoff), and delegates to `EnforcementEngine.submit_override`, `SignoffGate.request`, or `EnforcementEngine.record_event`.
- `policy.py` (18 lines) — Thin helper: `resolve_cell()` maps a finding's severity rank against a configured `fail_on` threshold to produce either the gate cell or `SURFACE_ONLY`.
- `__init__.py` (1 line) — Empty aside from module docstring.

**Dependencies:**
- Inbound: `service/` (scan_route handler), `api/` and `mcp.py` (adapters supply the scan payload and call service)
- Outbound: `enforcement/engine.py` (`EnforcementEngine`), `enforcement/signoff.py` (`SignoffGate`), `enforcement/signing.py` (`verify`), `identity/entity_key.py` (`EntityKey`)

**Patterns Observed:**
- "Wardline analyses, Legis governs" enforced structurally: `ingest.py` module docstring (line 5) states "legis never re-analyzes — it reads findings and governs"; `TRUST_TIERS` and `KNOWN_KINDS` are explicitly labelled "carried, never re-derived" (ingest.py:16, ingest.py:43).
- Fail-closed on `FINDINGS_KEY` absence: `active_defects()` raises `WardlinePayloadError` rather than defaulting to empty (ingest.py:488–493), guarding against the G1 false-green where a producer key rename produces zero defects under a green status.
- Fail-closed on unknown `kind`: any kind outside `KNOWN_KINDS` is rejected loudly (ingest.py:511–517), closing the G1 twin (value-axis) where a drifted `kind` token silently removes a defect from the gate population.
- Agent-suppressed findings require proof: `waived`/`suppressed` findings without `suppression_proof`, `suppression_ticket`, or `suppression_reason` raise `WardlinePayloadError` (ingest.py:521–527).
- Dirty-tree amber is type-distinct from malformed-or-tampered: `WardlineDirtyTreeError` is intentionally not a subclass of `WardlinePayloadError` (ingest.py:191); its `to_payload()` produces `SKIPPED_DIRTY_TREE` so harnesses distinguish "commit first" from "scan is broken".
- Entity resolution before write: `governor.py` resolves all SEIs in `prepared` before opening any write transaction (governor.py:108–111), so identity network calls never run inside a SQLite transaction.
- Cross-store mixing rejected before any write: the guard at governor.py:94–97 rejects a batch that would span engine and signoff stores simultaneously.

**Concerns:**
- Transaction atomicity is partial: the pre-write guard (governor.py:65–66 comment) explicitly acknowledges that a mid-loop runtime failure after some findings persist leaves those writes permanent. This is accepted but undocumented at the call-site level for callers who may not read the comment.
- The `cell_map` dependency check (governor.py:80–84) is deliberately conservative — it validates all mapped cells, not only those triggered by present findings. The inline comment (governor.py:74–79) flags that narrowing this requires recomputing from present findings, leaving it as acknowledged future work.
- No rate-limit or per-agent throttle on the findings batch beyond `MAX_FINDINGS = 500` (ingest.py:26). A batch at exactly the maximum is accepted without an audit-trail event marking it as a large batch.

**Confidence:** High — Read all three implementation files (ingest.py 534 lines, governor.py 178 lines, policy.py 18 lines) fully. Cross-verified dependency claims against imports and governance-honesty invariants confirmed in code at cited lines.


## Filigree Sign-off Binding

**Location:** `src/legis/filigree/` and `src/legis/governance/`

**Responsibility:** Bind a cleared, governed sign-off to a Filigree issue via an SEI-keyed entity-association, record the binding in a local HMAC-signed append-only ledger, and gate issue closure on verified ledger evidence — without touching Filigree's issue lifecycle (locked decision 5).

**Key Components:**
- `filigree/client.py` (185 lines) — `HttpFiligreeClient` and `FiligreeClient` Protocol: HTTP transport to Filigree using stdlib `urllib`, with injectable `fetch` for offline testing. Explicitly omits `X-Weft-*` transport HMAC headers (client.py:6–13, 44–45); the app-level `binding_signature` in the JSON body is the governance evidence.
- `governance/signoff_binding.py` (83 lines) — `bind_signoff_to_issue()`: validates `entity_key.identity_stable` (raises `ValueError` if false — locator-keyed bind is rejected), optionally HMAC-signs the binding payload, calls `filigree.attach()`, then calls `ledger.record()` in validate→attach→record order.
- `governance/binding_ledger.py` (94 lines) — `BindingLedger`: append-only tamper-bound store of `issue_binding` records, each signed with the LEGIS HMAC key. `get()` and `get_by_issue_id()` call `verify()` before returning data (fail-closed: tampered ledger raises `BindingError`, never returns data).
- `governance/filigree_gate.py` (33 lines) — Pure decision: `evaluate_issue_closure()` calls `ledger.get_by_issue_id()` (which verifies the chain) and returns `allowed: False` if no verified binding record exists.
- `governance/gaps.py` (121 lines) — `find_orphan_gaps()` and `find_lineage_integrity()`: scans the governance audit trail for SEI-keyed records, resolves current liveness/lineage from Loomweave, surfaces orphaned attestations and lineage divergences. Prefix-check semantics: lineage appends are legitimate; a removed or mutated prior event is divergence (gaps.py:6–9).
- `governance/sei_backfill.py` (269 lines) — Append-only migration: upgrades legacy locator-keyed audit rows to SEI-keyed `SEI_BACKFILL` events without rewriting history. Checks integrity before running; dry-run default.
- `governance/params.py` (10 lines) — Policy constants: `OVERRIDE_RATE_THRESHOLD = 0.2`, `OVERRIDE_RATE_WINDOW = 100`, `OVERRIDE_RATE_MIN_SAMPLE = 20`. Explicitly marked as ADR-0002 policy — not tuneable via request parameters.
- `governance/__init__.py` (1 line) — Empty aside from module docstring.

**Dependencies:**
- Inbound: `service/` (`bind_signoff_issue`, `read_filigree_closure_gate`), `mcp.py` (`signoff_bind_issue`, `filigree_closure_gate_get`)
- Outbound: `filigree/client.py` → `weft_signing.weft_body_bytes`; `signoff_binding.py` → `enforcement/signing.sign`, `filigree/client.FiligreeClient`, `governance/binding_ledger.BindingLedger`, `identity/entity_key.EntityKey`; `binding_ledger.py` → `clock.Clock`, `enforcement/signing.sign`+`verify`, `identity/entity_key.EntityKey`, `store/protocol.AppendOnlyStore`; `gaps.py` → `canonical.content_hash`, `identity/loomweave_client.LoomweaveIdentity`, `store/protocol.AuditRecordLike`; `sei_backfill.py` → `canonical.content_hash`, `clock.Clock`, `identity/loomweave_client.LoomweaveIdentity`, `identity/entity_key.EntityKey`, `identity/resolver.*`, `store/protocol.*`

**Patterns Observed:**
- SEI-stability gate is the first check in `bind_signoff_to_issue()` (signoff_binding.py:46–49): a locator key raises `ValueError` before any network call, enforcing ADR-0003 fail-closed semantics.
- App-level `binding_signature` is the governance evidence, not transport HMAC: client.py explicitly omits `X-Weft-*` headers (client.py:9–13) to avoid dead handshake with a non-verifying Filigree route; binding integrity lives in the local ledger's HMAC chain.
- Validate→attach→record order in `bind_signoff_to_issue()` (signoff_binding.py:71–82): if `ledger.record()` raises after `filigree.attach()` succeeds, the code comment (signoff_binding.py:72–76) honestly documents the accepted trade-off — a binding with no ledger entry is surfaced by `verify()`, not silently lost.
- Ledger always verifies before reading: both `get()` and `get_by_issue_id()` call `self.verify()` as the first operation (binding_ledger.py:79, 87), so a tampered ledger raises `BindingError` and returns no data.
- Filigree does not own lifecycle: `evaluate_issue_closure()` is a pure read-decision that returns structured `allowed/reason/evidence` without writing to Filigree or mutating issue state (filigree_gate.py:14–32).
- Lineage integrity uses prefix semantics, not whole-list equality: `find_lineage_integrity()` computes `content_hash(current[:n])` against the stored snapshot (gaps.py:110), so appended rename events do not trigger false divergences.
- `params.py` constants cannot be tuned by request (params.py:7–9 comment): the override-rate threshold reads from this file, not from request parameters.

**Concerns:**
- Uncompensated partial-write window in `bind_signoff_to_issue()`: if `ledger.record()` raises after `filigree.attach()` succeeds, Filigree holds the association pointer but legis has no tamper-bound record of it. The code correctly documents this (signoff_binding.py:72–76), but there is no reconciliation path or operator repair tool identified — a `BindingLedger.verify()` call surfaces the mismatch but cannot heal it.
- `filigree/client.py` response integrity depends on TLS only: the inline comment (client.py:127) acknowledges that `LEGIS_ALLOW_INSECURE_REMOTE_HTTP=1` with a non-loopback Filigree host makes responses forgeable on-path. The escape hatch is guarded by the env flag and log warning, but there is no posture/doctor check that flags a non-loopback HTTP Filigree URL in production.
- `get_by_issue_id()` returns the *last* verified binding record for an issue (binding_ledger.py:88–93); if multiple bindings exist for the same `issue_id` (re-bind after a re-sign-off), earlier records are silently shadowed. No audit event marks a supersession.

**Confidence:** High — Read all 7 files fully (signoff_binding.py 83 lines, binding_ledger.py 94 lines, filigree_gate.py 33 lines, gaps.py 121 lines, sei_backfill.py 269 lines, params.py 10 lines, filigree/client.py 185 lines). Cross-verified transport-boundary claims and SEI-stability guard at signoff_binding.py:46–49.


## Warpline Preflight Advisory Consumer

**Location:** `src/legis/warpline_preflight/`

**Responsibility:** Provide read-only advisory access to Warpline's impact-radius and reverify-worklist data, surfaced as a sibling informational tool that is structurally isolated from every governance verdict path.

**Key Components:**
- `client.py` (144 lines) — `HttpWarplineClient` and `WarplineClient` Protocol: two read-only GETs (`impact_radius`, `reverify_worklist`) via stdlib `urllib`, with injectable `fetch`. HTTPS-required for non-loopback, redirect-blocked, response size-capped at 1 MB. No signing — Warpline's advisory responses are not HMAC-authenticated.
- `__init__.py` (1 line) — Empty.
- `service/preflight.py` (39 lines, not in this directory but the sole consumption point) — `read_warpline_preflight()`: returns `{"status": "unavailable", ...}` when client is `None` or raises `WarplineError`; returns `{"status": "checked", ...}` on success. Transport failures are contained as `unavailable` and never propagate as `INTERNAL_ERROR`.

**Dependencies:**
- Inbound: `service/preflight.read_warpline_preflight` (consumed only by `mcp.py:_tool_warpline_preflight_get` — a dedicated MCP tool, not embedded in any governance tool handler)
- Outbound: stdlib only (`urllib`, `json`, `ipaddress`, `os`, `logging`)

**Patterns Observed:**
- Advisory boundary is enforced by structural isolation: `client.py` module docstring (line 7) states "nothing it returns may reach a governance verdict path"; grep of `service/policy.py`, `enforcement/engine.py`, and all governance tool handlers confirms zero cross-references between warpline preflight and any verdict, gate, sign-off, or honesty-read path.
- Fail-unavailable, not fail-empty: an unconfigured or unreachable Warpline returns `{"status": "unavailable", "unavailable": [{"reason": ...}]}` (preflight.py:21–33), never an empty affected-set that could read as "nothing impacted".
- No request signing: `_transport_fetch` passes an empty headers dict (client.py:129), consistent with the advisory posture — no HMAC contract with Warpline exists.
- `mcp.py` constructs `HttpWarplineClient` lazily at runtime (mcp.py:234–238) and stores it on `McpRuntime.warpline`; a `WarplineError` during construction makes it `None`, triggering the unavailable path.

**Concerns:**
- Advisory boundary relies on discipline, not a type wall: the `WarplineClient` Protocol and its response dicts are untyped at the governance layer — there is no newtype or sealed return type that would prevent a future developer from accidentally plumbing a Warpline response into a verdict path. The contract is documented in comments but not machine-enforced.
- Response integrity depends on TLS only (same structural gap as the Filigree client): a non-loopback HTTP Warpline URL under `LEGIS_ALLOW_INSECURE_REMOTE_HTTP=1` yields forgeable advisory data (client.py:106–114). Since advisory data is never supposed to reach governance verdicts, this is lower risk than the Filigree case, but the doctor check gap is the same.
- None observed for advisory-boundary enforcement in the governance verdict paths — verified by grepping `service/policy.py` and `enforcement/engine.py` for any warpline reference (both returned empty).

**Confidence:** High — Read `client.py` (144 lines) fully and `service/preflight.py` (39 lines) fully. Advisory boundary verified by negative grep across enforcement and policy service modules. MCP wiring verified at mcp.py:2277–2286 and mcp.py:234–238.

---

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

---

## install.py — Project Installer

**Location:** `src/legis/install.py`

**Responsibility:** Stands up legis in a project by injecting a versioned instruction block into CLAUDE.md/AGENTS.md, installing the legis-workflow skill pack, registering a Claude Code SessionStart hook in .claude/settings.json, writing .gitignore rules, minting the posture-ledger GENESIS and operator key, and registering the MCP server entry in .mcp.json — all idempotent, all symlink-escape-guarded.

**Key Components:**
- `project_path` / `ensure_project_dir` / `reject_symlink` (lines 132–160) — symlink-escape guards applied to every installer write; raise `UnsafeInstallPathError` on traversal outside project root
- `inject_instructions` (lines 311–387) — foreign-fence-aware instruction-block injector; uses `_first_own_open_fence_pos` + `_first_foreign_fence_pos` to never delete a co-resident sibling block (wardline/filigree); writes via `_atomic_write_text` (temp + `os.replace`)
- `_atomic_write_text` (lines 278–308) — empty-content guard + mode-preserving atomic write (refuses empty payload, rejects symlink direct target); used for all text writes in install
- `_install_skill_to` (lines 416–483) — concurrent-safe skill-pack copytree with rename race: stages to a temp dir, renames target aside, atomically swaps in new tree; on failure restores the prior pack rather than silently dropping it
- `install_claude_code_hooks` (lines 733–837) — registers `legis session-context` as a SessionStart hook; upgrades stale/bare commands to the resolved binary path; backs up malformed `settings.json` before resetting rather than silently clobbering; only rewrites unscoped blocks (never touches user-scoped blocks)
- `register_mcp_json` (lines 1199–1289) — idempotent MCP entry manager; a usable existing entry (command resolves + args valid + env clean) is NEVER regenerated; on rebuild preserves the operator-owned `env` dict minus blocked keys (`_safe_mcp_env`); `_REJECTED_MCP_ENV_KEYS` + `_REJECTED_MCP_ENV_PREFIXES` scrub secrets and unsafe escape-hatch vars
- `install_posture` (lines 1367–1431) — posture-ledger genesis; key minted once, handed to custody sink BEFORE `GENESIS` is written (fail-closed: no fingerprint written if custody fails); idempotency guard at `current_epoch_fingerprint()` prevents second-mint; env-backend adopts `LEGIS_OPERATOR_KEY` rather than minting a throwaway (legis-1844bf8ac9)
- `_default_key_sink` (lines 1462–1502) — custody router: `env`=no-op, `age-file`=atomic blob write, `keychain`=loud failure (adapter not shipped); raises `OperatorKeyCustodyError` rather than dropping the key
- `_find_legis_command` (lines 522–562) — binary resolution; prefers `sys.argv[0]` (faithful to the running binary, legis-788a85fac1) over PATH; skips project-local hits to avoid pinning a venv shim that doctor would immediately flag as stale

**Dependencies:**
- Inbound: `hooks.py` (imports `inject_instructions`, `install_skills`, `install_codex_skills`, `_get_skills_source_dir`, `_skill_tree_fingerprint`, `_instructions_block_is_current`, `_marker_token`, `INSTRUCTIONS_MARKER`, `SKILL_NAME`); `doctor.py` (imports `_install` module, calls `mcp_entry_is_current`, `inject_instructions`, `install_claude_code_hooks`, `install_skills`, `install_codex_skills`, `gitignore_rules_present`, `ensure_gitignore`, `ensure_legis_dir_gitignore`, `_has_unscoped_session_start_hook`, `_own_open_marker_tokens`, `_marker_token`, `SESSION_CONTEXT_COMMAND`, `SKILL_NAME`, `LEGIS_DIR_GITIGNORE_MARKER`); `posture/` (imports `install_posture` for genesis)
- Outbound: `legis.config` (posture DB URL); `legis.posture` (`PostureLedger`, `mint_key`, `key_fingerprint`, `wrap_key`, `select_backend`); `legis.clock`; `importlib.resources` / `importlib.metadata` (bundled instructions, version); stdlib (`hashlib`, `shutil`, `tempfile`, `os`, `json`, `re`, `stat`)

**Patterns Observed:**
- Fail-closed on every operation: custody failure before GENESIS write, empty-content guard before any text write, `UnsafeInstallPathError` on symlink escape — the codebase never auto-accepts partial success
- Strict idempotency contract: every installer function checks current state before acting; a second `install` over a healthy project modifies nothing material (returns early with "already registered" / "already present")
- Operator-env preservation on `.mcp.json` updates: the existing `env` dict is carried forward (minus scrubbed secret keys) rather than wiped — named fix for legis-788a85fac1; `_safe_mcp_env` is the scrub gate
- Foreign-fence awareness in instruction injection: `_INSTR_FENCE_RE` detects any tool's namespace fence (case-insensitive); the injector never deletes inter-block content owned by wardline/filigree (C-4 multi-owner block contract)
- `_find_legis_command` avoids project-local path poisoning: prefers the running binary, skips `.venv/bin/legis` hits so the registered hook/MCP command doesn't bounce on freshness checks

**Concerns:**
- `_keychain_available()` (line 1348–1349) always returns `False` — the live OS-keychain backend is not yet implemented. This means `choose_install_backend` never selects `keychain` automatically. The comment documents it as deferred, but a caller providing `backend="keychain"` directly would route to the `_default_key_sink` `raise` path. The honesty posture is correct (fail-closed, not silent), but the gap means the most-secure custody path is unattainable without a custom `key_sink` injection.
- `install.py` is 1503 lines and owns six distinct responsibilities (instruction injection, skill pack, hook, gitignore, MCP registration, posture genesis). The functions are well-decomposed but the file is a god module by size; a future author adding a seventh install artifact has no forcing function to split it.
- The `settings.json` backup-on-corrupt path (lines 761–768, 804–817) writes `settings.json.bak` by copying via `shutil.copy2` then overwrites without `reject_symlink` on the backup path itself — a symlink at `.claude/settings.json.bak` could cause the backup to land outside the project tree. The backup path does call `reject_symlink` (lines 763, 807) before the copy, so this is mitigated, but only for the direct symlink case, not for symlinked parent directories. Evidence: line 763 `reject_symlink(backup)` is present, so direct symlink is blocked.

**Confidence:** High — Read 100% of install.py (1503 lines). Every claim cites specific line ranges. Cross-verified the `hooks.py` import list against actual `from legis.install import (...)` at hooks.py:23–32. Verified `register_mcp_json` env-preservation logic at lines 1282–1284. Verified `install_posture` idempotency guard at lines 1411–1413. Verified `_keychain_available` stub at lines 1347–1349.


## doctor.py — Operator Health and Repair

**Location:** `src/legis/doctor.py`

**Responsibility:** Inspects and (with `--fix`) repairs legis's install and runtime artifacts, reporting each problem as `[auto-fixable]` or `[operator]`, sharing the machine-readable report surface (`doctor_payload`) with the MCP `doctor_get` tool so CLI and agent surfaces cannot drift.

**Key Components:**
- `DoctorCheck` (lines 28–49) — frozen dataclass with `id`, `status` (`ok`/`warn`/`error`), `fixed`, `message`, `repairable`; the `repairable` field is the source of truth for the `[auto-fixable]` vs `[operator]` tag rendered in `render_text`
- `render_text` (lines 71–114) — renders `[fixed]`/`[auto-fixable]`/`[operator]` tags; a `repairable=False` check that is not fixed renders `[operator]`; a `repairable=True` check that is not fixed renders `[auto-fixable]`; confirmed honest: split-brain blocks set `repairable=False` (line 197) matching their "resolve it by hand" message
- `doctor_payload` (lines 56–64) — single source of the machine-readable schema shared by CLI `--format json` and MCP `doctor_get`; both render from this function (docstring confirmed; cross-validated against `mcp.py` usage by import path)
- `collect_checks` (lines 967–996) — runs 25 checks in order; repair branches live inside individual check functions (not here), so the orchestrator is pure composition
- `check_instruction_block` (lines 172–205) — distinguishes missing / drifted / split-brain; split-brain (`len(tokens) > 1`) returns `repairable=False` (line 197) because the injector cannot canonicalise across a sibling's block — honesty-correct; `--fix` re-runs `inject_instructions` and re-checks state before reporting success
- `check_mcp_json` (lines 117–137) — repair calls `register_mcp_json` and re-checks `mcp_entry_is_current` before returning `fixed=True`; never writes env secrets (delegates to `_safe_mcp_env` inside `register_mcp_json`)
- `check_audit_chain` (lines 461–487) — absent store → `ok` (never creates DB); tampered chain → `error`, `repairable=False`; never auto-repairs a hash-chain failure
- `check_posture_chain` / `check_posture_ledger` / `check_posture_key_reset` / `check_operator_key_accessible` (lines 561–810) — posture-ledger integrity checks; all report-only; `check_operator_key_accessible` probes key reachability without rendering the key value (lines 763–791); env escape hatch presence yields `warn`, not `ok` (honesty note at line 773)
- `check_weft_toml` (lines 339–358) — distinguishes absent (ok / defaults apply) from present-but-broken (error / config silently not applying), per C-9(b); NEVER writes `weft.toml` (confirmed — no write call anywhere in this function)
- `check_filigree_binding_scope` (lines 927–964) — triggered by unscoped filigree URL presence, NOT local install; `repairable=False` (operator-pinned URL); closes the false-green where doctor said "ok" while scans silently non-emitted
- `_store_dir_for` (lines 329–336) — anchored at `root`, not `cwd`, and explicitly ignores `weft.toml` (comment at line 332); custody rule correctly enforced in doctor's own store-path logic

**Dependencies:**
- Inbound: CLI (`legis.cli` `doctor` subcommand); MCP tool surface (`legis.mcp` `doctor_get` tool uses `doctor_payload` / `collect_checks`); integration tests
- Outbound: `legis.install` (all repair operations delegate back to install functions); `legis.config` (`STORE_DB_SPECS`, `protected_policies`, `posture_db_url`, `operator_age_path`); `legis.store.audit_store` (`AuditStore`); `legis.posture.ledger` (`PostureLedger`); `legis.posture.signing` (`key_fingerprint`, `unwrap_key`); `legis.posture.records` (kind constants); `legis.enforcement.signing` (`verify`)

**Patterns Observed:**
- Report-then-repair contract: every check function verifies current state first; repair branches are conditional on the `repair` flag; post-repair state is re-verified before claiming `fixed=True` (e.g. `check_hook` lines 259–261)
- `repairable` flag drives honest tagging: split-brain blocks, operator-key items, and audit-chain failures all set `repairable=False`; auto-fixable items all set `repairable=True`; the tag in `render_text` derives directly from this flag, not from ad-hoc conditions
- Doctor never writes `weft.toml` (C-9(b)): confirmed — no `weft.toml` write in any check function; `check_weft_toml` is read-only
- `_store_dir_for` ignores `weft.toml` and uses `root`-anchored path (line 332 comment); doctor's store resolution is independent of the runtime config's `LEGIS_*_DB` overrides for the store-path check itself (overrides are respected only by `_store_url` when building actual DB URLs for integrity checks)
- `STORE_DB_SPECS` imported from `config` (line 325) ensures doctor's override-env list can never silently drop a store when a 6th store is added — single-source enumeration closes that coverage gap

**Concerns:**
- `check_wardline_artifact_key` (line 836) reports a `warn` when `LEGIS_WARDLINE_ARTIFACT_KEY` is absent, saying all scans govern as `artifact_status=unverified`. The honesty diagnosis (PDR-0023) is correct and the signal is present. However the message does not name a path for a "warn" exit in CI: operators who see a `warn` may not know whether CI fails on `warn` or only on `error`. `run_doctor` (line 999–1002) returns non-zero only when any check is not `.ok` — and `warn` is not "ok" (`.ok` is `status != "error"`, not `status == "ok"` — confirmed: `DoctorCheck.ok` at line 38 returns `self.status != "error"`). This means `warn`s do NOT cause a non-zero exit. An unset `LEGIS_WARDLINE_ARTIFACT_KEY` therefore yields a `warn` that does NOT fail CI — which is documented as intentional ("deliberately a warn, not an error") but could mislead operators who expect CI-blocking behavior for unsigned verification.
- At 1002 lines `doctor.py` carries both the check domain logic and the rendering/orchestration logic. It is coherent but large; adding a new sibling or posture check requires editing a single growing file with no structural boundary.

**Confidence:** High — Read 100% of doctor.py (1003 lines). Every claim cites specific line ranges. Verified `DoctorCheck.ok` property logic at line 38. Confirmed `repairable=False` for split-brain at line 197. Confirmed `check_weft_toml` has no write call. Confirmed `run_doctor` exit-code logic at lines 999–1002.


## hooks.py — SessionStart Hook and Refresh

**Location:** `src/legis/hooks.py`

**Responsibility:** Implements the `legis session-context` SessionStart hook, which refreshes drifted instruction blocks and skill packs in place and emits a one-line posture banner (instructions, skill, cells, posture floor) that is always non-empty to distinguish "nothing to report" from "broken."

**Key Components:**
- `refresh_instructions` (lines 38–93) — refreshes drifted instruction blocks (byte-exact check via `_instructions_block_is_current`) and stale skill packs (fingerprint check via `_skill_tree_fingerprint`); only touches marker-bearing files and already-installed skill dirs; never creates a block or dir that doesn't already exist (that is install's job)
- `generate_session_context` (lines 198–222) — the top-level entry point; always returns a non-empty string (dogfood N-1); composes four posture sub-strings: `_instructions_posture`, `_skill_pack_posture`, `_cells_posture`, `_posture_floor`; exceptions from `refresh_instructions` are caught and reported as a failure line, not raised
- `_posture_floor` (lines 173–195) — reads the posture ledger with `initialize=False` (never creates the DB); absent/empty ledger returns `"posture floor: none (fail-closed structured)"` not a false-green claim; unreadable ledger returns `"posture floor: unreadable"` (warn, not silent); imported lazily inside the function to avoid circular import at module load
- `_cells_posture` (lines 145–170) — mirrors `mcp._load_policy_cell_registry` file precedence (`LEGIS_POLICY_CELLS` > `policy/cells.toml`) but is explicitly documented as report-only at hook process scope, never claiming server runtime posture; unreadable cells → `"cells config: unreadable"`, not a false-green
- `_skill_pack_posture` (lines 122–142) — when bundled source is missing, returns `"skill pack unverifiable (bundled source missing)"` (line 138) rather than claiming currency — honesty-correct; only claims "current" when fingerprints compare equal

**Dependencies:**
- Inbound: `legis.cli` (the `session-context` subcommand calls `generate_session_context`); `legis.mcp` (MCP startup calls `refresh_instructions` best-effort)
- Outbound: `legis.install` (substantial: `inject_instructions`, `install_skills`, `install_codex_skills`, `_get_skills_source_dir`, `_skill_tree_fingerprint`, `_instructions_block_is_current`, `_marker_token`, `INSTRUCTIONS_MARKER`, `SKILL_NAME`); `legis.policy.cells` (`load_policy_cells`); `legis.config` (`posture_db_url`); `legis.posture.ledger` (`PostureLedger`)

**Patterns Observed:**
- Refresh-only-in-place invariant: `refresh_instructions` checks `if not md_path.exists(): continue` (line 50) and `if not target_root.is_dir(): continue` (line 83) — never creates absent install artifacts; install vs hooks boundary is structurally enforced
- All four posture sub-functions are fail-closed: each returns a distinct "unreadable" or "not installed" string rather than silently eliding the field or returning an empty string
- Lazy import of `legis.config` / `legis.posture.ledger` inside `_posture_floor` (lines 183–184) avoids circular import; consistent with the pattern used across enforcement modules

**Concerns:**
- `refresh_instructions` warns via `logger.warning` (lines 69–71, 88–90) when drift re-injection fails, but the warning goes to the log, not to the session banner. An operator reading the banner without checking logs would see no signal about the failure. The comment at line 69 notes this is intentional ("Surface it for the operator (peer of the boot-log path)"), but in practice an agent running headlessly may have no log reader. The `_instructions_posture` post-refresh check (line 116) does catch still-drifted state and returns `"instructions stale (refresh failed; see logs)"` in the banner — so this is only a partial gap.
- `hooks.py` imports eight private symbols from `install.py` (prefixed `_`). This is a documented dependency (the module comment explains the two callers), but changes to private install helpers require cross-checking hooks.py. The coupling is inward-only (hooks does not re-export these) and exists because hooks is explicitly a "lighter-weight" refresh surface reusing install's logic.

**Confidence:** High — Read 100% of hooks.py (223 lines). Verified `refresh_instructions` never creates absent paths (lines 50, 83). Verified `_posture_floor` uses `initialize=False` (line 189). Verified `_skill_pack_posture` unverifiable path (line 138). Confirmed private symbol imports from install at lines 23–32.


## config.py — Store Resolution and Env Configuration

**Location:** `src/legis/config.py`

**Responsibility:** Resolves all SQLite store URLs and composition-root configuration (protected policies, operator paths) from environment variables, with `LEGIS_*_DB` overrides as the sole relocation mechanism — `weft.toml` is explicitly and deliberately ignored for store paths.

**Key Components:**
- `STORE_DB_SPECS` (lines 71–77) — stably-ordered tuple of `(env_var, db_filename)` for all five stores; the single source of store identity so doctor and any future consumer never re-list the env vars / filenames independently
- `_resolve_db_url` (lines 110–123) — the single resolution point for all stores: `env_var in os.environ` (membership check, not `.get()`) so a present-but-empty override returns verbatim rather than silently falling through to the default; a present-but-empty override is therefore a broken override, never a "use default" fallback
- `_store_dir` (lines 90–97) — ignores `weft.toml` by design (comment at line 92); builds `.weft/legis/` under the provided root or `Path(".")` (relative, resolved against cwd at call time)
- `protected_policies` (lines 171–184) — single parse point for `LEGIS_PROTECTED_POLICIES`: `frozenset` of comma-split, stripped, non-empty names; read at call time so the CLI can write the env var from `--protected-policies` before composition roots read it
- `ensure_sqlite_parent` (lines 187–203) — creates the parent directory lazily at store-open time, never at URL-compute time; importing `config` or computing a default URL never litters `.weft/` directories
- `operator_session_path` / `operator_age_path` (lines 151–168) — operator-elevation file paths, both under `.weft/legis/`; documented as holding references/encrypted blobs only, never key plaintext

**Dependencies:**
- Inbound: every module that opens a store (`api/app.py`, `mcp.py`, `cli.py`, `store/`, `posture/`, `install.py`, `doctor.py`, `hooks.py`)
- Outbound: `sqlalchemy.engine.make_url` (URL parsing in `ensure_sqlite_parent`); `os`, `pathlib`

**Patterns Observed:**
- `weft.toml`-is-enrich-only documented at module level (lines 18–23) and structurally enforced: `_store_dir` does not read `weft.toml` at all; no `tomllib` import in `config.py`
- Present-but-empty env var treated as verbatim override (line 121), not silent fallback — consistent with CLAUDE.md doctrine
- Call-time resolution (not module-load-time) for both DB URLs and `protected_policies`: env vars written late by the CLI (e.g. `--protected-policies` flag sets `os.environ` before the composition root reads it) always produce the correct value

**Concerns:**
- None observed. Verified: no `weft.toml` read in any path; present-but-empty override is handled correctly (line 121); `ensure_sqlite_parent` defers directory creation to store-open time (not import time); `STORE_DB_SPECS` is the single enumeration consumed by doctor. The module is 204 lines with a single, well-bounded responsibility.

**Confidence:** High — Read 100% of config.py (204 lines). Verified `env_var in os.environ` membership-check at line 121. Verified absence of `tomllib` import. Verified `_store_dir` comment at lines 91–93. Verified `STORE_DB_SPECS` structure at lines 71–77. Confirmed lazy `ensure_sqlite_parent` design at lines 193–203.

---

