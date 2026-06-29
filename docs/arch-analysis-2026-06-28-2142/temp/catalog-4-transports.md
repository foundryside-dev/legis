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
