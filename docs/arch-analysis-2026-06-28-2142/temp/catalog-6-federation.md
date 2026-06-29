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
