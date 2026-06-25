# Legis ↔ warpline interfaces — preflight consumer + per-SEI attestation read — design

**Date:** 2026-06-24
**Status:** Design approved (brainstorm), pre-implementation
**Scope:** The Legis side of warpline's requested interfaces (request item 5): **(a)** read warpline affected-set summaries as *advisory* preflight facts, and **(b)** expose a per-SEI attestation/governance-posture read so warpline can implement governance-as-verification (Rung 2). The rename feed warpline consumes (`git_rename_list` / `git_rename_feed_get`) **already ships** and is not rebuilt here.

---

## 1. Problem & motivation

Warpline (a Weft suite member; impact-radius / reverify-worklist analysis over `base..head`) has requested two interfaces from Legis:

1. **Advisory preflight context.** Before an agent acts, it is useful to see warpline's *affected set* (impact radius) and *reverify worklist* **next to** Legis's own governance honesty reads (`identity_gap_list`, `lineage_integrity_get`). Warpline is a heuristic impact analyzer; it must **never** decide a governance verdict — its output is purely advisory.

2. **Governance-as-verification (Rung 2).** Warpline wants to treat an entity that Legis has **attested at a given commit** as "proven-good" and skip reverifying it. Legis exposes no per-SEI attestation read today (it only serves `serve` / `mcp` / the governance-gate). This is **optional/future** on warpline's side — without it, warpline reports `governance=unavailable` (with a reason triple) and proceeds. Exposing it lets warpline shrink its reverify worklist using Legis attestations.

### The boundary that governs every decision below

> **Legis remains the only governance / sign-off / attestation authority. Warpline context is purely advisory.**
>
> **Acceptance:** governance decisions are **byte-identical** whether warpline is present or absent.

This is the same honesty discipline already pervasive in the codebase (the discriminated `checked` / `unavailable` / `diverged` reads, fail-closed verification). The novel risk is a *new* one: Legis is becoming an HTTP **client** of a sibling for the first time on a path that sits *next to* governance reads. The invariant is that warpline data is **structurally incapable** of reaching a verdict path — it lives in its own tool and is never an input to `policy_evaluate`, the gates, sign-off, or any honesty read.

## 2. Goals / non-goals

### Goals
- A new env-gated HTTP client (`HttpWarplineClient`, `WARPLINE_API_URL`) modeled exactly on `HttpFiligreeClient` — stdlib `urllib`, injectable `fetch`, loopback/HTTPS URL gating, response-size bound, no-redirect.
- A new MCP tool **`warpline_preflight_get`** (a *sibling*, not embedded in the governance reads) returning an honest discriminated read: `checked` (advisory facts) vs `unavailable` (with reasons).
- A new MCP tool **`attestation_get`** returning, for an SEI, the **verified human-cleared attestation facts** (no `proven_good` verdict), through the same fail-closed trail-verification path the other honesty reads use.
- An acceptance test proving governance verdicts are unchanged when `WARPLINE_API_URL` is unset vs set.
- Full surface bookkeeping (outputSchema, `_AGENT_TOOLS`, surface conformance, tool-count, output-schema conformance vectors).

### Non-goals
- Rebuilding the rename feed — `git_rename_list` / `git_rename_feed_get` ship today. Two-way rename-parser conformance vectors remain tracked by the existing open ticket **`legis-c4cbf78fdb`** (G16) and are out of scope here.
- Legis becoming an MCP *client* of warpline (rejected in brainstorm; HTTP mirrors the established sibling pattern).
- Any "skip reverification" / proven-good decision inside Legis — that is warpline's Rung-2 call. Legis returns facts.
- Warpline writing to Legis, or Legis feeding warpline data into any governance computation.
- Pinning warpline's exact wire format. The client is built to a **documented inferred contract** (see §6) that is shape-validated; it is corrected when warpline's real format lands.

## 3. Part (a) — warpline preflight consumer

### 3.1 Client: `HttpWarplineClient`

New module `src/legis/warpline_preflight/client.py`, a near-clone of `src/legis/filigree/client.py`:

- `class WarplineError(RuntimeError)` — a warpline call failed at the transport or decode layer.
- `_validate_base_url` — http(s) + host required; `http` to a non-loopback host rejected unless `LEGIS_ALLOW_INSECURE_REMOTE_HTTP=1` (with the same logged warning Filigree emits — warpline responses are advisory but a tampered "nothing impacted" should still be opt-in only).
- `MAX_RESPONSE_BYTES = 1_000_000`, no-redirect opener, JSON content-type check.
- Injectable `Fetch` callable so tests run fully offline (no network).
- `@runtime_checkable` `WarplineClient` Protocol with the two methods.
- Two methods, both read-only `GET`:
  - `impact_radius(base: str, head: str) -> dict`
  - `reverify_worklist(base: str, head: str) -> dict`

Wired in `build_runtime` exactly like Filigree:
```python
warpline = None
warpline_url = os.environ.get("WARPLINE_API_URL")
if warpline_url:
    from legis.warpline_preflight.client import HttpWarplineClient
    warpline = HttpWarplineClient(warpline_url)
```
and held on `McpRuntime` as `warpline: Any | None = None`.

### 3.2 Tool: `warpline_preflight_get`

- **Input:** `{base: string (required), head?: string}` — `head` defaults to `"HEAD"` (mirrors `git_rename_feed_get`).
- **Handler `_tool_warpline_preflight_get`:** delegates to a transport-agnostic service function `read_warpline_preflight(warpline_client, base, head)` in a new `src/legis/service/preflight.py`, mirroring how `read_identity_gaps` / `read_lineage_integrity` live in `service/governance.py`.
- **Honest discriminated output** (the house pattern — an empty affected-set must NOT read as "nothing impacted"):

  `status: "checked"`:
  ```json
  {"status": "checked", "impact_radius": {...}, "reverify_worklist": {...}}
  ```
  `status: "unavailable"` (client not configured, transport failure, **or payload shape mismatch**):
  ```json
  {"status": "unavailable", "unavailable": [{"reason": "warpline client not configured"}]}
  ```
- The service function calls both warpline methods; **either** failing degrades the whole read to `unavailable` with a reason (partial advisory context is not surfaced as `checked`). A `WarplineError` is caught and converted to an `unavailable` reason — it never escapes as `INTERNAL_ERROR`, exactly as `read_identity_gaps` converts `LoomweaveError`.
- Added to `_AGENT_TOOLS`.

### 3.3 Why a sibling tool, not embedded

`identity_gap_list` / `lineage_integrity_get` carry outputSchema conformance tests and *are* the governance authority surface this work must protect. Embedding an advisory external read into a governance honesty read muddies "Legis is the authority" and risks an advisory failure perturbing a governance read. A dedicated sibling keeps advisory and authority **structurally** separate; an agent composes a preflight view by calling all three.

## 4. Part (b) — per-SEI attestation read

### 4.1 Tool: `attestation_get`

- **Input:** `{sei: string (required)}`. Legis does **not** accept a commit. Warpline resolves the SEI's content_hash at commit X via Loomweave (which it already queries for `timeline` / `changed`) and matches it against the `content_hash` Legis returns. The match — and the "skip reverify" decision — is warpline's Rung-2 call, not Legis's.
- **Service function `read_sei_attestations(runtime_records, sei)`** in `service/governance.py` (next to the other honesty reads). It is reached **only when the trail is signature-verifiable** — the handler pre-gate requires BOTH a protected gate AND a `trail_verifier` (governance.py `verified_records` runs `TrailVerifier.verify` only when both are wired; with neither, it would return engine records UNVERIFIED). When verifiable, a tampered/forged record raises `AuditIntegrityError → AUDIT_INTEGRITY_FAILURE` upstream of the classifier, OR — for a forge the chain signature cannot catch, e.g. a mutated **unsigned** PENDING-request `content_hash` (FORGE-B) — the classifier itself omits it. The classifier admits a record only when every field it keys on is **covered by a signature** (`signing_fields` / `signoff_signing_fields`); a forged "attested" is therefore never returned when the trail is verifiable.
- **Honest discriminated output:**

  `status: "checked"`:
  ```json
  {"status": "checked", "sei": "<sei>", "attestations": [
    {"kind": "signoff_cleared",   "content_hash": "...", "recorded_at": "...", "seq": 12, "signoff_seq": 7},
    {"kind": "operator_override", "content_hash": "...", "recorded_at": "...", "seq": 19}
  ]}
  ```
  `status: "unavailable"` (trail not signature-verifiable — no protected gate / no `trail_verifier`; a no-key deployment still HAS a trail — chill overrides, unsigned procedural sign-offs — it is UNVERIFIABLE, not absent, and reading unverified records would be a false-green):
  ```json
  {"status": "unavailable", "sei": "<sei>", "attestations": [], "unavailable": [{"reason": "..."}]}
  ```

### 4.2 What counts as an attestation (decided: human-cleared only)

Only governance records that represent a **human clearance** for the SEI count — the strongest "governed-good" signal warpline can safely skip reverification on:

1. **Cleared sign-offs** — a `SIGNED_OFF` record (`extensions.signoff_state == SignoffState.SIGNED_OFF.value == "SIGNED_OFF"`, UPPERCASE — `verdict.py`) carrying a `signoff_signature` (the verified-selection marker), whose `entity_key` is the queried SEI and `identity_stable` is true. Its `content_hash` is joined from the matching `PENDING` request via the **signed** `extensions.request_seq` (the cleared record carries no loomweave content_hash of its own; the request does, at `extensions.loomweave.content_hash`). The join is **integrity-checked, not trusted** (FORGE-B): the classifier recomputes `legis.canonical.content_hash` over the FULL stored PENDING payload and requires it == the SIGNED_OFF record's signed `extensions.request_payload_hash`. `kind: "signoff_cleared"`, `seq` = the SIGNED_OFF record seq, `signoff_seq` = the request seq. Absent/empty content_hash → omit.
2. **Protected operator-overrides** — a record carrying a `judge_metadata_signature` (the verified-selection marker) with the **signed** `extensions.judge_verdict == Verdict.OVERRIDDEN_BY_OPERATOR.value` (`signing_fields["verdict"]` — FORGE-A is closed: mutating it breaks the signature and fails closed upstream), `extensions.protected_cell is True` (signed), entity == SEI with `identity_stable` true (read from the SIGNED `entity_key` dict, never the unsigned top-level `identity_stable` duplicate), and a non-empty inline `extensions.loomweave.content_hash` (signed). `kind: "operator_override"`.

**Discriminator discipline (necessary-but-not-sufficient trap):** admission keys off the **signature MARKER** (`judge_metadata_signature` / `signoff_signature`) present on the candidate, NOT the bare `judge_verdict` / `signoff_state` value — a marker-less injected record can ride through `TrailVerifier._requires_verification` UNVERIFIED, so marker presence is what proves THIS record was in the verified selection. The classifier never re-verifies signatures (the pre-gate did); it only keys off fields inside `signing_fields` / `signoff_signing_fields` and independently integrity-checks the sign-off join. Never key off `judge_advisory_verdict` or the simple-tier engine `judge_verdict` (both unsigned).

**Explicitly excluded (omitted):** chill/coached self-clear overrides, unsigned/procedural sign-offs (no `signoff_signature`), `BLOCKED` verdicts, empty content_hash, cross-SEI, `identity_stable` false — they are not proof of anything warpline should skip reverification on. WHEN IN DOUBT, OMIT. (The decision is conservative on purpose; broadening the set later is additive.)

**Shipped sound:** BOTH kinds (`operator_override`, `signoff_cleared`) shipped — each distinguishing/content field it keys on is signed (`signing_fields` protected.py / `signoff_signing_fields` signoff.py), so membership in the verified set proves the field authentic and the request-join is integrity-bound via the signed `request_payload_hash`. Neither kind is escalated/blocked. Covered by forge-negative unit tests in `tests/service/test_governance.py` and an end-to-end MCP test in `tests/mcp/test_server.py`.

## 5. Rename feed (part b, item 1) — confirm, don't rebuild

`git_rename_list` (committed renames over a rev range) and `git_rename_feed_get` (base/head + optional working-tree renames, Loomweave-ready) already ship and are unchanged. They are what warpline consumes to keep its `timeline` / `changed` stable across file moves. The only follow-up — two-way rename-parser conformance vectors — is the existing open ticket `legis-c4cbf78fdb` (G16). No code change here.

## 6. Inferred warpline contract (TO-CONFIRM)

Warpline's real wire format was not supplied. The client is built to this **inferred, shape-validated** contract; a mismatch degrades to `unavailable` (never fabricates an affected-set). When warpline ships its real shape, only the parser + one fixture change.

- `GET {base}/api/impact-radius?base=<base>&head=<head>` → object. Inferred shape: `{"affected": [{"sei": "...", "path": "...", ...}], "count": <int>, ...}`.
- `GET {base}/api/reverify-worklist?base=<base>&head=<head>` → object. Inferred shape: `{"entries": [{"sei": "...", "reason": "...", ...}], "count": <int>, ...}`.

Shape validation is **minimal and tolerant**: the client requires each response to be a JSON object (else `WarplineError`); the *fields within* are passed through verbatim to the advisory payload. This keeps Legis from coupling to warpline's evolving internal vocabulary while still refusing to present a non-object/garbage response as `checked`. **⚠️ Confirm paths + payloads with warpline before treating happy-path parsing as final.**

## 7. Honesty & error handling (the recurring bug class here)

- **No silent empties.** Both new reads discriminate `checked` from `unavailable`. An unreachable/unconfigured warpline → `unavailable` with a reason, never an empty affected-set that reads as "nothing impacted". An unwired governance trail → `unavailable`, never an empty attestations list that reads as "never attested".
- **Advisory failure is contained.** A `WarplineError` is caught in the service layer and mapped to `unavailable`; it never becomes `INTERNAL_ERROR` and never perturbs a governance read (different tool, different call).
- **Attestation reads are fail-closed.** A trail that is **not signature-verifiable** (no protected gate / no `trail_verifier` — e.g. no `LEGIS_HMAC_KEY`) → `unavailable`, reading no unverified record (NOT an empty `checked` that reads as "never attested"). When the trail IS verifiable: tamper → `AUDIT_INTEGRITY_FAILURE` via the shared `verified_records` path, and any forge the chain signature cannot catch (a mutated unsigned PENDING `content_hash`, FORGE-B) is omitted by the classifier's integrity-join. The classifier admits only signature-covered fields, so no forged attestation is returned **when the trail is verifiable**.
- **Insecure transport is opt-in.** `http` to non-loopback warpline is rejected unless `LEGIS_ALLOW_INSECURE_REMOTE_HTTP=1`, with the same warning Filigree logs.

## 8. Testing

- **`tests/service/test_preflight.py`** — `read_warpline_preflight`: checked (both methods succeed via injected fetch); unavailable when client is `None`; unavailable on `WarplineError`; unavailable on non-object payload.
- **`tests/service/test_governance.py` (extend)** — `read_sei_attestations`: cleared sign-off surfaces with joined content_hash + signoff_seq; operator override surfaces; chill/coached self-clear and `BLOCKED` are excluded; SEI filter and `identity_stable` filter; unavailable when no trail wired; `AUDIT_INTEGRITY_FAILURE` on a tampered trail.
- **`tests/warpline_preflight/test_client.py`** — URL validation (loopback ok, remote http rejected unless opt-in), response-size bound, no-redirect, non-JSON content-type → `WarplineError`, offline via injected fetch.
- **`tests/mcp/test_server.py` (extend)** — both tools dispatch end-to-end; `warpline_preflight_get` returns `unavailable` when `WARPLINE_API_URL` unset; `attestation_get` happy path + unavailable.
- **`tests/mcp/test_output_schema_conformance.py` (extend)** — outputSchema vectors for both new tools.
- **Surface/conformance** — `tests/checks/test_check_surface.py` (or the surface conformance test) tool-count + `_AGENT_TOOLS` membership.
- **Acceptance / invariant — `tests/mcp/test_warpline_advisory_boundary.py` (new):** run a representative governance path (e.g. `policy_evaluate` / an override submit / a sign-off read) with `WARPLINE_API_URL` unset and again with it set to an injected warpline that returns arbitrary impact data; assert the governance result is **byte-identical**. This is the spine of the whole change.

## 9. File manifest

**New**
- `src/legis/warpline_preflight/__init__.py`
- `src/legis/warpline_preflight/client.py` — `HttpWarplineClient`, `WarplineClient` Protocol, `WarplineError`.
- `src/legis/service/preflight.py` — `read_warpline_preflight`.
- `tests/warpline_preflight/test_client.py`
- `tests/service/test_preflight.py`
- `tests/mcp/test_warpline_advisory_boundary.py`

**Modified**
- `src/legis/mcp.py` — `McpRuntime.warpline`; `build_runtime` wiring; `warpline_preflight_get` + `attestation_get` tool definitions, handlers, `_TOOL_HANDLERS`, `_AGENT_TOOLS`; recovery hints for any new error codes.
- `src/legis/service/governance.py` — `read_sei_attestations`.
- `tests/service/test_governance.py`, `tests/mcp/test_server.py`, `tests/mcp/test_output_schema_conformance.py`, surface conformance test — extended.

## 10. Open items / future state

- **Warpline wire format** (§6) — confirm real paths + payloads; swap the inferred fixture.
- **Attestation set breadth** — human-cleared only for now; broadening to other verified records is additive if warpline asks.
- **Rename conformance vectors** — tracked separately as `legis-c4cbf78fdb` (G16).
