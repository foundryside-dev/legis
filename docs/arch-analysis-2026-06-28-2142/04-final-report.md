# 04 — Final Report

**Subject:** Legis — git/CI + governance layer of the Weft suite
**Checkout:** `fix/policy-boundary-containment` off `main` `25d64e2` (~16,585 LOC, ~78 files, 8 reviewer clusters)
**Deliverable tier:** Architect-Ready (C). Inputs: `01-discovery-findings.md`, `02-subsystem-catalog.md`, `temp/validation-catalog.md` (PASS_WITH_NOTES).

## Executive summary
Legis is a **governance-honesty** tool whose architecture is unusually faithful to its stated design. The "single source of governance truth in `service/`, with three thin transport adapters over it" claim is **real and measured**: HTTP/MCP/CLI all import `service/` (15/6/2 references) and translate `ServiceError` subclasses into their own shapes rather than re-deciding governance. The fail-closed ethos is implemented at the seams that matter — the cell-routing composition root defaults to `structured` (escalate) when unconfigured, sign-off binding refuses locator (non-SEI) keys and surfaces split-state via `verify()`, and the audit chain is HMAC-signed with v3 chain-position binding. Across 8 independent reviewers, **no live false-green or fail-open path was found**; every honesty-relevant residual is documented and fails closed (detectable), or is already tracked.

The architecture's weaknesses are **structural, not correctness**: two god-modules (`mcp.py` 2748 LOC, `install.py` 1503 LOC), a small set of coupling edges that invert the intended layering (`store↔enforcement`, `policy→service`, `posture→install`, `api→mcp`), and a few public-surface/robustness loose ends (incomplete `service` `__all__`, no sign-off reconciliation tool, keychain custody adapter still a stub). These are maintainability and evolvability risks, addressable incrementally without touching governance correctness.

## What the system does (recap)
Records and enforces, at the git/CI boundary, *what changed and whether a human authorized it for the code as it stands now*. Governance is graded through a 2×2 of structure (simple/complex) × inline LLM judge (off/on) → **chill / coached / structured / protected**, with HMAC-signed verdicts, operator sign-off, override-rate gating, and an append-only audit chain in the top cell. SEI (from Loomweave) keys attestations so they survive rename/move; siblings (Wardline, Filigree, Warpline) are separate authorities consumed across explicit federation seams.

## Architecture shape
- **Hub-and-adapters.** `service/` is the orchestration hub (→ enforcement, policy, identity, governance, wardline, warpline_preflight, canonical). Transports sit above; domain subsystems beside/below; a leaf layer (`canonical`, `clock`, `weft_signing`, `provenance`, `config`, `records`) underneath.
- **Persistence as evidence.** Five SQLite stores under `.weft/legis/`, append-only and HMAC-signed; relocation only via explicit `LEGIS_*_DB` (a repo `weft.toml` deliberately cannot redirect stores — a custody decision).
- **Federation as bounded authority.** Each sibling seam is read/advisory with a hard rule that an advisory consumer (Warpline preflight) never enters a verdict path; Wardline findings are routed but never re-adjudicated ("Wardline analyses, Legis governs").

## Strengths (evidence-backed)
1. **Adapter discipline holds.** No reviewer found a governance decision duplicated in an adapter; adapters only map `ServiceError` → shape. The one private cross-adapter import (`api`→`mcp._load_policy_cell_registry`) is a known helper-placement nit (Q-H2), not a decision leak.
2. **Fail-closed at the composition root.** Unconfigured cell routing → `structured`; chill requires explicit `LEGIS_DEV_DEFAULT_CELLS=1` (mcp.py:194-200).
3. **Honest residuals.** The raw-DB-write tamper class, the sign-off split-state window, and the keychain stub are all documented and fail closed / detectable — they do not masquerade as green.
4. **Self-hosted honesty gate.** The `@policy_boundary` decorator + boundary scanner enforce governance-honesty over Legis's own source in CI, and never report a vacuous PASS on zero scope.

## Concerns (validated; full detail in `05-quality-assessment.md`)
After validation, **four high-severity-sounding reviewer concerns were reclassified** (none is a live gap): posture `read_floor` non-gating is a `main`-checkout artifact (fixed on the unmerged release line); the keychain stub is deliberate fail-closed future-work; the chill cell default is fenced behind a dev env var; the sign-off partial-write is a documented fail-closed trade-off. The surviving real themes are **god-module size**, **coupling inversions**, **public-surface completeness**, and **robustness/ops future-work**.

## Confidence & limitations
- **High** on structure, dependency direction, adapter discipline, and the fail-closed seams (directly measured / read in full by reviewers).
- **Medium** on exhaustive per-tool behavior of `mcp.py` (sampled at structural seams, not all 23 tools line-by-line).
- **Scope:** `governance_read.v1` and `plainweave_preflight/` contents are release-only (PR #21) and were not analyzed from source; the posture `read_floor` gate is likewise release-only. A re-run against the post-PR-#21 `main` would close these.
