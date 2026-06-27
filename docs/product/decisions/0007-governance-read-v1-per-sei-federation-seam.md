# PDR-0007 — Build `governance_read.v1`: a per-SEI governance read legis publishes for warpline (cleared-only v1)

Date: 2026-06-27   Status: accepted (owner-directed: build, parallel-execute with warpline, deploy locally; PUBLISH/push owner-gated)   Author: claude (opus, product-owner)
Supersedes: —   Related: tracker legis-a0e286f5aa (follow-up); plan `docs/plans/2026-06-27-governance-read-v1-per-sei.md`; contract `contracts/governance_read.v1.schema.json`; warpline prompt `docs/contracts/warpline-governance-read.v1-prompt.md`; hub SEAM 4 / GV-LG-1; [[0003-federation-read-doctrine]]; [[0004-ratify-implement-forge-proof-attestation-classifier]]; [[0006-warpline-preflight-conform-to-extant-mcp-envelope]]

## Context
The federation maintainer asked for a per-SEI governance read so warpline's `reverify_worklist(include_federation=True)` can enrich its worklist advisorily with legis governance facts (warpline→legis direction — the inverse of the PDR-0006 warpline-preflight seam). Legis is the governance authority; warpline echoes its facts as `enrichment.governance: present|absent|unavailable` and **never gates** on them. The closest existing surface is `read_sei_attestations` (the forge-proof per-SEI read behind MCP `attestation_get`, PDR-0004); legis had no *published contract artifact* and no CLI/HTTP exposure of a per-SEI governance read.

## Options considered
1. **Greenfield governance read, new shape.** Rejected — legis already holds a forge-proof per-SEI read; a parallel implementation duplicates admission logic and adds a new forge surface.
2. **Broad scope (in-flight + uncleared governance: open sign-offs, BLOCKED verdicts).** Considered — richest context for "what must I re-verify." Rejected for v1: expands the forge surface and the shape warpline needs is enrichment-only; in-flight is a clean v2 extension.
3. **Cleared-only v1, projecting `read_sei_attestations` into a posture-record shape, published as `governance_read.v1` on CLI + MCP + HTTP.** CHOSEN.

## The call
**Option 3.** `read_governance_for_sei` is a pure projection of the forge-proof admitted set (`operator_override` → `protected_override`; `signoff_cleared` → `operator_signoff`) into the frozen `governance_read.v1` shape — fail-closed (unverifiable → discriminated `unavailable`; tampered → loud raise; verified-but-none → `checked`/`[]`), a discriminated-union schema, a frozen-golden conformance oracle, on all three transports. **Scope confirmed cleared-only by warpline** (the coordination point): warpline accepts the disclosed caveat that a BLOCKED-awaiting-signoff entity reads as `absent`, and never renders `absent` as "ungoverned." Owner approved building it, directed parallel execution with warpline, and directed the local deploy of the build to the global `legis` tool.

## Rationale
Legis is the governance authority, so it owns the contract; cleared-only is the strongest *honest* answer and a **safe subset** — a future `governance_read.v2` ADDS dispositions/kinds and leaves every v1 record valid. The projection reuses the forge-proof discriminator wholesale (no new admission path, no unsigned field), so the 1.2.0 forge-resistance invariant is inherited, not re-litigated. The advisory boundary is preserved (warpline never gates; GV-LG-1 stays asserted) — this is a **federation-seam-quality** bet, NOT a north-star governance-honesty item (it fails safe; legis governance is byte-identical with/without the consumer). Validated by a 7-agent ultracode plan review (CHANGES_REQUESTED → all 8 must-fixes folded in, including a **Critical CLI false-green**: the CLI verify path used `TrailVerifier.verify` which lacks the hash-chain contiguity walk), a serial subagent-TDD build, a final opus whole-branch review (READY_TO_MERGE), my independent gate run (1335 passed, coverage 92.39%, floors hold), and a **mutation-proof** that the chain-tamper guard is load-bearing (neutering `verify_integrity()` flipped the CLI to a `checked`/`[]` false-green; the test caught it).

## Reversal trigger
- If warpline (or any consumer) needs **in-flight / uncleared** governance context (open sign-offs, BLOCKED verdicts) → `governance_read.v2` (ADD, never mutate v1) + a new PDR. (Disclosed caveat, not a defect.)
- If the **advisory-boundary byte-identity invariant** fails (a legis verdict diverges with the read present vs absent) → reopen immediately (the guardrail).
- If the v1 read is found to **leak an unsigned field or admit a forged/non-cleared record** → reopen (forge-resistance regression; the projection's whole safety rests on reading only admitted-attestation fields).
- If warpline's `LegisClient` Protocol / `enrichment.governance` shape changes such that cleared-only no longer maps → reconcile the contract before any v1 publish.

## Status note
The **legis surface is done, verified, and deployed locally** (global `legis` tool rebuilt from local main → `governance_read` reachable on CLI+MCP). The **integration half** (warpline wires `LegisGovernanceClient`, restarts its MCP connection, flips its legis member `disabled`→`clean`) is **pending warpline's live confirmation** — G1 is legis-side-done, not integration-done. The contract is frozen **locally**; PUBLISH (push/PyPI) is owner-gated (see current-state escalation).
