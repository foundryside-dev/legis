# PDR-0002 — Accept the warpline interfaces bet (Tasks 1–7); defer the attestation classifier (Task 8) as BLOCKED

Date: 2026-06-25   Status: accepted (build/accept within grant; MERGE is owner-gated — see flags)   Author: claude (opus, product-owner)
Supersedes: —   Related: [[0003-federation-read-doctrine]]; tracker legis-1734128d34; spec `docs/superpowers/specs/2026-06-24-legis-warpline-interfaces-design.md`; plan `docs/superpowers/plans/2026-06-24-legis-warpline-interfaces-plan.md`

## Context
Warpline (Weft sibling; impact-radius / reverify-worklist analysis) requested two Legis interfaces: an advisory preflight consumer and a per-SEI attestation read (governance-as-verification, Rung 2). This was the Now federation-seam bet (legis-1734128d34). Load-bearing constraint: governance verdicts must be **byte-identical** whether warpline is present or absent; Legis stays the **only** governance/attestation authority.

## Options considered
1. Build the whole feature including the attestation classifier in one pass.
2. Build the advisory boundary + the attestation **fail-closed scaffolding**, and DEFER the positive-admission classifier pending owner ratification of a forge-proof discriminator.
3. Don't build / defer the whole bet.

## The call
Option 2. Built Tasks 1–7 via subagent-driven TDD from a grounded, adversarially-reviewed plan: the stdlib `HttpWarplineClient`, `warpline_preflight_get` (advisory), `attestation_get` fail-closed scaffolding, the byte-identical advisory-boundary acceptance spine, and a derived structural guard over all tool handlers. The positive-admission classifier (Task 8) is **BLOCKED** and ships an honest `unavailable` (no false-green) because grounding proved the obvious operator-override discriminator is **forgeable** (the chill engine writes caller `extensions` verbatim) — shipping it unratified risks a false-"attested" → warpline skips reverify on un-cleared code (a security hole). Accepted on all CI-equivalent gates green (pytest 1225 passed, mypy clean, coverage 92.14% ≥88% floor, ruff) + a whole-branch review.

## Rationale
The advisory boundary is the whole point of the bet and is now proven (structural + behavioral byte-identity), not asserted. The classifier is the single piece that can introduce a false-green on the honesty surface, and its safe discriminator is a **spec-level security decision** that requires the owner. Deferring it (fail-closed, surfaces nothing) is honest and reversible; guessing it is a one-way security risk. Two review-caught defects — a stale structural guard and a false-green BLOCKED stub (`checked: []` in wired deployments) — were found and fixed before merge.

## Reversal trigger
- If the byte-identical advisory-boundary invariant ever fails (a governance verdict diverges with warpline present vs absent) → **reopen immediately**; that invariant is the guardrail (metrics.md).
- If the owner ratifies the four Task-8 classifier questions → Task 8 unblocks as a **new** decision (new PDR), flipping `attestation_get` from `unavailable` to real attestations.
- If warpline's real wire format contradicts the inferred §6 parser → the client's URL/parse layer reopens (isolated; degrades to `unavailable` until then).
