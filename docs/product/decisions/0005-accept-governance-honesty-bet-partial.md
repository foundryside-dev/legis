# PDR-0005 — Accept the governance-honesty bet (partial): 2 of 3 P2 findings closed; north-star 3 → 1

Date: 2026-06-27   Status: accepted (within grant; merges local-only, push/publish owner-gated)   Author: claude (opus, product-owner)
Supersedes: —   Related: PRD-0005; tracker legis-476ab6f125, legis-0c310712a7, legis-0186c23a2c; plans `docs/plans/2026-06-26-posture-read-floor-verify-integrity.md`, `docs/plans/2026-06-26-protected-batch-headanchor-transaction.md`

## Context
PRD-0005 (the Now bet) is the north-star: open governance-honesty defects → 0 by 2026-07-15, over three codex-confirmed P2 findings. This session executed the first two against a governance-honesty surface whose cardinal sin is a false-green.

## Options considered
1. Plan → execute each finding directly (single-pass).
2. Plan → multi-agent adversarial review → revise → re-review → subagent-driven TDD (fresh implementer + spec/quality review per task) → final whole-branch review → accept. Higher assurance.
3. Defer to a later session.

## The call
Option 2, for both findings.
- **legis-476ab6f125** (unverified posture tail): `read_floor()` now gates on `verify_integrity()` and fails closed to `None`→`structured`; the recomputed-chain forgery is pinned as the conceded raw-file-write residual (README.md:137), not implied-closed. **Closed @ main eb28e4b.** The round-1 review caught two real defects in the plan before any code: a test the gate breaks (whose mis-prescribed remedy could have nudged an implementer to *weaken the gate*), and a false "doctor backstops this residual" docstring claim. Both fixed pre-execution.
- **legis-0c310712a7** (un-anchored protected batch): `ProtectedGate.transaction()` (a verbatim `SignoffGate.transaction()` mirror) advances the HeadAnchor after commit; doubly-latent/preventive (production wires `anchor=None` and no caller batches protected appends today). **Closed @ main 79b4008.** Review APPROVED_WITH_WARNINGS; clean execution.

North-star **3 → 1**. legis-0186c23a2c (unbounded policy-boundary root) remains. Two P3 follow-ups filed so the closures are honest, not net-zero: legis-fcd59caa67 (ungated sibling reads `epoch_reset_unacknowledged` et al.) and legis-dfdeade118 (doctor `None`-cause diagnostic).

## Rationale
The adversarial review caught two false-green-adjacent defects on read_floor *before code was written* — exactly the failure mode the honesty surface exists to prevent — validating the heavier method for this bet. Both fixes preserve fail-closed and pass every CI gate (mypy/ruff/coverage floors/governance-gate/policy-boundary/SEI oracle). Median time-to-close = 6 days (within the owner-set ≤14).

## Reversal trigger
- If legis-476ab6f125 or legis-0c310712a7 **reopens** (a regression or a missed bypass) → reopen + a PDR-0001 reversal-trigger review.
- If **2026-07-15 passes with legis-0186c23a2c still open** → the north-star date target is missed → PDR-0001 reversal review (re-date or re-scope).
- If a **new confirmed governance-honesty bypass lands before 2026-07-15** → the north-star denominator grows → re-assess the date (PRD-0005 open-question).
