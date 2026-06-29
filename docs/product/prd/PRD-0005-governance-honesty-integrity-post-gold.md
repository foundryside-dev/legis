# PRD-0005 — Governance-honesty integrity, post-gold            Status: ready-for-planning
Decision: PDR-0001 (north-star established this as the Now bet; the three items are codex-confirmed P2 defects, so the is-it-worth-solving call is moot — proven bugs against the gold honesty guarantee)   Bet (roadmap.md): Now   Target metric (metrics.md): Open confirmed governance-honesty defects

## Problem
**Who:** the governed agents and human operators who rely on Legis's posture floor, protected-cell audit chain, and policy-boundary scan being *true*, plus the sibling tools (Warpline) about to consume its attestations. **Their pain:** three confirmed code paths let the honesty guarantee be bypassed — (1) the posture hot-read trusts an *unverified* ledger tail, so a raw-DB writer can force `floor="chill"` and the routing path believes it; (2) protected records committed inside an external batch leave the HeadAnchor at the pre-batch head, so truncation back to a stale anchor goes undetected; (3) `policy_boundary_check` scans attacker-supplied absolute roots *outside* the source boundary, leaking arbitrary tree contents/parse results. **Desired outcome:** each path authenticates its input or fails closed — the surface returns to Legis's defining property, "no provable false-green; an unauthorized change is always *detectable*." **Why now:** 1.2.0 just shipped; these are the *only* confirmed open defects against the gold-line honesty guarantee, and the north-star (open governance-honesty defects → 0) is gated entirely on them.

## Success metric (the signal the bet paid off)
**Open confirmed governance-honesty defects** (metrics.md north-star): **BASELINE 3** (read 2026-06-24) → **TARGET 0**, by **2026-07-15**. Falsification: >0 confirmed honesty-bypass defects still open on 2026-07-15 → the bet missed.

## Acceptance criteria (falsifiable)
1. **SUCCESS — legis-476ab6f125 (unverified posture tail) closed.** The hot keyless `read_floor()` verifies chain integrity (`verify_integrity()`) + tail-kind discipline and **fails closed** (returns `None` → `structured`) when integrity cannot be proven. Cryptographic `operator_sig` verification under the epoch key stays the operator-side `doctor` check — it needs the operator key the routing read deliberately must not hold (matching the existing keyless-read / key-holding-doctor split). A regression test that appends a raw-DB tail record `floor="chill"` **whose chain does not verify** shows the read fails closed (red before the fix, green after); a second test **documents** that a forgery which *recomputes* the keyless chain is the conceded raw-file-write residual (README §Known security limitations, README.md:137) — made visible in the suite, never silently implied-closed. Merged to main, CI green, by 2026-07-15.
   *Reject branch:* `read_floor()` still returns a floor from an integrity-broken ledger → finding stays open, criterion unmet.
2. **SUCCESS — legis-0c310712a7 (un-anchored protected batch) closed.** A protected record committed inside an external `AuditStore.transaction()` advances the HeadAnchor after commit (or an owned protected-gate transaction API does). A regression test that batches a protected append then truncates to the pre-batch anchor shows truncation is **detected**. Merged, CI green, by 2026-07-15.
   *Reject branch:* anchor still stale post-batch → unmet.
3. **SUCCESS — legis-0186c23a2c (unbounded policy-boundary root) closed.** `policy_boundary_check` normalizes roots and requires containment inside the configured source/repo boundary. A regression test passing an absolute root outside the boundary shows the scan is **refused** (not walked). Merged, CI green, by 2026-07-15.
   *Reject branch:* out-of-boundary root still scanned → unmet.
4. **SUCCESS (aggregate) — north-star reads 0.** The metrics.md north-star reads **0** open confirmed governance-honesty defects on 2026-07-15.
   *Reject branch:* >0 → bet rejected; open a follow-up PDR on the remainder.
5. **GUARDRAIL — no false-green / fail-closed preserved.** For each of the three paths, an adversarial test proves that absent / empty / malformed / unverifiable input resolves to **BLOCKED / fail-closed / refused — never a pass**.
   *Reject branch:* any path reads an absent/unverifiable input as a pass → bet rejected even if 1–4 pass (the cardinal sin).
6. **GUARDRAIL — the 1.2.0 invariants stay green.** The advisory-boundary byte-identity test (`tests/mcp/test_warpline_advisory_boundary.py` + the derived structural handler guard) and the attestation forge-resistance test pass unchanged over the same window.
   *Reject branch:* either regresses → bet rejected.
7. **GUARDRAIL — gates hold.** Coverage floors (global ≥88; `service/` ≥95; `mcp.py` ≥~92 via `scripts/check_coverage_floors.py`) and all CI gates (pytest, mypy, ruff E4/E7/E9/F, SEI oracle, `legis policy-boundary-check`, `legis governance-gate`) are green on the merge.
   *Reject branch:* any gate red → not acceptable.

## Non-goals (this bet)
- **Re-architecting** the posture, protected-cell, or policy subsystems — fix the bypass *in place*; structural rework is a separate bet.
- **Changing any federation contract** (SEI consume, git-rename provider, Filigree sign-off binding, Wardline routing, Warpline preflight/attestation) — those escalate to the owner.
- **New MCP tools** or surface additions; this bet hardens existing paths only.
- Making Legis **tamper-*proof*** — the conceded residual threats already in the README "Known security limitations" (raw-DB-write deletion/truncation beyond the opt-in mitigation) are out of scope; the honest claim stays "detectable," not "impossible."

## Constraints & guardrails
- **Fail-closed is the contract:** every decision path must resolve an absent/empty/malformed/unverifiable input to BLOCKED/unavailable/refused, never to a pass (CLAUDE.md cardinal-sin rule).
- **Keys stay out of agent reach:** no fix may move governance state into editable TOML or caller-controlled fields.
- **`canonical.py` stays `ensure_ascii=False`** (byte-for-byte HMAC contract with Wardline) — no fix touches the signing canonicalization.
- **Cadence guardrail (metrics.md input metric):** median time-to-close on a confirmed security finding ≤ 14 days (owner-set 2026-06-25). A process bound, not a headline acceptance bar.

## Open questions / assumptions
- **Assumes the three findings remain independent** (no shared fix surface). If closing one perturbs another's path (e.g., a shared store-transaction wrapper used by both posture and protected), sequencing changes — flag at planning.
- **Assumes "confirmed governance-honesty defect" = the codex-confirmed P2 set.** If a new honesty-bypass finding lands before 2026-07-15, the north-star denominator grows and the date target may need a PDR-0001 reversal-trigger review.
- **Assumes regression tests can simulate** the raw-DB-tail / stale-anchor / out-of-boundary attacker at unit level (per `tests/conftest.py` store isolation, no live keychain). If any proof requires the OS keychain it self-skips and drops to integration — name it in the plan.

## Handoff
- **Top item → /axiom-planning:** **legis-476ab6f125** (unverified posture tail) — the most direct false-green on a hot read path; becomes the first executable, codebase-validated implementation plan.
- **Solution shape → /axiom-solution-architect:** the authenticate-vs-fail-closed *mechanism* per finding (e.g., does the posture read verify the full chain or a signed tail-anchor; does protected get an owned transaction API or an after-commit hook). The PRD names the boundary; the design picks the mechanism.
- **Sequencing / forecast → /axiom-program-management:** the three findings as a sequenced set against the 2026-07-15 north-star date; this PRD emits no dated commitment.
- **Tracker IDs:** legis-476ab6f125, legis-0c310712a7, legis-0186c23a2c.
