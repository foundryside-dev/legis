# Metrics — Legis             Last read: 2026-07-01

> Legis is a governance-_honesty_ tool, not an engagement product. Its north-star
> is integrity of the honesty surface (no provable false-greens, no unverified
> trust on a hot path), not usage. Targets below carry a number and a date so a
> bet can be accepted or a PDR reversal trigger can fire. BASELINE/TARGET
> placeholders marked `(set)` need a real number from the owner.

## North-star
| Metric | Target (falsifiable) | Current | Read on | Trend |
|--------|----------------------|---------|---------|-------|
| Open **confirmed governance-honesty defects** (security/governance findings that let the honesty surface be bypassed or trust be trusted unverified) | = 0 by 2026-07-15 | **0 — TARGET MET, ahead of the 2026-07-15 deadline.** legis-0186c23a2c (the last confirmed P2 finding) fixed + shipped in **1.4.0** (`assert_within_boundary` containment; tracker closed 2026-07-01). ⚠ **The post-gold governance-honesty bet has hit its success criterion — the successor Now bet is the next `DECIDE`** (see current-state). | 2026-07-01 | ↓ 1→0 |

> Note (2026-06-26): closing legis-476ab6f125 surfaced two P3 follow-ups — legis-fcd59caa67 (ungated sibling reads `epoch_reset_unacknowledged` et al.) and legis-dfdeade118 (doctor `None`-cause diagnostic). These are NOT in the P2 north-star denominator (lower severity, partially mitigated / not a false-green) but are tracked so the closure is honest, not net-zero theatre.

## Input metrics (the levers that move the north-star)
| Metric | Target | Current | Read on |
|--------|--------|---------|---------|
| Confirmed P2 security findings remaining open | 0 by 2026-07-15 | **0** (legis-0186c23a2c shipped in 1.4.0) | 2026-07-01 |
| Median time-to-close on a confirmed security finding | ≤ 14 days (owner-set 2026-06-25) | ~6 days median (3 samples: legis-476ab6f125, -0c310712a7, -0186c23a2c [filed 06-20 → shipped 1.4.0 06-29, ~9d]); all within target | 2026-07-01 |

## Guardrails (must NOT degrade)
| Metric | Floor / ceiling | Current | Read on |
|--------|-----------------|---------|---------|
| **Advisory-boundary invariant** — governance verdicts byte-identical with a sibling absent vs present | must hold (binary) | **holds — re-proven ×2 this session.** (a) `governance_read.v1` (PDR-0007) is a read with no enforcement path; its 3 service fns pinned non-verdict-path in `test_warpline_advisory_boundary.py`; warpline never gates (GV-LG-1). (b) The Plainweave consumer (PDR-0008) carries its own byte-identity + structural + GV-LG-3 tests. **Re-confirmed clean across the whole consolidation by the 1.4.0 release review (6-area, GO).** | 2026-07-01 |
| **New-federation-surface false-green resistance** — a new governance read never reads tamper/absence as a pass | must hold (binary) | **holds — MUTATION-PROVEN.** Neutering `verify_integrity()` in the `governance-read` CLI flipped a chain-tampered store to `{status:checked, records:[]}` exit 0 (the exact false-green); the regression test caught it. Both verify halves (chain + signatures) run on all 3 transports; tamper fails loud (HTTP 500 / MCP AUDIT_INTEGRITY_FAILURE / CLI nonzero). **The 1.4.0 review's cardinal-sin sweep found no new false-green across governance_read / policy_boundary_check / posture / protected.** | 2026-07-01 |
| CI green (tests + mypy) | 100% | **1.4.0 shipped green** — `main` @ 3055d2c: pytest **1389 passed** / 9 skipped, mypy clean, ruff clean, coverage 92.5%, all per-package floors hold, governance-gate/policy-boundary/SEI-oracle pass; `release.yml` re-ran the whole battery before the PyPI publish | 2026-07-01 |
| **Attestation classifier forge-resistance** — `attestation_get` admits no forged / non-human-cleared record | must hold (binary) | **holds** — adversarial forge phase (4 lenses, live-run probes) admitted **0** forges; admission gates on the signature marker + keys only on signed fields + integrity-bound sign-off join (PDR-0004) | 2026-06-25 |
| Release publish gated on **live Loomweave SEI conformance** | skip-not-fail in remote CI (owner Path B, 2026-06-25); gates publish only when `LOOMWEAVE_URL` is set | **CONFIRMED LIVE in the 1.4.0 publish** — the `live-loomweave-conformance` job ran skip-not-fail as a no-op (oracle unconfigured) and the PyPI publish proceeded: no false block, no false publish | 2026-07-01 |
| Test coverage vs configured floors (`scripts/check_coverage_floors.py`) | ≥ floors | **92.5% total** (floor 88); all per-package floors hold, incl. a **new `crypto/` floor 93%** (actual 100%) added with the H-1 signing-leaf move to preserve the protection it had under `enforcement`'s floor — read at 1.4.0 (3055d2c) | 2026-07-01 |
