# Metrics — Legis             Last read: 2026-06-28

> Legis is a governance-_honesty_ tool, not an engagement product. Its north-star
> is integrity of the honesty surface (no provable false-greens, no unverified
> trust on a hot path), not usage. Targets below carry a number and a date so a
> bet can be accepted or a PDR reversal trigger can fire. BASELINE/TARGET
> placeholders marked `(set)` need a real number from the owner.

## North-star
| Metric | Target (falsifiable) | Current | Read on | Trend |
|--------|----------------------|---------|---------|-------|
| Open **confirmed governance-honesty defects** (security/governance findings that let the honesty surface be bypassed or trust be trusted unverified) | = 0 by 2026-07-15 | **1, unchanged** (legis-0186c23a2c) — this session's federation work (PDR-0007 governance_read.v1, PDR-0008 Plainweave consumer) is seam-QUALITY, NOT P2 findings, so it does not move the denominator | 2026-06-28 | → |

> Note (2026-06-26): closing legis-476ab6f125 surfaced two P3 follow-ups — legis-fcd59caa67 (ungated sibling reads `epoch_reset_unacknowledged` et al.) and legis-dfdeade118 (doctor `None`-cause diagnostic). These are NOT in the P2 north-star denominator (lower severity, partially mitigated / not a false-green) but are tracked so the closure is honest, not net-zero theatre.

## Input metrics (the levers that move the north-star)
| Metric | Target | Current | Read on |
|--------|--------|---------|---------|
| Confirmed P2 security findings remaining open | 0 by 2026-07-15 | 1 | 2026-06-26 |
| Median time-to-close on a confirmed security finding | ≤ 14 days (owner-set 2026-06-25) | 6 days (2 samples: legis-476ab6f125, -0c310712a7; both 2026-06-20→06-26) | 2026-06-26 |

## Guardrails (must NOT degrade)
| Metric | Floor / ceiling | Current | Read on |
|--------|-----------------|---------|---------|
| **Advisory-boundary invariant** — governance verdicts byte-identical with a sibling absent vs present | must hold (binary) | **holds — re-proven ×2 this session.** (a) `governance_read.v1` (PDR-0007) is a read with no enforcement path; its 3 service fns pinned non-verdict-path in `test_warpline_advisory_boundary.py`; warpline never gates (GV-LG-1). (b) The Plainweave consumer (PDR-0008) carries its own byte-identity + structural + GV-LG-3 tests. | 2026-06-28 |
| **New-federation-surface false-green resistance** — a new governance read never reads tamper/absence as a pass | must hold (binary) | **holds — MUTATION-PROVEN.** Neutering `verify_integrity()` in the `governance-read` CLI flipped a chain-tampered store to `{status:checked, records:[]}` exit 0 (the exact false-green); the regression test caught it. Both verify halves (chain + signatures) run on all 3 transports; tamper fails loud (HTTP 500 / MCP AUDIT_INTEGRITY_FAILURE / CLI nonzero). | 2026-06-28 |
| CI green (tests + mypy) | 100% | **`main` @ 27f12da green** — pytest **1377 passed** at HEAD (governance_read build independently verified at 1335 @ 395d7fc; Plainweave added ~42), mypy clean, ruff clean, coverage 92.39%+, all per-package floors hold (+ new `plainweave_preflight` 96.6%), governance-gate/policy-boundary/SEI-oracle pass | 2026-06-28 |
| **Attestation classifier forge-resistance** — `attestation_get` admits no forged / non-human-cleared record | must hold (binary) | **holds** — adversarial forge phase (4 lenses, live-run probes) admitted **0** forges; admission gates on the signature marker + keys only on signed fields + integrity-bound sign-off join (PDR-0004) | 2026-06-25 |
| Release publish gated on **live Loomweave SEI conformance** | skip-not-fail in remote CI (owner Path B, 2026-06-25); gates publish only when `LOOMWEAVE_URL` is set | **skip-not-fail** restored (PR #18/#19) — not a hard publish blocker absent a live Loomweave; the gate fires only when `LOOMWEAVE_URL` is configured | 2026-06-27 |
| Test coverage vs configured floors (`scripts/check_coverage_floors.py`) | ≥ floors | **92.25% total** (floor 88); all 8 per-package floors hold (+ a new `warpline_preflight` floor 88, actual 91.9%) — read on `main` @ 075edd0 | 2026-06-27 |
