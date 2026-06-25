# Metrics — Legis             Last read: 2026-06-25

> Legis is a governance-_honesty_ tool, not an engagement product. Its north-star
> is integrity of the honesty surface (no provable false-greens, no unverified
> trust on a hot path), not usage. Targets below carry a number and a date so a
> bet can be accepted or a PDR reversal trigger can fire. BASELINE/TARGET
> placeholders marked `(set)` need a real number from the owner.

## North-star
| Metric | Target (falsifiable) | Current | Read on | Trend |
|--------|----------------------|---------|---------|-------|
| Open **confirmed governance-honesty defects** (security/governance findings that let the honesty surface be bypassed or trust be trusted unverified) | = 0 by 2026-07-15 | 3 (legis-476ab6f125, -0c310712a7, -0186c23a2c) | 2026-06-24 | → |

## Input metrics (the levers that move the north-star)
| Metric | Target | Current | Read on |
|--------|--------|---------|---------|
| Confirmed P2 security findings remaining open | 0 by 2026-07-15 | 3 | 2026-06-24 |
| Median time-to-close on a confirmed security finding | ≤ 14 days `(set)` | unmeasured | 2026-06-24 |

## Guardrails (must NOT degrade)
| Metric | Floor / ceiling | Current | Read on |
|--------|-----------------|---------|---------|
| **Advisory-boundary invariant** — governance verdicts byte-identical with a sibling (Warpline) absent vs present | must hold (binary) | **holds — proven** by `tests/mcp/test_warpline_advisory_boundary.py` (byte-identical on real verdicts) + a derived structural guard over all tool handlers; warpline consumed only in its sibling tool | 2026-06-25 |
| CI green (tests + mypy) | 100% | `warpline-interfaces` branch (Tasks 1–8 complete): pytest 1237 passed, mypy clean (78 files), coverage 92.13% — CI-equivalent gate run locally; `main` green at 1.1.1 | 2026-06-25 |
| **Attestation classifier forge-resistance** — `attestation_get` admits no forged / non-human-cleared record | must hold (binary) | **holds** — adversarial forge phase (4 lenses, live-run probes) admitted **0** forges; admission gates on the signature marker + keys only on signed fields + integrity-bound sign-off join (PDR-0004) | 2026-06-25 |
| Release publish gated on **live Loomweave SEI conformance** | must pass before any PyPI publish | gate in place (PR #8 line) | 2026-06-24 |
| Test coverage vs configured floors (`scripts/check_coverage_floors.py`) | ≥ floors | **92.14% total** (floor 88); all per-package floors hold (mcp.py 92.4%, service/ 95.0%) — read on `warpline-interfaces` | 2026-06-25 |
