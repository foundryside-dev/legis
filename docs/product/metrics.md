# Metrics — Legis             Last read: 2026-06-27

> Legis is a governance-_honesty_ tool, not an engagement product. Its north-star
> is integrity of the honesty surface (no provable false-greens, no unverified
> trust on a hot path), not usage. Targets below carry a number and a date so a
> bet can be accepted or a PDR reversal trigger can fire. BASELINE/TARGET
> placeholders marked `(set)` need a real number from the owner.

## North-star
| Metric | Target (falsifiable) | Current | Read on | Trend |
|--------|----------------------|---------|---------|-------|
| Open **confirmed governance-honesty defects** (security/governance findings that let the honesty surface be bypassed or trust be trusted unverified) | = 0 by 2026-07-15 | 1 (legis-0186c23a2c; legis-476ab6f125 @ main eb28e4b + -0c310712a7 @ main 79b4008 CLOSED) | 2026-06-26 | ↓ |

> Note (2026-06-26): closing legis-476ab6f125 surfaced two P3 follow-ups — legis-fcd59caa67 (ungated sibling reads `epoch_reset_unacknowledged` et al.) and legis-dfdeade118 (doctor `None`-cause diagnostic). These are NOT in the P2 north-star denominator (lower severity, partially mitigated / not a false-green) but are tracked so the closure is honest, not net-zero theatre.

## Input metrics (the levers that move the north-star)
| Metric | Target | Current | Read on |
|--------|--------|---------|---------|
| Confirmed P2 security findings remaining open | 0 by 2026-07-15 | 1 | 2026-06-26 |
| Median time-to-close on a confirmed security finding | ≤ 14 days (owner-set 2026-06-25) | 6 days (2 samples: legis-476ab6f125, -0c310712a7; both 2026-06-20→06-26) | 2026-06-26 |

## Guardrails (must NOT degrade)
| Metric | Floor / ceiling | Current | Read on |
|--------|-----------------|---------|---------|
| **Advisory-boundary invariant** — governance verdicts byte-identical with a sibling (Warpline) absent vs present | must hold (binary) | **holds — re-proven** after the warpline-preflight MCP-transport rewrite (legis-a53d92507d): `tests/mcp/test_warpline_advisory_boundary.py` byte-identity + the derived structural guard over all tool handlers both green; warpline consumed only in its sibling tool | 2026-06-27 |
| CI green (tests + mypy) | 100% | **`main` @ 075edd0 green** — pytest 1282+ passed, mypy clean (78 files), coverage 92.25%, ruff clean, governance-gate/policy-boundary/SEI-oracle pass (CI-equivalent run locally; 3 fixes merged this session) | 2026-06-27 |
| **Attestation classifier forge-resistance** — `attestation_get` admits no forged / non-human-cleared record | must hold (binary) | **holds** — adversarial forge phase (4 lenses, live-run probes) admitted **0** forges; admission gates on the signature marker + keys only on signed fields + integrity-bound sign-off join (PDR-0004) | 2026-06-25 |
| Release publish gated on **live Loomweave SEI conformance** | skip-not-fail in remote CI (owner Path B, 2026-06-25); gates publish only when `LOOMWEAVE_URL` is set | **skip-not-fail** restored (PR #18/#19) — not a hard publish blocker absent a live Loomweave; the gate fires only when `LOOMWEAVE_URL` is configured | 2026-06-27 |
| Test coverage vs configured floors (`scripts/check_coverage_floors.py`) | ≥ floors | **92.25% total** (floor 88); all 8 per-package floors hold (+ a new `warpline_preflight` floor 88, actual 91.9%) — read on `main` @ 075edd0 | 2026-06-27 |
