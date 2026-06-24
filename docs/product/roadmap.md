# Roadmap — Legis            Updated: 2026-06-24 (PDR-0001)

> Sequencing, WSJF / cost-of-delay, and dated forecasts are produced by
> /axiom-program-management. This file records bets as INTENT, not a delivery
> schedule. Do not compute WSJF here; hand the committed bet over for sequencing.

## Now  (committed, in-flight)
- **Governance-honesty integrity, post-gold** — keep the surface that earns the gold line _true_: close the confirmed P2 codex-security findings that let the honesty surface be bypassed (unverified posture tail, un-anchored protected batch, unbounded policy-boundary root) · tracker: legis-476ab6f125, legis-0c310712a7, legis-0186c23a2c · metric: north-star (open governance-honesty defects → 0)
- **Federation interface readiness — Warpline seam** — publish the advisory preflight consumer + per-SEI attestation read warpline requested, without ever letting advisory context reach a verdict · tracker: legis-1734128d34 · metric: guardrail (advisory-boundary invariant holds)

## Next (shaped, decreasing certainty)
- **v2: unify keyed signing onto operator elevation sessions** — migrate protected-cell verdict + sign-off signing onto the elevation-session primitive shipped in the posture-ratchet line · tracker: legis-11b3a3dd14, legis-2d0537655d
- **Federation integration hardening (live-fire)** — run the cross-tool seams against real daemons, not stubs: real-Filigree bind/closure (G12), move-aware SEI backfill (G2), backfill failure guards (G8), two-way rename-parser conformance vectors (G16) · tracker: legis-356fe094dd, legis-bc9e5f3e60, legis-b7ce9fdc40, legis-c4cbf78fdb

## Later (directional bets, no order, no dates)
- **Additional key-custody backends** — 1Password / Vault signer backends beyond the v1 OS-keychain + age-file + env escape hatch.
- **Broader provider seams** — Clarion SEI consume seam and any further sibling fact-provider contracts as the federation grows.
- **Audit-trail retention / compaction** — the honest lever for the O(N)-per-read trail-verification cost if trail size ever becomes latency-bound.
