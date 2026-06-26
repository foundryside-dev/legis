# Roadmap — Legis            Updated: 2026-06-27 (PDR-0005, PDR-0006)

> Sequencing, WSJF / cost-of-delay, and dated forecasts are produced by
> /axiom-program-management. This file records bets as INTENT, not a delivery
> schedule. Do not compute WSJF here; hand the committed bet over for sequencing.

## Now  (committed, in-flight)
- **Governance-honesty integrity, post-gold** — keep the surface that earns the gold line _true_: close the confirmed P2 codex-security findings that let the honesty surface be bypassed. **2 of 3 done** (unverified posture tail @ eb28e4b, un-anchored protected batch @ 79b4008 — CLOSED); **remaining: unbounded policy-boundary root** · tracker: legis-0186c23a2c · metric: north-star (open governance-honesty defects → 0; now **1**)

## Recently shipped (record, not in-flight)
- **Federation interface readiness — Warpline seam** (legis-1734128d34) — advisory preflight consumer + forge-proof per-SEI attestation read · **SHIPPED in 1.2.0** (PR #17; PDR-0002/0004).
- **Warpline preflight — conform to the extant MCP envelope** (legis-a53d92507d) — replaced the phantom-HTTP seam + mis-frozen golden with an MCP-stdio client over warpline's real envelope · **shipped to local main @ 075edd0** (push / 1.3.0 publish owner-gated; PDR-0006).

## Next (shaped, decreasing certainty)
- **v2: unify keyed signing onto operator elevation sessions** — migrate protected-cell verdict + sign-off signing onto the elevation-session primitive shipped in the posture-ratchet line · tracker: legis-11b3a3dd14, legis-2d0537655d
- **Federation integration hardening (live-fire)** — run the cross-tool seams against real daemons, not stubs: real-Filigree bind/closure (G12), move-aware SEI backfill (G2), backfill failure guards (G8), two-way rename-parser conformance vectors (G16) · tracker: legis-356fe094dd, legis-bc9e5f3e60, legis-b7ce9fdc40, legis-c4cbf78fdb

## Later (directional bets, no order, no dates)
- **Additional key-custody backends** — 1Password / Vault signer backends beyond the v1 OS-keychain + age-file + env escape hatch.
- **Broader provider seams** — Clarion SEI consume seam and any further sibling fact-provider contracts as the federation grows.
- **Audit-trail retention / compaction** — the honest lever for the O(N)-per-read trail-verification cost if trail size ever becomes latency-bound.
