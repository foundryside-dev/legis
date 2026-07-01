# Roadmap — Legis            Updated: 2026-07-01 (PDR-0009, PDR-0010)

> Sequencing, WSJF / cost-of-delay, and dated forecasts are produced by
> /axiom-program-management. This file records bets as INTENT, not a delivery
> schedule. Do not compute WSJF here; hand the committed bet over for sequencing.

## Now  (committed, in-flight)
- **— open —** The post-gold governance-honesty bet is **WON**: all 3 confirmed P2 findings closed (the last, legis-0186c23a2c, shipped in 1.4.0), **north-star = 0**, met ahead of the 2026-07-15 target. No successor Now bet has been decided — that is the next `DECIDE`. Promotion candidates sit in **Next** (v2 keyed-signing unification; federation integration hardening). See `current-state.md` open questions.

## Recently shipped (record, not in-flight)
- **legis 1.4.0 — SHIPPED to PyPI** (PDR-0009, PDR-0010; tag `v1.4.0` @ 3055d2c) — one consolidated minor: `governance_read.v1` + the Plainweave consumer + the warpline MCP rewire + the posture/protected honesty hardenings + the **H-1…H-4 layering decouple** (signing → dependency-free `crypto/` leaf, `posture/errors.py`, `policy.cells` loader) + the **`policy_boundary_check` containment security fix** (closed the last north-star finding) + a **starlette** security bump. Owner-authorized publish; passed a 6-area adversarial release review (GO).
- **`governance_read.v1` — per-SEI governance read legis publishes for warpline** (PDR-0007) — cleared-only v1 on CLI+MCP+HTTP; warpline consumes advisorily (never gates). **PUBLISHED in 1.4.0** (the v1 contract is now publicly frozen); legis-side done, **integration pending warpline's live handshake** · tracker: legis-9a47068338, legis-a0e286f5aa (follow-up).
- **Plainweave preflight — advisory consumer** (PDR-0008) — legis reads Plainweave's `weft.plainweave.preflight_facts.v1` producer enrich-only; first sibling consumer. **Published in 1.4.0.** Live e2e capture is a flagged follow-up.
- **Federation interface readiness — Warpline seam** (legis-1734128d34) — advisory preflight consumer + forge-proof per-SEI attestation read · **SHIPPED in 1.2.0** (PR #17; PDR-0002/0004).
- **Warpline preflight — conform to the extant MCP envelope** (legis-a53d92507d) — replaced the phantom-HTTP seam + mis-frozen golden with an MCP-stdio client over warpline's real envelope · **shipped to local main @ 075edd0** (push / 1.3.0 publish owner-gated; PDR-0006).

## Next (shaped, decreasing certainty)
- **v2: unify keyed signing onto operator elevation sessions** — migrate protected-cell verdict + sign-off signing onto the elevation-session primitive shipped in the posture-ratchet line · tracker: legis-11b3a3dd14, legis-2d0537655d
- **Federation integration hardening (live-fire)** — run the cross-tool seams against real daemons, not stubs: real-Filigree bind/closure (G12), move-aware SEI backfill (G2), backfill failure guards (G8), two-way rename-parser conformance vectors (G16) · tracker: legis-356fe094dd, legis-bc9e5f3e60, legis-b7ce9fdc40, legis-c4cbf78fdb

## Later (directional bets, no order, no dates)
- **Additional key-custody backends** — 1Password / Vault signer backends beyond the v1 OS-keychain + age-file + env escape hatch.
- **Broader provider seams** — Clarion SEI consume seam and any further sibling fact-provider contracts as the federation grows.
- **Audit-trail retention / compaction** — the honest lever for the O(N)-per-read trail-verification cost if trail size ever becomes latency-bound.
