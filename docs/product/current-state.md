# Current State — Legis        Checkpoint: 2026-06-28 · committed (PDR-0007, PDR-0008)

## The bet right now
**Keep the governance-honesty surface true post-gold** (north-star: open governance-honesty defects → **0** by 2026-07-15; currently **1**). The last confirmed P2 finding is **legis-0186c23a2c** (policy_boundary_check accepts roots outside the source root) — unplanned; closing it takes the north-star to 0. This session shipped two **federation seams** (seam-quality, NOT north-star items) and deployed the governance_read surface locally.

## In flight / not yet started
- **legis-0186c23a2c** (unbounded policy-boundary root) — the **last** north-star P2 finding; confirmed, unplanned. Closing it → north-star **0**. **Next session's primary candidate.**
- **G1 integration tail** (legis-9a47068338) — legis-side DONE; **warpline must wire `LegisGovernanceClient` + restart its MCP connection** to flip its legis member `disabled`→`clean`. Awaiting warpline's live confirmation (not legis-blocked).

## Recently shipped this session (LOCAL main; NOT pushed)
- **`governance_read.v1`** (PDR-0007, legis-9a47068338) — per-SEI governance read legis publishes for warpline; cleared-only; CLI+MCP+HTTP + frozen discriminated-union contract; verified (1335 passed, **mutation-proven** false-green-free) + deployed to the global `legis` tool (1.3.0). Integration pending warpline.
- **Plainweave preflight consumer** (PDR-0008, parallel session `27f12da`) — legis reads Plainweave's `preflight_facts.v1` advisory/enrich-only; 1377 passed at HEAD.
- Follow-ups filed: **legis-a0e286f5aa** (MCP outputSchema looser than the frozen contract — Minor).

## Open questions / blocked-on-owner  (escalations)
- **⚠ Release (push + publish) — owner-gated; the one escalation this session.** Local `main` (HEAD `27f12da`) is now far ahead of origin: the 1.3.0 line + 3 prior fixes + warpline-preflight + **G1 governance_read.v1** + **Plainweave consumer**. Direct push is **ruleset-blocked** (PR required). Decide: **(a) SCOPE** — what ships next (fold G1 + Plainweave into 1.3.0, or cut a 1.4.0)? **(b) MECHANISM** — shall I push a branch + open the PR, and who cuts the GitHub Release / PyPI publish? **Nothing is pushed; `governance_read.v1` stays a LOCAL freeze until this lands** (keeps the v1 contract revisable if warpline needs a change before publish).
- **warpline handshake — live confirmation pending** (the G1 integration half; sibling-side).
- **Plainweave live e2e capture** — the parallel session's golden is CONSTRUCTED, not live-captured (hub MCP misroutes Plainweave); a flagged follow-up.

## What this checkpoint did
- Recorded **PDR-0007** (build `governance_read.v1` — cleared-only per-SEI federation read, owner-directed) and **PDR-0008** (record the parallel session's Plainweave advisory consumer under [[0003-federation-read-doctrine]]/[[0006-warpline-preflight-conform-to-extant-mcp-envelope]] doctrine).
- Refreshed `metrics.md` (north-star unchanged at 1; advisory boundary re-proven ×2; the new federation surface **mutation-proven** false-green-free; CI green, 1377 passed @ HEAD) and `roadmap.md` (two seams → recently-shipped).
- Reconciled the tracker: filed **legis-9a47068338** (G1 feature) + **legis-a0e286f5aa** (outputSchema follow-up).

## Next session starts here
**Plan legis-0186c23a2c** (the last north-star finding) via the `/axiom-planning` → review → execute path — closing it takes the north-star to **0**. OR, if the owner is ready: the **release decision** (scope + PR mechanism) for the now-substantial unpushed local `main`. The warpline + Plainweave integration tails are sibling-side, not legis-blocked.
