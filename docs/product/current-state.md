# Current State — Legis        Checkpoint: 2026-07-01 · committed (PDR-0009, PDR-0010)

## The bet right now
**— open —.** The post-gold governance-honesty bet is **WON**: **north-star = 0** open governance-honesty defects (met ahead of the 2026-07-15 target) after `legis-0186c23a2c` shipped in **1.4.0**. **No successor Now bet has been decided — that is the next `DECIDE`.** Promotion candidates (already shaped in `roadmap.md` → Next): **v2 keyed-signing unification** (legis-11b3a3dd14, legis-2d0537655d) and **federation integration hardening / live-fire** (legis-356fe094dd, -bc9e5f3e60, -b7ce9fdc40, -c4cbf78fdb).

## In flight / not yet started
- **governance_read.v1 → warpline integration** (legis-9a47068338) — legis-side **DONE + published in 1.4.0**; the v1 contract is now publicly frozen. **Warpline must wire `LegisGovernanceClient` + restart its MCP connection** to flip its legis member `disabled`→`clean`. Sibling-side, **not legis-blocked**.
- **Successor Now bet — undecided.** The next session's `DECIDE` picks it (candidates above).

## Recently shipped this session — legis 1.4.0 LIVE on PyPI (tag v1.4.0 @ 3055d2c)
One consolidated minor (PR #24, 6-area adversarial review → GO), owner-authorized publish:
- **`policy_boundary_check` containment** (legis-0186c23a2c) — closed the **last north-star finding** → north-star 0.
- **H-1…H-4 layering decouple** — signing → dependency-free `crypto/` leaf; `OperatorKeyCustodyError` → `posture/errors.py`; `_load_policy_cell_registry` → `policy.cells`; `policy→service` non-edge documented. Byte-identical signing move; cross-tool vectors untouched.
- **`governance_read.v1`** + **Plainweave consumer** + **warpline MCP rewire** + **posture/protected hardenings** — all now published.
- **starlette 1.2.1→1.3.1** security bump — cleared 2 of 3 dependabot alerts (PDR-0010).
- Ops: global `legis` uv tool replaced with the official 1.4.0 wheel; uv cache pruned of 11 old legis versions.

## Open questions / blocked-on-owner  (escalations)
- **Release publish — DONE under explicit owner authority this session; nothing awaits sign-off on it.** The owner directed the release live ("tag a new release on my authority"); v1.4.0 is on PyPI. Recorded as PDR-0009 (`accepted`). *(Stated here because the outward-facing action must be visible in the escalation section — it is resolved, not pending.)*
- **Successor Now bet needs deciding** — north-star is met; the honesty bet is won. What does Legis bet on next? (Owner steer welcome; candidates shaped in Next.)
- **governance_read.v1 is now publicly frozen** (inform) — if warpline's live integration needs a shape change, it is a **`governance_read.v2`** (ADD), never a v1 edit.
- **esbuild LOW advisory deferred** (legis-70658a5bbc, PDR-0010) — the dependabot alert stays open on the default branch until a separate site-only change; negligible impact (Windows-dev-only, not the wheel).
- **warpline handshake** — the G1 integration half; sibling-side, awaiting warpline's live confirmation.

## What this checkpoint did
- Recorded **PDR-0009** (ship 1.4.0 — consolidated release + owner-authorized PyPI publish) and **PDR-0010** (1.4.0 security scope — bring in starlette, defer esbuild).
- **north-star 1 → 0** (bet won); moved the honesty bet Now → won in `roadmap.md`; refreshed `metrics.md` with the 1.4.0 shipped readings (1389 passed, coverage 92.5% incl. new `crypto/` floor, publish-gate confirmed live, both boundary invariants re-proven).
- Reconciled the tracker: **closed legis-0186c23a2c** (verify-walked, shipped in 1.4.0); noted publish-done on legis-9a47068338; filed **legis-a7c9ad6404** (warpline stderr bound) + **legis-70658a5bbc** (esbuild site advisory). Open follow-up legis-a0e286f5aa (MCP outputSchema drift-guard) re-confirmed by the review.

## Next session starts here
**`DECIDE` the successor Now bet** — the honesty north-star is met, so Legis needs its next bet (promote from Next: v2 keyed-signing unification, or federation integration hardening / live-fire). The warpline handshake, the esbuild site fix, and the outputSchema drift-guard are tracked follow-ups, not blockers.
