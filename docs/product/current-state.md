# Current State — Legis        Checkpoint: 2026-07-01 · committed (PDR-0009, PDR-0010); DECIDE recorded (PDR-0011)

## The bet right now
**Federation offline contract hardening** (PDR-0011) — close the silent-divergence risk on the federation seams legis can prove **without a live daemon** (Path B holds). Two legis-unilateral, in-CI workstreams:
- **G16** (legis-c4cbf78fdb) — the rename feed's contract tests assert against `_parse_like_loomweave`, a **legis-authored Python mock** of Loomweave's Rust `parse_legis_rename_json` (one-way; the mock IS the oracle). This is live on the **shipped `/git/renames`** seam Loomweave consumes today. Replace it with a **committed two-way shared-vector file** + author that file as the Loomweave-facing artifact.
- **G8** (legis-b7ce9fdc40) — guard `resolve_batch`/`resolve_sei` at the backfill/helper layer; degrade to unresolved/unavailable with evidence (not a crash); add `BrokenResolveClient` coverage.

**Success criterion (falsifiable):** no legis-authored parser mock remains in the rename contract test (both directions assert against the committed vector file, published for Loomweave) **and** a `BrokenResolveClient` test proves the backfill path degrades not crashes. Guardrail: shipped rename-feed output shape stays byte-stable. Metric: new guardrail in `metrics.md` (rename-parser conformance vector-pinned, not self-referential — currently **BREACHED**, this bet closes it).

## In flight / not yet started
- **This bet is decided but not started** — no code written yet. Next session builds it (G16 first — designing faithful vectors is the subtle part — then G8).
- **Deferred by design (NOT this bet):** G12 real-Filigree live-fire (legis-356fe094dd) + the Loomweave live oracle → opt-in runbooks (fork b); G2 move-aware backfill (legis-bc9e5f3e60) → blocked on Loomweave exposing a historical-locator surface; reopening Path B → strategy-level (fork c). See roadmap Next.
- **governance_read.v1 → warpline integration** (legis-9a47068338) — legis-side done + published in 1.4.0; warpline's live handshake pending (sibling-side, not legis-blocked).

## Open questions / blocked-on-owner  (escalations)
- **⚠ Loomweave vector handoff — owner-gated (the one escalation on the Now bet).** Legis authoring + pinning its half of the rename vectors is in-grant and lands value alone; **Loomweave co-committing and running the SAME vectors against its real `parse_legis_rename_json`** is what fully closes the drift loop, and it touches a sibling maintainer → your call to route.
- **governance_read.v1 is publicly frozen** (inform) — a warpline-driven shape change is `governance_read.v2` (ADD), never a v1 edit.
- **esbuild LOW advisory deferred** (legis-70658a5bbc, PDR-0010) — dependabot alert stays open on the default branch until a site-only change.
- **warpline handshake** — sibling-side, awaiting warpline's live confirmation.

## What this session did
- **1.4.0 SHIPPED** (PDR-0009/0010): consolidated release live on PyPI; north-star **1 → 0** (post-gold honesty bet WON); the H-1…H-4 layering decouple + policy-boundary fix + starlette bump landed. Checkpoint committed (2d1d9a8).
- **DECIDE the successor bet** (PDR-0011): audited the federation seams (found them contract-shaped but never live-proven, with a silent-drift risk on the shipped rename seam), and — owner-directed — selected **federation offline contract hardening** (fork a of 3). Promoted to Now; added the rename-conformance guardrail; scoped G16+G8 in, G2/G12/live-fire out.
- Tracker: closed legis-0186c23a2c (1.4.0); filed legis-a7c9ad6404, legis-70658a5bbc; refined G16 (legis-c4cbf78fdb) scope.

## Next session starts here
**Build the Now bet** — start with **G16** (design the two-way shared rename-vector file that faithfully captures Loomweave's parser edge cases from legis's side, replace the `_parse_like_loomweave` mock, assert both directions), then **G8** (backfill resolve guards + `BrokenResolveClient` coverage). Plan-first via `/axiom-planning` is warranted for G16 (the vector-authoring is the subtle, drift-risk-laden part). The Loomweave co-commit handoff is a flagged owner escalation, not a blocker to legis's half.
