# PDR-0011 — Next Now bet: federation integration hardening, shaped as "offline contract hardening" (legis-only, in-CI core)

Date: 2026-07-01   Status: accepted (within grant — bet selection + shaping; the Loomweave vector handoff is FLAGGED for the owner, not enacted)   Author: claude (opus, product-owner)
Supersedes: —   Related: [[0009-ship-legis-1.4.0-consolidated-release]] (north-star → 0 freed the Now slot); [[0003-federation-read-doctrine]]; tracker legis-c4cbf78fdb (G16), legis-b7ce9fdc40 (G8); **out-of-scope by design:** legis-bc9e5f3e60 (G2, Loomweave-blocked), legis-356fe094dd (G12, live-fire)

## Context
The post-gold governance-honesty bet is **won** (north-star 0, PDR-0009), freeing the Now slot. The owner picked **federation integration hardening** as the next bet, with low confidence it is "in good shape." A per-seam audit this session confirmed the concern: every federation seam is *contract-shaped* (frozen goldens + graceful degradation) but **none is proven live against a real sibling in any CI gate**, and one **shipped** seam actively *hides* drift — the git rename feed's contract tests (`test_git_renames_contract.py` / `test_git_rename_feed_contract.py`) assert legis's output against `_parse_like_loomweave`, a **legis-authored Python mock of Loomweave's Rust `parse_legis_rename_json`** (one-way — the mock IS the oracle). This is live on **`/git/renames`** (the flat array Loomweave consumes today), i.e. the exact silent-divergence class Weft closed for *signing* (shared byte-pinned vectors) but never applied to *renames*. Under **Path B** (no CI-reachable siblings), live end-to-end can never be a CI gate, so the bet forks three ways: (a) offline contract hardening, (b) opt-in live-fire runbooks, (c) reopen Path B.

## Options considered
1. **Ship the whole "run seams against live daemons" catalogue as one bet** (G2/G8/G12/G16 + Warpline/Plainweave live-capture). Rejected — collides with Path B, mixes legis-only fixes with sibling-blocked/coordination work, and most of it crosses the authority boundary (the git-rename provider is a sibling-binding federation contract; anything touching sibling maintainers escalates).
2. **Live-fire runbooks (fork b)** — run the written seams green against disposable daemons + document runbooks. Rejected for now — catches drift only when run, needs sibling daemons stood up, and leaves the silent-drift risk on the *shipped* rename seam open until someone runs it.
3. **Reopen Path B (fork c).** Rejected — a vision/strategy decision with the biggest infra + coordination cost; not this bet.
4. **Offline contract hardening (fork a).** The legis-only, in-grant, in-CI core. **CHOSEN by the owner.**

## The call
**Fork (a).** Two legis-unilateral workstreams:
1. **G16 — de-self-reference the rename contract.** Replace the in-test `_parse_like_loomweave` mock with a **committed shared-vector file** (input rename JSON → expected `old_path`/`new_path`); assert `/git/renames` **and** `/git/rename-feed` **both directions** against it; **author** those candidate vectors as the Loomweave-facing cross-tool artifact.
2. **G8 — backfill resolve guards** (legis-b7ce9fdc40). Guard `resolve_batch`/`resolve_sei` at the helper/backfill layer; degrade to unresolved/unavailable with evidence instead of breaking resumability; add `BrokenResolveClient` coverage.

The remaining loop-closure — **Loomweave co-committing + running the same vectors against its real parser** — is **FLAGGED for the owner** (federation coordination touching a sibling maintainer), not enacted here.

## Rationale
This closes the sharpest, silent, **shipped-seam** risk (rename-parser drift) **unilaterally and in CI**, without a live daemon or a sibling — so it lands value alone and honestly under Path B, applying the discipline Weft already proved for signing (shared vectors break drift *somewhere* with no daemon) to the one seam that lacks it. It deliberately **excludes** the sibling-blocked (G2 — needs a Loomweave historical-locator surface) and live-fire (G12, the Loomweave oracle) work so the bet's success criterion depends on no one but legis. G8 rides along because it is a small, in-grant robustness fix on the same federation-audit cluster.

## Reversal trigger
- If authoring faithful vectors from legis's side proves infeasible without Loomweave's parser spec (edge cases can't be captured one-sided) → G16 becomes **sibling-coordination-first** (escalate the handoff earlier), not legis-authored.
- If a **live rename-parser divergence is found** before the vectors land → hotfix the feed + fast-track the vector pin (the risk materialized; tie to the new guardrail in `metrics.md`).
- If the owner **reopens Path B** or a CI-reachable Loomweave appears → the offline vectors become the Layer-2 half of a live oracle (ADD, not rework).

## Success criterion (falsifiable)
The rename contract test asserts **both directions against a committed vector file** (no legis-authored parser mock remains), that file is published as the Loomweave-facing artifact, **and** a `BrokenResolveClient` test proves the backfill/helper path **degrades rather than crashes**. Guardrail: the shipped rename-feed output shape stays byte-stable (existing shape tests green). Metric: new guardrail — *cross-tool rename-parser conformance is vector-pinned, not self-referential* (`metrics.md`).
