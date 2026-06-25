# PDR-0001 — Bootstrap the Legis product workspace from observed state

Date: 2026-06-24   Status: accepted   Author: claude (opus, product-owner)   Owner sign-off: partial (grant confirmed live; inferred vision/metrics not yet confirmed)
Supersedes: —   Related: vision.md, roadmap.md, metrics.md, current-state.md

## Context
Legis had no product-ownership workspace (`/product-checkpoint` halted on the missing precondition). Legis is a shipped gold product (v1.1.1) with a rich repo, README, CHANGELOG, a Weft member briefing, and a 145-issue filigree tracker. A workspace had to be constructed from that observed reality rather than fabricated from memory, so the next session can resume cold.

## Options considered
1. **Bootstrap from observed reality (README + git log + tracker + member briefing), confirm only the authority grant live.** — pro: grounded in fact, fast, the one load-bearing item (the grant) is human-confirmed; con: purpose/audience/metric _numbers_ are inferred and may need correction.
2. **Interrogate the owner for vision/metrics before writing anything.** — pro: maximally accurate; con: slow, and the README + member briefing already state purpose and direction plainly — interrogation would mostly re-elicit what's already written.
3. **Do nothing / stay stateless.** — pro: no risk of a wrong inference; con: forfeits continuity entirely, which is the whole point of ownership.

## The call
Option 1. Seeded `vision.md`, `roadmap.md`, `metrics.md`, `current-state.md` from the README, the Weft member briefing (`~/weft/members/legis.md`), git history, and the filigree tracker. The **authority grant was proposed and confirmed live** by the owner (Standard variant) during this `/own-product` run, so it is written as authoritative (not draft). Everything else is inferred-from-repo and marked as such.

## Rationale
The repo states purpose, audience, anti-goals, and recent direction explicitly and consistently with the federation doctrine; inference here is reading, not guessing. The only item that genuinely required a human (the delegation boundary) was confirmed interactively. Metric _numbers_ that the repo doesn't expose are left as `(set)` placeholders rather than invented, keeping every target falsifiable-or-flagged.

## Reversal trigger
Revisit on the **first owner review of this workspace**: if the owner corrects the purpose/audience framing in `vision.md` or sets real numbers against any `(set)` metric placeholder, supersede the inferred portions with a new PDR. Also revisit if the north-star ("open confirmed governance-honesty defects = 0") proves to be the wrong success measure once the P2 findings close.
