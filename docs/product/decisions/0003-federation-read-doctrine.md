# PDR-0003 — Federation-read doctrine: Legis exposes verified FACTS, never a verdict; advisory context is structurally isolated

Date: 2026-06-25   Status: accepted (reinforces existing vision anti-goals — no new sign-off)   Author: claude (opus, product-owner)
Supersedes: —   Related: [[0002-accept-warpline-bet-defer-classifier]]; vision.md anti-goals ("a second judge of trust", "an identity owner")

## Context
The warpline seam is Legis's first time being an HTTP **client** of a sibling on a path next to governance reads, and the first time it **exposes** a read a sibling treats as proof. This pattern recurs (Clarion SEI consume; future sibling fact-providers), so it needs a durable principle to stop future seams from eroding the authority boundary.

## Options considered
1. Legis returns a `proven_good` / skip-reverify **verdict** the sibling acts on directly (Legis decides).
2. Legis returns verified **FACTS** (attested content_hash, kind, seq); the sibling does its own Rung-2 commit-match and skip decision (Legis attests, the sibling decides).
3. Embed advisory sibling reads **inside** the governance honesty reads.

## The call
Option 2 for attestation; option 3 **rejected** — advisory context lives in a DEDICATED sibling tool structurally isolated from every verdict path. `attestation_get` returns facts; warpline makes the skip-reverify call. `warpline_preflight_get` is a sibling tool whose data is never an input to `policy_evaluate` / the gates / sign-off / the honesty reads, enforced by a derived structural test over all tool handlers (covers future tools by construction).

## Rationale
"Wardline analyses, Legis governs." Legis must never become a second judge of trust, and advisory context must be **structurally incapable** of reaching a verdict — not merely "we didn't wire it." Facts-not-verdict keeps Legis the sole authority while still letting siblings build verification on top. This is the doctrine for every future federation read.

## Reversal trigger
- If a sibling shows a need Legis cannot meet with facts-only (a genuine case where Legis must *decide*) → revisit as an explicit **vision / authority-grant escalation** (it would change the "not a second judge" anti-goal).
- If any future seam is found feeding sibling data into a verdict path → treat as a **Critical** regression against this doctrine.
