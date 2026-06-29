# PDR-0006 — Warpline preflight: conform to warpline's extant MCP envelope (transport = MCP); reverse the producer-obligation; reverify kept droppable

Date: 2026-06-27   Status: accepted (transport owner-confirmed 2026-06-26; merge local-only, push/1.3.0 publish owner-gated)   Author: claude (opus, product-owner)
Supersedes: —   Related: tracker legis-a53d92507d; plan `docs/plans/2026-06-26-warpline-preflight-mcp-transport.md`; hub interface-lock SEAM 4 §4A / GV-LG-1 / GV-LG-3; [[0003-federation-read-doctrine]]

## Context
The warpline maintainer found that legis's warpline preflight client spoke a **phantom HTTP wire** (`GET /api/impact-radius`) warpline never served — it had been copied from legis's loomweave HTTP-client pattern; warpline is MCP/CLI-only. Worse, a 1.3.0-prep commit (6f50a33, on local main) **froze the wrong flat shape** as a golden conformance vector and recorded a "WARPLINE PRODUCER-SIDE OBLIGATION" demanding warpline build an HTTP producer to match legis's flat assumption — the inverse of the real contract. The seam failed safe (→ `unavailable`) but was dead-on-arrival, and the golden asserted a wire warpline doesn't serve.

## Options considered
1. **Keep the flat HTTP shape; warpline ships an HTTP producer** (last night's producer-obligation). REJECTED — forces a sibling to reimplement something already extant; inverts SEAM 4 §4A (which pins the seam to `warpline_impact_radius_get` — the envelope) and GV-LG-3 (legis reads `meta.local_only`/`peer_side_effects` off the envelope; the flat shape has no `meta`).
2. **Transport = CLI subprocess** (`warpline … --json`). Workable, but the CLI verbs lack `--rev-range`, so legis must reconstruct the rev_range→affected resolution via a two-step — and the friction tempts a "warpline, add --rev-range" ask, a softer version of the same mistake.
3. **Transport = MCP stdio** — consume the EXTANT `warpline_impact_radius_get` / `warpline_reverify_worklist_get` tools with `rev_range`; one call per verb; the seam-lock literally references the MCP tool.

## The call
**Option 3** — owner-confirmed 2026-06-26, *reversing an initial CLI pick* after the owner's challenge ("didn't warpline tell us the standard? aren't we forcing them to reimplement something already extant?"). A stdlib stdio JSON-RPC client (no new dependency) over an injectable `invoke` seam; parses the real `warpline.impact_radius.v1`/`.reverify_worklist.v1` envelope (pass-through), enforces GV-LG-3 `meta` + `data.completeness`, fails closed on every fault; **real live-captured fixtures** (non-circular oracle, committed session transcripts); the producer-obligation **reversed**. Shipped to local main @ **075edd0**. Validated by a 7-agent review (round 1 CHANGES_REQUESTED — 2 verification-layer blockers; round 2 APPROVED_WITH_WARNINGS) + a final opus whole-branch review. The live-capture DoD gate caught warpline's *undocumented required* `repo` argument.

## Rationale
Legis conforms to what warpline already serves; warpline reimplements nothing. This is the durable federation principle, a sibling of [[0003-federation-read-doctrine]]'s facts-not-verdicts: **consume the sibling's extant standard; never force a sibling to reshape to a consumer's convenience.** The advisory boundary is preserved (byte-identity + the derived structural test); this is a **federation-seam-quality** bet, NOT a north-star governance-honesty item (it fails safe — governance is byte-identical with/without warpline).

## Reversal trigger
- If **wardline rules (SEAM 4 §2A)** that legis must not consume `reverify_worklist` (filigree is the lock's named reverify consumer) → **drop the reverify half** (the client method + `service/preflight.py:28`); the client is structured for a clean removal. If wardline blesses it as a new seam → a new PDR records the sanctioned dependency.
- If the **advisory-boundary byte-identity invariant** ever fails (a governance verdict diverges with warpline present vs absent) → reopen immediately (the guardrail).
- If warpline's **MCP surface changes** (envelope schema / required args) → the client's parse/args layer reopens (it degrades to `unavailable` until then).
