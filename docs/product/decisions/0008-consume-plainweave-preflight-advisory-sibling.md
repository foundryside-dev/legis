# PDR-0008 — legis consumes Plainweave's preflight-facts producer as an advisory sibling

Date: 2026-06-27   Status: accepted   Author: claude (opus) — **executed in a parallel legis session** (commit `27f12da`, John Morrissey, 2026-06-27 22:08); recorded here for workspace continuity
Supersedes: —   Related: commit `27f12da`; Plainweave producer `plainweave_preflight_facts_get` / envelope `weft.plainweave.preflight_facts.v1` (Plainweave ADR-006); GV-LG-3; [[0003-federation-read-doctrine]]; [[0006-warpline-preflight-conform-to-extant-mcp-envelope]]

## Context
Plainweave is a Weft sibling whose only implemented producer (`plainweave_preflight_facts_get`, envelope `weft.plainweave.preflight_facts.v1`) had **no sibling consumer** and had never been exercised end-to-end. A parallel legis session landed legis as a read-only **advisory consumer** of it, mirroring the existing warpline advisory-preflight read (PDR-0006) exactly. This is a *different* federation seam from PDR-0007's `governance_read.v1`: there legis is the **producer** (warpline consumes); here legis is the **consumer** (Plainweave produces).

## The call (recorded, not re-decided)
This is an **application of accepted doctrine** ([[0003-federation-read-doctrine]] facts-not-verdicts; [[0006-warpline-preflight-conform-to-extant-mcp-envelope]] consume-the-extant-standard), not a new bet — so it is recorded for continuity rather than re-litigated. What landed (`27f12da`):
- `legis/plainweave_preflight/client.py` — injectable `PlainweaveMcpClient` + `StdioMcpInvoke`; every contract fault fails **closed** → `PlainweaveError`. GV-LG-3 validated against Plainweave's *real* envelope shape (`data.authority_boundary.{local_only, live_peer_calls, governance_verdicts}` + mandatory `data.freshness`/`facts`) — Plainweave's `meta` carries no `local_only`/`peer_side_effects` (those are warpline's).
- `service/preflight.read_plainweave_preflight` — discriminated `checked`/`unavailable` sibling of `read_warpline_preflight`; None/fault → `unavailable` with a reason, NEVER `INTERNAL_ERROR`, NEVER empty-as-clean.
- `mcp.py` `plainweave_preflight_get` tool (separate advisory sibling, not merged with warpline's); `runtime.plainweave` from `PLAINWEAVE_MCP_CMD`, default None → `unavailable`; governance unaffected when absent/unconfigured.

## Rationale
ADVISORY ONLY, enrich-only — never changes a legis policy/governance decision; the advisory boundary is the load-bearing invariant. Pinned by tests: a byte-identity test (a hostile Plainweave client cannot perturb a real verdict), a structural test (no verdict-path function references `runtime.plainweave`), a GV-LG-3 test (refuses any producer claiming `governance_verdicts`), and the honest-degrade path (absent → `unavailable`; `ok:false` → `unavailable`). Gates green at the commit: ruff, mypy, pytest **1377 passed**, per-package floors (`plainweave_preflight` 96.6%), SEI oracle, policy-boundary-check.

## Reversal trigger
- If the **advisory-boundary byte-identity invariant** fails for the Plainweave read (a legis verdict diverges with Plainweave present vs absent) → reopen immediately.
- If Plainweave's `weft.plainweave.preflight_facts.v1` envelope changes (shape / authority_boundary fields) → the client's parse/boundary layer reopens (degrades to `unavailable` until then).

## Status note
The conformance oracle is driven over a **CONSTRUCTED** golden (built from the producer contract), NOT a live capture — the hub session's MCP wiring misroutes Plainweave. **Live end-to-end capture is a flagged follow-up** (a legis-rooted session), tracked separately by the parallel session. This PDR records the decision so the next `RESUME` does not mistake `27f12da` for unexplained drift.
