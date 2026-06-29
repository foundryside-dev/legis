# Warpline preflight golden — provenance

`warpline-preflight-golden.json` freezes the two envelope shapes warpline emits
via its MCP surface, live-captured from `warpline-mcp` (version 1.2.0):

  * `warpline_impact_radius_get`   → envelope schema `warpline.impact_radius.v1`
  * `warpline_reverify_worklist_get` → envelope schema `warpline.reverify_worklist.v1`

Both captured against the legis repo, rev_range `HEAD~1..HEAD`, on 2026-06-27.
The capture produced `completeness: "NO_SNAPSHOT"` and empty `affected`/`items`
lists (no Loomweave snapshot in place at capture time).  The meta fields
`local_only: true, peer_side_effects: []` are present and valid.

## Live-capture transcripts

Both halves of the golden are backed by committed raw MCP session transcripts
(three JSON-RPC lines each: id=1 initialize response, id=null
notifications/initialized error, id=2 tools/call response):

  * `warpline-mcp-live-session.jsonl`    — impact_radius session, captured 2026-06-26
  * `warpline-mcp-reverify-session.jsonl` — reverify_worklist session, captured 2026-06-27

Replay tests in `test_stdio_invoke.py` echo these raw bytes through `StdioMcpInvoke`
and assert known fields from the capture, so the real message order + result shape
(structuredContent vs content[].text + protocolVersion) are exercised, not just
legis-shaped assumptions.

## Legis conforms to warpline's extant envelope — warpline ships no producer

Per SEAM 4 §4A and GV-LG-3: legis is a CONSUMER of warpline's extant MCP
envelope.  Legis's `WarplineMcpClient._call` validates the envelope
(schema/ok/meta/completeness) and passes it through verbatim.  Warpline owns the
`warpline.impact_radius.v1` / `warpline.reverify_worklist.v1` schemas; legis does
not interpret or re-shape them.

Warpline ships no producer-side contract fixture for its MCP envelopes (no
`mcp-preflight-golden.json`).  The Layer-2 recheck in
`test_warpline_preflight_oracle.py` (`test_golden_matches_warpline_source`)
skips cleanly and will activate automatically if warpline vendors that fixture.

## Re-capturing the golden

Run `warpline-mcp` with stdio JSON-RPC calls for `warpline_impact_radius_get` and
`warpline_reverify_worklist_get` (see `warpline-mcp-live-session.jsonl` and
`warpline-mcp-reverify-session.jsonl` for the exact protocol), extract the
`structuredContent` from each `id=2` response, build the golden as
`{"impact_radius": <...>, "reverify_worklist": <...>, "_provenance":
{"source": "live-captured", ...}}`, then re-pin `GOLDEN_BLOB_SHA` in the oracle
to `git hash-object tests/warpline_preflight/fixtures/warpline-preflight-golden.json`.
