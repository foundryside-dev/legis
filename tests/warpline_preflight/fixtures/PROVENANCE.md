# Warpline preflight golden — provenance

`warpline-preflight-golden.json` freezes the two response shapes legis's real
warpline preflight consumer parses:

  * `GET /api/impact-radius`   -> `{"affected": [{"sei": ...}, ...], "count": N}`
  * `GET /api/reverify-worklist` -> `{"entries": [{"sei": ...}, ...], "count": N}`

These are the shapes `legis.warpline_preflight.client.HttpWarplineClient`
(`impact_radius` / `reverify_worklist`) and `legis.service.preflight.read_warpline_preflight`
expect today.

## NOT vendored from warpline — frozen to the legis-expected contract

This golden is **frozen to the shape legis's client expects**, NOT vendored
byte-identical from a warpline source fixture. As of this writing warpline ships
**no producer** for these flat REST shapes:

  * warpline has **no HTTP server**; its surface is MCP/CLI only.
  * warpline's `impact_radius` / `reverify_worklist` commands return the rich
    envelope schemas `warpline.impact_radius.v1` / `warpline.reverify_worklist.v1`
    (`{schema, ok, query, data: {... affected / items ...}, enrichment, ...}`),
    where the affected set is nested under `data` and the reverify list is
    `data.items` — NOT the top-level flat `{"affected"/"entries", "count"}` legis
    parses. There is no top-level `count`.
  * warpline's only legis-facing seam (`federation.py`) runs the OPPOSITE
    direction: warpline CONSULTS legis governance as a federation peer.

## WARPLINE PRODUCER-SIDE OBLIGATION

For this seam to reach a shared, byte-identical golden, warpline must ship a
producer (an HTTP `GET /api/impact-radius` + `GET /api/reverify-worklist`, or an
equivalent flat-shape projection) emitting exactly:

    impact-radius   : {"affected": [{"sei": "loomweave:eid:<32hex>", ...}], "count": N}
    reverify-worklist: {"entries":  [{"sei": "loomweave:eid:<32hex>", ...}], "count": N}

and vendor a contract fixture for it under
`warpline/tests/fixtures/contracts/warpline/`. The Layer-2 recheck in
`test_warpline_preflight_oracle.py` (`test_golden_matches_warpline_source`)
points at that path and `pytest.skip`s until it exists; it activates
automatically and will then enforce byte-equality (re-vendor + update the
byte-pin once the producer ships).
