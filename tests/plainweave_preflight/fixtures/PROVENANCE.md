# Plainweave preflight golden — provenance

`plainweave-preflight-golden.json` freezes the one envelope shape Plainweave
emits from its ONLY implemented producer:

  * `plainweave_preflight_facts_get` → envelope schema `weft.plainweave.preflight_facts.v1`
    (Plainweave ADR-006, `~/plainweave/docs/architecture/decisions/ADR-006-legis-preflight-fact-envelope.md`).

The frozen envelope is the `commit_range` scope output over `HEAD~1..HEAD` with no
explicit requirement / entity / baseline subjects — i.e. the **representative**
output of the consumer's actual call (`read_plainweave_preflight` always invokes
`scope_kind="commit_range"` with `base`/`head` and no subjects). That call resolves
no facts locally (`facts: []`, `freshness: "partial"`) and carries the producer's
standard capability-gap warnings (`live_diff_resolution_unavailable`,
`linked_work_facts_unavailable`, `finding_facts_unavailable`). This mirrors the
warpline golden precedent, which was likewise empty (`affected: []`, `NO_SNAPSHOT`)
because the consumer passes the envelope through verbatim and never reads fact
contents — a rich-fact fixture would misrepresent the call and test nothing extra.

The producer's boundary assertions live in `data.authority_boundary`
(`local_only: true, live_peer_calls: false, governance_verdicts: false`), NOT in
`meta` (Plainweave's `meta` has no `local_only`/`peer_side_effects` — those are
warpline's). Legis's `PlainweaveMcpClient._call` validates THOSE fields as the
GV-LG-3 fail-closed gate, plus the mandatory `data.freshness` / `data.facts`.

## This golden is CONSTRUCTED, not live-captured — live capture is a pending follow-up

`_provenance.source` is `"constructed-from-frozen-producer-contract"`: the golden
was built field-by-field from the frozen producer contract read in
`~/plainweave/src/plainweave/mcp_surface.py`
(`plainweave_preflight_facts_get`, `_preflight_scope`, `_preflight_warnings`,
`_preflight_summary`, `_preflight_freshness`, the `authority_boundary` block),
`~/plainweave/src/plainweave/envelopes.py` (`success_envelope`), and ADR-006 —
NOT from a live `plainweave-mcp` session.

This is deliberate and honest: this consumer was built from the **hub** session,
whose MCP wiring is the hub's, not legis's plainweave wiring. A live MCP call from
here would misroute and yield a false verdict, so it was not attempted. The golden
does **not** claim `"live-captured"`; `test_golden_provenance_is_constructed_not_live`
pins that honesty marker.

**Required follow-up (flagged to the hub):** in a legis-rooted session, run a live
`plainweave-mcp` capture of `plainweave_preflight_facts_get`
(`scope_kind="commit_range"`, real `base`/`head`), confirm the bytes match this
constructed golden field-for-field, and only then re-mark `_provenance.source` to
`"live-captured"` and re-pin `GOLDEN_BLOB_SHA`.

## Legis conforms to Plainweave's frozen producer — additive, enrich-only

Legis is a CONSUMER of Plainweave's already-frozen `weft.plainweave.preflight_facts.v1`
producer (ADR-006, registered + contract-tested on the Plainweave side). Legis's
`PlainweaveMcpClient._call` validates the envelope and passes it through verbatim;
it does not interpret, re-shape, or act on the facts. This creates **no Plainweave
obligation** — it ships solo per the federation change discipline (additive,
enrich-only). The read is a purely advisory SIBLING of the warpline advisory read
and the governance honesty reads; it never perturbs a Legis governance verdict.

## Re-pinning the golden

After a deliberate re-construction (or a live recapture), re-pin `GOLDEN_BLOB_SHA`
in `test_plainweave_preflight_oracle.py` to
`git hash-object tests/plainweave_preflight/fixtures/plainweave-preflight-golden.json`.
