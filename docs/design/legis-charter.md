# Legis Charter

## Summary

Legis is a shipped, admitted Weft product (`1.0.0`). It is responsible for project change provenance and the git/CI common operating picture. (The authoritative federation roster and axiom live in the Weft hub at `~/weft/doctrine.md`; this charter is Legis's own self-description, consistent with the hub's roster ruling.)

## Authority boundary

Legis owns:

- project change provenance,
- branch, commit, and pull request context,
- CI/check context, and
- governance and attestation context over project change.

Legis does not own:

- code identity or structure,
- issue or workflow state, or
- policy findings and dossier truth.

## Operating modes

### Solo mode

Legis can describe repository change and CI state on its own.

### Pair mode

- With Loomweave: Legis can supply git-history and rename evidence.
- With Filigree: Legis can connect work state to change state.
- With Wardline: Legis can connect policy findings to change and check context.

### Suite mode

Legis becomes the common operating picture for project change and governance while preserving the authority boundaries of the other Weft products.

## Known governance gaps

- **Self-asserted write actor (`verified_author: null`).** Actor identity on
  write events is self-asserted by the caller, not cryptographically verified.
  This holds in two places with the same trust property:
  - *Federation writes* (e.g. a comment or status change attributed to an agent
    on a sibling's surface) — Legis governs *change* provenance but does not mint
    or verify the actor identity carried on a sibling's write.
  - *Legis's own governance/audit records.* Every override and sign-off record
    stores a self-asserted actor — the `agent_id` (and `operator_id` for operator
    overrides) — written verbatim into the append-only, hash-chained audit store.
    The narrative `verified_author: null` maps to these concrete stored fields.
    Two real safeguards bound the gap, but neither is authentication: the MCP
    actor is **launch-bound** (the `--agent-id` is fixed at launch; no tool schema
    accepts actor identity as a call argument, so an in-session agent cannot pick,
    spoof, or rotate its actor per call), and the complex tier's HMAC signs *over*
    `agent_id` — but that is **tamper-evidence** (the value was not altered after
    write), not proof the value was true at write time. (Note: the governed
    *subject*'s identity — the SEI of a code entity — *is* resolved via Loomweave;
    only the *actor* is unauthenticated. The two are kept separate.)

  For trust-local, single-operator use this is acceptable. Non-repudiable write
  attribution would require an operator-held verified-identity binding at the
  write boundary (`service/governance.py` submit paths) — out-of-band, never an
  agent-reachable surface, per capability confinement (proposed convention C-8).
  Verified authorship is a deferred item in the governance story, not a current
  guarantee. The records do not *falsely* claim verification — the field is
  plainly `agent_id`, so this is an honesty/documentation gap, not a false
  assertion. (Surfaced in the 2026-06 lacuna dogfood as finding C3.)

## Status

Legis is at `1.0.0` — shipped, admitted to the federation, and runtime-implemented (`serve`, the MCP surface, and the CI gates are all live). This charter records the role the implementation fills; it is no longer a pre-implementation design sketch. For what Legis does *not* yet guarantee, see the **Known governance gaps** above — the open item there (verified write authorship) is the honest limit on the current `1.0.0` story, not a closed one.
