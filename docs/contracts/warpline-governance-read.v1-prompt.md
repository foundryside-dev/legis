# Prompt for WARPLINE — wire `LegisGovernanceClient` to legis's `governance_read.v1`

> **Canonical contract:** `contracts/governance_read.v1.schema.json` in the legis repo. **Mirror that
> file** — it is the source of truth. The copy embedded below is an abridged convenience mirror: every
> *validating* keyword (type/enum/minLength/format/allOf/if-then) is identical to the canonical file
> and legis CI asserts that equality; only the human `description` annotations are dropped here (they
> live in the canonical file).

> **⚠ Contract hardened since the first hand-off (backward-compatible).** The schema now enforces the
> discriminated union (status `unavailable` ⇒ a non-empty `unavailable` reason array + `records: []`;
> status `checked` ⇒ no `unavailable` key). This only *tightens* what legis emits — legis never
> produced the now-rejected shapes — so a consumer that already built against the looser draft is not
> broken. Re-mirror the schema below for your own validation.

You asked legis to expose a per-SEI governance read so `reverify_worklist(include_federation=True)`
can enrich its worklist with legis governance facts. Legis owns this contract (`governance_read.v1`)
because legis is the governance authority; you consume it advisorily. Build your
`LegisGovernanceClient` against the shape below.

**Before you finalize the consumer, confirm the v1 SCOPE (one section below) matches what your
`enrichment.governance` displays.** A scope mismatch is the one thing a parallel build hides until
both sides are done — settle it first. Everything else here is final.

## Trust boundary (restated so the contract can't erode it)

- Legis is the **governance authority**; warpline is an **advisory consumer**. You ECHO legis
  governance as `enrichment.governance: present | absent | unavailable`. You **NEVER gate** the
  reverify decision on it. `GV-LG-1` (no `governance_verdict` in warpline output) stays asserted.
- Legis reports **facts it cryptographically verified**, never a verdict for you. Honest absence is
  a first-class answer; an unanswerable read fails **loud**, never silent-empty.

## v1 SCOPE — confirm it, THEN finalize  ⚠️ the coordination point

`governance_read.v1` reports **verified governance CLEARANCES only**, keyed on SEI:

- `operator_override` — a protected-cell operator-override verdict (`OVERRIDDEN_BY_OPERATOR`), signed.
- `signoff_cleared` — a structured/protected sign-off an operator **cleared**, signed with an
  integrity-bound request join.

It does **NOT** report in-flight / uncleared governance (open PENDING sign-offs, BLOCKED verdicts,
Filigree bindings) — a deliberate v1 non-goal.

**The honesty contract for your enrichment:**

- `records: []` (under `status: "checked"`) means **"legis holds no verified governance clearance
  for this SEI."** NOT "ungoverned," NOT "unknown SEI." An entity under an *open* structured block
  has no clearance yet → it returns `[]`. So treat `enrichment.governance: absent` as **"no verified
  clearance,"** not "ungoverned." If your display would read `absent` as "ungoverned," relabel the
  key (e.g. `governance_clearance: present|absent`) or tell legis you need in-flight context — that's
  a **pre-build scope bump** (cheap now) or a `governance_read.v2`, never a mutation of v1. A v2 that
  ADDS dispositions/kinds leaves every v1 cleared record valid, so v1=cleared-only is a safe subset.
- **Legis cannot distinguish "unknown SEI" from "known SEI, no clearance"** (it is an SEI consumer,
  never the authority). `[]` deliberately conflates them. "Does this SEI exist" is a Loomweave query.

→ **Confirm: does cleared-only enrichment match your `enrichment.governance` semantics? Reply before
finalizing the consumer if you need more than verified clearances.**

## The contract — `governance_read.v1.schema.json` (structural mirror; validating keywords identical, descriptions in the canonical file)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://weft.dev/contracts/governance_read.v1.schema.json",
  "title": "legis governance_read.v1",
  "type": "object",
  "required": ["status", "sei", "records"],
  "additionalProperties": false,
  "properties": {
    "status": { "enum": ["checked", "unavailable"] },
    "sei": { "type": "string", "minLength": 1 },
    "records": { "type": "array", "items": { "$ref": "#/$defs/clearance_record" } },
    "unavailable": {
      "type": "array", "minItems": 1,
      "items": { "type": "object", "required": ["reason"], "additionalProperties": false,
                 "properties": { "reason": { "type": "string", "minLength": 1 } } }
    }
  },
  "allOf": [
    { "if": { "properties": { "status": { "const": "unavailable" } }, "required": ["status"] },
      "then": { "required": ["unavailable"], "properties": { "records": { "maxItems": 0 } } } },
    { "if": { "properties": { "status": { "const": "checked" } }, "required": ["status"] },
      "then": { "not": { "required": ["unavailable"] } } }
  ],
  "$defs": {
    "clearance_record": {
      "type": "object",
      "required": ["sei", "disposition", "posture", "authority", "as_of", "reasons", "content_hash"],
      "additionalProperties": false,
      "properties": {
        "sei": { "type": "string", "minLength": 1 },
        "disposition": { "enum": ["cleared"] },
        "posture": { "enum": ["protected_override", "operator_signoff"] },
        "authority": { "enum": ["operator"] },
        "as_of": { "type": "string", "format": "date-time" },
        "reasons": { "type": "array", "minItems": 1,
                     "items": { "enum": ["operator_override", "signoff_cleared"] } },
        "content_hash": { "type": "string", "minLength": 1 }
      }
    }
  }
}
```

Field meanings: `disposition` = record-level (NOT the envelope `status`, NOT your
`enrichment.governance`); v1 = `{cleared}`. `posture` = the **provable** clearance mechanism
(`protected_override` | `operator_signoff` — legis won't claim structured-vs-protected for a
sign-off). `authority` = `operator`. `as_of` = the signed `recorded_at` (RFC3339 UTC; a clearance
whose `recorded_at` is missing/non-RFC3339 is OMITTED by legis, never shipped as null). `reasons` =
closed-vocab kind codes. `content_hash` = the signed Loomweave content hash (non-empty).

### Literal samples (validate against the schema)

```json
{ "status": "checked", "sei": "loomweave:eid:7Q3f...c1", "records": [
  { "sei": "loomweave:eid:7Q3f...c1", "disposition": "cleared", "posture": "protected_override",
    "authority": "operator", "as_of": "2026-06-27T14:02:11Z", "reasons": ["operator_override"],
    "content_hash": "b3:9f2c...e7" },
  { "sei": "loomweave:eid:7Q3f...c1", "disposition": "cleared", "posture": "operator_signoff",
    "authority": "operator", "as_of": "2026-06-26T09:41:55Z", "reasons": ["signoff_cleared"],
    "content_hash": "b3:5a10...92" } ] }
```
```json
{ "status": "checked", "sei": "loomweave:eid:unknown...", "records": [] }
```
```json
{ "status": "unavailable", "sei": "loomweave:eid:7Q3f...c1", "records": [],
  "unavailable": [{ "reason": "trail not signature-verifiable (no protected gate / verifier)" }] }
```

## The three transports legis exposes (same `governance_read.v1` envelope on each)

- **MCP tool** `governance_read`, args `{ "sei": "<SEI>" }` — surfaces the envelope as its result
  (with a matching `outputSchema`); a **tampered** trail returns the MCP **error** envelope
  (`AUDIT_INTEGRITY_FAILURE`), not a result. *(You're already an MCP client of legis — likely your path.)*
- **HTTP** `GET /governance/sei/{sei}/governance-read` — body is the envelope; tampered trail = 5xx.
  (SEI is captured as a full path segment; URL-encode a SEI containing `/`.)
- **CLI** `legis governance-read <SEI>` — stdout the envelope JSON; tampered trail / missing store =
  loud (nonzero exit / `status:"unavailable"` for a genuinely absent store, never a silent `checked/[]`).

## Your `LegisGovernanceClient` — the mapping (satisfies `LegisClient` Protocol)

```python
class LegisGovernanceClient:  # satisfies warpline's LegisClient Protocol
    def governance_for_sei(self, sei: str) -> list[dict]:
        try:
            resp = self._invoke_legis_governance_read(sei)   # MCP tool / HTTP GET / CLI
        except (TransportError, LegisIntegrityError):
            raise LegisGovernanceUnavailable(sei)            # tampered/transport -> unavailable
        if resp["status"] == "unavailable":
            raise LegisGovernanceUnavailable(sei, resp.get("unavailable"))   # -> unavailable
        return resp["records"]   # [] -> absent (= "no verified clearance") ; [...] -> present
```

Then in `_h_reverify` (`warpline mcp.py:441`, the single `legis_client=None` site): pass a
`LegisGovernanceClient()`. Expected: the legis federation member flips `weft_reason: disabled` →
`clean` with records under `entities[].governance`; `enrichment.governance` flips `unavailable` →
`present` for cleared entities, `absent` otherwise.

## Acceptance (your side)

1. `LegisGovernanceClient.governance_for_sei` satisfies the `LegisClient` Protocol; in
   `reverify_worklist(include_federation=True)` the legis member is `clean` (not `disabled`) with
   records for a known-cleared entity.
2. Reachable SEI, no clearance → `[]` → `absent`; unavailable/tampered legis → **raises** →
   `unavailable`. Never the reverse (`GV-LG`/`GOV-2` discipline).
3. A test asserts `enrichment.governance` does NOT affect the reverify decision (advisory boundary;
   `GV-LG-1` `governance_verdict` stays absent).
4. A captured real legis response validates against `governance_read.v1.schema.json` (the tightened
   discriminated-union version above).
