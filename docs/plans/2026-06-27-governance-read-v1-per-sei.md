# governance_read.v1 — per-SEI governance read (warpline→legis seam) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to execute this plan task-by-task.
> **REVISION 2** — incorporates the 7-agent review (CHANGES_REQUESTED → addressed): the CLI
> false-green (must-fix #1), the tautological oracle (#2), missing-DB downgrade (#3), schema
> discriminator (#5), as_of guard (#6), MCP `_one_of` outputSchema (#7), durable artifacts (#8), and
> all warnings. The contract (`contracts/governance_read.v1.schema.json` + the warpline prompt at
> `docs/contracts/warpline-governance-read.v1-prompt.md`) is **already authored & on disk** (the
> tightened, discriminated-union version) — Task 1 tests + commits it, it does not re-derive it.

**Goal:** Expose legis's verified per-SEI governance clearances as the published `governance_read.v1`
contract on CLI + MCP + HTTP, so warpline's `reverify_worklist(include_federation=True)` can enrich
its worklist advisorily (never gate) with legis governance facts.

**Architecture:** Project the EXISTING forge-proof per-SEI read (`read_sei_attestations`,
`service/governance.py:223`) into a posture-record shape. One service projection
(`read_governance_for_sei`) + a verified-gate wrapper (`read_governance_for_sei_gate`, mirroring
`evaluate_override_rate_gate`) + a shared unavailable-envelope helper, all in `service/governance.py`.
Three thin adapters; each owns its fail-closed "is the trail signature-verifiable?" pre-gate exactly
as `attestation_get` does. The wire shape is FROZEN in `contracts/governance_read.v1.schema.json`.

**Tech Stack:** Python 3.12, `uv`, FastAPI, JSON-RPC stdio, argparse, `jsonschema>=4.21`, pytest.

**Prerequisites:**
- `uv sync --dev` run.
- Read before starting: `service/governance.py:223-350` (`read_sei_attestations`, the forge-proof
  core) and `:381-409` (`evaluate_override_rate_gate`, the verify-gate pattern Task 2/5 mirror);
  `mcp.py:324` (`_one_of`), `:2292-2333` (`_governance_trail_records`, `_tool_attestation_get`),
  `:1268-1316` (the `attestation_get` `_one_of` outputSchema); `api/app.py:717-723` + `:865-871`;
  `cli.py:263` (`_missing_sqlite_db`), `:287-329` (`_check_override_rate`); the FROZEN
  `contracts/governance_read.v1.schema.json`; `tests/conformance/test_warpline_attestation_oracle.py`
  (the frozen-golden pattern Task 3's oracle mirrors).

---

## Global Constraints (every task; the reviewer's attention lens — copy verbatim)

1. **FAIL-CLOSED / no false-green (cardinal sin).** Unverifiable trail → `status:"unavailable"`
   (discriminated, with reason), NEVER silent `records:[]`. A tampered trail (signature OR
   hash-chain contiguity) RAISES loudly. `records:[]` is reachable ONLY under `status:"checked"`.
   **Both verification halves are mandatory on every path: `store.verify_integrity()` (the chain /
   delete-reorder-truncate defence) AND `TrailVerifier.verify()` (signatures).** `TrailVerifier.verify`
   alone is NOT sufficient — it has no seq-contiguity walk (that lives only in `verify_integrity`).
2. **Honest scope (cleared-only, v1).** `records:[]` = "no verified clearance for this SEI on the
   verified trail" — NOT "ungoverned," NOT "unknown SEI." legis is an SEI consumer; it cannot and
   must not pretend to distinguish unknown-from-ungoverned.
3. **Forge-proofing inherited, not re-implemented.** `read_governance_for_sei` obtains records ONLY
   by calling `read_sei_attestations`; no trail re-walk, no re-derived admission, no unsigned field.
4. **`posture` claims only the PROVABLE mechanism.** `operator_override` → `"protected_override"`;
   `signoff_cleared` → `"operator_signoff"`. Never an enforcement cell for a sign-off.
5. **Record field is `disposition`, not `status`** (avoids the envelope-status / enrichment.governance
   3-way collision).
6. **Service layer is single source of truth.** The projection, the verified-gate wrapper, and the
   unavailable helper live in `service/governance.py`; adapters are thin; no governance decision
   duplicated in an adapter (the CLI verify path goes through the service wrapper, NOT a hand-rolled
   `TrailVerifier` call).
7. **Guardrails (must not degrade):** advisory-boundary byte-identity; attestation forge-resistance
   (reused, untouched); coverage floors via `scripts/check_coverage_floors.py` — actual floors are
   **`src/legis/service/` = 92.0, `src/legis/mcp.py` = 80.0, `src/legis/api/` = 88.0** (global 88);
   all CI gates green (pytest, mypy `src/legis`, ruff `E4/E7/E9/F`, SEI oracle, policy-boundary,
   governance-gate).
8. **No contract mutation post-commit, no touching** `audit_store.py`/`head_anchor.py`/`canonical.py`
   (stays `ensure_ascii=False`). Signing keys out of reach. `.v1` is a one-way door — any change is
   `.v2`, never an edit.
9. Commit trailer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Do NOT push
   or open a PR (owner-gated). Implementers: commit ONLY your task's files; no history mutation.

---

### Task 1: Test + commit the FROZEN contract (`governance_read.v1.schema.json`)

The schema and the warpline prompt are ALREADY on disk (authored as the contract freeze). This task
adds the validation tests and commits all three together.

**Files:**
- Already on disk (commit, do not rewrite): `contracts/governance_read.v1.schema.json`,
  `docs/contracts/warpline-governance-read.v1-prompt.md`
- Create: `tests/contract/test_governance_read_v1_schema.py`  (dir is `tests/contract`, NO `s`)
- Modify: `pyproject.toml` dev group — add `"jsonschema[format]"` (enables the `date-time` format
  assertion; `jsonschema` is already pinned, this adds the rfc3339 backend). Run `uv sync --dev`.

**Step 1: Write the failing test** — load `contracts/governance_read.v1.schema.json`, build
`Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)`. Tests:
- POSITIVE: checked+two-clearances validates; checked+empty-records validates; unavailable+reason
  validates.
- DISCRIMINATOR NEGATIVES (must-fix #5): `test_unavailable_without_reason_rejected`
  (`{status:unavailable, records:[]}` no `unavailable` key → rejected); `test_unavailable_with_records_rejected`
  (`{status:unavailable, records:[rec], unavailable:[…]}` → rejected); `test_checked_with_unavailable_key_rejected`.
- CONSTRAINT NEGATIVES (warnings): `test_unknown_status_rejected`; `test_record_extra_field_rejected`;
  `test_envelope_extra_field_rejected`; `test_empty_content_hash_rejected`; `test_empty_envelope_sei_rejected`;
  `test_empty_record_sei_rejected`; `test_empty_reasons_rejected` (minItems:1); `test_invalid_posture_rejected`.
- FORMAT (must-fix #6): `test_non_rfc3339_as_of_rejected` (`as_of:"not-a-date"` → rejected *because*
  `format_checker` is wired; assert it passes WITHOUT the checker to prove the checker is load-bearing).
- DRIFT GUARD (must-fix #8): `test_prompt_schema_block_matches_committed_file` — extract the JSON
  fenced block under "## The contract" in `docs/contracts/warpline-governance-read.v1-prompt.md`,
  `json.loads` both it and the committed schema file, assert the two parsed objects are EQUAL
  (JSON-equal, not byte-equal — robust to whitespace).

The reference shapes for these tests are the three literal samples in the warpline prompt + the
ad-hoc bad shapes; reuse the validation matrix already proven in
`scratchpad`-free form (the schema was validated at authoring — these tests pin it permanently).

**Step 2: Run to verify failure** — `uv run pytest tests/contract/test_governance_read_v1_schema.py -v`
(fails: test file absent / `jsonschema[format]` not synced).

**Step 3:** No schema to write (frozen on disk). Add the dep, `uv sync --dev`, write the tests.

**Step 4: Run to verify pass** — same command; all green. `uv run python -c "import json,jsonschema;
jsonschema.Draft202012Validator.check_schema(json.load(open('contracts/governance_read.v1.schema.json')))"`.

**Step 5: Commit** — schema + prompt + tests + pyproject change, one "freeze governance_read.v1
contract" commit.

**Definition of Done:**
- [ ] All positive + 3 discriminator-negative + 8 constraint-negative + 1 format + 1 drift test pass.
- [ ] `format_checker` is wired and proven load-bearing (the without-checker assertion).
- [ ] Prompt's schema block parses EQUAL to the committed schema file.
- [ ] Contract committed; `.v1` is now frozen (changes → `.v2`).

---

### Task 2: Service — projection + verified-gate wrapper + unavailable helper

**Files:**
- Modify: `src/legis/service/governance.py` (after `read_sei_attestations`, ~line 350)
- Modify: `src/legis/service/__init__.py` (export `read_governance_for_sei`,
  `read_governance_for_sei_gate`, `governance_read_unavailable`)
- Test: `tests/service/test_governance_read.py`

**Step 1: Write the failing test** — cover:
- `test_projects_override_to_clearance_record`: a record admitted as `operator_override` →
  `posture:"protected_override"`, full dict asserted. **Fixture uses `Verdict.OVERRIDDEN_BY_OPERATOR.value`,
  not the literal string** (warning), with a comment naming the coupling.
- `test_signoff_projection_full_dict` (monkeypatch `read_sei_attestations`): assert the WHOLE record
  dict (sei/disposition/posture=`operator_signoff`/authority/as_of/reasons/content_hash), not just
  posture (warning: expand the signoff test).
- `test_verified_but_no_clearance_is_checked_empty` → `{status:checked, sei, records:[]}` (honest
  absence, NOT unavailable).
- `test_as_of_none_is_omitted` (must-fix #6): monkeypatch `read_sei_attestations` to return an
  attestation with `recorded_at: None` → the record is OMITTED (empty records), not emitted with
  `as_of: null`.
- `test_as_of_non_rfc3339_is_omitted` (must-fix #6): `recorded_at:"garbage"` → omitted.
- `test_unknown_kind_is_omitted` (warning): monkeypatch an attestation with `kind:"future_kind"` →
  `_POSTURE_BY_KIND.get` returns None → omitted (WHEN IN DOUBT, OMIT), no KeyError crash.
- `test_status_propagated_not_hardcoded`: monkeypatch `read_sei_attestations` to return
  `status:"checked"` (current invariant) and assert the wrapper carries it; add an assert/guard so a
  future non-`checked` status from `read_sei_attestations` does not get silently relabeled.
- `test_gate_raises_on_signature_tamper` (must-fix #1): build a protected record set, corrupt a
  signature, call `read_governance_for_sei_gate(records, sei, hmac_key=…, protected_policies=…)` →
  raises `AuditIntegrityError`.
- `test_gate_requires_key_for_protected`: protected records present, `hmac_key=None` → raises
  `ProtectedKeyRequiredError`.
- `test_unavailable_helper_shape`: `governance_read_unavailable(sei, "reason")` →
  `{status:unavailable, sei, records:[], unavailable:[{reason}]}`.

**Step 2: Run to verify failure** (`ImportError`).

**Step 3: Implement** in `service/governance.py`:

```python
from datetime import datetime

_POSTURE_BY_KIND = {
    "operator_override": "protected_override",   # provable: protected_cell + OVERRIDDEN_BY_OPERATOR signed
    "signoff_cleared": "operator_signoff",       # provable: SIGNED_OFF + integrity-bound request
}
# Three coupled points: read_sei_attestations' admitted kinds, these map keys, and the schema's
# `posture` enum. A new clearance kind must update all three. reasons = clearance-kind code (WHAT
# happened); posture = provable mechanism (HOW) — distinct axes, 1:1 in v1.


def _is_rfc3339(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def read_governance_for_sei(verified_runtime_records: list, sei: str) -> dict[str, Any]:
    """Per-SEI VERIFIED GOVERNANCE CLEARANCES as the ``governance_read.v1`` envelope.

    A pure PROJECTION of ``read_sei_attestations`` (the forge-proof admitted set) — adds NO admission
    logic and reads NO unsigned field, inheriting the signature-coverage/asymmetric-error guarantees.
    A clearance whose ``recorded_at`` is absent or non-RFC3339, or whose ``kind`` has no known
    posture, is OMITTED (asymmetric-error: a missing clearance only wastes warpline work; a malformed
    one is the unsafe direction). The caller owns the ``status:"unavailable"`` pre-gate via
    ``governance_read_unavailable`` for the no-key / unverifiable-trail case.
    """
    att = read_sei_attestations(verified_runtime_records, sei)
    if att.get("status") != "checked":
        # read_sei_attestations is contracted to return "checked" here (the handler owns the
        # unavailable pre-gate). If that ever changes, fail loud rather than relabel it "checked".
        raise AuditIntegrityError(
            f"read_sei_attestations returned unexpected status {att.get('status')!r}"
        )
    records: list[dict[str, Any]] = []
    for a in att["attestations"]:
        posture = _POSTURE_BY_KIND.get(a["kind"])
        if posture is None:
            continue  # unknown kind -> omit, never fabricate a posture
        if not _is_rfc3339(a.get("recorded_at")):
            continue  # missing / malformed timestamp -> omit, never ship as_of:null
        records.append(
            {
                "sei": sei,
                "disposition": "cleared",
                "posture": posture,
                "authority": "operator",
                "as_of": a["recorded_at"],
                "reasons": [a["kind"]],
                "content_hash": a["content_hash"],
            }
        )
    return {"status": "checked", "sei": sei, "records": records}


def read_governance_for_sei_gate(
    records: list, sei: str, *, hmac_key: str | None, protected_policies
) -> dict[str, Any]:
    """Verified governance read for the CLI/batch path: detect protected -> require key -> verify
    signatures (fail closed) -> project. Mirrors ``evaluate_override_rate_gate`` exactly, so the CLI
    measures the same trust the HTTP/MCP paths do (Constraint 6). The store-level hash-chain check
    (``verify_integrity``) is the CALLER's responsibility BEFORE this call (as in
    ``_check_override_rate``) — both halves are mandatory (Constraint 1).
    """
    protected_present = any(
        _requires_protected_verification(r.payload, protected_policies) for r in records
    )
    if protected_present and not hmac_key:
        raise ProtectedKeyRequiredError(
            "Protected audit records require LEGIS_HMAC_KEY for verification"
        )
    if hmac_key:
        verifier = TrailVerifier(hmac_key.encode("utf-8"), protected_policies)
        try:
            verifier.verify(records)
        except TamperError as exc:
            raise AuditIntegrityError(
                f"Protected audit trail verification failed: {exc}"
            ) from exc
    return read_governance_for_sei(records, sei)


def governance_read_unavailable(sei: str, reason: str) -> dict[str, Any]:
    """The shared ``governance_read.v1`` unavailable envelope (one shape across all 3 adapters).
    NEVER a silent ``checked``/``[]`` — an unverifiable trail reads as "could not check" (GOV-2)."""
    return {"status": "unavailable", "sei": sei, "records": [], "unavailable": [{"reason": reason}]}
```

(`TamperError` is already imported in `governance.py` for `evaluate_override_rate_gate`; confirm and
reuse the same import. `AuditIntegrityError`, `ProtectedKeyRequiredError`,
`_requires_protected_verification`, `TrailVerifier` likewise.)

**Step 4: Run to verify pass**; then `uv run mypy src/legis`.

**Step 5: Commit.**

**Definition of Done:**
- [ ] All ~10 tests pass; mypy clean.
- [ ] Projection calls `read_sei_attestations`; omits unknown-kind / bad-`as_of`; propagates/guards
  status; reads no unsigned field.
- [ ] `read_governance_for_sei_gate` mirrors `evaluate_override_rate_gate` (key-required + signature
  verify, `AuditIntegrityError` on tamper); three names exported.

---

### Task 3: MCP tool `governance_read` (handler + `_one_of` outputSchema + frozen-golden oracle)

**Files:**
- Modify: `src/legis/mcp.py` — name list (~106); tool def w/ `_one_of` outputSchema (near the
  `attestation_get` def ~1268); handler (near `_tool_attestation_get` ~2308); `_TOOL_HANDLERS`
  registry (~2568, the dict is `_TOOL_HANDLERS`, not `_TOOLS`).
- Test: `tests/mcp/test_governance_read_tool.py`
- Modify: `tests/mcp/test_output_schema_conformance.py` (per-tool tests — add explicit cases for the
  new tool's BOTH variants; this file is NOT auto-iterating).
- Create: `tests/conformance/test_governance_read_oracle.py` (FROZEN GOLDEN — mirror
  `test_warpline_attestation_oracle.py`)
- Create (committed by the oracle on first run): `tests/conformance/fixtures/governance_read_*.json`

**Step 1: Write the failing tests:**
- Handler tests: (a) verifiable trail with a clearance → `{status:checked, records:[…]}`;
  (b) `protected_gate is None or trail_verifier is None` → `{status:unavailable, …}` (NOT empty
  checked); (c) tampered trail → `AuditIntegrityError` → `AUDIT_INTEGRITY_FAILURE` error envelope.
  Reuse runtime fixtures from `tests/mcp/test_attestation*.py`.
- outputSchema conformance: add two explicit cases in `test_output_schema_conformance.py` — the
  `checked` variant and the `unavailable` variant of `governance_read` each validate against the
  declared `_one_of` outputSchema.
- **Frozen-golden oracle** (must-fix #2): mirror `test_warpline_attestation_oracle.py` exactly —
  `_build_attested_store` (reuse the attestation oracle's helper) to write GENUINE signed records for
  BOTH clearance kinds; `call_tool(runtime, "governance_read", {"sei": _SEI})`; write
  `structuredContent` to a committed fixture; pin its git blob SHA1 as `GOLDEN_BLOB_SHA`; the test
  asserts LIVE output == FROZEN golden by VALUE (not `schema.validate(live)`). Add
  `test_both_clearance_kinds_are_pinned`. The golden is a projection of the existing attestation
  golden — cross-check the content_hashes match.

**Step 2: Run to verify failure** (unknown tool / missing fixture).

**Step 3: Implement** — handler mirrors `_tool_attestation_get`:

```python
def _tool_governance_read(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    from legis.service.governance import governance_read_unavailable, read_governance_for_sei

    sei = _require(args, "sei")
    # FAIL-CLOSED pre-gate (same invariant as attestation_get): a verifiable answer needs BOTH a
    # protected gate AND a trail_verifier. Missing either -> unavailable (discriminated), never [].
    if runtime.protected_gate is None or runtime.trail_verifier is None:
        return _tool_result(
            governance_read_unavailable(
                sei, "trail not signature-verifiable (no protected gate / verifier)"
            )
        )
    # _governance_trail_records -> verified_records runs BOTH verify_integrity (chain) and
    # TrailVerifier.verify (signatures), raising AuditIntegrityError (-> AUDIT_INTEGRITY_FAILURE) on
    # a tampered protected trail (loud, never a result).
    return _tool_result(read_governance_for_sei(_governance_trail_records(runtime), sei))
```

Tool def: inputSchema `{sei: string, required}`; **outputSchema built with `_one_of([checked_variant,
unavailable_variant])` using the v1 `clearance_record` fields** (NOT attestation_get's fields,
must-fix #7) — `checked_variant`: `status:const checked`, `records` array of the 7-field record;
`unavailable_variant`: `status:const unavailable`, `records` maxItems 0, `unavailable` array of
`{reason}`. Description: "Per-SEI VERIFIED governance CLEARANCE facts (governance_read.v1).
Advisory — never gate on this. records:[] under 'checked' = no verified clearance, NOT ungoverned;
'unavailable' ≠ 'absent'." Register in the name list + `_TOOL_HANDLERS`.

**Step 4: Run to verify pass** — the tool tests + the oracle + `test_output_schema_conformance.py`
(and any meta-test that every tool has an outputSchema).

**Step 5: Commit** (incl. the committed golden fixture).

**Definition of Done:**
- [ ] Tool registered (name list, def w/ `_one_of` outputSchema over v1 fields, `_TOOL_HANDLERS`).
- [ ] Unavailable pre-gate gates on BOTH objects; tamper → `AUDIT_INTEGRITY_FAILURE`.
- [ ] Oracle is a FROZEN GOLDEN with a pinned blob SHA, asserting LIVE == FROZEN (not schema-validate);
  both clearance kinds pinned.

---

### Task 4: HTTP route `GET /governance/sei/{sei:path}/governance-read`

**Files:**
- Modify: `src/legis/api/app.py` (route near `identity_gaps`/`lineage_integrity` ~865; import the two
  service fns with the other service imports)
- Test: `tests/api/test_governance_read_route.py`

**Step 1: Write the failing test** — TestClient: (a) wired gate+verifier + a clearance → 200
`{status:checked, records:[…]}`; (b) no gate/verifier → 200 `{status:unavailable, …}`; (c) tampered
trail → 500. Add (d) a SEI containing `/` (e.g. URL-encoded) round-trips to the handler (the
`{sei:path}` capture, warning). Mirror the identity-gap/lineage app-construction fixtures.

**Step 2: Run to verify failure** (404).

**Step 3: Implement** inside `create_app`:

```python
    @app.get("/governance/sei/{sei:path}/governance-read")
    def governance_read(sei: str) -> dict:
        # {sei:path} captures a SEI that may contain '/'. FAIL-CLOSED pre-gate mirrors the MCP tool;
        # verified_governance_records() runs BOTH chain + signature checks and maps tamper to HTTP 500.
        if protected_gate is None or trail_verifier is None:
            return _governance_read_unavailable(
                sei, "trail not signature-verifiable (no protected gate / verifier)"
            )
        return _read_governance_for_sei(verified_governance_records(), sei)
```

Import `read_governance_for_sei as _read_governance_for_sei`, `governance_read_unavailable as
_governance_read_unavailable`.

**Step 4: Run to verify pass.**

**Step 5: Commit.**

**Definition of Done:**
- [ ] Route returns the v1 envelope; unavailable w/o gate/verifier; 500 on tamper; `{sei:path}`
  handles a `/`-bearing SEI.

---

### Task 5: CLI `legis governance-read <sei>` (verified path through the service gate)

**Files:**
- Modify: `src/legis/cli.py` — subparser near `governance-gate` (~109); dispatch near ~741; the
  `_governance_read(db_url, sei)` helper near `_check_override_rate` (~292)
- Test: `tests/cli/test_governance_read_cli.py`

**Step 1: Write the failing test** (mirror existing CLI test invocation):
- (a) `LEGIS_HMAC_KEY` set + verifiable store w/ a clearance → exit 0, stdout JSON `{status:checked,
  records:[…]}`.
- (b) NO `LEGIS_HMAC_KEY` → exit 0, stdout `{status:unavailable,…}` (can't verify sigs).
- (c) **CHAIN-tampered store** (delete/reorder a non-protected record — NOT just a bad signature,
  must-fix #1) → nonzero exit AND stderr contains "audit integrity". This is the false-green
  regression test; it MUST exercise `verify_integrity`, which `TrailVerifier.verify` alone would miss.
- (d) signature-tampered protected store → nonzero exit + "audit integrity" on stderr.
- (e) **missing/relocated DB** (point `--db` at a nonexistent path, must-fix #3) → stdout
  `{status:unavailable,…}` ("governance store not found"), NOT a silent `checked/[]` from an
  auto-created empty DB.

**Step 2: Run to verify failure.**

**Step 3: Implement** — subparser `governance-read` with positional `sei` and `--db`
(default `governance_db_url()`); **no `--json` flag** (output is always JSON; warning). Dispatch
branch `if args.command == "governance-read": return _governance_read(args.db, args.sei)`. Helper:

```python
def _governance_read(db_url: str, sei: str) -> int:
    import os
    from legis.config import protected_policies
    from legis.service.errors import AuditIntegrityError, ProtectedKeyRequiredError
    from legis.service.governance import governance_read_unavailable, read_governance_for_sei_gate
    from legis.store.audit_store import AuditStore

    hmac_key = os.environ.get("LEGIS_HMAC_KEY")
    if not hmac_key:
        # No key -> signatures unverifiable from the CLI -> unavailable, never silent checked/[].
        print(json.dumps(governance_read_unavailable(
            sei, "trail not signature-verifiable (LEGIS_HMAC_KEY unset)"), sort_keys=True))
        return 0
    missing_db = _missing_sqlite_db(db_url)
    if missing_db is not None:
        # Absent store on a READ = unavailable (NOT the override-rate CI PASS_WITH_NOTICE axis, and
        # NOT an auto-created empty DB read as checked/[]).
        print(json.dumps(governance_read_unavailable(
            sei, f"governance store not found: {missing_db}"), sort_keys=True))
        return 0
    store = AuditStore(db_url)
    if not store.verify_integrity():  # the chain / delete-reorder-truncate half (mandatory)
        print("Error: audit integrity failure: database hash chain verification failed", file=sys.stderr)
        return 1
    records = store.read_all()
    try:  # the signature half, through the service gate (Constraint 6)
        envelope = read_governance_for_sei_gate(
            records, sei, hmac_key=hmac_key, protected_policies=protected_policies())
    except (ProtectedKeyRequiredError, AuditIntegrityError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(envelope, sort_keys=True))
    return 0
```

**Step 4: Run to verify pass** — especially the chain-tamper (c) and missing-DB (e) cases.

**Step 5: Commit.**

**Definition of Done:**
- [ ] Both verify halves run: `store.verify_integrity()` (chain) BEFORE `read_all`, then the service
  gate (signatures). Chain-tamper test (c) is RED without `verify_integrity`, GREEN with it.
- [ ] No key → unavailable; missing DB → unavailable; tamper → nonzero + "audit integrity" stderr.
- [ ] Exceptions caught are `ProtectedKeyRequiredError`/`AuditIntegrityError` (TamperError is wrapped
  inside the service gate) — no bare `except`.

---

### Task 6: Guardrails — advisory-boundary pin, coverage floors, full gate sweep

**Files:** `tests/mcp/test_warpline_advisory_boundary.py` (one edit); otherwise verification.

**Steps:**
1. **Advisory-boundary structural pin** (warning): add `read_governance_for_sei`,
   `read_governance_for_sei_gate`, and `governance_read_unavailable` to the explicit symbol list in
   `test_runtime_warpline_referenced_in_no_verdict_path_function`
   (`tests/mcp/test_warpline_advisory_boundary.py:~218-235`), so the new service fns are pinned as
   non-verdict-path. Run that file + the byte-identity advisory test — both green.
2. **Forge-resistance untouched:** `uv run pytest -k "attestation"` green.
3. **Coverage floors** (corrected numbers): `uv run pytest --cov=legis --cov-fail-under=88` then
   `uv run python scripts/check_coverage_floors.py` — `service/` ≥92, `mcp.py` ≥80, `api/` ≥88. Add a
   missing unavailable/tamper-branch test if a floor dips.
4. **Full CI-equivalent sweep:** `uv run ruff check src`, `uv run mypy src/legis`,
   `uv run pytest tests/conformance/test_sei_oracle.py`,
   `uv run legis policy-boundary-check --root src --repo-root .`, `uv run legis governance-gate`.
5. **Cross-transport schema agreement:** one captured MCP result (the Task 3 golden), one HTTP body,
   and one CLI stdout each validate against `contracts/governance_read.v1.schema.json` (with the
   format checker).

**Definition of Done:**
- [ ] Advisory-boundary tests green; the three new service fns pinned in the structural test.
- [ ] All coverage floors hold (corrected: service 92 / mcp 80 / api 88); all CI gates green locally.
- [ ] One captured output per transport validates against the frozen v1 schema.

---

## Execution notes for the controller

- **Scope gate (review must-fix #4):** the owner directed parallel execution (warpline is building
  its side now), so cleared-only v1 proceeds. It is a SAFE SUBSET — a future `governance_read.v2`
  that ADDS dispositions/kinds leaves every v1 record valid. The cleared-only scope is flagged to
  warpline in the prompt for pre-finalize confirmation; do NOT expand scope here. If warpline needs
  in-flight governance, that is a `.v2` + a new plan, never a v1 edit.
- **Schema amendment (must-fix #5):** already applied — the committed schema enforces the
  discriminated union, and the warpline prompt carries the same tightened bytes + a
  backward-compatible note. No further coordination needed unless warpline reports a consumer break
  (it should not — the tightening only constrains legis's own output).
- Order is strict: Task 1 (contract) → Task 2 (service) → Tasks 3/4/5 (adapters, each depends on
  Task 2) → Task 6. Within each task: TDD (red → green → commit).
- Local merge only; do NOT push or open a PR (owner-gated, like the prior three findings).
