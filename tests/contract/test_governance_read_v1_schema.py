"""Contract freeze test for governance_read.v1.

These tests pin the JSON schema at contracts/governance_read.v1.schema.json and the
warpline hand-off prompt at docs/contracts/warpline-governance-read.v1-prompt.md.
.v1 is a ONE-WAY DOOR — any change to the validation logic requires a .v2 schema and
a new plan, never an in-place edit.

TDD note: the format test (test_non_rfc3339_as_of_rejected) is the RED→GREEN signal for
this task — it ONLY passes when jsonschema[format] (rfc3339-validator backend) is installed.

Cross-transport schema agreement: the ``test_cross_transport_*`` tests each capture a REAL
output (MCP golden / HTTP body / CLI stdout) from the respective transport and validate it
against the committed frozen schema with the rfc3339 format checker wired. This ensures that
all three adapters produce output that conforms to the same frozen contract.
"""
import json
import pathlib
import re

import pytest
from jsonschema import Draft202012Validator

# ── paths ──────────────────────────────────────────────────────────────────────
_REPO = pathlib.Path(__file__).parent.parent.parent  # legis repo root
_SCHEMA_PATH = _REPO / "contracts" / "governance_read.v1.schema.json"
_PROMPT_PATH = _REPO / "docs" / "contracts" / "warpline-governance-read.v1-prompt.md"

# ── fixtures ───────────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def schema():
    with open(_SCHEMA_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def validator(schema):
    """Draft202012Validator WITH format checking (rfc3339-validator backend required)."""
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


# Sample data ──────────────────────────────────────────────────────────────────
_SEI = "loomweave:eid:7Q3f...c1"

_RECORD_OVERRIDE = {
    "sei": _SEI,
    "disposition": "cleared",
    "posture": "protected_override",
    "authority": "operator",
    "as_of": "2026-06-27T14:02:11Z",
    "reasons": ["operator_override"],
    "content_hash": "b3:9f2c...e7",
}
_RECORD_SIGNOFF = {
    "sei": _SEI,
    "disposition": "cleared",
    "posture": "operator_signoff",
    "authority": "operator",
    "as_of": "2026-06-26T09:41:55Z",
    "reasons": ["signoff_cleared"],
    "content_hash": "b3:5a10...92",
}


# ── POSITIVE TESTS ─────────────────────────────────────────────────────────────

def test_checked_two_clearances_valid(validator):
    """Sample 1 from the warpline prompt: checked + two clearance records."""
    doc = {"status": "checked", "sei": _SEI, "records": [_RECORD_OVERRIDE, _RECORD_SIGNOFF]}
    validator.validate(doc)


def test_checked_empty_records_valid(validator):
    """Sample 2: checked + empty records (honest absence, not ungoverned)."""
    doc = {"status": "checked", "sei": "loomweave:eid:unknown...", "records": []}
    validator.validate(doc)


def test_unavailable_with_reason_valid(validator):
    """Sample 3: unavailable + reason array."""
    doc = {
        "status": "unavailable",
        "sei": _SEI,
        "records": [],
        "unavailable": [{"reason": "trail not signature-verifiable (no protected gate / verifier)"}],
    }
    validator.validate(doc)


# ── DISCRIMINATOR NEGATIVES ────────────────────────────────────────────────────
# The schema enforces the discriminated union: status=unavailable REQUIRES the
# `unavailable` key (non-empty) AND records:[] (maxItems 0); status=checked FORBIDS it.

def test_unavailable_without_reason_rejected(validator):
    """status:unavailable without the `unavailable` key is REJECTED (must-fix #5)."""
    bad = {"status": "unavailable", "sei": _SEI, "records": []}
    errors = list(validator.iter_errors(bad))
    assert errors, "schema should have rejected unavailable without `unavailable` key"


def test_unavailable_with_records_rejected(validator):
    """status:unavailable with non-empty records is REJECTED (maxItems:0 enforced)."""
    bad = {
        "status": "unavailable",
        "sei": _SEI,
        "records": [_RECORD_OVERRIDE],
        "unavailable": [{"reason": "some-reason"}],
    }
    errors = list(validator.iter_errors(bad))
    assert errors, "schema should have rejected unavailable with non-empty records"


def test_checked_with_unavailable_key_rejected(validator):
    """status:checked with the `unavailable` key is REJECTED (not: required[unavailable])."""
    bad = {
        "status": "checked",
        "sei": _SEI,
        "records": [],
        "unavailable": [{"reason": "this should not be here"}],
    }
    errors = list(validator.iter_errors(bad))
    assert errors, "schema should have rejected checked with `unavailable` key present"


# ── CONSTRAINT NEGATIVES ───────────────────────────────────────────────────────

def test_unknown_status_rejected(validator):
    bad = {"status": "unknown", "sei": _SEI, "records": []}
    assert list(validator.iter_errors(bad))


def test_record_extra_field_rejected(validator):
    """clearance_record has additionalProperties:false."""
    rec = {**_RECORD_OVERRIDE, "extra_field": "not-allowed"}
    bad = {"status": "checked", "sei": _SEI, "records": [rec]}
    assert list(validator.iter_errors(bad))


def test_envelope_extra_field_rejected(validator):
    """Envelope has additionalProperties:false."""
    bad = {"status": "checked", "sei": _SEI, "records": [], "unexpected": "value"}
    assert list(validator.iter_errors(bad))


def test_empty_content_hash_rejected(validator):
    """content_hash has minLength:1 — empty string is rejected."""
    rec = {**_RECORD_OVERRIDE, "content_hash": ""}
    bad = {"status": "checked", "sei": _SEI, "records": [rec]}
    assert list(validator.iter_errors(bad))


def test_empty_envelope_sei_rejected(validator):
    """Envelope sei has minLength:1 — empty string is rejected."""
    bad = {"status": "checked", "sei": "", "records": []}
    assert list(validator.iter_errors(bad))


def test_empty_record_sei_rejected(validator):
    """clearance_record sei has minLength:1 — empty string is rejected."""
    rec = {**_RECORD_OVERRIDE, "sei": ""}
    bad = {"status": "checked", "sei": _SEI, "records": [rec]}
    assert list(validator.iter_errors(bad))


def test_empty_reasons_rejected(validator):
    """reasons has minItems:1 — empty array is rejected."""
    rec = {**_RECORD_OVERRIDE, "reasons": []}
    bad = {"status": "checked", "sei": _SEI, "records": [rec]}
    assert list(validator.iter_errors(bad))


def test_invalid_posture_rejected(validator):
    """posture is a closed enum; unknown value is rejected."""
    rec = {**_RECORD_OVERRIDE, "posture": "chill"}
    bad = {"status": "checked", "sei": _SEI, "records": [rec]}
    assert list(validator.iter_errors(bad))


# ── FORMAT TEST ────────────────────────────────────────────────────────────────

def test_non_rfc3339_as_of_rejected(schema, validator):
    """as_of: "not-a-date" must be rejected WHEN format_checker is wired.

    The WITH-checker assertion is the RED→GREEN signal for jsonschema[format].
    The WITHOUT-checker assertion proves the checker is load-bearing
    (the format keyword alone does not validate without a backend).
    """
    rec = {**_RECORD_OVERRIDE, "as_of": "not-a-date"}
    bad = {"status": "checked", "sei": _SEI, "records": [rec]}

    # WITHOUT format_checker: format assertions are silently skipped → valid
    validator_no_checker = Draft202012Validator(schema)
    errors_without = list(validator_no_checker.iter_errors(bad))
    assert not errors_without, (
        "Without format_checker the schema should still accept 'not-a-date' (format not enforced); "
        f"got errors: {errors_without}"
    )

    # WITH format_checker (rfc3339-validator backend required): must REJECT "not-a-date"
    errors_with = list(validator.iter_errors(bad))
    assert errors_with, (
        "With format_checker the schema should reject as_of:'not-a-date' — "
        "this assertion fails if rfc3339-validator is not installed (jsonschema[format] missing)"
    )


# ── DRIFT GUARD ────────────────────────────────────────────────────────────────

def _strip_descriptions(obj):
    """Recursively remove 'description' keys (non-validating annotations).

    The committed schema carries descriptions on every property for human readers;
    the warpline prompt carries an equivalent condensed block without them (the
    prose provides the semantics). The drift guard compares STRUCTURAL content only.
    Strip only 'description' — 'title' and all validating keywords are preserved so
    that enum, type, minLength, format, allOf, etc. drift is still caught.
    """
    if isinstance(obj, dict):
        return {k: _strip_descriptions(v) for k, v in obj.items() if k != "description"}
    if isinstance(obj, list):
        return [_strip_descriptions(item) for item in obj]
    return obj


def test_prompt_schema_block_matches_committed_file():
    """The JSON block embedded in the warpline prompt must match the committed schema.

    Structural (non-description) equality is asserted. If this test fails, the prompt
    and the committed schema have diverged on a validating keyword — a genuine drift
    that must be resolved (never buried by altering the comparison).

    Note: the prompt header claims 'byte-equal' and the plan says 'JSON-equal'; the
    only difference between the files is description annotations (non-validating).
    Stripping descriptions before comparing keeps the guard strict on every keyword
    that affects validation behaviour.
    """
    with open(_SCHEMA_PATH) as f:
        committed = json.load(f)

    with open(_PROMPT_PATH) as f:
        content = f.read()

    # Extract the first JSON fenced block under the "## The contract" heading
    m = re.search(
        r"## The contract.*?\n```json\n(.*?)\n```",
        content,
        re.DOTALL,
    )
    assert m, "Could not find a JSON fenced block under '## The contract' in the warpline prompt"
    prompt_block = json.loads(m.group(1))

    committed_stripped = _strip_descriptions(committed)
    prompt_stripped = _strip_descriptions(prompt_block)
    assert committed_stripped == prompt_stripped, (
        "Structural drift detected between the committed schema and the prompt's embedded block. "
        "Diff (committed keys only in descriptions are expected and ignored): resolve any "
        "difference in validating keywords (type, enum, minLength, format, allOf, etc.) before "
        "committing. A .v1 change is never allowed — use .v2."
    )


# ── CROSS-TRANSPORT SCHEMA AGREEMENT ──────────────────────────────────────────
# Each test below captures a REAL output from one transport (MCP golden / HTTP /
# CLI) and validates it against the committed frozen schema WITH the rfc3339
# format checker wired.  These are the only tests that couple the three adapters
# to the single frozen contract file — not hand-authored shapes, not embedded
# _one_of outputSchemas, but actual transport outputs.

_GOLDEN_PATH = _REPO / "tests" / "conformance" / "fixtures" / "legis-governance-read.golden.json"

# SEI / key / policy / clock mirroring test_governance_read_route.py for HTTP + CLI fixtures.
_XPORT_CLOCK_ISO = "2026-06-02T12:00:00+00:00"
_XPORT_KEY = b"xport-schema-key"
_XPORT_KEY_STR = "xport-schema-key"
_XPORT_POLICY = "protected.xport"
_XPORT_SEI = "loomweave:eid:xport-schema-test"
_XPORT_PROTECTED = frozenset({_XPORT_POLICY})


def test_cross_transport_mcp_golden_validates_against_frozen_schema(validator):
    """The Task 3 FROZEN GOLDEN (a real captured MCP wire output) must validate
    against the frozen v1 schema WITH the rfc3339 format checker.  This is the
    canonical cross-transport check for the MCP adapter — it operates on an actual
    captured output, not a hand-authored shape.
    """
    golden = json.loads(_GOLDEN_PATH.read_text(encoding="utf-8"))
    # Must not raise — any schema violation here means the MCP adapter drifted from v1.
    validator.validate(golden)


def test_cross_transport_http_body_validates_against_frozen_schema(tmp_path, validator):
    """A REAL HTTP response body from the FastAPI route must validate against the
    frozen v1 schema.  Drives the actual app (not a mock), so a route-level field
    rename or missing key fails here immediately.
    """
    import hashlib

    from fastapi.testclient import TestClient

    from legis.api.app import create_app
    from legis.clock import FixedClock
    from legis.enforcement.engine import EnforcementEngine
    from legis.enforcement.protected import ProtectedGate, TrailVerifier
    from legis.enforcement.verdict import JudgeOpinion, Verdict
    from legis.identity.entity_key import EntityKey
    from legis.policy.cells import PolicyCellRegistry, PolicyCellRule
    from legis.posture.ledger import PostureLedger
    from legis.store.audit_store import AuditStore

    class _Judge:
        def evaluate(self, record):  # noqa: ANN001
            return JudgeOpinion(Verdict.BLOCKED, "j@1", "advisory")

    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock(_XPORT_CLOCK_ISO)
    pg_write = ProtectedGate(store, clock, judge=_Judge(), key=_XPORT_KEY,
                             protected_policies=_XPORT_PROTECTED)
    pg_write.operator_override(
        policy=_XPORT_POLICY,
        entity_key=EntityKey(value=_XPORT_SEI, identity_stable=True),
        rationale="approved",
        operator_id="op-xport",
        file_fingerprint="sha256:ff",
        ast_path="Module/Call",
        extensions={"loomweave": {"content_hash": "blake3:xport-test"}},
    )

    ledger = PostureLedger(f"sqlite:///{tmp_path / 'posture.db'}", initialize=True)
    fp = hashlib.sha256(b"k" * 32).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")

    app = create_app(
        enforcement=EnforcementEngine(store, clock),
        protected_gate=ProtectedGate(store, clock, judge=_Judge(), key=_XPORT_KEY,
                                     protected_policies=_XPORT_PROTECTED),
        trail_verifier=TrailVerifier(_XPORT_KEY, _XPORT_PROTECTED),
        cell_registry=PolicyCellRegistry(
            default_cell="chill",
            rules=(PolicyCellRule(pattern=_XPORT_POLICY, cell="protected"),),
        ),
        posture_ledger=ledger,
    )
    import pytest as _pytest
    _pytest.importorskip("fastapi")  # defensive — already a dep
    client = TestClient(app, headers={"Authorization": "Bearer dev-token"})
    resp = client.get(f"/governance/sei/{_XPORT_SEI}/governance-read")
    assert resp.status_code == 200
    body = resp.json()
    # The core assertion: the REAL HTTP output validates against the frozen contract.
    validator.validate(body)


def test_cross_transport_cli_stdout_validates_against_frozen_schema(
    tmp_path, monkeypatch, capsys, validator
):
    """A REAL CLI stdout from `legis governance-read` must validate against the
    frozen v1 schema WITH the rfc3339 format checker.  Captures actual main() output
    so any CLI serialization drift from the v1 envelope shape fails here.
    """
    from legis.cli import main
    from legis.clock import FixedClock
    from legis.enforcement.protected import ProtectedGate
    from legis.enforcement.verdict import JudgeOpinion, Verdict
    from legis.identity.entity_key import EntityKey
    from legis.store.audit_store import AuditStore

    class _AcceptJudge:
        def evaluate(self, record):  # noqa: ANN001
            return JudgeOpinion(verdict=Verdict.ACCEPTED, model="j@1", rationale="ok")

    db_path = tmp_path / "gov.db"
    store = AuditStore(f"sqlite:///{db_path}")
    gate = ProtectedGate(store, FixedClock(_XPORT_CLOCK_ISO), judge=_AcceptJudge(),
                         key=_XPORT_KEY, protected_policies=_XPORT_PROTECTED)
    gate.operator_override(
        policy=_XPORT_POLICY,
        entity_key=EntityKey(value=_XPORT_SEI, identity_stable=True),
        rationale="operator clears",
        operator_id="op-cli-xport",
        file_fingerprint="sha256:ff",
        ast_path="Module.Call",
        extensions={"loomweave": {"content_hash": "ch:cli-xport-test"}},
    )

    monkeypatch.setenv("LEGIS_HMAC_KEY", _XPORT_KEY_STR)
    monkeypatch.setenv("LEGIS_PROTECTED_POLICIES", _XPORT_POLICY)

    rc = main(["governance-read", "--db", f"sqlite:///{db_path}", _XPORT_SEI])
    assert rc == 0
    out, err = capsys.readouterr()
    assert not err, f"unexpected stderr: {err!r}"
    envelope = json.loads(out)
    # The core assertion: the REAL CLI output validates against the frozen contract.
    validator.validate(envelope)
