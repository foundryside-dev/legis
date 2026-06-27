"""HTTP route ``GET /governance/sei/{sei:path}/governance-read`` tests.

TDD for Task 4. Mirrors the MCP governance_read tool tests (test_governance_read_tool.py)
and the identity-gap/lineage-integrity route tests (test_sei_api.py).

Cases:
  (a) wired gate+verifier + a clearance -> 200 {status:checked, records:[…]}
  (b) no gate/verifier -> 200 {status:unavailable, …}
  (c) tampered trail -> 500
  (d) a SEI containing '/' round-trips correctly ({sei:path} capture)

FAIL-CLOSED invariant: verified_governance_records() runs BOTH chain + signature
checks and maps tamper to HTTP 500; absent gate/verifier yields discriminated
``unavailable``, NEVER a silent ``checked``/``[]``.
"""
from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from legis.api.app import create_app
from legis.canonical import canonical_json, content_hash
from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.protected import ProtectedGate, TrailVerifier
from legis.enforcement.signoff import SignoffGate
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.identity.entity_key import EntityKey
from legis.policy.cells import PolicyCellRegistry, PolicyCellRule
from legis.posture.ledger import PostureLedger
from legis.store.audit_store import GENESIS, AuditStore, _chain

pytestmark = pytest.mark.usefixtures("unsafe_dev_auth")

_CLOCK_ISO = "2026-06-02T12:00:00+00:00"
_KEY = b"route-test-key"
_POLICY = "protected.governance"
_SEI = "loomweave:eid:governance-route-test"
_PROTECTED = frozenset({_POLICY})


class _AdvisoryJudge:
    def evaluate(self, record):  # noqa: ANN001
        return JudgeOpinion(Verdict.BLOCKED, "judge@1", "advisory only")


def _genesis_ledger(tmp_path):
    url = f"sqlite:///{tmp_path / 'posture.db'}"
    ledger = PostureLedger(url, initialize=True)
    fp = hashlib.sha256(b"k" * 32).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    return ledger


def _registry():
    return PolicyCellRegistry(
        default_cell="chill",
        rules=(PolicyCellRule(pattern=_POLICY, cell="protected"),),
    )


def _simple_app(tmp_path):
    """App WITHOUT protected_gate / trail_verifier — triggers the unavailable pre-gate."""
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    eng = EnforcementEngine(store, FixedClock(_CLOCK_ISO))
    app = create_app(
        enforcement=eng,
        cell_registry=PolicyCellRegistry(default_cell="chill"),
        posture_ledger=_genesis_ledger(tmp_path),
    )
    return TestClient(app)


def _wired_app_with_clearance(tmp_path):
    """App with BOTH gate + verifier wired, and a genuine operator_override clearance
    for _SEI already written to the shared store (mirrors _wired_runtime_with_clearance
    from test_governance_read_tool.py)."""
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock(_CLOCK_ISO)

    # Write a genuine OVERRIDDEN_BY_OPERATOR record directly (mirrors MCP fixture)
    pg_write = ProtectedGate(
        store,
        clock,
        judge=_AdvisoryJudge(),
        key=_KEY,
        protected_policies=_PROTECTED,
    )
    pg_write.operator_override(
        policy=_POLICY,
        entity_key=EntityKey(value=_SEI, identity_stable=True),
        rationale="approved",
        operator_id="op-sec",
        file_fingerprint="sha256:abc",
        ast_path="Module/Call",
        extensions={"loomweave": {"content_hash": "blake3:clearance-override"}},
    )

    # Build the read-side app using the SAME store (so it sees the written record)
    pg_read = ProtectedGate(
        store,
        clock,
        judge=_AdvisoryJudge(),
        key=_KEY,
        protected_policies=_PROTECTED,
    )
    app = create_app(
        protected_gate=pg_read,
        trail_verifier=TrailVerifier(_KEY, _PROTECTED),
        cell_registry=_registry(),
        posture_ledger=_genesis_ledger(tmp_path),
    )
    return TestClient(app), store


# --- (a) verified trail with clearance -> 200 {status:checked, records:[…]} ---

def test_governance_read_checked_with_clearance(tmp_path):
    """Wired gate + verifier + a genuine clearance -> 200 checked with one record."""
    client, _store = _wired_app_with_clearance(tmp_path)
    resp = client.get(f"/governance/sei/{_SEI}/governance-read")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "checked"
    assert body["sei"] == _SEI
    assert len(body["records"]) == 1
    rec = body["records"][0]
    assert rec["disposition"] == "cleared"
    assert rec["posture"] == "protected_override"
    assert rec["authority"] == "operator"
    assert rec["sei"] == _SEI
    assert rec["reasons"] == ["operator_override"]
    assert rec["content_hash"] == "blake3:clearance-override"
    assert rec["as_of"] == _CLOCK_ISO


# --- (b) no gate/verifier -> 200 {status:unavailable, …} ---

def test_governance_read_unavailable_when_no_gate(tmp_path):
    """No protected_gate wired -> 200 unavailable (discriminated), NEVER checked/[]."""
    client = _simple_app(tmp_path)
    resp = client.get(f"/governance/sei/{_SEI}/governance-read")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "unavailable"
    assert body["sei"] == _SEI
    assert body["records"] == []
    assert body.get("unavailable") and "reason" in body["unavailable"][0]


# --- (c) tampered trail -> 500 ---

def test_governance_read_500_on_tamper(tmp_path):
    """A signature-tampered trail must propagate as HTTP 500 (fail closed)."""
    client, store = _wired_app_with_clearance(tmp_path)

    # Confirm the clean trail reads 200 first
    assert client.get(f"/governance/sei/{_SEI}/governance-read").status_code == 200

    # Corrupt a signed field on the record (like judge_verdict) to break the
    # HMAC signature — mirrors _tamper_first_record in test_complex_api.py.
    import sqlite3

    db = str(tmp_path / "gov.db")
    con = sqlite3.connect(db)
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    seq, payload = con.execute(
        "SELECT seq, payload FROM audit_log ORDER BY seq ASC LIMIT 1"
    ).fetchone()
    p = json.loads(payload)
    # Flip the signed judge_verdict field to break the HMAC signature
    p.setdefault("extensions", {})["judge_verdict"] = "FORGED"
    con.execute("UPDATE audit_log SET payload=? WHERE seq=?", (canonical_json(p), seq))
    # Re-chain so the unkeyed hash-chain check still passes (only HMAC is broken)
    prev = GENESIS
    for s, pl in con.execute(
        "SELECT seq, payload FROM audit_log ORDER BY seq ASC"
    ).fetchall():
        ch = content_hash(json.loads(pl))
        con.execute(
            "UPDATE audit_log SET content_hash=?, prev_hash=?, chain_hash=? WHERE seq=?",
            (ch, prev, _chain(prev, ch), s),
        )
        prev = _chain(prev, ch)
    con.commit()
    con.close()

    # Now the HMAC signature check must fail -> AuditIntegrityError -> HTTP 500
    resp = client.get(f"/governance/sei/{_SEI}/governance-read")
    assert resp.status_code == 500


# --- (d) SEI containing '/' round-trips via {sei:path} capture ---

def test_governance_read_slash_bearing_sei_round_trips(tmp_path):
    """A SEI with embedded '/' is captured correctly by {sei:path} and echoed back."""
    slash_sei = "loomweave:eid:namespace/entity-id"
    client = _simple_app(tmp_path)
    # Use the unavailable (no-gate) path — it echoes sei without needing records.
    resp = client.get(f"/governance/sei/{slash_sei}/governance-read")
    assert resp.status_code == 200
    body = resp.json()
    # The key invariant: {sei:path} round-tripped the slash-bearing SEI intact.
    assert body["sei"] == slash_sei
    assert body["status"] == "unavailable"
