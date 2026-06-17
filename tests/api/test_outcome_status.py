"""Phase 9.2 — discriminated-outcome → HTTP status contract for POST /overrides.

201 self-clear / judge-accept; 202 structured escalation (NOT 201, so an old
"201 == accepted" reader cannot misread a pending escalation as an acceptance);
409 judge-block; 422 NEED_INPUTS / unresolved.
"""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from legis.api.app import create_app
from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.protected import ProtectedGate, TrailVerifier
from legis.enforcement.signoff import SignoffGate
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.policy.cells import PolicyCellRegistry, PolicyCellRule
from legis.posture.ledger import PostureLedger
from legis.store.audit_store import AuditStore

pytestmark = pytest.mark.usefixtures("unsafe_dev_auth")

KEY = b"k"


class ScriptedJudge:
    def __init__(self, opinion):
        self.opinion = opinion

    def evaluate(self, record):
        return self.opinion


def _registry():
    return PolicyCellRegistry(
        default_cell="chill",
        rules=(
            PolicyCellRule(pattern="no-eval", cell="protected"),
            PolicyCellRule(pattern="prod-deploy", cell="structured"),
            PolicyCellRule(pattern="coached-*", cell="coached"),
        ),
    )


def _genesis_ledger(tmp_path):
    url = f"sqlite:///{tmp_path / 'posture.db'}"
    ledger = PostureLedger(url, initialize=True)
    fp = hashlib.sha256(b"k" * 32).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    return ledger


def _app(tmp_path, *, opinion=JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock("2026-06-02T12:00:00+00:00")
    eng = EnforcementEngine(store, clock, judge=ScriptedJudge(opinion))
    pg = ProtectedGate(store, clock, judge=ScriptedJudge(opinion), key=KEY, validator=lambda r: True)
    sg = SignoffGate(store, clock)
    app = create_app(
        repo_path=tmp_path,
        enforcement=eng,
        protected_gate=pg,
        signoff_gate=sg,
        trail_verifier=TrailVerifier(KEY, frozenset({"no-eval"})),
        cell_registry=_registry(),
        posture_ledger=_genesis_ledger(tmp_path),
    )
    return TestClient(app)


def _fp(tmp_path):
    source = tmp_path / "src" / "x.py"
    source.parent.mkdir(exist_ok=True)
    source.write_text("def f():\n    return 1\n")
    return "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()


def _chill_app(tmp_path):
    # no judge -> chill self-clear
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock("2026-06-02T12:00:00+00:00")
    eng = EnforcementEngine(store, clock)
    app = create_app(
        repo_path=tmp_path,
        enforcement=eng,
        cell_registry=PolicyCellRegistry(default_cell="chill"),
        posture_ledger=_genesis_ledger(tmp_path),
    )
    return TestClient(app)


def test_self_clear_201(tmp_path):
    c = _chill_app(tmp_path)
    resp = c.post("/overrides", json={"policy": "x", "entity": "e", "rationale": "r", "agent_id": "a"})
    assert resp.status_code == 201
    assert resp.json()["outcome"] == "accepted"


def test_judge_block_409(tmp_path):
    c = _app(tmp_path, opinion=JudgeOpinion(Verdict.BLOCKED, "judge@1", "no"))
    resp = c.post("/overrides", json={"policy": "coached-thing", "entity": "e", "rationale": "r", "agent_id": "a"})
    assert resp.status_code == 409
    assert resp.json()["outcome"] == "blocked"


def test_escalation_202(tmp_path):
    c = _app(tmp_path)
    resp = c.post("/overrides", json={"policy": "prod-deploy", "entity": "e", "rationale": "r", "agent_id": "a"})
    assert resp.status_code == 202
    assert resp.json()["outcome"] == "escalation_requested"
    assert "request_seq" in resp.json()


def test_protected_gate_201(tmp_path):
    c = _app(tmp_path)
    resp = c.post(
        "/overrides",
        json={
            "policy": "no-eval", "entity": "src/x.py:f", "rationale": "r", "agent_id": "a",
            "file_fingerprint": _fp(tmp_path), "ast_path": "ap",
        },
    )
    assert resp.status_code == 201
    assert resp.json()["outcome"] == "accepted"
    assert resp.json()["cell"] == "protected"


def test_need_inputs_422(tmp_path):
    c = _app(tmp_path)
    resp = c.post("/overrides", json={"policy": "no-eval", "entity": "src/x.py:f", "rationale": "r", "agent_id": "a"})
    assert resp.status_code == 422
    assert resp.json()["outcome"] == "need_inputs"
