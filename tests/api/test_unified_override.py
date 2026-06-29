"""Phase 9.1 — the unified ``POST /overrides`` route (added alongside the
operator-clear routes), routing by the FlooredRegistry effective cell.

The three cell-addressed submit routes collapse into one policy-routed
``POST /overrides``. The route resolves ``cell_for(body.policy)`` through a
FlooredRegistry (floor read per request) and dispatches:

  * chill    -> self-clear (201, ``accepted``)
  * coached  -> inline judge (201 accept / 409 block)
  * structured -> sign-off request (202, ``escalation_requested``)
  * protected -> protected gate (201/409), or ``need_inputs`` (422) when the
    file_fingerprint/ast_path are absent.

The operator-clear routes (``/signoff/{seq}/sign``,
``/protected/operator-override``) keep their distinct ``verify_operator`` auth.
The legacy env-var ``protected_set`` 403 guard is removed — the FlooredRegistry
owns protected routing now.
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
    # no-eval -> protected, prod-deploy -> structured, everything else chill.
    return PolicyCellRegistry(
        default_cell="chill",
        rules=(
            PolicyCellRule(pattern="no-eval", cell="protected"),
            PolicyCellRule(pattern="prod-deploy", cell="structured"),
            PolicyCellRule(pattern="coached-*", cell="coached"),
        ),
    )


def _ledger(tmp_path, floor=None):
    """A posture ledger seeded with GENESIS (chill) + optional raised floor."""
    from legis.crypto import signing as enf_signing

    url = f"sqlite:///{tmp_path / 'posture.db'}"
    ledger = PostureLedger(url, initialize=True)
    key = b"k" * 32
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    if floor is not None and floor != "chill":

        class _MemSigner:
            def fingerprint(self):
                return fp

            def sign(self, fields):
                return enf_signing.sign(fields, key, version="v3")

        ledger.transition(
            floor,
            signer=_MemSigner(),
            session_id="sess-1",
            key_fingerprint=fp,
            agent_id="op",
            rationale="raise",
            recorded_at="t1",
        )
    return ledger


def _fingerprint(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _app(tmp_path, *, floor=None, opinion=JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock("2026-06-02T12:00:00+00:00")
    eng = EnforcementEngine(store, clock)
    pg = ProtectedGate(
        store, clock, judge=ScriptedJudge(opinion), key=KEY,
        validator=lambda record: True,
    )
    sg = SignoffGate(store, clock)
    app = create_app(
        repo_path=tmp_path,
        enforcement=eng,
        protected_gate=pg,
        signoff_gate=sg,
        trail_verifier=TrailVerifier(KEY, frozenset({"no-eval"})),
        cell_registry=_registry(),
        posture_ledger=_ledger(tmp_path, floor=floor),
    )
    return TestClient(app), store


def _source_body(tmp_path, **overrides):
    source = tmp_path / "src" / "x.py"
    source.parent.mkdir(exist_ok=True)
    if not source.exists():
        source.write_text("def f():\n    return 1\n")
    return {
        "policy": "no-eval",
        "entity": "src/x.py:f",
        "rationale": "sandboxed",
        "agent_id": "agent-9",
        "file_fingerprint": _fingerprint(source),
        "ast_path": "ap",
        **overrides,
    }


def test_unified_route_exists(tmp_path):
    c, _ = _app(tmp_path)
    resp = c.post(
        "/overrides",
        json={
            "policy": "anything-chill",
            "entity": "src/app.py:h",
            "rationale": "re-raised",
            "agent_id": "agent-7",
        },
    )
    assert resp.status_code == 201
    assert resp.json()["outcome"] == "accepted"
    assert resp.json()["cell"] == "chill"


def test_discriminated_outcome_shape(tmp_path):
    c, _ = _app(tmp_path)
    # chill self-clear
    chill = c.post(
        "/overrides",
        json={"policy": "x", "entity": "e", "rationale": "r", "agent_id": "a"},
    ).json()
    assert chill["outcome"] == "accepted"
    assert chill["cell"] == "chill"
    assert isinstance(chill["seq"], int)
    # structured escalation
    esc = c.post(
        "/overrides",
        json={"policy": "prod-deploy", "entity": "e", "rationale": "r", "agent_id": "a"},
    ).json()
    assert esc["outcome"] == "escalation_requested"
    assert esc["cell"] == "structured"
    assert isinstance(esc["request_seq"], int)


def test_operator_routes_unchanged(tmp_path):
    c, _ = _app(tmp_path, opinion=JudgeOpinion(Verdict.BLOCKED, "judge@1", "no"))
    # operator-override route keeps verify_operator + 201 semantics
    body = _source_body(tmp_path)
    del body["agent_id"]
    body["operator_id"] = "op-1"
    resp = c.post("/protected/operator-override", json=body)
    assert resp.status_code == 201
    assert resp.json()["verdict"] == "OVERRIDDEN_BY_OPERATOR"
    # signoff sign route still present
    req = c.post(
        "/overrides",
        json={"policy": "prod-deploy", "entity": "svc/api", "rationale": "hotfix", "agent_id": "a"},
    )
    seq = req.json()["request_seq"]
    signed = c.post(f"/signoff/{seq}/sign", json={"operator_id": "op-1", "rationale": "ok"})
    assert signed.status_code == 200
    assert signed.json()["cleared"] is True


def test_protected_need_inputs(tmp_path):
    c, _ = _app(tmp_path)
    # protected cell, file_fingerprint/ast_path absent -> NEED_INPUTS discriminant (422)
    resp = c.post(
        "/overrides",
        json={"policy": "no-eval", "entity": "src/x.py:f", "rationale": "r", "agent_id": "a"},
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["outcome"] == "need_inputs"
    assert body["cell"] == "protected"
    fields = {item["field"] for item in body["required_inputs"]}
    assert {"file_fingerprint", "ast_path"} <= fields


def test_old_submit_routes_are_gone(tmp_path):
    # Phase 9.4b: the cell-addressed submit routes were collapsed into
    # POST /overrides; the old paths 404 (the cell, not the URL, selects the gate).
    c, _ = _app(tmp_path)
    assert c.post("/protected/overrides", json=_source_body(tmp_path)).status_code == 404
    assert c.post(
        "/signoff/request",
        json={"policy": "prod-deploy", "entity": "e", "rationale": "r", "agent_id": "a"},
    ).status_code == 404


def test_no_legacy_protected_set_403_guard(tmp_path):
    # A policy in the protected set routes to the protected gate via the
    # FlooredRegistry, NOT via the old env-var protected_set 403 guard.
    c, store = _app(tmp_path)
    resp = c.post("/overrides", json=_source_body(tmp_path))
    assert resp.status_code == 201
    assert resp.json()["outcome"] == "accepted"
    assert resp.json()["cell"] == "protected"
    # the record exists (it went through the protected gate, not a 403 refusal)
    assert len(store.read_all()) == 1
