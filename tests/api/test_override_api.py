"""Phase 9.4 — chill/coached writes via the unified POST /overrides route.

The route now routes by the FlooredRegistry effective cell and returns a
discriminated outcome (``outcome``/``cell``), not the legacy ``accepted`` shape.
A chill-default registry + a genesis (chill) posture ledger keep an unlisted
policy on the self-clear path; a coached rule exercises the inline judge.
"""

import hashlib

import pytest
from fastapi.testclient import TestClient

from legis.api.app import create_app
from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.policy.cells import PolicyCellRegistry, PolicyCellRule
from legis.posture.ledger import PostureLedger
from legis.store.audit_store import AuditStore

pytestmark = pytest.mark.usefixtures("unsafe_dev_auth")


class ScriptedJudge:
    def __init__(self, opinion):
        self.opinion = opinion

    def evaluate(self, record):
        return self.opinion


def _genesis_ledger(tmp_path):
    url = f"sqlite:///{tmp_path / 'posture.db'}"
    ledger = PostureLedger(url, initialize=True)
    fp = hashlib.sha256(b"k" * 32).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    return ledger


# ``no-broad-except`` is unlisted -> default chill; ``coached-*`` -> coached.
def _registry():
    return PolicyCellRegistry(
        default_cell="chill",
        rules=(PolicyCellRule(pattern="coached-*", cell="coached"),),
    )


def chill_client(tmp_path):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    eng = EnforcementEngine(store, FixedClock("2026-06-02T12:00:00+00:00"))
    return TestClient(create_app(
        enforcement=eng, cell_registry=_registry(), posture_ledger=_genesis_ledger(tmp_path),
    ))


def coached_client(tmp_path, opinion):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    eng = EnforcementEngine(
        store, FixedClock("2026-06-02T12:00:00+00:00"), judge=ScriptedJudge(opinion)
    )
    return TestClient(create_app(
        enforcement=eng, cell_registry=_registry(), posture_ledger=_genesis_ledger(tmp_path),
    ))


CHILL_BODY = {
    "policy": "no-broad-except",
    "entity": "src/app.py:handler",
    "rationale": "re-raised after logging",
    "agent_id": "agent-7",
}
COACHED_BODY = {**CHILL_BODY, "policy": "coached-no-broad-except"}


def test_chill_post_override_returns_201_and_records(tmp_path):
    c = chill_client(tmp_path)
    resp = c.post("/overrides", json=CHILL_BODY)
    assert resp.status_code == 201
    body = resp.json()
    assert body["outcome"] == "accepted"
    assert body["cell"] == "chill"
    assert body["verdict"] is None

    trail = c.get("/overrides").json()
    assert len(trail) == 1
    assert trail[0]["policy"] == "no-broad-except"
    assert trail[0]["identity_stable"] is False


def test_authenticated_token_actor_overrides_body_agent_id(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_API_TOKEN_ACTORS", "agent-a:writer=token-a")
    c = chill_client(tmp_path)
    resp = c.post(
        "/overrides",
        json={**CHILL_BODY, "agent_id": "spoofed-agent"},
        headers={"Authorization": "Bearer token-a"},
    )
    assert resp.status_code == 201
    trail = c.get("/overrides").json()
    assert trail[0]["agent_id"] == "agent-a"


def test_coached_blocked_post_returns_409_with_judge_reasoning(tmp_path):
    c = coached_client(
        tmp_path, JudgeOpinion(Verdict.BLOCKED, "judge@1", "rationale is boilerplate")
    )
    resp = c.post("/overrides", json=COACHED_BODY)
    assert resp.status_code == 409
    body = resp.json()
    assert body["outcome"] == "blocked"
    assert body["cell"] == "coached"
    assert body["verdict"] == "BLOCKED"
    assert body["judge_rationale"] == "rationale is boilerplate"
    # Even blocked, the attempt is in the trail for async review.
    assert len(c.get("/overrides").json()) == 1


def test_coached_accepted_post_returns_201(tmp_path):
    c = coached_client(
        tmp_path, JudgeOpinion(Verdict.ACCEPTED, "judge@1", "specific and correct")
    )
    resp = c.post("/overrides", json=COACHED_BODY)
    assert resp.status_code == 201
    body = resp.json()
    assert body["outcome"] == "accepted"
    assert body["cell"] == "coached"
    assert body["verdict"] == "ACCEPTED"
    assert body["judge_model"] == "judge@1"
