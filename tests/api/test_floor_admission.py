"""Phase 9.3 — posture-floor admission on POST /overrides.

The floor is read per request through the shared ledger handle: a chill-registry
policy under a structured floor escalates (202), never self-clears (201); a fresh
TRANSITION written to posture.db between two TestClient calls is reflected without
a restart; a missing ledger fails closed to structured.
"""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from legis.api.app import create_app
from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.signoff import SignoffGate
from legis.policy.cells import PolicyCellRegistry
from legis.posture.ledger import PostureLedger
from legis.store.audit_store import AuditStore

pytestmark = pytest.mark.usefixtures("unsafe_dev_auth")

KEY = b"k" * 32


def _fp():
    return hashlib.sha256(KEY).hexdigest()


def _mem_signer():
    from legis.crypto import signing as enf_signing

    class _MemSigner:
        def __init__(self):
            self._key = KEY

        def fingerprint(self):
            return _fp()

        def sign(self, fields):
            return enf_signing.sign(fields, self._key, version="v3")

    return _MemSigner()


def _seeded_ledger(tmp_path, floor=None):
    url = f"sqlite:///{tmp_path / 'posture.db'}"
    ledger = PostureLedger(url, initialize=True)
    ledger.genesis(key_fingerprint=_fp(), agent_id="installer", recorded_at="t0")
    if floor is not None and floor != "chill":
        ledger.transition(
            floor, signer=_mem_signer(), session_id="s1",
            key_fingerprint=_fp(), agent_id="op", rationale="raise", recorded_at="t1",
        )
    return ledger


def _app(tmp_path, *, posture_ledger, registry=None):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock("2026-06-02T12:00:00+00:00")
    eng = EnforcementEngine(store, clock)
    sg = SignoffGate(store, clock)
    app = create_app(
        repo_path=tmp_path,
        enforcement=eng,
        signoff_gate=sg,
        cell_registry=registry or PolicyCellRegistry(default_cell="chill"),
        posture_ledger=posture_ledger,
    )
    return TestClient(app)


BODY = {"policy": "anything", "entity": "e", "rationale": "r", "agent_id": "a"}


def test_structured_floor_refuses_chill_self_clear(tmp_path):
    c = _app(tmp_path, posture_ledger=_seeded_ledger(tmp_path, floor="structured"))
    resp = c.post("/overrides", json=BODY)
    assert resp.status_code == 202
    assert resp.json()["outcome"] == "escalation_requested"


def test_floor_read_per_request(tmp_path):
    ledger = _seeded_ledger(tmp_path, floor=None)  # chill genesis only
    c = _app(tmp_path, posture_ledger=ledger)
    # first call: chill -> self-clear 201
    assert c.post("/overrides", json=BODY).status_code == 201
    # raise the floor on the SAME ledger handle (no app restart)
    ledger.transition(
        "structured", signer=_mem_signer(), session_id="s2",
        key_fingerprint=_fp(), agent_id="op", rationale="raise", recorded_at="t2",
    )
    # second call reflects the new floor: structured escalation (202)
    resp = c.post("/overrides", json=BODY)
    assert resp.status_code == 202
    assert resp.json()["outcome"] == "escalation_requested"


def test_missing_ledger_floor_structured(tmp_path):
    # No genesis written: read_floor() is None -> the effective floor is
    # structured even when the underlying registry would otherwise self-clear.
    url = f"sqlite:///{tmp_path / 'absent-posture.db'}"
    absent = PostureLedger(url, initialize=False)
    c = _app(
        tmp_path,
        posture_ledger=absent,
        registry=PolicyCellRegistry(default_cell="chill"),
    )
    resp = c.post("/overrides", json=BODY)
    assert resp.status_code == 202
    assert resp.json()["outcome"] == "escalation_requested"


def test_unregistered_policy_respects_floor(tmp_path):
    # Dev-default chill registry + structured floor: a policy NOT in the registry
    # still escalates (202), never self-clears (201) — closes the
    # dev-registry-plus-elevated-floor self-clear hole.
    c = _app(
        tmp_path,
        posture_ledger=_seeded_ledger(tmp_path, floor="structured"),
        registry=PolicyCellRegistry(default_cell="chill"),
    )
    resp = c.post("/overrides", json={"policy": "totally-unknown", "entity": "e", "rationale": "r", "agent_id": "a"})
    assert resp.status_code == 202
    assert resp.json()["outcome"] == "escalation_requested"
