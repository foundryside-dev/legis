import pytest
import sqlite3
from fastapi.testclient import TestClient

from legis.api.app import create_app
from legis.cli import main
from legis.clock import FixedClock
from legis.enforcement.signoff import SignoffGate
from legis.git.surface import GitSurface, GitError
from legis.policy.decorator import check_policy_boundary, policy_boundary, fingerprint
from legis.store.audit_store import AuditStore


def test_git_surface_double_dash(git_repo):
    s = GitSurface(git_repo)
    with pytest.raises(GitError):
        s.commit("--version")
    with pytest.raises(GitError):
        s.commits("--version")
    with pytest.raises(GitError):
        s.merge_base("--version", "main")
    with pytest.raises(GitError):
        s.renames("--version")


def test_signoff_gate_out_of_bounds(tmp_path):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    try:
        g = SignoffGate(store, FixedClock("2026-06-02T12:00:00+00:00"))
        with pytest.raises(ValueError) as excinfo:
            g.sign_off(request_seq=999, operator_id="op", rationale="r")
        assert "No pending sign-off request found at sequence 999" in str(excinfo.value)
    finally:
        store._engine.dispose()


def test_api_overrides_protected_policy_routes_via_floored_cell_not_403(
    tmp_path, monkeypatch, unsafe_dev_auth
):
    # Phase 9: the legacy env-var ``protected_set`` 403 guard on POST /overrides
    # is removed — it read a config-era set, not the floored governance cell, and
    # contradicted floor routing. A policy whose floored cell is ``protected``
    # now routes to the protected gate via the FlooredRegistry. Submitted without
    # the source/AST binding it returns the NEED_INPUTS discriminant (422), NOT a
    # 403 "use the protected endpoint" refusal (there is no separate endpoint).
    from legis.policy.cells import PolicyCellRegistry, PolicyCellRule

    monkeypatch.setenv("LEGIS_PROTECTED_POLICIES", "no-eval,protected-policy")
    monkeypatch.setenv("LEGIS_HMAC_KEY", "secret-key")
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov.db'}")
    registry = PolicyCellRegistry(
        default_cell="chill",
        rules=(PolicyCellRule(pattern="protected-policy", cell="protected"),),
    )
    app = create_app(cell_registry=registry)
    client = TestClient(app)
    res = client.post("/overrides", json={
        "policy": "protected-policy",
        "entity": "loomweave:eid:abc",
        "rationale": "bypass",
        "agent_id": "agent-1"
    })
    assert res.status_code == 422
    body = res.json()
    assert body["outcome"] == "need_inputs"
    assert body["cell"] == "protected"


def test_api_admin_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_API_SECRET", "super-secret")
    # Q-H1: single-secret mode is writer-only by default; an operator
    # deployment must explicitly grant the operator scope. Granting it here
    # exercises the authenticated-operator path.
    monkeypatch.setenv("LEGIS_API_SECRET_SCOPE", "writer|operator")
    monkeypatch.setenv("LEGIS_HMAC_KEY", "secret-key")
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov.db'}")
    app = create_app()
    client = TestClient(app)

    # 1. operator override unauthenticated
    res = client.post("/protected/operator-override", json={
        "policy": "no-eval",
        "entity": "loomweave:eid:abc",
        "rationale": "override",
        "operator_id": "op-1",
        "file_fingerprint": "fp",
        "ast_path": "ap"
    })
    assert res.status_code == 401

    # operator override authenticated
    res = client.post("/protected/operator-override", json={
        "policy": "no-eval",
        "entity": "loomweave:eid:abc",
        "rationale": "override",
        "operator_id": "op-1",
        "file_fingerprint": "fp",
        "ast_path": "ap"
    }, headers={"Authorization": "Bearer super-secret"})
    assert res.status_code == 201

    # 2. signoff sign unauthenticated
    res = client.post("/signoff/1/sign", json={
        "operator_id": "op-1",
        "rationale": "override"
    })
    assert res.status_code == 401


def test_api_policy_evaluate_logging(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_API_SECRET", "super-secret")
    monkeypatch.setenv("LEGIS_HMAC_KEY", "secret-key")
    db_path = tmp_path / "gov.db"
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{db_path}")
    app = create_app()
    client = TestClient(app)

    # Unknown policy evaluation unauthenticated
    res = client.post("/policy/evaluate", json={
        "policy": "unknown-policy-here",
        "target": {"value": "some-val"}
    })
    assert res.status_code == 401

    store = AuditStore(f"sqlite:///{db_path}")
    try:
        records = store.read_all()
        assert len(records) == 0

        # Unknown policy evaluation authenticated
        res = client.post("/policy/evaluate", json={
            "policy": "unknown-policy-here",
            "target": {"value": "some-val"}
        }, headers={"Authorization": "Bearer super-secret"})
        assert res.status_code == 200

        records = store.read_all()
        assert len(records) == 1
        assert records[0].payload["policy"] == "unknown-policy-here"
    finally:
        store._engine.dispose()


def test_cli_check_override_rate_tampered_db(tmp_path):
    db_path = tmp_path / "gov.db"
    db_url = f"sqlite:///{db_path}"
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE audit_log (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT,
            content_hash TEXT,
            prev_hash TEXT,
            chain_hash TEXT
        )
    """)
    cursor.execute("""
        INSERT INTO audit_log (seq, payload, content_hash, prev_hash, chain_hash)
        VALUES (1, '{"policy": "p", "entity_key": {"value": "x"}}', 'hash1', 'prev1', 'tampered-hash')
    """)
    conn.commit()
    cursor.close()
    conn.close()
    
    rc = main(["check-override-rate", "--db", db_url])
    assert rc == 1


class BoundaryClassLocalTest:
    def class_method(self):
        pass


def fake_bound_test():
    # references class_method and no-eval
    instance = BoundaryClassLocalTest()
    result = instance.class_method()
    assert result is None, "no-eval"


def test_honesty_gate_bound_methods():
    def resolver(ref):
        return fake_bound_test
        
    class BoundaryClassLocal:
        @policy_boundary(
            source="src/legis/x.py:1",
            suppresses=("no-eval",),
            invariant="class invariant",
            test_ref="fake_ref",
            test_fingerprint=fingerprint(fake_bound_test),
        )
        def class_method(self):
            return "ok"
            
    # Test checking unbound function / method accessed on class
    finding = check_policy_boundary(BoundaryClassLocal.class_method, resolver)
    assert finding.ok is True, finding.reason

    # Test checking bound method
    inst = BoundaryClassLocal()
    finding_bound = check_policy_boundary(inst.class_method, resolver)
    assert finding_bound.ok is True, finding_bound.reason
