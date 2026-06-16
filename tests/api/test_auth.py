import pytest
from fastapi.testclient import TestClient

from legis.api.app import create_app
from legis.policy.cells import PolicyCellRegistry


def _chill_registry() -> PolicyCellRegistry:
    # These tests exercise AUTH, not posture/cell routing. Pin a chill-default
    # registry so an unlisted ``no-eval`` write self-clears (201), isolating the
    # auth assertion from the governance floor (Phase 9 unification).
    return PolicyCellRegistry(default_cell="chill")


def test_mutating_routes_default_deny_without_unsafe_dev_flag(monkeypatch):
    monkeypatch.delenv("LEGIS_UNSAFE_DEV_AUTH", raising=False)
    monkeypatch.delenv("LEGIS_API_SECRET", raising=False)
    monkeypatch.delenv("LEGIS_API_TOKEN_ACTORS", raising=False)
    client = TestClient(create_app())

    resp = client.post(
        "/overrides",
        json={
            "policy": "no-eval",
            "entity": "src/x.py:f",
            "rationale": "local exception",
            "agent_id": "agent-1",
        },
    )

    assert resp.status_code == 401


def test_unsafe_dev_flag_allows_unauthenticated_local_writes(monkeypatch):
    monkeypatch.setenv("LEGIS_UNSAFE_DEV_AUTH", "1")
    monkeypatch.delenv("LEGIS_API_SECRET", raising=False)
    monkeypatch.delenv("LEGIS_API_TOKEN_ACTORS", raising=False)
    client = TestClient(create_app(cell_registry=_chill_registry()))

    resp = client.post(
        "/overrides",
        json={
            "policy": "no-eval",
            "entity": "src/x.py:f",
            "rationale": "local exception",
            "agent_id": "agent-1",
        },
    )

    assert resp.status_code == 201


@pytest.mark.parametrize(
    ("method", "path", "json"),
    [
        ("post", "/checks", {
            "check_name": "wardline",
            "run_id": "run-1",
            "commit_sha": "a" * 40,
            "outcome": "pass",
        }),
        # Phase 9: the structured/protected submit paths are reached through the
        # unified POST /overrides; the old cell-addressed submit routes are gone
        # (covered by the 404 check in test_unified_override.py).
        ("post", "/overrides", {
            "policy": "no-eval",
            "entity": "src/x.py:f",
            "rationale": "local exception",
            "agent_id": "agent-1",
            "file_fingerprint": "fp",
            "ast_path": "ap",
        }),
        ("post", "/protected/operator-override", {
            "policy": "no-eval",
            "entity": "src/x.py:f",
            "rationale": "local exception",
            "operator_id": "op-1",
            "file_fingerprint": "fp",
            "ast_path": "ap",
        }),
        ("post", "/signoff/1/bind-issue", {"issue_id": "ISSUE-1"}),
        ("post", "/policy/evaluate", {"policy": "unknown", "target": {}}),
        ("post", "/git/pulls", {
            "number": 7,
            "title": "Add eval guard",
            "base": "main",
            "head": "feature/guard",
            "state": "open",
            "url": "https://forge/pr/7",
        }),
        ("post", "/wardline/scan-results", {
            "cell": "surface_only",
            "agent_id": "agent-1",
            "scan": {"findings": []},
        }),
    ],
)
def test_mutating_routes_require_secret_when_configured(monkeypatch, method, path, json):
    monkeypatch.setenv("LEGIS_API_SECRET", "super-secret")
    client = TestClient(create_app())

    resp = getattr(client, method)(path, json=json)

    assert resp.status_code == 401


def test_scoped_tokens_separate_writer_and_operator_authority(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "LEGIS_API_TOKEN_ACTORS",
        "agent-a:writer=agent-token,op-a:operator=op-token",
    )
    monkeypatch.setenv("LEGIS_HMAC_KEY", "secret-key")
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov.db'}")
    client = TestClient(create_app(cell_registry=_chill_registry()))

    writer = {"Authorization": "Bearer agent-token"}
    operator = {"Authorization": "Bearer op-token"}
    protected_body = {
        "policy": "no-eval",
        "entity": "service:override",
        "rationale": "override",
        "operator_id": "spoofed-op",
        "file_fingerprint": "fp",
        "ast_path": "ap",
    }

    assert client.post(
        "/overrides",
        json={
            "policy": "no-eval",
            "entity": "src/x.py:f",
            "rationale": "local exception",
            "agent_id": "spoofed-agent",
        },
        headers=writer,
    ).status_code == 201
    assert client.post(
        "/protected/operator-override", json=protected_body, headers=writer
    ).status_code == 403
    assert client.post(
        "/protected/operator-override", json=protected_body, headers=operator
    ).status_code == 201


def test_unscoped_token_actor_does_not_grant_operator_authority(monkeypatch, tmp_path):
    monkeypatch.setenv("LEGIS_API_TOKEN_ACTORS", "op-a=token-a")
    monkeypatch.setenv("LEGIS_HMAC_KEY", "secret-key")
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov.db'}")
    client = TestClient(create_app())

    resp = client.post(
        "/protected/operator-override",
        json={
            "policy": "no-eval",
            "entity": "service:override",
            "rationale": "operator exception",
            "file_fingerprint": "fp",
            "ast_path": "ap",
        },
        headers={"Authorization": "Bearer token-a"},
    )

    assert resp.status_code == 403


def test_authenticated_writer_identity_does_not_require_body_agent_id(monkeypatch, tmp_path):
    monkeypatch.setenv("LEGIS_API_TOKEN_ACTORS", "agent-a:writer=agent-token")
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov.db'}")
    client = TestClient(create_app(cell_registry=_chill_registry()))

    resp = client.post(
        "/overrides",
        json={
            "policy": "no-eval",
            "entity": "src/x.py:f",
            "rationale": "local exception",
        },
        headers={"Authorization": "Bearer agent-token"},
    )

    assert resp.status_code == 201
    trail = client.get("/overrides").json()
    assert trail[0]["agent_id"] == "agent-a"


def test_authenticated_operator_identity_does_not_require_body_operator_id(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("LEGIS_API_TOKEN_ACTORS", "op-a:operator=op-token")
    monkeypatch.setenv("LEGIS_HMAC_KEY", "secret-key")
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov.db'}")
    client = TestClient(create_app())

    resp = client.post(
        "/protected/operator-override",
            json={
                "policy": "no-eval",
                "entity": "service:override",
                "rationale": "operator exception",
                "file_fingerprint": "fp",
            "ast_path": "ap",
        },
        headers={"Authorization": "Bearer op-token"},
    )

    assert resp.status_code == 201
    trail = client.get("/overrides").json()
    assert trail[0]["agent_id"] == "op-a"


def test_single_secret_defaults_to_writer_only_and_fails_closed_on_operator(monkeypatch, tmp_path):
    # Q-H1: a single shared secret cannot represent a writer/operator split, so
    # operator routes fail closed by default. The same secret still authorises
    # writer routes.
    monkeypatch.setenv("LEGIS_API_SECRET", "super-secret")
    monkeypatch.setenv("LEGIS_HMAC_KEY", "secret-key")
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov.db'}")
    monkeypatch.delenv("LEGIS_API_SECRET_SCOPE", raising=False)
    client = TestClient(create_app(cell_registry=_chill_registry()))
    auth = {"Authorization": "Bearer super-secret"}

    # writer route: allowed
    assert client.post(
        "/overrides",
        json={"policy": "no-eval", "entity": "src/x.py:f", "rationale": "x"},
        headers=auth,
    ).status_code == 201
    # operator route: fail closed (403)
    assert client.post(
        "/protected/operator-override",
        json={"policy": "no-eval", "entity": "service:override", "rationale": "x",
              "file_fingerprint": "fp", "ast_path": "ap"},
        headers=auth,
    ).status_code == 403


def test_single_secret_operator_scope_opt_in_grants_operator(monkeypatch, tmp_path):
    # Q-H1: an explicit LEGIS_API_SECRET_SCOPE granting operator restores the
    # single-operator deployment.
    monkeypatch.setenv("LEGIS_API_SECRET", "super-secret")
    monkeypatch.setenv("LEGIS_API_SECRET_SCOPE", "writer|operator")
    monkeypatch.setenv("LEGIS_HMAC_KEY", "secret-key")
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov.db'}")
    client = TestClient(create_app(cell_registry=_chill_registry()))
    auth = {"Authorization": "Bearer super-secret"}

    assert client.post(
        "/overrides",
        json={"policy": "no-eval", "entity": "src/x.py:f", "rationale": "x"},
        headers=auth,
    ).status_code == 201
    assert client.post(
        "/protected/operator-override",
        json={"policy": "no-eval", "entity": "service:override", "rationale": "x",
              "file_fingerprint": "fp", "ast_path": "ap"},
        headers=auth,
    ).status_code == 201
