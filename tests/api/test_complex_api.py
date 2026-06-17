import json
import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from legis.api.app import create_app
from legis.canonical import canonical_json, content_hash
from legis.clock import FixedClock
from legis.enforcement.protected import ProtectedGate, TrailVerifier
from legis.enforcement.signoff import SignoffGate
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.policy.cells import PolicyCellRegistry, PolicyCellRule
from legis.posture.ledger import PostureLedger
from legis.store.audit_store import GENESIS, AuditStore, _chain

pytestmark = pytest.mark.usefixtures("unsafe_dev_auth")


class ScriptedJudge:
    def __init__(self, opinion):
        self.opinion = opinion

    def evaluate(self, record):
        return self.opinion


KEY = b"k"
PROTECTED = frozenset({"no-eval"})
PBODY = {
    "policy": "no-eval",
    "entity": "src/x.py:f",
    "rationale": "sandboxed",
    "agent_id": "agent-9",
    "file_fingerprint": "fp",
    "ast_path": "ap",
}


# Phase 9: the unified route routes by registry cell. no-eval -> protected,
# prod-deploy -> structured; everything else chill.
def _registry():
    return PolicyCellRegistry(
        default_cell="chill",
        rules=(
            PolicyCellRule(pattern="no-eval", cell="protected"),
            PolicyCellRule(pattern="prod-deploy", cell="structured"),
        ),
    )


def _genesis_ledger(tmp_path):
    url = f"sqlite:///{tmp_path / 'posture.db'}"
    ledger = PostureLedger(url, initialize=True)
    fp = hashlib.sha256(b"k" * 32).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    return ledger


def _fingerprint(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _source_body(tmp_path, **overrides):
    source = tmp_path / "src" / "x.py"
    source.parent.mkdir(exist_ok=True)
    if not source.exists():
        source.write_text("def f():\n    return 1\n")
    return {**PBODY, "file_fingerprint": _fingerprint(source), **overrides}


def _app(tmp_path, opinion=JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok"), repo_path=None):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock("2026-06-02T12:00:00+00:00")
    # JUDGE-3: protected cell is fail-closed; confirm deterministically so an
    # ACCEPTED override clears (these tests exercise the cleared-path mechanics).
    pg = ProtectedGate(
        store, clock, judge=ScriptedJudge(opinion), key=KEY,
        validator=lambda record: True,
    )
    sg = SignoffGate(store, clock)
    app = create_app(
        repo_path=repo_path or tmp_path,
        protected_gate=pg,
        signoff_gate=sg,
        trail_verifier=TrailVerifier(KEY, PROTECTED),
        cell_registry=_registry(),
        posture_ledger=_genesis_ledger(tmp_path),
    )
    return TestClient(app), store


def test_protected_post_records_and_verified_read_succeeds(tmp_path):
    c, _ = _app(tmp_path)
    resp = c.post("/overrides", json=_source_body(tmp_path))
    assert resp.status_code == 201
    assert resp.json()["cell"] == "protected"
    trail = c.get("/overrides")
    assert trail.status_code == 200
    sig = trail.json()[0]["extensions"]["judge_metadata_signature"]
    # AUD-1: protected verdicts now sign at v3 (chain position bound).
    assert sig.startswith("hmac-sha256:v3:")


def test_protected_post_rejects_stale_source_fingerprint_before_signing(tmp_path):
    source = tmp_path / "src" / "x.py"
    source.parent.mkdir()
    source.write_text("def f():\n    return 1\n")
    c, store = _app(tmp_path, repo_path=tmp_path)

    resp = c.post(
        "/overrides",
        json={**PBODY, "file_fingerprint": "sha256:" + "0" * 64},
    )

    assert resp.status_code == 422
    assert "fingerprint does not match current source" in resp.json()["detail"]
    assert store.read_all() == []


def test_protected_post_records_verified_source_binding(tmp_path):
    source = tmp_path / "src" / "x.py"
    source.parent.mkdir()
    source.write_text("def f():\n    return 1\n")
    c, store = _app(tmp_path, repo_path=tmp_path)

    resp = c.post(
        "/overrides",
        json={**PBODY, "file_fingerprint": _fingerprint(source)},
    )

    assert resp.status_code == 201
    ext = store.read_all()[0].payload["extensions"]
    assert ext["source_binding"]["status"] == "verified"
    assert ext["source_binding"]["source_path"] == "src/x.py"


def test_protected_cell_source_binding_preserved(tmp_path):
    # Phase 9.4: the protected source binding survives the route collapse — a
    # POST /overrides with a protected policy + file_fingerprint produces a
    # populated source_binding extension on the governance record.
    source = tmp_path / "src" / "x.py"
    source.parent.mkdir()
    source.write_text("def f():\n    return 1\n")
    c, store = _app(tmp_path, repo_path=tmp_path)

    resp = c.post("/overrides", json={**PBODY, "file_fingerprint": _fingerprint(source)})

    assert resp.status_code == 201
    assert resp.json()["cell"] == "protected"
    ext = store.read_all()[0].payload["extensions"]
    assert ext["source_binding"]["status"] == "verified"
    assert ext["source_binding"]["source_path"] == "src/x.py"


def test_protected_blocked_post_is_409(tmp_path):
    c, _ = _app(tmp_path, JudgeOpinion(Verdict.BLOCKED, "judge@1", "no"))
    assert c.post("/overrides", json=_source_body(tmp_path)).status_code == 409


def test_operator_override_post_is_201_and_distinct(tmp_path):
    c, _ = _app(tmp_path, JudgeOpinion(Verdict.BLOCKED, "judge@1", "no"))
    body = _source_body(tmp_path, operator_id="op-1")
    del body["agent_id"]
    resp = c.post("/protected/operator-override", json=body)
    assert resp.status_code == 201
    assert resp.json()["verdict"] == "OVERRIDDEN_BY_OPERATOR"


def test_authenticated_token_actor_overrides_body_operator_id(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_API_TOKEN_ACTORS", "op-a:operator=token-a")
    c, _ = _app(tmp_path, JudgeOpinion(Verdict.BLOCKED, "judge@1", "no"))
    body = _source_body(tmp_path, operator_id="spoofed-op")
    del body["agent_id"]
    resp = c.post(
        "/protected/operator-override",
        json=body,
        headers={"Authorization": "Bearer token-a"},
    )
    assert resp.status_code == 201
    trail = c.get("/overrides").json()
    assert trail[0]["agent_id"] == "op-a"


def test_signoff_request_then_sign_clears(tmp_path):
    c, _ = _app(tmp_path)
    req = c.post(
        "/overrides",
        json={
            "policy": "prod-deploy",
            "entity": "svc/api",
            "rationale": "hotfix",
            "agent_id": "agent-3",
        },
    )
    assert req.status_code == 202
    assert req.json()["outcome"] == "escalation_requested"
    seq = req.json()["request_seq"]
    signed = c.post(f"/signoff/{seq}/sign", json={"operator_id": "op-1", "rationale": "ok"})
    assert signed.status_code == 200
    assert signed.json()["cleared"] is True


def test_tampered_protected_read_is_a_500(tmp_path):
    c, store = _app(tmp_path)
    assert c.post("/overrides", json=_source_body(tmp_path)).status_code == 201
    db = str(tmp_path / "gov.db")
    con = sqlite3.connect(db)
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    seq, payload = con.execute(
        "SELECT seq, payload FROM audit_log ORDER BY seq ASC LIMIT 1"
    ).fetchone()
    p = json.loads(payload)
    p["rationale"] = "FORGED"
    con.execute("UPDATE audit_log SET payload=? WHERE seq=?", (canonical_json(p), seq))
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
    assert store.verify_integrity() is True
    assert c.get("/overrides").status_code == 500


def test_override_rate_endpoint_uses_policy_constants(tmp_path):
    c, _ = _app(tmp_path)
    r = c.get("/governance/override-rate")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"status", "rate", "sample_size"}
    assert body["status"] == "PASS_WITH_NOTICE"  # empty trail < min_sample


def _tamper_first_record(db, mutate):
    """Apply ``mutate(payload_dict)`` to the first record and fully re-chain so
    the unkeyed Sprint 0 integrity check still passes."""
    con = sqlite3.connect(db)
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    seq, payload = con.execute(
        "SELECT seq, payload FROM audit_log ORDER BY seq ASC LIMIT 1"
    ).fetchone()
    p = json.loads(payload)
    mutate(p)
    con.execute("UPDATE audit_log SET payload=? WHERE seq=?", (canonical_json(p), seq))
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


def test_override_rate_gate_fails_closed_on_a_tampered_trail(tmp_path):
    # The enforcement gate must not trust the store blind: flipping an
    # OVERRIDDEN_BY_OPERATOR to ACCEPTED to lower the apparent rate must be
    # caught, not silently scored.
    c, store = _app(tmp_path, JudgeOpinion(Verdict.BLOCKED, "judge@1", "no"))
    body = _source_body(tmp_path, operator_id="op-1")
    del body["agent_id"]
    c.post("/protected/operator-override", json=body)

    def flip(p):
        p["extensions"]["judge_verdict"] = "ACCEPTED"

    _tamper_first_record(str(tmp_path / "gov.db"), flip)
    assert store.verify_integrity() is True  # unkeyed chain fooled
    assert c.get("/governance/override-rate").status_code == 500


def test_identity_gaps_scan_the_protected_trail(tmp_path):
    from legis.identity.resolver import IdentityResolver

    class OrphanClient:
        def capability(self):
            return True

        def resolve_locator(self, locator):
            return {"sei": "loomweave:eid:abc123", "current_locator": locator,
                    "content_hash": "h", "alive": True}

        def resolve_sei(self, sei):
            return {"sei": sei, "alive": False, "lineage": [{"event": "orphaned"}]}

        def lineage(self, sei):
            return [{"event": "born"}]

    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock("2026-06-02T12:00:00+00:00")
    pg = ProtectedGate(store, clock, judge=ScriptedJudge(
        JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")), key=KEY,
        validator=lambda record: True)  # JUDGE-3: confirm so ACCEPTED clears
    app = create_app(repo_path=tmp_path, protected_gate=pg, trail_verifier=TrailVerifier(KEY, PROTECTED),
                     identity=IdentityResolver(OrphanClient()),
                     cell_registry=_registry(), posture_ledger=_genesis_ledger(tmp_path))
    c = TestClient(app)
    # A protected override keyed on an SEI Loomweave now reports dead.
    assert c.post("/overrides", json=_source_body(tmp_path)).status_code == 201
    body = c.get("/governance/identity-gaps").json()
    assert body["status"] == "checked"
    assert [g["sei"] for g in body["gaps"]] == ["loomweave:eid:abc123"]


def test_lineage_integrity_detects_divergence_on_the_protected_trail(tmp_path):
    from legis.identity.resolver import IdentityResolver

    class ShrinkingClient:
        def __init__(self):
            self._calls = 0

        def capability(self):
            return True

        def resolve_locator(self, locator):
            return {"sei": "loomweave:eid:abc123", "current_locator": locator,
                    "content_hash": "h", "alive": True}

        def resolve_sei(self, sei):
            return {"sei": sei, "alive": True}

        def lineage(self, sei):
            self._calls += 1
            # First call = snapshot at write time (length 2); later =
            # truncated (prefix broken).
            if self._calls == 1:
                return [{"event": "born"}, {"event": "moved"}]
            return [{"event": "born"}]

    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock("2026-06-02T12:00:00+00:00")
    pg = ProtectedGate(store, clock, judge=ScriptedJudge(
        JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")), key=KEY,
        validator=lambda record: True)  # JUDGE-3: confirm so ACCEPTED clears
    app = create_app(repo_path=tmp_path, protected_gate=pg, trail_verifier=TrailVerifier(KEY, PROTECTED),
                     identity=IdentityResolver(ShrinkingClient()),
                     cell_registry=_registry(), posture_ledger=_genesis_ledger(tmp_path))
    c = TestClient(app)
    assert c.post("/overrides", json=_source_body(tmp_path)).status_code == 201
    body = c.get("/governance/lineage-integrity").json()
    # A confirmed tamper must surface at the top-level status, not just in the
    # divergences list — "verified" alongside a divergence is a false green (GOV-1).
    assert body["status"] == "diverged"
    assert [d["sei"] for d in body["divergences"]] == ["loomweave:eid:abc123"]
    assert body["divergences"][0]["recorded_length"] == 2
    assert body["divergences"][0]["current_length"] == 1


def test_create_app_wires_env_configured_openrouter_judge_for_protected_overrides(
    tmp_path, monkeypatch
):
    from legis.enforcement.llm_client import OpenRouterLLMClient

    source = tmp_path / "src" / "x.py"
    source.parent.mkdir()
    source.write_text("def f():\n    return 1\n")

    def fake_init(self, config, *, fetch=None):
        self.model_id = "openrouter:test-model"

    monkeypatch.setenv("LEGIS_HMAC_KEY", "secret")
    monkeypatch.setenv("LEGIS_JUDGE_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret-key")
    monkeypatch.setenv("LEGIS_JUDGE_MODEL", "anthropic/claude-opus-4.7")
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov-env.db'}")
    monkeypatch.setattr(OpenRouterLLMClient, "__init__", fake_init)
    monkeypatch.setattr(
        OpenRouterLLMClient,
        "complete",
        lambda self, prompt: '{"verdict":"ACCEPTED","rationale":"ok"}',
    )

    client = TestClient(create_app(
        repo_path=tmp_path,
        cell_registry=_registry(),
        posture_ledger=_genesis_ledger(tmp_path),
    ))
    resp = client.post(
        "/overrides",
        json={**PBODY, "file_fingerprint": _fingerprint(source)},
    )

    # JUDGE-3: the env-configured judge IS wired and consulted (judge_model is
    # populated), but in the default production config no deterministic validator
    # is wired, so the protected cell is fail-closed: the model's ACCEPTED is
    # advisory and downgraded to BLOCKED (409). Clearing requires operator
    # sign-off (or a wired validator).
    assert resp.status_code == 409
    assert resp.json()["outcome"] == "blocked"
    assert resp.json()["cell"] == "protected"
    assert resp.json()["verdict"] == "BLOCKED"
    assert resp.json()["judge_model"] == "openrouter:test-model"
