import io
import json
import logging
import sqlite3

from legis.canonical import canonical_json, content_hash
from legis.checks.models import CheckOutcome, CheckRun
from legis.checks.surface import CheckSurface
from legis.cli import build_parser
from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.protected import ProtectedGate, TrailVerifier
from legis.enforcement.signoff import SignoffGate
from legis.enforcement.signing import sign
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.git.surface import GitSurface
from legis.identity.entity_key import EntityKey
from legis.policy.grammar import AllowlistBoundary, PolicyGrammar
from legis.policy.cells import PolicyCellRegistry, PolicyCellRule
from legis.pulls.models import PullRequest, PullRequestState
from legis.pulls.surface import PullSurface
from legis.store.audit_store import GENESIS, _chain
from legis.store.audit_store import AuditStore
from legis.wardline.ingest import wardline_artifact_fields


def _messages(*items):
    return "\n".join(json.dumps(item) for item in items) + "\n"


def _run(messages, runtime):
    from legis.mcp import run_jsonrpc

    inp = io.StringIO(messages)
    out = io.StringIO()
    run_jsonrpc(inp, out, runtime)
    return [json.loads(line) for line in out.getvalue().splitlines()]


class _ScriptedJudge:
    def __init__(self, *opinions):
        self._opinions = list(opinions)

    def evaluate(self, record):
        if self._opinions:
            return self._opinions.pop(0)
        return JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")


KEY = b"protected-key-1"


def _chill_posture_ledger(tmp_path):
    import hashlib
    import uuid

    from legis.posture.ledger import PostureLedger

    ledger = PostureLedger(
        f"sqlite:///{tmp_path / f'posture-{uuid.uuid4().hex}.db'}",
        initialize=True,
    )
    key = b"k" * 32
    ledger.genesis(
        key_fingerprint=hashlib.sha256(key).hexdigest(),
        agent_id="installer",
        recorded_at="t0",
    )
    return ledger


def _runtime(
    tmp_path,
    *,
    agent_id="agent-launch",
    check_surface=None,
    judge=None,
):
    from legis.mcp import McpRuntime

    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    engine = EnforcementEngine(
        store, FixedClock("2026-06-02T12:00:00+00:00"), judge=judge
    )
    return McpRuntime(
        agent_id=agent_id,
        initialized=True,
        engine=engine,
        check_surface=check_surface,
        posture_ledger=_chill_posture_ledger(tmp_path),
    ), store


def _active_scan():
    return {
        "findings": [
            {
                "rule_id": "PY-WL-101",
                "message": "untrusted reaches trusted",
                "severity": "ERROR",
                "kind": "defect",
                "fingerprint": "fp1",
                "qualname": "m.f",
                "properties": {"actual_return": "UNKNOWN_RAW"},
                "suppression_state": "active",
            }
        ]
    }


def _signed_wardline_scan(scan, key=b"wardline-key"):
    return {**scan, "artifact_signature": sign(wardline_artifact_fields(scan), key)}


def _tamper_first_record_and_rechain(db, mutate):
    con = sqlite3.connect(db)
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
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


def test_cli_has_mcp_subcommand_with_launch_bound_agent_id():
    args = build_parser().parse_args(["mcp", "--agent-id", "agent-1"])
    assert args.command == "mcp"
    assert args.agent_id == "agent-1"


def test_mcp_runtime_positional_constructor_preserves_identity_slot():
    from legis.mcp import McpRuntime

    identity = object()

    runtime = McpRuntime("agent-1", False, None, None, identity)

    assert runtime.identity is identity
    assert runtime.coached_engine is None


def test_build_runtime_wires_env_configured_openrouter_judge(tmp_path, monkeypatch):
    from legis.enforcement.llm_client import OpenRouterLLMClient
    from legis.mcp import build_runtime

    def fake_init(self, config, *, fetch=None):
        self.model_id = "openrouter:test-model"

    monkeypatch.setenv("LEGIS_HMAC_KEY", "secret")
    monkeypatch.setenv("LEGIS_JUDGE_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret-key")
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov-env.db'}")
    monkeypatch.setattr(OpenRouterLLMClient, "__init__", fake_init)
    monkeypatch.setattr(
        OpenRouterLLMClient,
        "complete",
        lambda self, prompt: '{"verdict":"ACCEPTED","rationale":"ok"}',
    )

    runtime = build_runtime("agent-launch")

    assert runtime.protected_gate is not None
    result = runtime.protected_gate.submit(
        policy="no-eval",
        entity_key=EntityKey.from_locator("src/x.py:f"),
        rationale="specific rationale",
        agent_id="agent-launch",
        file_fingerprint="fp",
        ast_path="ap",
    )
    assert result.judge_model == "openrouter:test-model"


def test_build_runtime_wires_env_judge_for_simple_coached_override(tmp_path, monkeypatch):
    from legis.enforcement.llm_client import OpenRouterLLMClient
    from legis.mcp import build_runtime

    def fake_init(self, config, *, fetch=None):
        self.model_id = "openrouter:test-model"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov-env.db'}")
    monkeypatch.setenv("LEGIS_JUDGE_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret")
    monkeypatch.setattr(OpenRouterLLMClient, "__init__", fake_init)
    monkeypatch.setattr(
        OpenRouterLLMClient,
        "complete",
        lambda self, prompt: '{"verdict":"ACCEPTED","rationale":"ok"}',
    )
    runtime = build_runtime("agent-launch")
    runtime.initialized = True
    runtime.cell_registry = PolicyCellRegistry(default_cell="coached")
    runtime.posture_ledger = _chill_posture_ledger(tmp_path)

    call = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "override_submit",
            "arguments": {
                "policy": "review.rationale",
                "entity": "src/x.py:f",
                "rationale": "specific rationale",
                "idempotency_key": "coached-retry-1",
            },
        },
    }
    responses = _run(
        _messages(
            {**call, "id": 1},
            {**call, "id": 2},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "override_rate_get",
                    "arguments": {},
                },
            },
        ),
        runtime,
    )

    result = responses[0]["result"]["structuredContent"]
    retried = responses[1]["result"]["structuredContent"]
    rate = responses[2]["result"]["structuredContent"]

    assert result["outcome"] == "ACCEPTED_BY_JUDGE"
    assert result["cell"] == "coached"
    assert result["judge_model"] == "openrouter:test-model"
    assert retried["seq"] == result["seq"]
    assert rate["sample_size"] == 1

    fresh_runtime = build_runtime("agent-fresh")
    fresh_runtime.initialized = True
    fresh_rate = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "override_rate_get", "arguments": {}},
            }
        ),
        fresh_runtime,
    )[0]["result"]["structuredContent"]
    assert fresh_rate["sample_size"] == 1


def test_initialize_and_tools_list_exposes_full_agent_surface(tmp_path):
    runtime, _store = _runtime(tmp_path)
    runtime.initialized = False
    responses = _run(
        _messages(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ),
        runtime,
    )

    assert responses[0]["result"]["serverInfo"]["name"] == "legis"
    assert responses[0]["result"]["protocolVersion"] == "2025-03-26"
    tools = responses[1]["result"]["tools"]
    by_name = {tool["name"]: tool for tool in tools}

    assert set(by_name) == {
        "policy_explain",
        "policy_list",
        "override_submit",
        "signoff_status_get",
        "signoff_bind_issue",
        "policy_evaluate",
        "scan_route",
        "git_branch_list",
        "git_commit_get",
        "git_rename_list",
        "git_rename_feed_get",
        "pull_request_get",
        "check_list",
        "override_rate_get",
        "filigree_closure_gate_get",
        "identity_gap_list",
        "lineage_integrity_get",
        "check_report",
        "override_list",
        "doctor_get",
        "policy_boundary_check",
        "posture_get",
        "warpline_preflight_get",
        "attestation_get",
    }
    # posture_get is the dedicated read-only posture surface (Phase 8); the
    # change gate (posture set) stays operator/CLI only — no posture_set tool.
    assert "posture_set" not in by_name
    # Named decision (legis-e5c57dedd1): PR recording stays OFF the agent
    # surface — the forge, not the agent, is the source of truth for PR state;
    # the legis PR store is a CI/forge-integration mirror (HTTP writer token).
    # check_report IS exposed because the agent that ran the check is the
    # natural source of that claim.
    assert "pull_request_record" not in by_name
    assert "signoff_sign" not in by_name
    assert "protected_operator_override" not in by_name
    assert "operator_override" not in by_name
    assert "submit_override" not in by_name
    assert "protected_override" not in by_name
    assert "signoff_request" not in by_name
    for tool in tools:
        assert not tool["name"].startswith("legis_")
        props = tool["inputSchema"].get("properties", {})
        assert "agent_id" not in props
        assert "operator_id" not in props

    submit_description = by_name["override_submit"]["description"]
    assert "routes to the governing cell" in submit_description


def test_tools_reject_before_initialize(tmp_path):
    runtime, _store = _runtime(tmp_path)
    runtime.initialized = False

    responses = _run(
        _messages({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
        runtime,
    )

    assert responses[0]["error"]["code"] == -32002


def test_initialize_negotiates_unsupported_protocol_version(tmp_path):
    # MCP spec: an unsupported (or newer) requested version must not hard-error;
    # the server replies with a version it does support and lets the client
    # decide. This is what lets newer clients (e.g. 2025-06-18) connect.
    runtime, _store = _runtime(tmp_path)
    runtime.initialized = False

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            }
        ),
        runtime,
    )

    assert "error" not in responses[0]
    assert responses[0]["result"]["protocolVersion"] == "2025-03-26"
    assert responses[0]["result"]["serverInfo"]["name"] == "legis"


def test_build_runtime_initialize_does_not_create_local_state(tmp_path, monkeypatch):
    from legis.mcp import build_runtime

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)
    monkeypatch.delenv("LEGIS_GOVERNANCE_DB", raising=False)
    monkeypatch.delenv("LEGIS_CHECK_DB", raising=False)
    monkeypatch.delenv("LEGIS_PULL_DB", raising=False)
    runtime = build_runtime("agent-1")

    responses = _run(
        _messages({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        runtime,
    )

    assert responses[0]["result"]["serverInfo"]["name"] == "legis"
    # The federated store subtree must not be created on the initialize path —
    # stores are opened lazily, so neither the .weft/legis dir nor any DB appears.
    assert not (tmp_path / ".weft").exists()
    assert not (tmp_path / ".weft" / "legis" / "legis-governance.db").exists()
    assert not (tmp_path / ".weft" / "legis" / "legis-checks.db").exists()
    assert not (tmp_path / ".weft" / "legis" / "legis-pulls.db").exists()


def test_policy_explain_returns_service_explanation_payload(tmp_path):
    runtime, _store = _runtime(tmp_path)
    runtime.cell_registry = PolicyCellRegistry(
        default_cell="chill",
        rules=(PolicyCellRule(pattern="human.*", cell="structured"),),
    )
    runtime.signoff_gate = object()

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "policy_explain",
                    "arguments": {
                        "policy": "human.release-signoff",
                        "entity": "src/x.py:f",
                    },
                },
            }
        ),
        runtime,
    )

    result = responses[0]["result"]
    assert "isError" not in result
    assert result["structuredContent"] == {
        "cell": "structured",
        "judge_inline": False,
        "self_clearable": False,
        "human_in_loop": True,
        "enabled": True,
        "available_moves": ["override_submit", "signoff_status_get"],
        "required_inputs": [],
        "matched_rule": "human.*",
        "policy_known": True,
    }


def test_policy_explain_reports_null_matched_rule_for_unconfigured_policy(tmp_path):
    # LEG-1(c): an unconfigured policy name is routed by default_cell and reports
    # matched_rule:null — distinguishing "real-but-disabled" from "hallucinated".
    # N-9: policy_known:false makes that distinction an explicit boolean.
    runtime, _store = _runtime(tmp_path)
    runtime.cell_registry = PolicyCellRegistry(
        default_cell="chill",
        rules=(PolicyCellRule(pattern="human.*", cell="structured"),),
    )

    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "policy_explain",
                    "arguments": {"policy": "no.such.policy", "entity": "src/x.py:f"},
                },
            }
        ),
        runtime,
    )[0]["result"]

    assert result["structuredContent"]["cell"] == "chill"
    assert result["structuredContent"]["matched_rule"] is None
    assert result["structuredContent"]["policy_known"] is False


def _policy_list(runtime):
    return _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "policy_list", "arguments": {}},
            }
        ),
        runtime,
    )[0]["result"]


def test_policy_list_reports_routing_table_and_cells(tmp_path):
    # LEG-1(b): default_cell + rules + per-cell metadata in tier order.
    runtime, _store = _runtime(tmp_path)
    runtime.cell_registry = PolicyCellRegistry(
        default_cell="structured",
        rules=(
            PolicyCellRule(pattern="secure.source", cell="protected"),
            PolicyCellRule(pattern="review.*", cell="coached"),
        ),
    )

    payload = _policy_list(runtime)["structuredContent"]

    assert payload["default_cell"] == "structured"
    assert payload["rules"] == [
        {"pattern": "secure.source", "cell": "protected"},
        {"pattern": "review.*", "cell": "coached"},
    ]
    assert [c["cell"] for c in payload["cells"]] == [
        "chill",
        "coached",
        "structured",
        "protected",
    ]


def test_policy_list_cells_cover_every_valid_cell(tmp_path):
    # legis-a50c000052: the cells block must list EVERY governance cell, so a
    # cell added to VALID_CELLS cannot be silently omitted from policy_list
    # (re-opening the discoverability gap). Guards against re-hardcoding a
    # membership tuple that drifts from VALID_CELLS.
    from legis.policy.cells import VALID_CELLS

    runtime, _store = _runtime(tmp_path)
    payload = _policy_list(runtime)["structuredContent"]

    assert {c["cell"] for c in payload["cells"]} == set(VALID_CELLS)


def test_policy_list_keyless_runtime_reports_complex_tier_disabled(tmp_path):
    # Cardinal governance/false-green guard: without LEGIS_HMAC_KEY the complex
    # tier (structured/protected) is NOT wired, so policy_list must report
    # enabled:false for those cells — never enabled:true to look complete.
    runtime, _store = _runtime(tmp_path)  # no signoff_gate / protected_gate
    assert runtime.signoff_gate is None
    assert runtime.protected_gate is None

    payload = _policy_list(runtime)["structuredContent"]
    by_cell = {c["cell"]: c for c in payload["cells"]}

    assert by_cell["structured"]["enabled"] is False
    assert by_cell["protected"]["enabled"] is False


def test_policy_list_cells_do_not_carry_policy_known(tmp_path):
    # N-9 guard: policy_known belongs to policy_explain (a policy referent
    # exists). The per-cell rows in policy_list must not carry a misleading
    # policy_known:false.
    runtime, _store = _runtime(tmp_path)
    payload = _policy_list(runtime)["structuredContent"]

    for cell_row in payload["cells"]:
        assert "policy_known" not in cell_row


def test_policy_list_complex_tier_enabled_when_gates_wired(tmp_path):
    runtime, store = _runtime(tmp_path)
    runtime.signoff_gate = SignoffGate(
        store, FixedClock("2026-06-02T12:00:00+00:00")
    )
    runtime.protected_gate = ProtectedGate(
        store,
        FixedClock("2026-06-02T12:00:00+00:00"),
        _ScriptedJudge(JudgeOpinion(Verdict.ACCEPTED, "judge@protected", "ok")),
        b"secret",
    )

    payload = _policy_list(runtime)["structuredContent"]
    by_cell = {c["cell"]: c for c in payload["cells"]}

    assert by_cell["structured"]["enabled"] is True
    assert by_cell["protected"]["enabled"] is True


def test_policy_list_and_policy_explain_never_disagree(tmp_path):
    # Locks the cardinal invariant: per-cell fields in policy_list match what
    # policy_explain reports for a policy routed to that cell (same source).
    runtime, _store = _runtime(tmp_path)
    runtime.cell_registry = PolicyCellRegistry(
        default_cell="chill",
        rules=(PolicyCellRule(pattern="review.*", cell="coached"),),
    )

    list_by_cell = {
        c["cell"]: c for c in _policy_list(runtime)["structuredContent"]["cells"]
    }

    explain = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "policy_explain",
                    "arguments": {"policy": "review.rationale", "entity": "src/x.py:f"},
                },
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]

    assert explain["cell"] == "coached"
    coached = list_by_cell["coached"]
    for field in ("enabled", "judge_inline", "self_clearable", "human_in_loop"):
        assert coached[field] == explain[field]


def test_override_submit_chill_records_launch_agent_and_returns_accepted_self(tmp_path):
    runtime, store = _runtime(tmp_path, agent_id="agent-launch")
    runtime.cell_registry = PolicyCellRegistry(default_cell="chill")

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "ordinary.policy",
                        "entity": "src/x.py:f",
                        "rationale": "generated file; lint is not applicable",
                    },
                },
            }
        ),
        runtime,
    )

    result = responses[0]["result"]
    assert "isError" not in result
    assert result["structuredContent"] == {
        "outcome": "ACCEPTED_SELF",
        "cell": "chill",
        "seq": 1,
        "note": "self-cleared; human reviews asynchronously",
    }
    assert store.read_all()[0].payload["agent_id"] == "agent-launch"


def test_override_submit_entity_sei_binds_on_the_sei(tmp_path):
    # weft SEI-on-entry (L1): an agent supplies a SEI it already holds; legis
    # verifies it alive via resolve_sei and keys the record directly on it.
    from legis.identity.resolver import IdentityResolver

    runtime, store = _runtime(tmp_path, agent_id="agent-launch")
    runtime.cell_registry = PolicyCellRegistry(default_cell="chill")
    runtime.identity = IdentityResolver(_FakeLoomweave(alive=True))

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "ordinary.policy",
                        "entity": "src/x.py:f",
                        "entity_sei": "loomweave:eid:abc123",
                        "rationale": "generated file; lint is not applicable",
                    },
                },
            }
        ),
        runtime,
    )

    result = responses[0]["result"]
    assert "isError" not in result
    assert result["structuredContent"]["outcome"] == "ACCEPTED_SELF"
    recorded = store.read_all()[0].payload
    assert recorded["entity_key"] == {
        "value": "loomweave:eid:abc123",
        "identity_stable": True,
    }
    assert recorded["identity_stable"] is True


def test_override_submit_rejects_entity_sei_for_unrelated_locator(tmp_path):
    # Both identities are live, but they do not bind to the same entity. The
    # authoring surface must reject instead of recording under the wrong SEI.
    from legis.identity.resolver import IdentityResolver

    runtime, store = _runtime(tmp_path, agent_id="agent-launch")
    runtime.cell_registry = PolicyCellRegistry(default_cell="chill")
    runtime.identity = IdentityResolver(_FakeLoomweave(alive=True))

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "ordinary.policy",
                        "entity": "src/x.py:f",
                        "entity_sei": "loomweave:eid:attacker",
                        "rationale": "anything",
                    },
                },
            }
        ),
        runtime,
    )

    result = responses[0]["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "UNRESOLVED_INPUT"
    assert store.read_all() == []


def test_override_submit_unresolvable_entity_sei_records_nothing_with_weft_reason(tmp_path):
    # A non-resolving entity_sei returns UNRESOLVED_INPUT (weft-reason
    # unresolved_input {cause, fix}) and creates NOTHING — never an
    # unbound-but-looks-bound record.
    from legis.identity.resolver import IdentityResolver

    runtime, store = _runtime(tmp_path, agent_id="agent-launch")
    runtime.cell_registry = PolicyCellRegistry(default_cell="chill")
    runtime.identity = IdentityResolver(_FakeLoomweave(alive=False))  # SEI not alive

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "ordinary.policy",
                        "entity": "src/x.py:f",
                        "entity_sei": "loomweave:eid:dead",
                        "rationale": "anything",
                    },
                },
            }
        ),
        runtime,
    )

    result = responses[0]["result"]
    assert result["isError"] is True
    sc = result["structuredContent"]
    assert sc["error_code"] == "UNRESOLVED_INPUT"
    assert sc["weft_reason"]["kind"] == "unresolved_input"
    assert sc["weft_reason"]["cause"] and sc["weft_reason"]["fix"]
    assert store.read_all() == []  # NOTHING recorded


def test_n3_acceptance_chill_is_reachable_keyless_via_build_runtime(tmp_path, monkeypatch):
    # N3 (weft-df8d2ef454) acceptance branch 1: a fresh stdio launch CAN reach a
    # configured non-secret governance surface. Pins the claim our errors/docs
    # assert as fact — chill/coached are reachable WITHOUT LEGIS_HMAC_KEY — end to
    # end through the real launch path (build_runtime + the lazy keyless _engine),
    # not via an injected engine. The chill posture is explicit signed state here:
    # a missing posture ledger fails closed to structured.
    import hashlib

    from legis.mcp import build_runtime, call_tool
    from legis.posture.ledger import PostureLedger

    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)
    monkeypatch.delenv("LEGIS_POLICY_CELLS", raising=False)
    monkeypatch.setenv("LEGIS_SOURCE_ROOT", str(tmp_path))  # no policy/cells.toml here
    monkeypatch.setenv("LEGIS_DEV_DEFAULT_CELLS", "1")  # operator dev posture -> chill
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov.db'}")
    posture_db = tmp_path / "posture.db"
    monkeypatch.setenv("LEGIS_POSTURE_DB", f"sqlite:///{posture_db}")
    key = b"k" * 32
    PostureLedger(f"sqlite:///{posture_db}", initialize=True).genesis(
        key_fingerprint=hashlib.sha256(key).hexdigest(),
        agent_id="installer",
        recorded_at="t0",
    )
    runtime = build_runtime("agent-1")
    assert runtime.protected_gate is None  # genuinely keyless launch

    result = call_tool(
        runtime,
        "override_submit",
        {"policy": "ordinary.policy", "entity": "src/x.py:f", "rationale": "n/a"},
    )

    assert result.get("isError") is not True
    assert result["structuredContent"]["outcome"] == "ACCEPTED_SELF"
    assert result["structuredContent"]["cell"] == "chill"


def test_override_submit_idempotency_key_prevents_duplicate_records(tmp_path):
    runtime, store = _runtime(tmp_path, agent_id="agent-launch")
    runtime.cell_registry = PolicyCellRegistry(default_cell="chill")
    call = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "override_submit",
            "arguments": {
                "policy": "ordinary.policy",
                "entity": "src/x.py:f",
                "rationale": "generated file; lint is not applicable",
                "idempotency_key": "retry-1",
            },
        },
    }

    responses = _run(
        _messages({**call, "id": 1}, {**call, "id": 2}),
        runtime,
    )

    assert responses[0]["result"]["structuredContent"]["seq"] == 1
    assert responses[1]["result"]["structuredContent"]["seq"] == 1
    assert len(store.read_all()) == 1
    assert store.read_all()[0].payload["extensions"]["mcp_idempotency_key"] == "retry-1"


def test_override_submit_idempotency_key_is_scoped_to_exact_request(tmp_path):
    runtime, store = _runtime(tmp_path, agent_id="agent-launch")
    runtime.cell_registry = PolicyCellRegistry(
        default_cell="chill",
        rules=(
            PolicyCellRule("protected.policy", "protected"),
            PolicyCellRule("release.signoff", "structured"),
        ),
    )
    runtime.protected_gate = ProtectedGate(
        store,
        FixedClock("2026-06-02T12:00:00+00:00"),
        _ScriptedJudge(JudgeOpinion(Verdict.ACCEPTED, "judge@protected", "ok")),
        b"secret",
    )
    runtime.signoff_gate = SignoffGate(
        store, FixedClock("2026-06-02T12:00:00+00:00")
    )

    first = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "ordinary.policy",
                        "entity": "src/x.py:f",
                        "rationale": "generated file; lint is not applicable",
                        "idempotency_key": "retry-1",
                    },
                },
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]

    assert first["outcome"] == "ACCEPTED_SELF"
    recorded_ext = store.read_all()[0].payload["extensions"]
    assert recorded_ext["mcp_idempotency_key"] == "retry-1"
    assert "mcp_idempotency_request_hash" in recorded_ext

    replay = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "ordinary.policy",
                        "entity": "src/x.py:f",
                        "rationale": "generated file; lint is not applicable",
                        "idempotency_key": "retry-1",
                    },
                },
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]

    assert replay["seq"] == first["seq"]
    assert len(store.read_all()) == 1

    protected_reuse = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "protected.policy",
                        "entity": "src/secret.py:danger",
                        "rationale": "needs exception",
                        "idempotency_key": "retry-1",
                    },
                },
            }
        ),
        runtime,
    )[0]["result"]

    assert protected_reuse["isError"] is True
    assert protected_reuse["structuredContent"]["error_code"] == "INVALID_ARGUMENT"
    assert "different override request" in protected_reuse["structuredContent"]["message"]

    structured_reuse = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "release.signoff",
                        "entity": "svc/api",
                        "rationale": "production deploy",
                        "idempotency_key": "retry-1",
                    },
                },
            }
        ),
        runtime,
    )[0]["result"]

    assert structured_reuse["isError"] is True
    assert structured_reuse["structuredContent"]["error_code"] == "INVALID_ARGUMENT"
    assert len(store.read_all()) == 1


def test_tools_call_rejects_unexpected_arguments(tmp_path):
    runtime, store = _runtime(tmp_path, agent_id="agent-launch")
    runtime.cell_registry = PolicyCellRegistry(default_cell="chill")

    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "ordinary.policy",
                        "entity": "src/x.py:f",
                        "rationale": "generated file; lint is not applicable",
                        "agent_id": "spoofed-agent",
                    },
                },
            }
        ),
        runtime,
    )[0]["result"]

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "INVALID_ARGUMENT"
    assert "unexpected" in result["structuredContent"]["message"]
    assert store.read_all() == []


def test_override_submit_non_chill_cell_returns_cell_not_enabled_without_write(tmp_path):
    runtime, store = _runtime(tmp_path)
    runtime.cell_registry = PolicyCellRegistry(
        default_cell="chill",
        rules=(PolicyCellRule(pattern="human.*", cell="structured"),),
    )

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "human.release-signoff",
                        "entity": "src/x.py:f",
                        "rationale": "needs release signoff",
                    },
                },
            }
        ),
        runtime,
    )

    result = responses[0]["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "CELL_NOT_ENABLED"
    assert "structured" in result["structuredContent"]["message"]
    assert store.read_all() == []


def test_override_submit_coached_accepts_and_blocks_with_reason_code(tmp_path):
    runtime, store = _runtime(
        tmp_path,
        judge=_ScriptedJudge(
            JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ship it"),
            JudgeOpinion(
                Verdict.BLOCKED,
                "judge@1",
                "rationale insufficient for this exception",
            ),
        ),
    )
    runtime.cell_registry = PolicyCellRegistry(default_cell="coached")

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "reviewed.policy",
                        "entity": "src/x.py:f",
                        "rationale": "first accepted path",
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "reviewed.policy",
                        "entity": "src/x.py:g",
                        "rationale": "trust me",
                    },
                },
            },
        ),
        runtime,
    )

    accepted = responses[0]["result"]["structuredContent"]
    assert accepted == {
        "outcome": "ACCEPTED_BY_JUDGE",
        "cell": "coached",
        "seq": 1,
        "judge_model": "judge@1",
        "judge_rationale": "ship it",
        "note": "may be re-judged later",
    }

    blocked = responses[1]["result"]["structuredContent"]
    assert blocked == {
        "outcome": "BLOCKED",
        "cell": "coached",
        "seq": 2,
        "judge_model": "judge@1",
        "judge_rationale": "rationale insufficient for this exception",
        "blocked_reason_code": "RATIONALE_INSUFFICIENT",
        "self_clearable": False,
        "next_actions": ["REVISE_CODE", "REVISE_RATIONALE"],
        "note": "this attempt does not count toward your override-rate",
    }
    assert len(store.read_all()) == 2


def test_override_submit_structured_escalates_and_status_poll_reflects_signoff(tmp_path):
    runtime, store = _runtime(tmp_path, agent_id="agent-structured")
    runtime.cell_registry = PolicyCellRegistry(default_cell="structured")
    runtime.signoff_gate = SignoffGate(
        store, FixedClock("2026-06-02T12:00:00+00:00")
    )

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "release.signoff",
                        "entity": "svc/api",
                        "rationale": "production deploy",
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "signoff_status_get",
                    "arguments": {"seq": "1"},
                },
            },
        ),
        runtime,
    )

    assert responses[0]["result"]["structuredContent"] == {
        "outcome": "ESCALATED_PENDING",
        "cell": "structured",
        "seq": 1,
        "cleared": False,
        "human_required": True,
        "operator_instruction": "Human sign-off required for seq 1.",
        "poll_tool": "signoff_status_get",
        "poll_handle": 1,
    }
    assert responses[1]["result"]["structuredContent"] == {"cleared": False, "seq": 1}
    assert store.read_all()[0].payload["agent_id"] == "agent-structured"

    poll_handle = responses[0]["result"]["structuredContent"]["poll_handle"]
    poll_with_handle = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {
                    "name": "signoff_status_get",
                    "arguments": {"seq": poll_handle},
                },
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]
    assert poll_with_handle == {"cleared": False, "seq": 1}

    runtime.signoff_gate.sign_off(
        request_seq=1, operator_id="op-release", rationale="approved"
    )
    signed = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "signoff_status_get",
                    "arguments": {"seq": "1"},
                },
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]
    assert signed == {
        "cleared": True,
        "seq": 1,
        "signed_by": "op-release",
        "signed_at": "2026-06-02T12:00:00+00:00",
    }


def test_override_submit_protected_needs_inputs_without_write_then_blocks(tmp_path):
    runtime, store = _runtime(tmp_path)
    runtime.cell_registry = PolicyCellRegistry(default_cell="protected")
    runtime.protected_gate = ProtectedGate(
        store,
        FixedClock("2026-06-02T12:00:00+00:00"),
        _ScriptedJudge(
            JudgeOpinion(Verdict.BLOCKED, "judge@protected", "code violation: eval")
        ),
        b"secret",
    )
    source_file = tmp_path / "src" / "x.py"
    source_file.parent.mkdir()
    source_file.write_text("print('hello')\n", encoding="utf-8")
    runtime.source_root = tmp_path

    missing_inputs = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "protected.policy",
                        "entity": "src/x.py:f",
                        "rationale": "needs exception",
                    },
                },
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]

    assert missing_inputs == {
        "outcome": "NEED_INPUTS",
        "cell": "protected",
        "required_inputs": [
            {
                "field": "file_fingerprint",
                "how": "sha256 of the target file contents",
            },
            {"field": "ast_path", "how": "dotted path to the AST node"},
        ],
    }
    assert store.read_all() == []

    blocked = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "override_submit",
                    "arguments": {
                        "policy": "protected.policy",
                        "entity": "src/x.py:f",
                        "rationale": "needs exception",
                        "file_fingerprint": "sha256:03e693d9f2f687e0f40e36a8df7fcb4d1c22974012b7c2a55c000eb30f305824",
                        "ast_path": "Module/Expr",
                    },
                },
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]
    assert blocked["outcome"] == "BLOCKED"
    assert blocked["cell"] == "protected"
    assert blocked["seq"] == 1
    assert blocked["judge_model"] == "judge@protected"
    assert blocked["blocked_reason_code"] == "CODE_VIOLATION"
    assert len(store.read_all()) == 1


def test_policy_evaluate_returns_unknown_distinct_from_clear(tmp_path):
    runtime, _store = _runtime(tmp_path)
    grammar = PolicyGrammar()
    grammar.register(AllowlistBoundary("imports", frozenset({"json"})))
    runtime.grammar = grammar

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "policy_evaluate",
                    "arguments": {
                        "policy": "imports",
                        "target": {"value": "socket"},
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "policy_evaluate",
                    "arguments": {
                        "policy": "missing",
                        "target": {},
                    },
                },
            },
        ),
        runtime,
    )

    assert responses[0]["result"]["structuredContent"]["outcome"] == "VIOLATION"
    assert responses[0]["result"]["structuredContent"]["provenance_gap"] is False
    assert responses[1]["result"]["structuredContent"]["outcome"] == "UNKNOWN"
    assert responses[1]["result"]["structuredContent"]["provenance_gap"] is True


def test_scan_route_requires_exactly_one_cell_spec_and_routes_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING", "1")
    runtime, store = _runtime(tmp_path)
    scan = _active_scan()

    invalid = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "scan_route",
                    "arguments": {
                        "scan": scan,
                        "cell": "surface_override",
                        "severity_map": {"ERROR": "surface_override"},
                    },
                },
            }
        ),
        runtime,
    )[0]["result"]
    assert invalid["isError"] is True
    assert invalid["structuredContent"]["error_code"] == "INVALID_CELL_SPEC"
    assert store.read_all() == []

    routed = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "scan_route",
                    "arguments": {"scan": scan, "cell": "surface_override"},
                },
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]
    assert routed == {
        "outcome": "ROUTED",
        # opp #6: scan-level posture echoed at the root (keyless + unsigned here).
        "artifact_status": "unverified",
        # STRIKE D (PDR-0023): the unverified posture names WHY — key-absent
        # (verification DISABLED), distinguishable from a verification failure.
        "artifact_status_reason": "key_absent",
        "routed": [
            {
                "mode": "surface_override",
                "fingerprint": "fp1",
                "seq": 1,
                "accepted": True,
            }
        ],
    }


def test_scan_route_echoes_top_level_artifact_status_posture(tmp_path, monkeypatch):
    # opp #6 / vacuous-green (same class as wardline W2): a keyless dev-grade
    # pass must be distinguishable from a CI-signed pass at the TOP LEVEL of the
    # response — not only buried in each routed record's provenance (and absent
    # entirely when nothing routes). An agent relaying "governance passed" needs
    # the posture echoed at the response root.
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    runtime, _store = _runtime(tmp_path)

    structured = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "scan_route", "arguments": {"scan": _active_scan()}},
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]

    assert structured["outcome"] == "ROUTED"
    # keyless + unsigned => dev-grade "unverified" posture, echoed at the root
    assert structured["artifact_status"] == "unverified"


def test_scan_route_rejects_empty_severity_map(tmp_path, monkeypatch):
    # Drift fix: the HTTP adapter already rejected an empty cell_by_severity, but
    # MCP silently accepted an empty severity_map (routed nothing). Both transports
    # now reject it up front via the shared resolver — no silent governance skip.
    monkeypatch.setenv("LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING", "1")
    runtime, store = _runtime(tmp_path)
    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "scan_route",
                    "arguments": {"scan": _active_scan(), "severity_map": {}},
                },
            }
        ),
        runtime,
    )[0]["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "INVALID_CELL_SPEC"
    assert store.read_all() == []


def test_scan_route_rejects_request_routing_when_server_owned(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    runtime, store = _runtime(tmp_path)
    scan = _active_scan()

    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "scan_route",
                    "arguments": {"scan": scan, "cell": "surface_override"},
                },
            }
        ),
        runtime,
    )[0]["result"]

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "INVALID_CELL_SPEC"
    assert "server-owned" in result["structuredContent"]["message"]
    # N3 (weft-df8d2ef454) / C-10(c): the recovery hint names the concrete
    # enablement key, not a generic "use a valid cell configuration".
    assert "LEGIS_WARDLINE_CELL" in result["structuredContent"]["next_action"]
    assert store.read_all() == []


def test_scan_route_server_owned_error_names_supplied_cell(tmp_path, monkeypatch):
    # LEG-3(c): the SERVER_OWNED rejection must name the supplied request-side
    # "cell" (the cell trap), not just say "server-owned".
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    runtime, store = _runtime(tmp_path)

    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "scan_route",
                    "arguments": {"scan": _active_scan(), "cell": "surface_override"},
                },
            }
        ),
        runtime,
    )[0]["result"]

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "INVALID_CELL_SPEC"
    message = result["structuredContent"]["message"]
    assert "server-owned" in message
    # Pin the echo CLAUSE, not the bare token: "cell" also appears in the static
    # prose "pins the cell", so `"cell" in message` would still pass on a generic
    # message with the supplied-args echo stripped. This phrase comes only from
    # the supplied_request_args echo.
    assert "arg(s) cell were rejected" in message
    assert store.read_all() == []


def test_scan_route_defaults_to_server_owned_routing(tmp_path, monkeypatch):
    monkeypatch.delenv("LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING", raising=False)
    runtime, store = _runtime(tmp_path)
    scan = _active_scan()

    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "scan_route",
                    "arguments": {"scan": scan, "cell": "surface_only"},
                },
            }
        ),
        runtime,
    )[0]["result"]

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "INVALID_CELL_SPEC"
    assert "server-owned" in result["structuredContent"]["message"]
    # N3 (weft-df8d2ef454) / C-10(c): the recovery hint names the concrete
    # enablement key, not a generic "use a valid cell configuration".
    assert "LEGIS_WARDLINE_CELL" in result["structuredContent"]["next_action"]
    assert store.read_all() == []


def test_scan_route_uses_server_owned_cell(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    runtime, store = _runtime(tmp_path)

    routed = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "scan_route", "arguments": {"scan": _active_scan()}},
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]

    assert routed["routed"][0]["mode"] == "surface_only"
    assert store.read_all()[0].payload["kind"] == "wardline_surfaced"


def test_scan_route_requires_signed_artifact_when_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_WARDLINE_ARTIFACT_KEY", "wardline-key")
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    runtime, store = _runtime(tmp_path)
    scan = {
        "scanner_identity": "wardline@1",
        "rule_set_version": "rules@abc123",
        "commit_sha": "a" * 40,
        "tree_sha": "b" * 40,
        **_active_scan(),
    }

    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "scan_route", "arguments": {"scan": scan}},
            }
        ),
        runtime,
    )[0]["result"]

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "INVALID_ARGUMENT"
    assert "artifact signature" in result["structuredContent"]["message"]
    assert store.read_all() == []


def test_scan_route_records_verified_artifact_provenance(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_WARDLINE_ARTIFACT_KEY", "wardline-key")
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    runtime, store = _runtime(tmp_path)
    scan = _signed_wardline_scan(
        {
            "scanner_identity": "wardline@1",
            "rule_set_version": "rules@abc123",
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
            **_active_scan(),
        }
    )

    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "scan_route", "arguments": {"scan": scan}},
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]

    assert result["routed"][0]["mode"] == "surface_only"
    wardline = store.read_all()[0].payload["extensions"]["wardline"]
    assert wardline["artifact_status"] == "verified"
    assert wardline["scanner_identity"] == "wardline@1"
    assert wardline["artifact_signature"].startswith("hmac-sha256:v2:")


def _dirty_scan():
    return {
        "scanner_identity": "wardline@1.0.0rc1",
        "rule_set_version": "rules@abc123",
        "commit_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "dirty": True,
        **_active_scan(),
    }


def test_scan_route_dirty_tree_is_error_skip_not_success(tmp_path, monkeypatch):
    # P1: a dirty dev artifact in the CI posture (key configured) is a typed
    # dirty-tree error, not a successful scan_route result, because nothing is
    # governed.
    monkeypatch.setenv("LEGIS_WARDLINE_ARTIFACT_KEY", "wardline-key")
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    monkeypatch.delenv("LEGIS_WARDLINE_ALLOW_DIRTY", raising=False)
    runtime, store = _runtime(tmp_path)

    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "scan_route", "arguments": {"scan": _dirty_scan()}},
            }
        ),
        runtime,
    )[0]["result"]

    assert result["isError"] is True
    structured = result["structuredContent"]
    assert structured["error_code"] == "WARDLINE_DIRTY_TREE"
    assert "SKIPPED_DIRTY_TREE" in structured["message"]
    assert "LEGIS_WARDLINE_ALLOW_DIRTY" in structured["next_action"]
    assert store.read_all() == []


def test_scan_route_dirty_tree_governs_under_devmode_optin(tmp_path, monkeypatch):
    # P0: the explicit server-side dev-mode opt-in governs the unsigned dirty
    # artifact, recorded honestly as artifact_status="dirty".
    monkeypatch.setenv("LEGIS_WARDLINE_ARTIFACT_KEY", "wardline-key")
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    monkeypatch.setenv("LEGIS_WARDLINE_ALLOW_DIRTY", "1")
    runtime, store = _runtime(tmp_path)

    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "scan_route", "arguments": {"scan": _dirty_scan()}},
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]

    assert result["outcome"] == "ROUTED"
    assert result["routed"][0]["mode"] == "surface_only"
    wardline = store.read_all()[0].payload["extensions"]["wardline"]
    assert wardline["artifact_status"] == "dirty"
    assert "artifact_signature" not in wardline


def test_scan_route_malformed_finding_is_invalid_argument_red(tmp_path, monkeypatch):
    # The other half of the dirty-vs-malformed contract (cf. the dirty-tree test
    # above): a malformed finding — here an unknown severity — is a generic red
    # INVALID_ARGUMENT, NOT WARDLINE_DIRTY_TREE. WardlinePayloadError is
    # deliberately not a WardlineDirtyTreeError, so the boundary keeps "broken or
    # tampered scan" distinct from "commit first". Nothing is governed.
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    runtime, store = _runtime(tmp_path)
    malformed = {
        "findings": [
            {
                "rule_id": "PY-WL-101",
                "message": "untrusted reaches trusted",
                "severity": "NOT_A_SEVERITY",
                "kind": "defect",
                "fingerprint": "fp1",
            }
        ]
    }

    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "scan_route", "arguments": {"scan": malformed}},
            }
        ),
        runtime,
    )[0]["result"]

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "INVALID_ARGUMENT"
    assert store.read_all() == []


def test_scan_route_fail_on_threshold_routes_each_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING", "1")
    runtime, _store = _runtime(tmp_path)
    scan = {
        "findings": [
            {
                "rule_id": "PY-WL-E",
                "message": "error finding",
                "severity": "ERROR",
                "kind": "defect",
                "fingerprint": "fp-error",
                "qualname": "m.error",
                "properties": {},
                "suppression_state": "active",
            },
            {
                "rule_id": "PY-WL-W",
                "message": "warn finding",
                "severity": "WARN",
                "kind": "defect",
                "fingerprint": "fp-warn",
                "qualname": "m.warn",
                "properties": {},
                "suppression_state": "active",
            },
        ]
    }

    routed = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "scan_route",
                        "arguments": {
                            "scan": scan,
                            "cell": "surface_override",
                            "fail_on": "ERROR",
                        },
                },
            }
        ),
        runtime,
    )[0]["result"]["structuredContent"]["routed"]

    assert {item["fingerprint"]: item["mode"] for item in routed} == {
        "fp-error": "surface_override",
        "fp-warn": "surface_only",
    }


def test_override_rate_get_fails_closed_on_rechained_protected_tamper(tmp_path):
    db = tmp_path / "gov.db"
    store = AuditStore(f"sqlite:///{db}")
    gate = ProtectedGate(
        store,
        FixedClock("2026-06-02T12:00:00+00:00"),
        judge=_ScriptedJudge(JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")),
        key=KEY,
    )
    gate.submit(
        policy="no-eval",
        entity_key=EntityKey.from_locator("src/x.py:f"),
        rationale="original",
        agent_id="agent-launch",
        file_fingerprint="fp",
        ast_path="ap",
    )
    _tamper_first_record_and_rechain(db, lambda p: p.update({"rationale": "FORGED"}))
    assert store.verify_integrity() is True

    runtime, _unused = _runtime(tmp_path)
    runtime.engine = None
    runtime.protected_gate = gate
    runtime.trail_verifier = TrailVerifier(KEY, frozenset({"no-eval"}))

    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "override_rate_get", "arguments": {}},
            }
        ),
        runtime,
    )[0]["result"]

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "AUDIT_INTEGRITY_FAILURE"


def test_read_tools_return_git_pull_checks_and_override_rate(tmp_path, git_repo):
    checks = CheckSurface(f"sqlite:///{tmp_path / 'checks.db'}")
    checks.record(
        CheckRun(
            check_name="unit",
            run_id="run-1",
            commit_sha="abc123",
            outcome=CheckOutcome.PASS,
            pr=7,
            ran_against="abc123",
        )
    )
    pulls = PullSurface(f"sqlite:///{tmp_path / 'pulls.db'}")
    pulls.record(
        PullRequest(
            number=7,
            title="Feature",
            base="main",
            head="feature",
            state=PullRequestState.OPEN,
            url="https://example.test/pr/7",
        )
    )
    runtime, _store = _runtime(tmp_path, check_surface=checks)
    runtime.git_surface = GitSurface(git_repo)
    runtime.pull_surface = pulls
    runtime.engine.submit_override(
        policy="ordinary.policy",
        entity_key=EntityKey.from_locator("x"),
        rationale="r",
        agent_id="agent-launch",
    )

    head = GitSurface(git_repo).commits(limit=1)[0].sha
    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "git_branch_list", "arguments": {}},
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "git_commit_get",
                    "arguments": {"sha": head},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "git_rename_list",
                    "arguments": {"rev_range": "HEAD~1..HEAD"},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "pull_request_get",
                    "arguments": {"number": "7"},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "override_rate_get", "arguments": {}},
            },
        ),
        runtime,
    )

    assert {b["name"] for b in responses[0]["result"]["structuredContent"]["branches"]} == {
        "main",
        "feature",
    }
    assert responses[1]["result"]["structuredContent"]["commit"]["sha"] == head
    assert responses[2]["result"]["structuredContent"]["renames"][0]["old_path"] == "a.txt"
    pr = responses[3]["result"]["structuredContent"]
    assert pr["number"] == 7
    assert pr["checks"][0]["check_name"] == "unit"
    rate = responses[4]["result"]["structuredContent"]
    assert rate["sample_size"] == 0
    assert rate["note"] == "measures operator force-pasts; not movable by agent retries"


def test_pull_request_get_returns_checks_on_a_fresh_runtime(tmp_path, monkeypatch):
    # Regression: build_runtime yields check_surface=None, and the first tool
    # call an agent makes may be pull_request_get (no prior check_list to lazily
    # initialise the surface). The result must NOT be call-order-dependent — a PR
    # with recorded checks must report them, or a governance agent is told a PR is
    # clean when checks exist and may be failing.
    checks = CheckSurface(f"sqlite:///{tmp_path / 'checks.db'}")
    checks.record(
        CheckRun(
            check_name="unit",
            run_id="run-1",
            commit_sha="abc123",
            outcome=CheckOutcome.FAIL,
            pr=7,
            ran_against="abc123",
        )
    )
    # The lazy _checks() builder resolves the DB from LEGIS_CHECK_DB, exactly as a
    # deployed server does — so the surface is uninitialised but reachable.
    monkeypatch.setenv("LEGIS_CHECK_DB", f"sqlite:///{tmp_path / 'checks.db'}")
    pulls = PullSurface(f"sqlite:///{tmp_path / 'pulls.db'}")
    pulls.record(
        PullRequest(
            number=7,
            title="Feature",
            base="main",
            head="feature",
            state=PullRequestState.OPEN,
            url="https://example.test/pr/7",
        )
    )
    # Fresh runtime: check_surface left at its build_runtime default (None).
    runtime, _store = _runtime(tmp_path, check_surface=None)
    runtime.pull_surface = pulls

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "pull_request_get",
                    "arguments": {"number": "7"},
                },
            },
        ),
        runtime,
    )

    pr = responses[0]["result"]["structuredContent"]
    assert pr["number"] == 7
    assert pr["checks"][0]["check_name"] == "unit"
    assert pr["checks"][0]["outcome"] == "fail"


def test_check_list_reads_recorded_checks_by_commit_and_pr(tmp_path):
    checks = CheckSurface(f"sqlite:///{tmp_path / 'checks.db'}")
    checks.record(
        CheckRun(
            check_name="unit",
            run_id="run-1",
            commit_sha="abc123",
            outcome=CheckOutcome.PASS,
            branch="main",
            pr=7,
            ran_against="abc123",
        )
    )
    runtime, _store = _runtime(tmp_path, check_surface=checks)

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "check_list",
                    "arguments": {"target_type": "commit", "target": "abc123"},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "check_list",
                    "arguments": {"target_type": "pr", "target": "7"},
                },
            },
        ),
        runtime,
    )

    for response in responses:
        result = response["result"]
        assert "isError" not in result
        assert result["structuredContent"]["checks"] == [
            {
                "check_name": "unit",
                "run_id": "run-1",
                "commit_sha": "abc123",
                "outcome": "pass",
                "branch": "main",
                "pr": 7,
                "ran_against": "abc123",
                "rule_set": None,
                "policy_version": None,
                "started_at": None,
                "finished_at": None,
            }
        ]


def test_check_list_invalid_target_type_is_tool_error(tmp_path):
    checks = CheckSurface(f"sqlite:///{tmp_path / 'checks.db'}")
    runtime, _store = _runtime(tmp_path, check_surface=checks)

    responses = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "check_list",
                    "arguments": {"target_type": "tag", "target": "v1"},
                },
            }
        ),
        runtime,
    )

    result = responses[0]["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "INVALID_ARGUMENT"
    assert "target_type" in result["structuredContent"]["message"]
    assert result["structuredContent"]["recoverable"] is True
    assert "retry" in result["structuredContent"]["next_action"].lower()


def test_non_wp_m3_tool_names_are_not_callable(tmp_path):
    runtime, store = _runtime(tmp_path)

    for non_m3_name in (
        "submit_override",
        "protected_override",
        "signoff_request",
        "wardline_scan_results",
        "list_overrides",
        "override_rate",
    ):
        responses = _run(
            _messages(
                {
                    "jsonrpc": "2.0",
                    "id": non_m3_name,
                    "method": "tools/call",
                    "params": {"name": non_m3_name, "arguments": {}},
                }
            ),
            runtime,
        )
        result = responses[0]["result"]
        assert result["isError"] is True
        assert result["structuredContent"]["error_code"] == "UNKNOWN_TOOL"

    assert store.read_all() == []


def test_tools_call_with_non_object_params_returns_invalid_argument(tmp_path):
    runtime, _store = _runtime(tmp_path)
    responses = _run(
        _messages(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "bad"}
        ),
        runtime,
    )

    result = responses[0]["result"]
    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "INVALID_ARGUMENT"
    assert "params" in result["structuredContent"]["message"]


def test_build_runtime_loads_policy_cells_from_configured_path(tmp_path, monkeypatch):
    cells = tmp_path / "cells.toml"
    cells.write_text(
        """
default_cell = "chill"

[[policy]]
pattern = "secure.*"
cell = "protected"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("LEGIS_POLICY_CELLS", str(cells))
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov.db'}")
    monkeypatch.setenv("LEGIS_CHECK_DB", f"sqlite:///{tmp_path / 'checks.db'}")

    from legis.mcp import build_runtime

    runtime = build_runtime("agent-1")

    assert runtime.cell_registry is not None
    assert runtime.cell_registry.cell_for("secure.source") == "protected"
    assert runtime.cell_registry.cell_for("ordinary.policy") == "chill"


def test_tool_registries_are_in_sync():
    # mcp.py hand-maintains three parallel name registries: the public schema
    # (tool_definitions), the dispatch table (_TOOL_HANDLERS), and the agent-
    # exposed set (_AGENT_TOOLS). They MUST agree. A handler without a schema
    # entry is reachable-but-unvalidated (it accepts arbitrary arg keys); a
    # schema entry without a handler advertises a tool that errors UNKNOWN_TOOL.
    # The table-driven dispatch makes exactly this drift easy to introduce, so
    # pin it directly rather than inferring it from per-tool listing tests.
    from legis.mcp import _AGENT_TOOLS, _TOOL_HANDLERS, tool_definitions

    defined = {t["name"] for t in tool_definitions()}
    assert defined == set(_TOOL_HANDLERS) == set(_AGENT_TOOLS)


def test_every_emitted_error_code_yields_a_nonempty_next_action():
    # LEG-2(b): _tool_error must emit a non-empty next_action string for every
    # error_code legis actually emits — locks the recovery hints against drift.
    # The code set is the runtime source of truth (_recovery_for + the default
    # fall-through codes from _service_error); update this list when codes change.
    from legis.mcp import _tool_error

    emitted_codes = (
        # codes in _recovery_for's explicit map
        "INVALID_ARGUMENT",
        "INVALID_CELL_SPEC",
        "CELL_NOT_ENABLED",
        "NO_SUCH_REQUEST",
        "NOT_FOUND",
        "UNKNOWN_TOOL",
        "AUDIT_INTEGRITY_FAILURE",
        "GIT_ERROR",
        "SIGNOFF_NOT_CLEARED",
        "BINDING_UNAVAILABLE",
        "FILIGREE_UNAVAILABLE",
        # codes that hit the default next_action (still must be non-empty)
        "SERVICE_ERROR",
        "INTERNAL_ERROR",
    )
    for code in emitted_codes:
        next_action = _tool_error(code, "msg")["structuredContent"]["next_action"]
        assert isinstance(next_action, str) and next_action, code


def test_c8_no_agent_reachable_enablement_or_signing_surface():
    # C-8 capability confinement (red-team guard for N3/N4): the MCP surface must
    # never expose a tool that enables a cell, provisions/sets a key, or otherwise
    # lets an agent self-grant signing/governance authority. Enablement is an
    # operator-only, out-of-band action (env + relaunch / CLI doctor). This pins
    # that no such tool was introduced.
    from legis.mcp import _TOOL_HANDLERS, tool_definitions

    forbidden = ("enable", "provision", "grant", "hmac", "sign_key", "set_key")
    for name in _TOOL_HANDLERS:
        low = name.lower()
        assert not any(tok in low for tok in forbidden), f"C-8: suspicious tool {name!r}"

    # scan_route must not have grown a dirty-govern / key / cell-override knob:
    # the dirty-snapshot opt-in (LEGIS_WARDLINE_ALLOW_DIRTY) and the artifact key
    # stay env-only operator switches, never call arguments (N4 guard).
    scan_route = next(t for t in tool_definitions() if t["name"] == "scan_route")
    description = scan_route["description"]
    assert "default keyless posture is governed" in description
    assert "artifact_status=dirty" in description
    assert "SKIPPED_DIRTY_TREE" in description
    assert "WARDLINE_DIRTY_TREE" not in description
    props = set(scan_route["inputSchema"]["properties"])
    assert props == {"scan", "cell", "severity_map", "fail_on"}
    for forbidden_arg in ("allow_dirty", "artifact_key", "hmac_key", "agent_id"):
        assert forbidden_arg not in props


def test_warpline_tools_introduce_no_new_error_codes(tmp_path):
    # warpline_preflight_get / attestation_get degrade to success-envelope
    # status:"unavailable"; their only error path is the pre-existing
    # AUDIT_INTEGRITY_FAILURE. No new error code => no _recovery_for / pinned-code change.
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)
    assert not call_tool(runtime, "warpline_preflight_get", {"base": "x"}).get("isError")
    assert not call_tool(runtime, "attestation_get", {"sei": "x#1"}).get("isError")


def test_git_rename_feed_get_is_listed():
    from legis.mcp import tool_definitions

    names = {t["name"] for t in tool_definitions()}
    assert "git_rename_feed_get" in names


def test_git_rename_feed_get_returns_committed_renames(git_repo, monkeypatch):
    from legis.mcp import build_runtime, call_tool

    monkeypatch.setenv("LEGIS_SOURCE_ROOT", str(git_repo))
    runtime = build_runtime("agent-1")

    result = call_tool(runtime, "git_rename_feed_get", {"base": "HEAD~1", "head": "HEAD"})

    assert result["structuredContent"]["committed"][0]["new_path"] == "renamed.txt"
    assert result["structuredContent"]["status"] == "committed_only"


def test_filigree_closure_gate_get_is_listed():
    from legis.mcp import tool_definitions

    names = {t["name"] for t in tool_definitions()}
    assert "filigree_closure_gate_get" in names


def test_tool_error_text_content_carries_next_action():
    # LEG-2: text-only MCP clients never see structuredContent, so the recovery
    # hint must ride in the text content too. The "{code}: {message}" first
    # line stays a stable prefix (clients may parse it); the remediation is
    # appended after it.
    from legis.mcp import _tool_error

    result = _tool_error("CELL_NOT_ENABLED", "binding ledger not enabled")

    text = result["content"][0]["text"]
    assert text.startswith("CELL_NOT_ENABLED: binding ledger not enabled")
    assert f"\nnext_action: {result['structuredContent']['next_action']}" in text


def test_binding_ledger_not_enabled_message_names_operator_key(monkeypatch):
    # LEG-2: the MESSAGE itself names the enabling knob (scan_route quality
    # bar) — phrased as an operator action, never an agent one (C-8).
    from legis.mcp import build_runtime, call_tool

    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)
    runtime = build_runtime("agent-1")

    result = call_tool(runtime, "filigree_closure_gate_get", {"issue_id": "ISSUE-7"})

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "CELL_NOT_ENABLED"
    message = result["structuredContent"]["message"]
    assert "LEGIS_HMAC_KEY" in message
    assert "operator" in message
    # The text content surfaces both the message and the recovery hint.
    assert "LEGIS_HMAC_KEY" in result["content"][0]["text"]
    assert "next_action:" in result["content"][0]["text"]


def test_signoff_status_get_not_enabled_message_names_operator_key(tmp_path):
    runtime, _store = _runtime(tmp_path)  # no signoff gate wired

    result = _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "signoff_status_get", "arguments": {"seq": 1}},
            }
        ),
        runtime,
    )[0]["result"]

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "CELL_NOT_ENABLED"
    message = result["structuredContent"]["message"]
    assert "LEGIS_HMAC_KEY" in message
    assert "operator" in message


def test_policy_explain_description_documents_policy_known():
    # N-9: agents must learn the policy_known semantics from tools/list alone.
    from legis.mcp import tool_definitions

    description = next(
        t for t in tool_definitions() if t["name"] == "policy_explain"
    )["description"]
    assert "policy_known" in description
    assert "default_cell" in description


def test_filigree_closure_gate_get_not_enabled_without_ledger(monkeypatch):
    from legis.mcp import build_runtime, call_tool

    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)
    runtime = build_runtime("agent-1")

    result = call_tool(runtime, "filigree_closure_gate_get", {"issue_id": "ISSUE-7"})

    # NotEnabledError is mapped to an error envelope, not raised.
    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "CELL_NOT_ENABLED"
    # Le1 (weft-f506e5f845) + N3 (weft-df8d2ef454): the recovery hint names the
    # concrete enablement path for BOTH axes — the simple tier (policy-cell
    # definitions, keyless) and the complex tier (the operator-held key).
    next_action = result["structuredContent"]["next_action"]
    assert "LEGIS_HMAC_KEY" in next_action  # complex tier (Le1, preserved)
    # simple tier: chill/coached are reachable keyless via the policy-cell config
    assert "LEGIS_POLICY_CELLS" in next_action or "policy/cells.toml" in next_action


def test_filigree_closure_gate_get_surfaces_integrity_failure(monkeypatch, tmp_path):
    # A tampered binding ledger must surface AUDIT_INTEGRITY_FAILURE via MCP,
    # mirroring the HTTP 500 path — not a generic INTERNAL_ERROR.
    from legis.governance.binding_ledger import BindingError
    from legis.mcp import McpRuntime, call_tool

    class _TamperedLedger:
        def get_by_issue_id(self, issue_id):
            raise BindingError("hash chain integrity check failed")

    runtime = McpRuntime(agent_id="agent-1", binding_ledger=_TamperedLedger())
    result = call_tool(runtime, "filigree_closure_gate_get", {"issue_id": "ISSUE-7"})

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "AUDIT_INTEGRITY_FAILURE"


# --- roadmap 14: stdin JSON-RPC line-size bound ---

def test_run_jsonrpc_rejects_oversized_line_and_stays_framed(tmp_path, monkeypatch):
    # A single line over the bound is rejected with -32700 and does not consume
    # the following request — framing realigns at the next newline.
    monkeypatch.setenv("LEGIS_MCP_MAX_REQUEST_BYTES", "400")
    runtime, _store = _runtime(tmp_path)
    runtime.initialized = False
    oversized = {
        "jsonrpc": "2.0", "id": 99, "method": "tools/list",
        "params": {"pad": "A" * 2000},
    }
    responses = _run(
        _messages(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-03-26"}},
            oversized,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ),
        runtime,
    )

    assert responses[0]["id"] == 1 and "result" in responses[0]
    assert responses[1]["id"] is None
    assert responses[1]["error"]["code"] == -32700
    assert "maximum size" in responses[1]["error"]["message"]
    # The request AFTER the oversized line is still parsed and answered.
    assert responses[2]["id"] == 2 and "result" in responses[2]


def test_max_request_bytes_env_override_and_fallback(monkeypatch, caplog):
    from legis.mcp import _DEFAULT_MAX_REQUEST_BYTES, _max_request_bytes

    monkeypatch.delenv("LEGIS_MCP_MAX_REQUEST_BYTES", raising=False)
    assert _max_request_bytes() == _DEFAULT_MAX_REQUEST_BYTES
    monkeypatch.setenv("LEGIS_MCP_MAX_REQUEST_BYTES", "4096")
    assert _max_request_bytes() == 4096
    # Both the unparseable and the non-positive fat-finger fall back, but neither
    # may do so silently — an operator lowering the bound must see why it was
    # ignored.
    for bad in ("not-an-int", "0", "-5"):
        caplog.clear()
        monkeypatch.setenv("LEGIS_MCP_MAX_REQUEST_BYTES", bad)
        with caplog.at_level(logging.WARNING, logger="legis.mcp"):
            assert _max_request_bytes() == _DEFAULT_MAX_REQUEST_BYTES
        assert "LEGIS_MCP_MAX_REQUEST_BYTES" in caplog.text


def test_read_bounded_line_enforces_bytes_not_chars():
    # The bound is named in BYTES; readline() counts characters. A record that
    # fits the char count but whose UTF-8 encoding exceeds the cap (multibyte
    # content) must still overflow — otherwise the byte limit could be exceeded
    # ~4×. The record AFTER it must stay framed.
    from legis.mcp import _read_bounded_line

    multibyte = "中" * 200  # 200 chars, 600 UTF-8 bytes — under 400 chars, over 400 bytes
    stream = io.StringIO(f"{multibyte}\n" + '{"next":true}\n')

    line, overflow = _read_bounded_line(stream, 400)
    assert overflow is True
    assert line.startswith("中")

    nxt, nxt_overflow = _read_bounded_line(stream, 400)
    assert nxt_overflow is False
    assert nxt == '{"next":true}\n'


def test_read_bounded_line_at_byte_boundary():
    # The bound counts the trailing newline (fail-safe off-by-one): a 399-byte
    # data record + "\n" == 400 bytes passes; one more byte overflows.
    from legis.mcp import _read_bounded_line

    ok_line, ok_overflow = _read_bounded_line(io.StringIO("x" * 399 + "\n"), 400)
    assert ok_overflow is False
    assert ok_line == "x" * 399 + "\n"

    _, over_overflow = _read_bounded_line(io.StringIO("x" * 400 + "\n"), 400)
    assert over_overflow is True


def test_read_bounded_line_drains_oversized_multibyte_record():
    # A record longer than the *character* cap forces the drain loop (first
    # branch) — exercise it with multibyte content and assert the next record
    # stays framed (the existing multibyte test stays under the char cap and
    # hits the second branch instead).
    from legis.mcp import _read_bounded_line

    stream = io.StringIO("中" * 20 + "\n" + "{}\n")  # 20 chars > 10-char cap
    line, overflow = _read_bounded_line(stream, 10)
    assert overflow is True
    assert line.startswith("中")

    nxt, nxt_overflow = _read_bounded_line(stream, 10)
    assert nxt == "{}\n"
    assert nxt_overflow is False


def test_service_error_logs_unexpected_internal_error(caplog):
    # An unexpected exception is surfaced to the caller as INTERNAL_ERROR; it must
    # also be logged server-side (with the exception) so the operator/Sentry sees
    # what the agent caller's payload alone would hide.
    from legis.mcp import _service_error

    with caplog.at_level(logging.ERROR, logger="legis.mcp"):
        result = _service_error(RuntimeError("kaboom"))

    assert result["structuredContent"]["error_code"] == "INTERNAL_ERROR"
    assert any(r.levelno == logging.ERROR and r.exc_info for r in caplog.records)


def test_service_error_does_not_log_expected_typed_errors(caplog):
    # Expected, typed service errors map to typed codes and must NOT spam the
    # server log — only the unexpected INTERNAL_ERROR fall-through logs.
    from legis.mcp import _service_error
    from legis.service.errors import NotFoundError

    with caplog.at_level(logging.ERROR, logger="legis.mcp"):
        result = _service_error(NotFoundError("nope"))

    assert result["structuredContent"]["error_code"] == "NOT_FOUND"
    assert not caplog.records


# --- legis-428f05c9ca: signoff_bind_issue + binding read over pure MCP ---

class _FakeFiligree:
    def __init__(self):
        self.attached = []

    def attach(self, issue_id, entity_id, content_hash, *, actor,
               signoff_seq=None, signature=None):
        self.attached.append(
            (issue_id, entity_id, content_hash, actor, signoff_seq, signature)
        )
        return {"issue_id": issue_id, "loomweave_entity_id": entity_id,
                "content_hash_at_attach": content_hash, "attached_at": "t",
                "attached_by": actor}

    def associations_for_entity(self, entity_id):
        return []


def _bind_runtime(tmp_path, *, with_ledger=True):
    from legis.governance.binding_ledger import BindingLedger

    runtime, store = _runtime(tmp_path)
    clock = FixedClock("2026-06-02T12:00:00+00:00")
    runtime.signoff_gate = SignoffGate(store, clock)
    runtime.filigree = _FakeFiligree()
    if with_ledger:
        runtime.binding_ledger = BindingLedger(
            AuditStore(f"sqlite:///{tmp_path / 'bind.db'}"), clock, key=b"ledger-key"
        )
    runtime.binding_key = b"bind-key"
    return runtime, store


def _cleared_sei_request(gate, *, content_hash="blake3"):
    req = gate.request(
        policy="prod-deploy",
        entity_key=EntityKey.from_sei("loomweave:eid:abc"),
        rationale="needs a human",
        agent_id="agent-1",
        extensions={"loomweave": {"content_hash": content_hash, "alive": True,
                                  "lineage_snapshot": None}},
    )
    gate.sign_off(request_seq=req.seq, operator_id="op-1")
    return req


def test_signoff_bind_issue_is_listed():
    from legis.mcp import tool_definitions

    names = {t["name"] for t in tool_definitions()}
    assert "signoff_bind_issue" in names
    # The sign itself stays operator-only, off the agent surface (locked decision).
    assert "signoff_sign" not in names


def test_signoff_bind_issue_completes_the_pure_mcp_closure_flow(tmp_path):
    # The legis-428f05c9ca acceptance: REQUEST (override_submit, covered
    # elsewhere) -> poll -> BIND -> closure gate green, all over MCP tools only.
    from legis.mcp import call_tool

    runtime, _store = _bind_runtime(tmp_path)
    req = _cleared_sei_request(runtime.signoff_gate)

    bound = call_tool(
        runtime, "signoff_bind_issue", {"seq": req.seq, "issue_id": "ISSUE-1"}
    )
    assert not bound.get("isError")
    payload = bound["structuredContent"]
    assert payload["binding_seq"] == 1
    assert payload["signoff_seq"] == req.seq
    # The SEI and content_hash come from the recorded, CLEARED sign-off — never
    # from the caller (same governed sourcing as the HTTP bind-issue route).
    issue_id, entity_id, chash, actor, seq, signature = runtime.filigree.attached[0]
    assert (issue_id, entity_id, chash, actor, seq) == (
        "ISSUE-1", "loomweave:eid:abc", "blake3", "legis", req.seq
    )
    assert signature is not None  # binding_key wired -> signed attestation

    # The binding read rides in signoff_status_get's cleared payload.
    status = call_tool(runtime, "signoff_status_get", {"seq": req.seq})
    status_payload = status["structuredContent"]
    assert status_payload["cleared"] is True
    assert status_payload["binding"]["issue_id"] == "ISSUE-1"
    assert status_payload["binding"]["entity_key"]["value"] == "loomweave:eid:abc"
    assert status_payload["binding"]["content_hash"] == "blake3"

    # And the Filigree closure gate goes green — the flow is completable.
    gate = call_tool(runtime, "filigree_closure_gate_get", {"issue_id": "ISSUE-1"})
    assert gate["structuredContent"]["allowed"] is True


def test_signoff_status_get_cleared_payload_reports_unbound_as_null(tmp_path):
    # Ledger wired but nothing bound yet: binding is an explicit null, so an
    # agent can tell "not bound yet" from "no ledger on this deployment"
    # (key omitted entirely — pinned by the exact-equality assertion in
    # test_override_submit_structured_escalates_and_status_poll_reflects_signoff).
    from legis.mcp import call_tool

    runtime, _store = _bind_runtime(tmp_path)
    req = _cleared_sei_request(runtime.signoff_gate)

    status = call_tool(runtime, "signoff_status_get", {"seq": req.seq})
    payload = status["structuredContent"]
    assert payload["cleared"] is True
    assert payload["binding"] is None


def test_signoff_bind_issue_rejects_uncleared_request_with_poll_guidance(tmp_path):
    from legis.mcp import call_tool

    runtime, _store = _bind_runtime(tmp_path)
    req = runtime.signoff_gate.request(
        policy="prod-deploy",
        entity_key=EntityKey.from_sei("loomweave:eid:abc"),
        rationale="needs a human",
        agent_id="agent-1",
    )

    result = call_tool(
        runtime, "signoff_bind_issue", {"seq": req.seq, "issue_id": "ISSUE-1"}
    )

    assert result["isError"] is True
    sc = result["structuredContent"]
    assert sc["error_code"] == "SIGNOFF_NOT_CLEARED"
    assert sc["recoverable"] is True
    assert "signoff_status_get" in sc["next_action"]
    assert runtime.filigree.attached == []


def test_signoff_bind_issue_unknown_seq_is_no_such_request(tmp_path):
    from legis.mcp import call_tool

    runtime, _store = _bind_runtime(tmp_path)

    result = call_tool(runtime, "signoff_bind_issue", {"seq": 99, "issue_id": "I-1"})

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "NO_SUCH_REQUEST"
    assert runtime.filigree.attached == []


def test_signoff_bind_issue_locator_keyed_signoff_is_binding_unavailable(tmp_path):
    # ADR-0003: a locator-keyed (non-SEI) sign-off fails closed rather than
    # recording a rename-fragile binding. Typed amber, not INTERNAL_ERROR.
    from legis.mcp import call_tool

    runtime, _store = _bind_runtime(tmp_path)
    req = runtime.signoff_gate.request(
        policy="prod-deploy",
        entity_key=EntityKey.from_locator("python:function:m.f"),
        rationale="needs a human",
        agent_id="agent-1",
    )
    runtime.signoff_gate.sign_off(request_seq=req.seq, operator_id="op-1")

    result = call_tool(
        runtime, "signoff_bind_issue", {"seq": req.seq, "issue_id": "ISSUE-1"}
    )

    assert result["isError"] is True
    sc = result["structuredContent"]
    assert sc["error_code"] == "BINDING_UNAVAILABLE"
    assert runtime.filigree.attached == []


def test_signoff_bind_issue_uses_sei_backfill_for_locator_keyed_request(tmp_path):
    # The recovery half of ADR-0003: a SEI_BACKFILL event resolves the locator
    # to a stable identity and the bind succeeds with the backfilled SEI.
    from legis.mcp import call_tool

    runtime, store = _bind_runtime(tmp_path)
    req = runtime.signoff_gate.request(
        policy="prod-deploy",
        entity_key=EntityKey.from_locator("python:function:m.f"),
        rationale="needs a human",
        agent_id="agent-1",
    )
    runtime.signoff_gate.sign_off(request_seq=req.seq, operator_id="op-1")
    store.append(
        {
            "event": "SEI_BACKFILL",
            "original_seq": req.seq,
            "entity_key": EntityKey.from_sei("loomweave:eid:abc").to_dict(),
            "identity_stable": True,
            "agent_id": "legis-sei-backfill",
            "recorded_at": "2026-06-04T12:00:00+00:00",
            "extensions": {
                "loomweave": {
                    "alive": True,
                    "content_hash": "hash-abc",
                    "lineage_snapshot": {"length": 1, "hash": "lineage"},
                    "identity_resolution_status": "resolved",
                    "lineage_snapshot_status": "verified",
                },
                "backfill": {
                    "source": "pre_sei_locator",
                    "original_seq": req.seq,
                    "original_entity_key": EntityKey.from_locator(
                        "python:function:m.f"
                    ).to_dict(),
                },
            },
        }
    )

    result = call_tool(
        runtime, "signoff_bind_issue", {"seq": req.seq, "issue_id": "ISSUE-1"}
    )

    assert not result.get("isError")
    issue_id, entity_id, chash, _actor, _seq, _sig = runtime.filigree.attached[0]
    assert (issue_id, entity_id, chash) == ("ISSUE-1", "loomweave:eid:abc", "hash-abc")


def test_signoff_bind_issue_without_filigree_names_operator_knob(tmp_path):
    from legis.mcp import call_tool

    runtime, _store = _bind_runtime(tmp_path)
    runtime.filigree = None

    result = call_tool(runtime, "signoff_bind_issue", {"seq": 1, "issue_id": "I-1"})

    assert result["isError"] is True
    sc = result["structuredContent"]
    assert sc["error_code"] == "CELL_NOT_ENABLED"
    # LEG-2: the message names the operator knob, phrased as an operator action.
    assert "FILIGREE_API_URL" in sc["message"]
    assert "operator" in sc["message"]


def test_signoff_bind_issue_without_signoff_gate_names_operator_key(tmp_path):
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)  # no signoff gate wired
    runtime.filigree = _FakeFiligree()

    result = call_tool(runtime, "signoff_bind_issue", {"seq": 1, "issue_id": "I-1"})

    assert result["isError"] is True
    sc = result["structuredContent"]
    assert sc["error_code"] == "CELL_NOT_ENABLED"
    assert "LEGIS_HMAC_KEY" in sc["message"]


def test_signoff_bind_issue_fails_closed_on_tampered_signed_signoff(tmp_path):
    # Same fail-closed property the HTTP route has: a tampered signed sign-off
    # trail is an AUDIT_INTEGRITY_FAILURE and nothing is attached to Filigree.
    from legis.mcp import call_tool

    runtime, _store = _bind_runtime(tmp_path)
    db = tmp_path / "gov.db"
    gate = SignoffGate(
        AuditStore(f"sqlite:///{db}"),
        FixedClock("2026-06-02T12:00:00+00:00"),
        signer=True,
        key=KEY,
    )
    runtime.signoff_gate = gate
    runtime.trail_verifier = TrailVerifier(KEY, frozenset())
    req = _cleared_sei_request(gate)
    _tamper_first_record_and_rechain(
        db,
        lambda p: p["extensions"]["loomweave"].update({"content_hash": "forged"}),
    )

    result = call_tool(
        runtime, "signoff_bind_issue", {"seq": req.seq, "issue_id": "ISSUE-1"}
    )

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "AUDIT_INTEGRITY_FAILURE"
    assert runtime.filigree.attached == []


def test_signoff_bind_issue_filigree_transport_failure_is_typed(tmp_path):
    # A Filigree that is down/unreachable is an expected operational state for
    # an agent — a typed, recoverable error, not INTERNAL_ERROR.
    from legis.filigree.client import FiligreeError
    from legis.mcp import call_tool

    class _DownFiligree:
        def attach(self, *a, **kw):
            raise FiligreeError("POST http://filigree/attach failed: refused")

        def associations_for_entity(self, entity_id):
            return []

    runtime, _store = _bind_runtime(tmp_path)
    runtime.filigree = _DownFiligree()
    req = _cleared_sei_request(runtime.signoff_gate)

    result = call_tool(
        runtime, "signoff_bind_issue", {"seq": req.seq, "issue_id": "ISSUE-1"}
    )

    assert result["isError"] is True
    sc = result["structuredContent"]
    assert sc["error_code"] == "FILIGREE_UNAVAILABLE"
    assert sc["recoverable"] is True


def test_build_runtime_wires_filigree_and_binding_key_from_env(tmp_path, monkeypatch):
    from legis.filigree.client import HttpFiligreeClient
    from legis.mcp import build_runtime

    monkeypatch.setenv("LEGIS_HMAC_KEY", "secret")
    monkeypatch.setenv("FILIGREE_API_URL", "http://localhost:8971")
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", f"sqlite:///{tmp_path / 'gov-env.db'}")
    monkeypatch.setenv("LEGIS_BINDING_DB", f"sqlite:///{tmp_path / 'bind-env.db'}")

    runtime = build_runtime("agent-launch")

    assert isinstance(runtime.filigree, HttpFiligreeClient)
    assert runtime.binding_key == b"secret"


def test_build_runtime_leaves_filigree_unwired_without_env(tmp_path, monkeypatch):
    from legis.mcp import build_runtime

    monkeypatch.delenv("FILIGREE_API_URL", raising=False)
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)

    runtime = build_runtime("agent-launch")

    assert runtime.filigree is None
    assert runtime.binding_key is None


# --- legis-62c7c58ae4: SEI lineage-honesty reads over MCP ---

class _FakeLoomweave:
    """Duck-typed LoomweaveIdentity read client (mirrors tests/api FakeClient)."""

    def __init__(self, lineage=None, alive=True):
        self._lineage = lineage or []
        self._alive = alive

    def capability(self):
        return True

    def resolve_locator(self, locator):
        return {"sei": "loomweave:eid:abc123", "current_locator": locator,
                "content_hash": "h", "alive": True}

    def resolve_sei(self, sei):
        if self._alive:
            return {"sei": sei, "alive": True}
        return {"sei": sei, "alive": False, "lineage": [{"event": "orphaned"}]}

    def lineage(self, sei):
        return self._lineage


def _sei_record(sei="loomweave:eid:abc123", *, loomweave_ext=None):
    payload = {
        "policy": "no-eval",
        "entity_key": {"value": sei, "identity_stable": True},
        "agent_id": "agent-1",
        "rationale": "reviewed",
    }
    if loomweave_ext is not None:
        payload["extensions"] = {"loomweave": loomweave_ext}
    return payload


def test_lineage_honesty_read_tools_are_listed():
    from legis.mcp import tool_definitions

    names = {t["name"] for t in tool_definitions()}
    assert "identity_gap_list" in names
    assert "lineage_integrity_get" in names


def test_identity_gap_list_unwired_loomweave_is_unavailable_not_empty_green(tmp_path):
    # GOV-2: a bare [] when Loomweave is unwired would read as an all-clear on
    # exactly the condition the tool exists to catch. status must say so.
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)  # no identity resolver wired

    result = call_tool(runtime, "identity_gap_list", {})

    assert not result.get("isError")
    assert result["structuredContent"] == {
        "status": "unavailable",
        "gaps": [],
        "unavailable": [{"reason": "loomweave client not configured"}],
    }


def test_lineage_integrity_get_unwired_loomweave_is_unavailable_not_verified(tmp_path):
    # GOV-1 twin of the above for the lineage read.
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)

    result = call_tool(runtime, "lineage_integrity_get", {})

    assert not result.get("isError")
    assert result["structuredContent"] == {
        "status": "unavailable",
        "divergences": [],
        "unavailable": [{"reason": "loomweave client not configured"}],
    }


def test_identity_gap_list_surfaces_orphaned_attestation(tmp_path):
    from legis.identity.resolver import IdentityResolver
    from legis.mcp import call_tool

    runtime, store = _runtime(tmp_path)
    runtime.identity = IdentityResolver(_FakeLoomweave(alive=False))
    store.append(_sei_record())

    result = call_tool(runtime, "identity_gap_list", {})

    payload = result["structuredContent"]
    assert payload["status"] == "checked"
    assert payload["gaps"] == [
        {"sei": "loomweave:eid:abc123", "reason": "orphaned",
         "lineage": [{"event": "orphaned"}]}
    ]


def test_lineage_integrity_get_three_way_status_precedence(tmp_path):
    # GOV-1: diverged > unverified > verified — a divergence is never masked by
    # an unavailable sibling, and unavailable is never reported verified.
    from legis.identity.resolver import IdentityResolver
    from legis.mcp import call_tool

    lineage = [{"event": "born"}]
    runtime, store = _runtime(tmp_path)
    runtime.identity = IdentityResolver(_FakeLoomweave(lineage=lineage))

    # verified: snapshot is a prefix of the current lineage
    store.append(_sei_record(loomweave_ext={
        "lineage_snapshot": {"length": 1, "hash": content_hash(lineage)},
    }))
    verified = call_tool(runtime, "lineage_integrity_get", {})["structuredContent"]
    assert verified == {"status": "verified", "divergences": [], "unavailable": []}

    # unverified: a second SEI recorded with no snapshot
    store.append(_sei_record("loomweave:eid:nosnap", loomweave_ext={
        "lineage_snapshot": None, "lineage_snapshot_status": "unavailable",
    }))
    unverified = call_tool(runtime, "lineage_integrity_get", {})["structuredContent"]
    assert unverified["status"] == "unverified"
    assert unverified["divergences"] == []
    assert unverified["unavailable"] == [
        {"sei": "loomweave:eid:nosnap", "reason": "unavailable"}
    ]

    # diverged beats unverified: a third SEI whose recorded prefix no longer holds
    store.append(_sei_record("loomweave:eid:diverged", loomweave_ext={
        "lineage_snapshot": {"length": 1, "hash": "not-the-recorded-prefix"},
    }))
    diverged = call_tool(runtime, "lineage_integrity_get", {})["structuredContent"]
    assert diverged["status"] == "diverged"
    assert diverged["divergences"] == [
        {"sei": "loomweave:eid:diverged", "recorded_length": 1, "current_length": 1}
    ]
    assert diverged["unavailable"] == [
        {"sei": "loomweave:eid:nosnap", "reason": "unavailable"}
    ]


def test_identity_gap_list_reads_trail_on_fresh_runtime(tmp_path, monkeypatch):
    # The keyless trail is read through the lazily-initialised engine store, so
    # the result is not call-order-dependent (same bug class as the
    # pull_request_get fresh-runtime fix): a fresh runtime must see records an
    # earlier session persisted, not report a hollow zero-gap green.
    from legis.identity.resolver import IdentityResolver
    from legis.mcp import McpRuntime, call_tool

    db = f"sqlite:///{tmp_path / 'gov.db'}"
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", db)
    AuditStore(db).append(_sei_record())
    runtime = McpRuntime(
        agent_id="agent-1",
        initialized=True,
        identity=IdentityResolver(_FakeLoomweave(alive=False)),
    )

    result = call_tool(runtime, "identity_gap_list", {})

    payload = result["structuredContent"]
    assert payload["status"] == "checked"
    assert [g["sei"] for g in payload["gaps"]] == ["loomweave:eid:abc123"]


def test_lineage_honesty_reads_fail_closed_on_tampered_protected_trail(tmp_path):
    # Same fail-closed property as the HTTP routes (tampered trail -> 500): the
    # reads consume the VERIFIED trail, never a tampered one.
    from legis.identity.resolver import IdentityResolver
    from legis.mcp import call_tool

    db = tmp_path / "gov.db"
    store = AuditStore(f"sqlite:///{db}")
    gate = ProtectedGate(
        store,
        FixedClock("2026-06-02T12:00:00+00:00"),
        judge=_ScriptedJudge(JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")),
        key=KEY,
    )
    gate.submit(
        policy="no-eval",
        entity_key=EntityKey.from_locator("src/x.py:f"),
        rationale="original",
        agent_id="agent-launch",
        file_fingerprint="fp",
        ast_path="ap",
    )
    _tamper_first_record_and_rechain(db, lambda p: p.update({"rationale": "FORGED"}))

    runtime, _unused = _runtime(tmp_path)
    runtime.engine = None
    runtime.protected_gate = gate
    runtime.trail_verifier = TrailVerifier(KEY, frozenset({"no-eval"}))
    runtime.identity = IdentityResolver(_FakeLoomweave())

    for tool in ("identity_gap_list", "lineage_integrity_get"):
        result = call_tool(runtime, tool, {})
        assert result["isError"] is True, tool
        assert result["structuredContent"]["error_code"] == "AUDIT_INTEGRITY_FAILURE"


# --- legis-e5c57dedd1: check_report write + pull_request_record named decision ---

def test_check_report_records_launch_bound_agent_and_reads_back(tmp_path):
    from legis.mcp import call_tool

    checks = CheckSurface(f"sqlite:///{tmp_path / 'checks.db'}")
    runtime, _store = _runtime(tmp_path, agent_id="agent-ci", check_surface=checks)

    result = call_tool(runtime, "check_report", {
        "check_name": "pytest",
        "run_id": "run-1",
        "commit_sha": "c" * 40,
        "outcome": "fail",
        "branch": "rc5",
        "pr": 7,
    })

    assert not result.get("isError")
    payload = result["structuredContent"]
    assert payload["check_name"] == "pytest"
    assert payload["outcome"] == "fail"
    # Attribution is the launch-bound agent_id (stronger than the HTTP writer
    # token), never a call argument.
    assert payload["recorded_by"] == "agent-ci"
    # Q-M2 honesty: a recorded check is a writer-supplied claim, not a
    # forge-attested fact — the recorder sees that posture in the result.
    assert payload["provenance"] == "unauthenticated"

    listed = call_tool(runtime, "check_list", {"target_type": "pr", "target": "7"})
    assert [c["run_id"] for c in listed["structuredContent"]["checks"]] == ["run-1"]
    by_commit = call_tool(
        runtime, "check_list", {"target_type": "commit", "target": "c" * 40}
    )
    assert [c["run_id"] for c in by_commit["structuredContent"]["checks"]] == ["run-1"]


def test_check_report_rejects_unknown_outcome_without_recording(tmp_path):
    from legis.mcp import call_tool

    checks = CheckSurface(f"sqlite:///{tmp_path / 'checks.db'}")
    runtime, _store = _runtime(tmp_path, check_surface=checks)

    result = call_tool(runtime, "check_report", {
        "check_name": "pytest", "run_id": "run-1",
        "commit_sha": "c" * 40, "outcome": "green",
    })

    assert result["isError"] is True
    sc = result["structuredContent"]
    assert sc["error_code"] == "INVALID_ARGUMENT"
    # The message names the valid vocabulary (LEG-2 quality bar).
    for valid in ("pass", "fail", "skipped", "timeout"):
        assert valid in sc["message"]
    assert checks.for_commit("c" * 40) == []


def test_check_report_rejects_caller_supplied_identity(tmp_path):
    # The launch-binding is the attribution; identity-shaped arguments are
    # rejected as unexpected keys, same as every other tool on the surface.
    from legis.mcp import call_tool

    checks = CheckSurface(f"sqlite:///{tmp_path / 'checks.db'}")
    runtime, _store = _runtime(tmp_path, check_surface=checks)

    for forged in ({"agent_id": "someone-else"}, {"recorded_by": "someone-else"}):
        result = call_tool(runtime, "check_report", {
            "check_name": "pytest", "run_id": "run-1",
            "commit_sha": "c" * 40, "outcome": "pass", **forged,
        })
        assert result["isError"] is True, forged
        assert result["structuredContent"]["error_code"] == "INVALID_ARGUMENT"
    assert checks.for_commit("c" * 40) == []


def test_check_report_records_on_fresh_runtime(tmp_path, monkeypatch):
    # The check surface lazily initialises from LEGIS_CHECK_DB on a fresh
    # runtime (build_runtime leaves it None) — recording must not depend on
    # some other tool having initialised the surface first.
    from legis.mcp import McpRuntime, call_tool

    db = f"sqlite:///{tmp_path / 'checks.db'}"
    monkeypatch.setenv("LEGIS_CHECK_DB", db)
    runtime = McpRuntime(agent_id="agent-fresh", initialized=True)

    result = call_tool(runtime, "check_report", {
        "check_name": "ruff", "run_id": "run-9",
        "commit_sha": "d" * 40, "outcome": "pass",
    })

    assert not result.get("isError")
    recorded = CheckSurface(db).for_commit("d" * 40)
    assert [r.run_id for r in recorded] == ["run-9"]
    assert recorded[0].recorded_by == "agent-fresh"


# --- legis-72d4e85d05: override-trail read (override_list) ---
# --- legis-8587a1f2c0: report-only doctor_get ---
# --- legis-716d4934e7: policy_boundary_check in the authoring loop ---


def test_gap_analysis_read_tools_are_listed():
    from legis.mcp import tool_definitions

    names = {t["name"] for t in tool_definitions()}
    assert {"override_list", "doctor_get", "policy_boundary_check"} <= names


def test_override_list_returns_verified_trail_with_seq(tmp_path):
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)
    runtime.engine.submit_override(
        policy="p.a",
        entity_key=EntityKey.from_locator("src/a.py:f"),
        rationale="r1",
        agent_id="agent-launch",
    )
    runtime.engine.submit_override(
        policy="p.b",
        entity_key=EntityKey.from_locator("src/b.py:g"),
        rationale="r2",
        agent_id="other-agent",
    )

    result = call_tool(runtime, "override_list", {})

    assert not result.get("isError")
    overrides = result["structuredContent"]["overrides"]
    assert [o["policy"] for o in overrides] == ["p.a", "p.b"]
    # seq is the poll/idempotency handle other tools speak (signoff_status_get,
    # override_submit responses) — the read must carry it.
    assert [o["seq"] for o in overrides] == [1, 2]
    assert overrides[0]["agent_id"] == "agent-launch"
    assert overrides[0]["entity_key"]["value"] == "src/a.py:f"


def test_override_list_filters_by_policy_entity_and_agent(tmp_path):
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)
    for policy, entity, agent in (
        ("p.a", "src/a.py:f", "agent-launch"),
        ("p.b", "src/b.py:g", "agent-launch"),
        ("p.a", "src/b.py:g", "other-agent"),
    ):
        runtime.engine.submit_override(
            policy=policy,
            entity_key=EntityKey.from_locator(entity),
            rationale="r",
            agent_id=agent,
        )

    by_policy = call_tool(runtime, "override_list", {"policy": "p.a"})
    assert [o["seq"] for o in by_policy["structuredContent"]["overrides"]] == [1, 3]

    by_entity = call_tool(runtime, "override_list", {"entity": "src/b.py:g"})
    assert [o["seq"] for o in by_entity["structuredContent"]["overrides"]] == [2, 3]

    # The filter is "submitted_by", never "agent_id" — no tool schema accepts
    # an agent_id argument (launch-binding invariant); this filters the
    # RECORDED agent_id, it does not assert caller identity.
    by_agent = call_tool(runtime, "override_list", {"submitted_by": "other-agent"})
    assert [o["seq"] for o in by_agent["structuredContent"]["overrides"]] == [3]

    combined = call_tool(
        runtime, "override_list", {"policy": "p.a", "submitted_by": "agent-launch"}
    )
    assert [o["seq"] for o in combined["structuredContent"]["overrides"]] == [1]


def test_override_list_reads_trail_on_fresh_runtime(tmp_path, monkeypatch):
    # Same bug class as the pull_request_get fresh-runtime fix: a fresh
    # build_runtime-shaped runtime (engine=None) must lazily open the
    # governance store, not report an empty trail that an agent would read as
    # "never overridden before".
    from legis.mcp import McpRuntime, call_tool

    db = f"sqlite:///{tmp_path / 'gov.db'}"
    engine = EnforcementEngine(AuditStore(db), FixedClock("2026-06-02T12:00:00+00:00"))
    engine.submit_override(
        policy="p.a",
        entity_key=EntityKey.from_locator("src/a.py:f"),
        rationale="r",
        agent_id="agent-earlier",
    )
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", db)
    runtime = McpRuntime(agent_id="agent-fresh", initialized=True)

    result = call_tool(runtime, "override_list", {})

    overrides = result["structuredContent"]["overrides"]
    assert [o["policy"] for o in overrides] == ["p.a"]
    assert overrides[0]["agent_id"] == "agent-earlier"


def test_override_list_fails_closed_on_rechained_protected_tamper(tmp_path):
    # Same verified-records-only honesty as GET /overrides: a tampered
    # protected trail is AUDIT_INTEGRITY_FAILURE, never silently read.
    from legis.mcp import call_tool

    db = tmp_path / "gov.db"
    store = AuditStore(f"sqlite:///{db}")
    gate = ProtectedGate(
        store,
        FixedClock("2026-06-02T12:00:00+00:00"),
        judge=_ScriptedJudge(JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")),
        key=KEY,
    )
    gate.submit(
        policy="no-eval",
        entity_key=EntityKey.from_locator("src/x.py:f"),
        rationale="original",
        agent_id="agent-launch",
        file_fingerprint="fp",
        ast_path="ap",
    )
    _tamper_first_record_and_rechain(db, lambda p: p.update({"rationale": "FORGED"}))
    assert store.verify_integrity() is True

    runtime, _unused = _runtime(tmp_path)
    runtime.engine = None
    runtime.protected_gate = gate
    runtime.trail_verifier = TrailVerifier(KEY, frozenset({"no-eval"}))

    result = call_tool(runtime, "override_list", {})

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "AUDIT_INTEGRITY_FAILURE"


def test_doctor_get_returns_the_same_json_payload_the_cli_emits(tmp_path):
    from legis.doctor import collect_checks, render_json
    from legis.mcp import McpRuntime, call_tool

    runtime = McpRuntime(agent_id="agent-1", initialized=True, source_root=str(tmp_path))

    result = call_tool(runtime, "doctor_get", {})

    assert not result.get("isError")
    payload = result["structuredContent"]
    assert payload == json.loads(render_json(collect_checks(tmp_path, repair=False)))
    # A bare directory is missing every install artifact — the read must say so.
    assert payload["ok"] is False
    assert payload["next_actions"]


def test_doctor_get_is_report_only_and_never_repairs(tmp_path):
    # C-8: repairs stay operator/CLI (`legis doctor --fix`); the MCP read must
    # not write anything and must not expose a repair knob.
    from legis.mcp import McpRuntime, call_tool, tool_definitions

    runtime = McpRuntime(agent_id="agent-1", initialized=True, source_root=str(tmp_path))

    result = call_tool(runtime, "doctor_get", {})

    assert list(tmp_path.iterdir()) == []  # nothing created or repaired
    assert not any(c["fixed"] for c in result["structuredContent"]["checks"])

    tool = next(t for t in tool_definitions() if t["name"] == "doctor_get")
    assert tool["inputSchema"]["properties"] == {}
    assert "report-only" in tool["description"].lower()
    for forbidden_arg in ("fix", "repair", "root"):
        assert forbidden_arg not in tool["inputSchema"]["properties"]


def test_policy_boundary_check_pass_on_clean_tree(tmp_path):
    from legis.mcp import McpRuntime, call_tool

    src = tmp_path / "src"
    src.mkdir()
    (src / "clean.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    runtime = McpRuntime(agent_id="agent-1", initialized=True, source_root=str(tmp_path))

    result = call_tool(runtime, "policy_boundary_check", {})

    payload = result["structuredContent"]
    assert payload["outcome"] == "PASS"
    assert payload["findings"] == []
    # The result now echoes what was scanned so a wrong-but-existing default root
    # is visible rather than silently trusted.
    assert payload["scanned_root"] == str(src)
    assert payload["repo_root"] == str(tmp_path)


def test_policy_boundary_check_reports_findings(tmp_path):
    from legis.mcp import McpRuntime, call_tool

    src = tmp_path / "src"
    src.mkdir()
    (src / "guarded.py").write_text(
        '@policy_boundary(suppresses=("no-eval",))\n'
        "def f():\n"
        "    pass\n",
        encoding="utf-8",
    )
    runtime = McpRuntime(agent_id="agent-1", initialized=True, source_root=str(tmp_path))

    result = call_tool(runtime, "policy_boundary_check", {})

    payload = result["structuredContent"]
    assert payload["outcome"] == "FINDINGS"
    assert payload["findings"][0]["rule_id"] == "POLICY_BOUNDARY_TEST_REF_MISSING"
    assert payload["findings"][0]["qualname"] == "f"
    assert payload["findings"][0]["file_path"] == "src/guarded.py"


def test_policy_boundary_check_resolves_relative_roots_against_repo_root(tmp_path):
    from legis.mcp import McpRuntime, call_tool

    lib = tmp_path / "pkg" / "lib"
    lib.mkdir(parents=True)
    (lib / "x.py").write_text(
        '@policy_boundary(suppresses=("no-eval",))\n'
        "def g():\n"
        "    pass\n",
        encoding="utf-8",
    )
    runtime = McpRuntime(agent_id="agent-1", initialized=True, source_root=str(tmp_path))

    result = call_tool(
        runtime, "policy_boundary_check", {"root": "lib", "repo_root": "pkg"}
    )

    payload = result["structuredContent"]
    assert payload["outcome"] == "FINDINGS"
    assert payload["findings"][0]["file_path"] == "lib/x.py"


# --- fix/legis-policy-boundary-no-vacuous-pass: never PASS on a zero-file scan ---
# Friction D (cf. weft-ef2e898642 silent-clean-on-zero-scope): a governance gate
# that returns PASS/findings=[] when the resolved scan root is nonexistent or
# holds zero analyzable source files is a vacuous green. The surface must return
# a DISTINCT discriminated outcome (NO_ROOT), never PASS.


def test_policy_boundary_check_no_root_when_default_src_missing(tmp_path):
    from legis.mcp import McpRuntime, call_tool

    # repo_root resolves to tmp_path (no src/ layout) -> default <repo_root>/src
    # does not exist. Must NOT read as a clean PASS.
    (tmp_path / "code.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    runtime = McpRuntime(agent_id="agent-1", initialized=True, source_root=str(tmp_path))

    result = call_tool(runtime, "policy_boundary_check", {})

    payload = result["structuredContent"]
    assert payload["outcome"] == "NO_ROOT"
    assert payload["findings"] == []
    assert "scanned_root" in payload


def test_policy_boundary_check_no_root_when_root_has_zero_source_files(tmp_path):
    from legis.mcp import McpRuntime, call_tool

    # The root EXISTS but contains zero analyzable .py files. Scanning it yields
    # zero findings, which must NOT collapse to PASS.
    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("# docs only, no python\n", encoding="utf-8")
    runtime = McpRuntime(agent_id="agent-1", initialized=True, source_root=str(tmp_path))

    result = call_tool(runtime, "policy_boundary_check", {})

    payload = result["structuredContent"]
    assert payload["outcome"] == "NO_ROOT"
    assert payload["findings"] == []


def test_policy_boundary_check_no_root_when_explicit_root_nonexistent(tmp_path):
    from legis.mcp import McpRuntime, call_tool

    runtime = McpRuntime(agent_id="agent-1", initialized=True, source_root=str(tmp_path))

    result = call_tool(
        runtime, "policy_boundary_check", {"root": str(tmp_path / "nope")}
    )

    payload = result["structuredContent"]
    assert payload["outcome"] == "NO_ROOT"
    assert payload["findings"] == []
    assert str(tmp_path / "nope") in payload["scanned_root"]


def test_policy_boundary_check_outcome_schema_includes_no_root():
    from legis.mcp import tool_definitions

    tool = next(t for t in tool_definitions() if t["name"] == "policy_boundary_check")
    enum = tool["outputSchema"]["properties"]["outcome"]["enum"]
    assert set(enum) == {"PASS", "FINDINGS", "NO_ROOT"}


# --- legis-1611d1673f: pull_request_get number schema/handler type agreement ---
# --- legis-40a0ff7799: check_list.target_type enum discoverability ---


def test_pull_request_get_number_schema_is_integer_like_seq():
    # Schema/impl agreement: the handler runs _require_int, so the advertised
    # schema must say integer (minimum 1) — exactly like signoff_status_get.seq.
    from legis.mcp import tool_definitions

    by_name = {t["name"]: t for t in tool_definitions()}
    number = by_name["pull_request_get"]["inputSchema"]["properties"]["number"]
    seq = by_name["signoff_status_get"]["inputSchema"]["properties"]["seq"]
    assert number == seq == {"type": "integer", "minimum": 1}


def test_pull_request_get_accepts_schema_faithful_integer(tmp_path):
    # A schema-faithful client sends an int; the legacy "7" string coercion is
    # covered by test_read_tools_return_git_pull_checks_and_override_rate.
    from legis.mcp import call_tool

    pulls = PullSurface(f"sqlite:///{tmp_path / 'pulls.db'}")
    pulls.record(
        PullRequest(
            number=7,
            title="Feature",
            base="main",
            head="feature",
            state=PullRequestState.OPEN,
        )
    )
    runtime, _store = _runtime(
        tmp_path, check_surface=CheckSurface(f"sqlite:///{tmp_path / 'checks.db'}")
    )
    runtime.pull_surface = pulls

    result = call_tool(runtime, "pull_request_get", {"number": 7})

    assert not result.get("isError")
    assert result["structuredContent"]["number"] == 7


def test_check_list_target_type_schema_declares_enum_matching_handler(tmp_path):
    # The valid values must be discoverable from tools/list, not by triggering
    # INVALID_ARGUMENT — and the schema enum must agree with what the handler
    # actually accepts (single-sourced constant).
    from legis.mcp import _CHECK_TARGET_TYPES, call_tool, tool_definitions

    tool = next(t for t in tool_definitions() if t["name"] == "check_list")
    prop = tool["inputSchema"]["properties"]["target_type"]
    assert prop["enum"] == list(_CHECK_TARGET_TYPES) == ["commit", "branch", "pr"]
    # target_type=pr needs an integer-coercible target — said in the schema, not
    # discovered by failing.
    assert "integer" in prop.get("description", "")

    # Handler agreement: every advertised value is accepted...
    runtime, _store = _runtime(
        tmp_path, check_surface=CheckSurface(f"sqlite:///{tmp_path / 'checks.db'}")
    )
    for target_type, target in (("commit", "abc"), ("branch", "main"), ("pr", "7")):
        result = call_tool(
            runtime, "check_list", {"target_type": target_type, "target": target}
        )
        assert not result.get("isError"), target_type
    # ...and the rejection message names the same set.
    rejected = call_tool(
        runtime, "check_list", {"target_type": "tag", "target": "v1"}
    )
    assert rejected["isError"] is True
    for value in _CHECK_TARGET_TYPES:
        assert value in rejected["structuredContent"]["message"]


# ---------------------------------------------------------------------------
# Task 3: warpline_preflight_get advisory sibling tool
# ---------------------------------------------------------------------------


def test_build_runtime_wires_warpline_from_env(monkeypatch, tmp_path):
    from legis.mcp import build_runtime
    from legis.warpline_preflight.client import WarplineMcpClient

    monkeypatch.setenv("WARPLINE_MCP_CMD", "echo")
    monkeypatch.setenv("LEGIS_SOURCE_ROOT", str(tmp_path))
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)  # engine-only: no protected gate
    # NOTE: build_runtime(agent_id) takes ONLY agent_id (mcp.py:200); source root
    # and DBs are env-driven (LEGIS_SOURCE_ROOT, mcp.py:275). There is NO
    # source_root= kwarg — passing one raises TypeError before any assertion.
    runtime = build_runtime("agent-x")
    assert isinstance(runtime.warpline, WarplineMcpClient)


def test_build_runtime_leaves_warpline_unwired_without_env(monkeypatch, tmp_path):
    from legis.mcp import build_runtime

    monkeypatch.delenv("WARPLINE_MCP_CMD", raising=False)
    monkeypatch.setenv("LEGIS_SOURCE_ROOT", str(tmp_path))
    runtime = build_runtime("agent-x")
    assert runtime.warpline is None


def test_build_runtime_degrades_warpline_to_none_on_bad_cmd(monkeypatch, tmp_path):
    # A misconfigured ADVISORY command must NOT crash the sole governance authority
    # at startup; it degrades to no advisory context (governance unaffected).
    from legis.mcp import build_runtime

    monkeypatch.setenv("WARPLINE_MCP_CMD", "   ")  # blank after shlex.split -> fail-safe None
    monkeypatch.setenv("LEGIS_SOURCE_ROOT", str(tmp_path))
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)
    runtime = build_runtime("agent-x")
    assert runtime.warpline is None


def test_warpline_preflight_get_unavailable_when_unwired(tmp_path):
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)  # warpline defaults to None
    result = call_tool(runtime, "warpline_preflight_get", {"base": "aaa"})
    assert not result.get("isError")
    assert result["structuredContent"] == {
        "status": "unavailable",
        "unavailable": [{"reason": "warpline client not configured"}],
    }


def test_warpline_preflight_get_checked_with_injected_client(tmp_path):
    from legis.mcp import call_tool

    class _FakeWarpline:
        def impact_radius(self, base, head):
            return {"affected": [{"sei": "S1"}], "count": 1}

        def reverify_worklist(self, base, head):
            return {"entries": [], "count": 0}

    runtime, _store = _runtime(tmp_path)
    runtime.warpline = _FakeWarpline()
    result = call_tool(runtime, "warpline_preflight_get", {"base": "aaa", "head": "bbb"})
    assert not result.get("isError")
    sc = result["structuredContent"]
    assert sc["status"] == "checked"
    assert sc["impact_radius"] == {"affected": [{"sei": "S1"}], "count": 1}
    assert sc["reverify_worklist"] == {"entries": [], "count": 0}


# Task 5: attestation_get fail-closed scaffolding
# ---------------------------------------------------------------------------


def test_attestation_get_unavailable_when_no_protected_gate(tmp_path):
    # ENGINE-ONLY DEPLOYMENT: no LEGIS_HMAC_KEY -> runtime.protected_gate is None.
    # The trail is not signature-verifiable, so attestation_get MUST return a
    # success-envelope unavailable, NOT a silent empty that reads as "never attested".
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)  # no protected gate wired
    assert runtime.protected_gate is None
    result = call_tool(runtime, "attestation_get", {"sei": "mod.fn#1"})
    assert not result.get("isError")
    sc = result["structuredContent"]
    assert sc["status"] == "unavailable"
    assert sc["sei"] == "mod.fn#1"
    assert sc["attestations"] == []
    assert sc["unavailable"] and "reason" in sc["unavailable"][0]


def test_attestation_get_tamper_yields_audit_integrity_failure(tmp_path):
    # FAIL-CLOSED: a tampered protected trail -> AUDIT_INTEGRITY_FAILURE, nothing
    # surfaced. Build a protected runtime whose trail verifier raises TamperError.
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)

    class _TamperVerifier:
        def verify(self, records):
            from legis.enforcement.protected import TamperError

            raise TamperError("record 4 hash mismatch")

    class _FakeProtectedGate:
        def records(self):
            return ["bad-record"]

    runtime.protected_gate = _FakeProtectedGate()
    runtime.trail_verifier = _TamperVerifier()
    result = call_tool(runtime, "attestation_get", {"sei": "mod.fn#1"})
    assert result.get("isError")
    assert result["structuredContent"]["error_code"] == "AUDIT_INTEGRITY_FAILURE"


def test_attestation_get_wired_deployment_empty_trail_is_checked(tmp_path):
    # KEY-WIRED DEPLOYMENT (Task 8 shipped): when BOTH protected_gate AND
    # trail_verifier are wired, the pre-gate passes and the classifier runs over
    # the VERIFIED trail. An empty verified trail honestly yields status='checked'
    # with an empty attestations list — the trail WAS checked and the SEI simply
    # has no human clearance. (Unavailable is reserved for the no-key pre-gate.)
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)

    class _OkVerifier:
        def verify(self, records):
            return None

    class _FakeProtectedGate:
        def records(self):
            return []

    runtime.protected_gate = _FakeProtectedGate()
    runtime.trail_verifier = _OkVerifier()
    result = call_tool(runtime, "attestation_get", {"sei": "mod.fn#1"})
    assert not result.get("isError")
    sc = result["structuredContent"]
    assert sc["status"] == "checked"
    assert sc["sei"] == "mod.fn#1"
    assert sc["attestations"] == []


def test_attestation_get_wired_deployment_admits_genuine_signoff(tmp_path):
    # END-TO-END (Task 8): a real signed sign-off through the MCP handler surfaces
    # as a signoff_cleared attestation under the queried SEI.
    from legis.clock import FixedClock
    from legis.enforcement.signoff import SignoffGate
    from legis.mcp import call_tool

    runtime, store = _runtime(tmp_path)
    key = b"signoff-key"
    gate = SignoffGate(store, FixedClock("2026-06-02T12:00:00+00:00"), signer=True, key=key)
    req = gate.request(
        policy="protected.x",
        entity_key=EntityKey(value="loomweave:eid:cleared", identity_stable=True),
        rationale="review",
        agent_id="agent-1",
        extensions={"loomweave": {"content_hash": "ch:e2e"}},
    )
    cleared = gate.sign_off(request_seq=req.seq, operator_id="op-1", rationale="ok")

    runtime.protected_gate = gate
    runtime.trail_verifier = TrailVerifier(key, frozenset({"protected.x"}))

    result = call_tool(runtime, "attestation_get", {"sei": "loomweave:eid:cleared"})
    assert not result.get("isError")
    sc = result["structuredContent"]
    assert sc["status"] == "checked"
    assert sc["attestations"] == [
        {
            "kind": "signoff_cleared",
            "content_hash": "ch:e2e",
            "recorded_at": "2026-06-02T12:00:00+00:00",
            "seq": cleared.seq,
            "signoff_seq": req.seq,
        }
    ]
