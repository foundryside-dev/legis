"""Phase 8 / Task 8.1 — MCP ``posture_get`` (per-policy floored effective cell).

The explain/list flooring already landed in Phase 4 (D0); ``posture_get`` is the
dedicated read-only tool that surfaces the governing floor itself plus, for a
named policy, the floored effective cell (``max(floor, registry.cell_for(...))``,
design §10).

Fail-closed (design §4): a missing/empty ledger reports the floor as
``structured`` (never ``chill``). The tool reads the floor per-invocation off the
held ledger handle (D2). There is no ``posture_set`` over MCP — the change gate
is operator/CLI only (C-8); only the read tool is exposed.
"""

from __future__ import annotations

import hashlib
import io
import json

from legis.clock import FixedClock
from legis.enforcement import signing as enf_signing
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.protected import ProtectedGate
from legis.enforcement.signoff import SignoffGate
from legis.policy.cells import PolicyCellRegistry, PolicyCellRule
from legis.posture.ledger import PostureLedger
from legis.posture.records import KIND_KEY_RESET, PostureRecord
from legis.store.audit_store import AuditStore


def _messages(*items):
    return "\n".join(json.dumps(item) for item in items) + "\n"


def _run(messages, runtime):
    from legis.mcp import run_jsonrpc

    inp = io.StringIO(messages)
    out = io.StringIO()
    run_jsonrpc(inp, out, runtime)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def _call(runtime, name, arguments):
    return _run(
        _messages(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        ),
        runtime,
    )[0]["result"]


def _seeded_ledger(tmp_path, floor=None, *, genesis=True):
    """A posture ledger with a GENESIS (chill) and an optional raised floor."""
    url = f"sqlite:///{tmp_path / 'posture.db'}"
    ledger = PostureLedger(url, initialize=True)
    key = b"k" * 32
    fp = hashlib.sha256(key).hexdigest()
    if genesis:
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
    return ledger, key, fp


def _runtime(tmp_path, *, ledger=None, registry=None):
    from legis.mcp import McpRuntime

    gov = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock("2026-06-02T12:00:00+00:00")
    engine = EnforcementEngine(gov, clock)
    key = b"hmac-key"
    signoff = SignoffGate(gov, clock, signer=True, key=key)
    protected = ProtectedGate(gov, clock, None, key)
    return McpRuntime(
        agent_id="agent-1",
        initialized=True,
        engine=engine,
        signoff_gate=signoff,
        protected_gate=protected,
        cell_registry=registry or PolicyCellRegistry(default_cell="chill"),
        posture_ledger=ledger,
    )


def test_posture_get_returns_global_floor(tmp_path):
    ledger, _key, _fp = _seeded_ledger(tmp_path, floor="structured")
    runtime = _runtime(tmp_path, ledger=ledger)
    result = _call(runtime, "posture_get", {})
    assert not result.get("isError"), result
    sc = result["structuredContent"]
    assert sc["floor"] == "structured"
    # No policy given -> no per-policy effective cell.
    assert "effective_cell" not in sc
    assert sc["epoch_reset_unacknowledged"] is False


def test_posture_get_returns_floored_effective_cell(tmp_path):
    # floor=structured, registry routes "X" to chill -> effective cell structured.
    ledger, _key, _fp = _seeded_ledger(tmp_path, floor="structured")
    registry = PolicyCellRegistry(
        default_cell="chill",
        rules=[PolicyCellRule(pattern="X", cell="chill")],
    )
    runtime = _runtime(tmp_path, ledger=ledger, registry=registry)
    sc = _call(runtime, "posture_get", {"policy": "X"})["structuredContent"]
    assert sc["floor"] == "structured"
    assert sc["effective_cell"] == "structured"

    # A registry cell ABOVE the floor is preserved (floor only raises).
    registry2 = PolicyCellRegistry(
        default_cell="chill",
        rules=[PolicyCellRule(pattern="X", cell="protected")],
    )
    runtime2 = _runtime(tmp_path, ledger=ledger, registry=registry2)
    sc2 = _call(runtime2, "posture_get", {"policy": "X"})["structuredContent"]
    assert sc2["effective_cell"] == "protected"


def test_posture_get_missing_ledger_structured(tmp_path):
    # No ledger handle at all -> fail-closed structured floor (never chill).
    runtime = _runtime(tmp_path, ledger=None)
    sc = _call(runtime, "posture_get", {})["structuredContent"]
    assert sc["floor"] == "structured"
    assert sc["epoch_reset_unacknowledged"] is False
    # And a per-policy read still floors to structured.
    sc2 = _call(runtime, "posture_get", {"policy": "anything"})["structuredContent"]
    assert sc2["effective_cell"] == "structured"


def test_posture_get_indicates_unacknowledged_key_reset(tmp_path):
    # A KEY_RESET with no follow-on signed transition -> the agent sees the same
    # pending-operator-action signal doctor surfaces (Quality medium).
    ledger, _key, fp = _seeded_ledger(tmp_path, floor="structured")
    # Append a KEY_RESET directly (rekey() lands in Phase 11); it resets to chill
    # and opens a new epoch, with no acknowledging transition after it.
    new_fp = hashlib.sha256(b"n" * 32).hexdigest()
    ledger.store.append(
        PostureRecord(
            kind=KIND_KEY_RESET,
            floor="chill",
            key_fingerprint=new_fp,
            agent_id="op",
            recorded_at="t2",
            rationale="rekey",
            operator_sig=None,
            session_id=None,
        ).to_payload()
    )
    runtime = _runtime(tmp_path, ledger=ledger)
    sc = _call(runtime, "posture_get", {})["structuredContent"]
    assert sc["epoch_reset_unacknowledged"] is True
    # The floor itself reads back as the KEY_RESET's chill reset.
    assert sc["floor"] == "chill"


def test_no_posture_set_over_mcp(tmp_path):
    # The change gate is operator/CLI only (C-8): no write tool on the surface.
    from legis.mcp import _AGENT_TOOLS, _TOOL_HANDLERS, tool_definitions

    names = {t["name"] for t in tool_definitions()}
    assert "posture_set" not in names
    assert "posture set" not in names
    assert "posture_set" not in _AGENT_TOOLS
    assert "posture_set" not in _TOOL_HANDLERS
    # But the read tool IS present.
    assert "posture_get" in names
