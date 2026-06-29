"""Phase 4 / Task 4.2 — FlooredRegistry wired into ALL MCP cell-resolution sites.

Fail-closed rule (design §4, D0): the floor is applied at every agent-visible
cell-resolution site — override routing, policy_explain, policy_list — not just
the routing branch. A chill-registry policy under a structured floor must read
back as ``structured`` everywhere and route to sign-off, never self-clear.

D2: the floor value is read per invocation (the ledger handle is held; no
``posture_floor`` field on McpRuntime). D4: an idempotency replay returns the
original outcome and is floor-exempt (a conscious decision, not a silent bypass).
"""

from __future__ import annotations

import io
import json

from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.protected import ProtectedGate
from legis.enforcement.signoff import SignoffGate
from legis.policy.cells import PolicyCellRegistry
from legis.posture.ledger import PostureLedger
from legis.store.audit_store import AuditStore


def _messages(*items):
    return "\n".join(json.dumps(item) for item in items) + "\n"


def _run(messages, runtime):
    from legis.mcp import run_jsonrpc

    inp = io.StringIO(messages)
    out = io.StringIO()
    run_jsonrpc(inp, out, runtime)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def _posture_ledger(tmp_path, floor=None):
    """A posture ledger seeded with a GENESIS (chill) and optional transition."""
    import hashlib

    from legis.crypto import signing as enf_signing

    url = f"sqlite:///{tmp_path / 'posture.db'}"
    ledger = PostureLedger(url, initialize=True)
    key = b"k" * 32
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    if floor is not None and floor != "chill":

        class _MemSigner:
            def __init__(self, held_key=key):
                self._key = held_key

            def fingerprint(self):
                return fp

            def sign(self, fields):
                return enf_signing.sign(fields, self._key, version="v3")

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


def _runtime(tmp_path, *, floor=None, default_cell="chill"):
    from legis.mcp import McpRuntime

    gov = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock("2026-06-02T12:00:00+00:00")
    engine = EnforcementEngine(gov, clock)
    key = b"hmac-key"
    signoff = SignoffGate(gov, clock, signer=True, key=key)
    protected = ProtectedGate(gov, clock, None, key)
    return (
        McpRuntime(
            agent_id="agent-1",
            initialized=True,
            engine=engine,
            signoff_gate=signoff,
            protected_gate=protected,
            cell_registry=PolicyCellRegistry(default_cell=default_cell),
            posture_ledger=_posture_ledger(tmp_path, floor=floor),
        ),
        gov,
    )


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


def test_mcp_override_submit_floored(tmp_path):
    # floor structured, chill-registry policy -> sign-off path, NOT self-clear.
    runtime, _gov = _runtime(tmp_path, floor="structured", default_cell="chill")
    result = _call(
        runtime,
        "override_submit",
        {"policy": "ordinary", "entity": "src/x.py:f", "rationale": "r"},
    )
    sc = result["structuredContent"]
    assert sc["cell"] == "structured"
    assert sc["outcome"] == "ESCALATED_PENDING"
    assert sc["outcome"] != "ACCEPTED_SELF"


def test_policy_explain_reflects_floor(tmp_path):
    runtime, _gov = _runtime(tmp_path, floor="structured", default_cell="chill")
    result = _call(
        runtime, "policy_explain", {"policy": "ordinary", "entity": "src/x.py:f"}
    )
    sc = result["structuredContent"]
    assert sc["cell"] == "structured"
    assert sc["self_clearable"] is False


def test_policy_list_reflects_floor(tmp_path):
    runtime, _gov = _runtime(tmp_path, floor="structured", default_cell="chill")
    # add a chill rule so we can check per-rule flooring too.
    from legis.policy.cells import PolicyCellRule

    runtime.cell_registry = PolicyCellRegistry(
        default_cell="chill",
        rules=[PolicyCellRule(pattern="ordinary", cell="chill")],
    )
    result = _call(runtime, "policy_list", {})
    sc = result["structuredContent"]
    assert sc["default_cell"] == "structured"
    assert sc["rules"][0]["cell"] == "structured"
    assert sc["rules"][0]["pattern"] == "ordinary"


def test_mcp_floor_read_per_invocation(tmp_path):
    # Change the floor between two tool calls on the same runtime; the second
    # call reflects the new floor (no cached posture_floor field).
    import hashlib

    from legis.crypto import signing as enf_signing

    runtime, _gov = _runtime(tmp_path, floor=None, default_cell="chill")
    first = _call(
        runtime, "policy_explain", {"policy": "ordinary", "entity": "e"}
    )["structuredContent"]
    assert first["cell"] == "chill"

    # Raise the floor on the live ledger handle.
    key = b"k" * 32
    fp = hashlib.sha256(key).hexdigest()

    class _MemSigner:
        def __init__(self, held_key=key):
            self._key = held_key

        def fingerprint(self):
            return fp

        def sign(self, fields):
            return enf_signing.sign(fields, self._key, version="v3")

    runtime.posture_ledger.transition(
        "structured",
        signer=_MemSigner(),
        session_id="s",
        key_fingerprint=fp,
        agent_id="op",
        rationale="raise",
        recorded_at="t1",
    )
    second = _call(
        runtime, "policy_explain", {"policy": "ordinary", "entity": "e"}
    )["structuredContent"]
    assert second["cell"] == "structured"


def test_idempotent_replay_is_floor_exempt(tmp_path):
    # Submit at chill with an idempotency key, raise the floor, resubmit with the
    # same key: the replay returns the ORIGINAL outcome (floor-exempt, D4).
    import hashlib

    from legis.crypto import signing as enf_signing

    runtime, _gov = _runtime(tmp_path, floor=None, default_cell="chill")
    args = {
        "policy": "ordinary",
        "entity": "src/x.py:f",
        "rationale": "r",
        "idempotency_key": "retry-1",
    }
    first = _call(runtime, "override_submit", args)["structuredContent"]
    assert first["outcome"] == "ACCEPTED_SELF"
    assert first["cell"] == "chill"

    key = b"k" * 32
    fp = hashlib.sha256(key).hexdigest()

    class _MemSigner:
        def __init__(self, held_key=key):
            self._key = held_key

        def fingerprint(self):
            return fp

        def sign(self, fields):
            return enf_signing.sign(fields, self._key, version="v3")

    runtime.posture_ledger.transition(
        "structured",
        signer=_MemSigner(),
        session_id="s",
        key_fingerprint=fp,
        agent_id="op",
        rationale="raise",
        recorded_at="t1",
    )
    replay = _call(runtime, "override_submit", args)["structuredContent"]
    # D4 (warning variant): the historical record is returned unchanged (the
    # action cannot be unwritten), AND a floor_warning flags that the posture
    # floor rose since — never a silent grandfather past the raised floor.
    assert replay["outcome"] == "ACCEPTED_SELF"
    assert replay["cell"] == "chill"
    assert replay["seq"] == first["seq"]
    assert "floor_warning" in replay
    assert "structured" in replay["floor_warning"]
