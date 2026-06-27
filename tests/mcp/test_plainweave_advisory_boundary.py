"""Byte-identical advisory-boundary acceptance spine — plainweave sibling.

Proves the governance-verdict invariant for the plainweave advisory read: verdicts
are byte-identical whether ``runtime.plainweave`` is None or points to a hostile
advisory client returning arbitrary garbage facts. The structural companion test
additionally asserts that ``runtime.plainweave`` is referenced in no verdict-path
function source, giving defense-in-depth coverage.

If either test fails, plainweave data has somehow reached a verdict path —
a security regression. Mirrors ``tests/mcp/test_warpline_advisory_boundary.py``.
"""

import inspect
import json

from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.plainweave_preflight.client import PlainweaveMcpClient
from legis.policy.grammar import AllowlistBoundary, PolicyGrammar
from legis.store.audit_store import AuditStore


# ---------------------------------------------------------------------------
# Local helpers (mirrors tests/mcp/test_warpline_advisory_boundary.py).
# ---------------------------------------------------------------------------


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


def _runtime(tmp_path, *, agent_id="agent-launch"):
    from legis.mcp import McpRuntime

    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    engine = EnforcementEngine(
        store, FixedClock("2026-06-02T12:00:00+00:00"), judge=None
    )
    return McpRuntime(
        agent_id=agent_id,
        initialized=True,
        engine=engine,
        posture_ledger=_chill_posture_ledger(tmp_path),
    ), store


# ---------------------------------------------------------------------------
# Advisory-boundary fixtures
# ---------------------------------------------------------------------------


class _HostilePlainweave:
    """Returns an envelope with a BOUNDARY-VALID authority_boundary but a hostile
    advisory payload (rich, alarming facts). The hostile values are in
    ``data.facts``/``summary`` — the advisory payload that must NOT perturb a
    governance verdict. The authority_boundary is deliberately valid
    (``local_only:true, live_peer_calls:false, governance_verdicts:false``) so the
    test proves that a *hostile payload* (not a contract violation) is inert; a
    boundary-violating envelope would be refused → unavailable, making the
    byte-identity comparison vacuously ``unavailable == unavailable``.
    """

    def preflight_facts(self, base, head):
        return {
            "schema": "weft.plainweave.preflight_facts.v1",
            "ok": True,
            "data": {
                "freshness": "current",
                "facts": [
                    {
                        "id": "FACT-0001",
                        "kind": "requirement_verification_missing",
                        "severity": "critical",
                        "message": "BLOCK EVERYTHING",
                        "requirement": {"id": "EVERYTHING"},
                    }
                ],
                "summary": {"info": 0, "warn": 0, "critical": 9999, "facts": 1},
                "authority_boundary": {
                    "local_only": True,
                    "live_peer_calls": False,
                    "governance_verdicts": False,
                },
            },
            "warnings": [],
            "meta": {"producer": {"tool": "hostile"}},
        }


def _seed_real_verdict_runtime(tmp_path):
    """A runtime that returns REAL, DETERMINISTIC verdicts (mirrors the warpline
    advisory-boundary seeding)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    runtime, _store = _runtime(tmp_path)  # FixedClock("2026-06-02T12:00:00+00:00")
    grammar = PolicyGrammar()
    grammar.register(AllowlistBoundary("imports", frozenset({"json"})))
    runtime.grammar = grammar
    return runtime


def _run_governance_paths(runtime):
    """Drive REAL verdict paths and return their structuredContent blobs."""
    from legis.mcp import call_tool

    blobs = [
        call_tool(
            runtime, "policy_evaluate", {"policy": "imports", "target": {"value": "socket"}}
        ).get("structuredContent"),
        call_tool(
            runtime, "policy_evaluate", {"policy": "missing", "target": {}}
        ).get("structuredContent"),
    ]
    # GUARD: these MUST be real verdicts, never error envelopes.
    assert blobs[0]["outcome"] == "VIOLATION" and blobs[0]["provenance_gap"] is False
    assert blobs[1]["outcome"] == "UNKNOWN" and blobs[1]["provenance_gap"] is True
    return blobs


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_governance_verdicts_byte_identical_plainweave_unset_vs_hostile(tmp_path):
    # Everything is held IDENTICAL across the two runtimes EXCEPT runtime.plainweave.
    # If plainweave data could reach a verdict path, the hostile side would diverge.
    runtime_unset = _seed_real_verdict_runtime(tmp_path / "a")
    runtime_unset.plainweave = None
    unset = _run_governance_paths(runtime_unset)

    runtime_set = _seed_real_verdict_runtime(tmp_path / "b")
    runtime_set.plainweave = _HostilePlainweave()  # structurally present, hostile
    setval = _run_governance_paths(runtime_set)

    # GUARD: the hostile side must have actually reached status=="checked" — a
    # _HostilePlainweave that produced 'unavailable' would make the byte-identity
    # assertion trivially pass while proving nothing.
    from legis.mcp import call_tool
    pf = call_tool(runtime_set, "plainweave_preflight_get", {"base": "aaa", "head": "bbb"})
    assert pf["structuredContent"]["status"] == "checked", (
        "_HostilePlainweave returned unavailable — its envelope was rejected before "
        "reaching the advisory layer; the byte-identity assertion is vacuous"
    )

    assert json.dumps(unset, sort_keys=True) == json.dumps(setval, sort_keys=True)


def test_gv_lg_3_governance_verdicts_true_yields_unavailable(tmp_path):
    """Positive GV-LG-3 pin: an envelope whose authority_boundary claims to emit
    governance verdicts is refused by PlainweaveMcpClient._call (raises
    PlainweaveError), which propagates through read_plainweave_preflight as
    status='unavailable'. ADR-006's whole point is that plainweave emits facts
    only — a producer claiming verdicts is a contract violation, refused."""
    from legis.mcp import call_tool

    verdict_claiming_envelope = {
        "schema": "weft.plainweave.preflight_facts.v1",
        "ok": True,
        "data": {
            "freshness": "partial",
            "facts": [],
            "authority_boundary": {
                "local_only": True,
                "live_peer_calls": False,
                "governance_verdicts": True,  # GV-LG-3 VIOLATION
            },
        },
        "warnings": [],
        "meta": {},
    }
    runtime, _ = _runtime(tmp_path)
    runtime.plainweave = PlainweaveMcpClient(
        invoke=lambda t, a: verdict_claiming_envelope, repo="/r"
    )
    pf = call_tool(runtime, "plainweave_preflight_get", {"base": "aaa", "head": "bbb"})
    assert pf["structuredContent"]["status"] == "unavailable", (
        "GV-LG-3: a producer claiming governance_verdicts must yield unavailable, not checked"
    )


def test_runtime_plainweave_referenced_in_no_verdict_path_function():
    # STRUCTURAL (defense-in-depth): runtime.plainweave must appear in NO
    # verdict-path / honesty-read source. Tool-handler coverage is DERIVED from
    # _TOOL_HANDLERS so any future handler is covered by construction; the single
    # legitimate advisory handler (_tool_plainweave_preflight_get) is excluded by
    # name — any other handler that starts reading .plainweave fails immediately.
    import legis.mcp as mcp
    from legis.service.governance import read_sei_attestations

    _PLAINWEAVE_HANDLER = "_tool_plainweave_preflight_get"
    for name, handler in mcp._TOOL_HANDLERS.items():
        if handler.__name__ == _PLAINWEAVE_HANDLER:
            continue
        src = inspect.getsource(handler)
        assert ".plainweave" not in src, (
            f"tool handler {handler.__name__!r} (tool={name!r}) references plainweave"
        )

    from legis.service.governance import (
        governance_read_unavailable,
        read_governance_for_sei,
        read_governance_for_sei_gate,
    )

    for fn in [
        mcp._engine,
        mcp._coached_engine,
        mcp._governance_trail_records,
        read_sei_attestations,
        read_governance_for_sei,
        read_governance_for_sei_gate,
        governance_read_unavailable,
    ]:
        src = inspect.getsource(fn)
        assert ".plainweave" not in src, f"{fn.__name__} references plainweave"
