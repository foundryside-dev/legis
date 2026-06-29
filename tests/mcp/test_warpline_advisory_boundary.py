"""Byte-identical advisory-boundary acceptance spine.

Proves the governance-verdict invariant: verdicts are byte-identical regardless
of whether ``runtime.warpline`` is None or points to a hostile advisory client
returning arbitrary garbage data. The structural companion test additionally
asserts that ``runtime.warpline`` is referenced in no verdict-path function
source, giving defense-in-depth coverage.

If either test fails, warpline data has somehow reached a verdict path —
a security regression.
"""

import inspect
import json

from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.policy.grammar import AllowlistBoundary, PolicyGrammar
from legis.store.audit_store import AuditStore
from legis.warpline_preflight.client import WarplineMcpClient


# ---------------------------------------------------------------------------
# Local helpers (copied verbatim from tests/mcp/test_server.py lines 53-91
# so this file is self-contained and does not import from a peer test module).
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


# ---------------------------------------------------------------------------
# Advisory-boundary fixtures
# ---------------------------------------------------------------------------


class _HostileWarpline:
    """Returns envelopes with a GV-LG-3-VALID meta but hostile advisory payload.

    The hostile values are in ``data.affected``/``data.items`` — the advisory
    payload that must NOT perturb a governance verdict.  The meta is deliberately
    valid (``local_only:true, peer_side_effects:[]``) so the test proves that a
    *hostile payload* (not a contract violation) is inert; a meta-violating
    envelope would be refused → unavailable, making the byte-identity comparison
    vacuously ``unavailable == unavailable``.
    """

    def impact_radius(self, base, head):
        return {
            "schema": "warpline.impact_radius.v1",
            "ok": True,
            "data": {
                "completeness": "FULL",
                "affected": [{"sei": "EVERYTHING", "depth": 9999}],
                "changed": [],
            },
            "meta": {"local_only": True, "peer_side_effects": [], "producer": {"tool": "hostile"}},
        }

    def reverify_worklist(self, base, head):
        return {
            "schema": "warpline.reverify_worklist.v1",
            "ok": True,
            "data": {
                "completeness": "FULL",
                "items": [{"sei": "EVERYTHING", "reason": "force"}],
            },
            "meta": {"local_only": True, "peer_side_effects": [], "producer": {"tool": "hostile"}},
        }


def _seed_real_verdict_runtime(tmp_path):
    """A runtime that returns REAL, DETERMINISTIC verdicts.

    Uses the _runtime fixture's FixedClock (timestamps identical across runs) and
    registers a real grammar so policy_evaluate returns an actual VIOLATION /
    UNKNOWN verdict — NOT an error envelope. An error envelope on BOTH sides would
    make the byte-identity assertion pass trivially and prove nothing — the exact
    defect the first draft of this test had. Mirrors the seeding in
    test_policy_evaluate_returns_unknown_distinct_from_clear (test_server.py:1225).
    """
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
        # A real VIOLATION verdict (socket not in the {json} allowlist).
        call_tool(
            runtime, "policy_evaluate", {"policy": "imports", "target": {"value": "socket"}}
        ).get("structuredContent"),
        # A real UNKNOWN verdict (unknown policy -> provenance gap).
        call_tool(
            runtime, "policy_evaluate", {"policy": "missing", "target": {}}
        ).get("structuredContent"),
    ]
    # GUARD: these MUST be real verdicts, never error envelopes — otherwise the
    # byte-identity assertion below is vacuous.
    assert blobs[0]["outcome"] == "VIOLATION" and blobs[0]["provenance_gap"] is False
    assert blobs[1]["outcome"] == "UNKNOWN" and blobs[1]["provenance_gap"] is True
    return blobs


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_governance_verdicts_byte_identical_warpline_unset_vs_hostile(tmp_path):
    # Everything is held IDENTICAL across the two runtimes (same FixedClock, same
    # seeded grammar) EXCEPT runtime.warpline. If warpline data could reach a
    # verdict path, the hostile side would diverge.
    runtime_unset = _seed_real_verdict_runtime(tmp_path / "a")
    runtime_unset.warpline = None
    unset = _run_governance_paths(runtime_unset)

    runtime_set = _seed_real_verdict_runtime(tmp_path / "b")
    runtime_set.warpline = _HostileWarpline()  # structurally present, hostile
    setval = _run_governance_paths(runtime_set)

    # GUARD: the hostile side must have actually reached status=="checked" — a
    # _HostileWarpline that raises exceptions would produce "unavailable" on both
    # sides and make the byte-identity assertion trivially pass while proving
    # nothing.  This side-assertion is NOT part of setval.
    from legis.mcp import call_tool
    pf = call_tool(runtime_set, "warpline_preflight_get", {"base": "aaa", "head": "bbb"})
    assert pf["structuredContent"]["status"] == "checked", (
        "_HostileWarpline returned unavailable — its envelope was rejected before "
        "reaching the advisory layer; the byte-identity assertion is vacuous"
    )

    assert json.dumps(unset, sort_keys=True) == json.dumps(setval, sort_keys=True)


def test_gv_lg_3_invalid_meta_peer_side_effects_yields_unavailable(tmp_path):
    """Positive GV-LG-3 pin: an envelope with non-empty peer_side_effects is
    refused by WarplineMcpClient._call (raises WarplineError), which propagates
    through read_warpline_preflight as status='unavailable'.  This ensures the
    boundary check fires end-to-end, not just in unit tests of _call."""
    from legis.mcp import call_tool

    invalid_meta_envelope = {
        "schema": "warpline.impact_radius.v1",
        "ok": True,
        "data": {"completeness": "FULL", "affected": []},
        "meta": {
            "local_only": True,
            "peer_side_effects": ["some-peer"],   # GV-LG-3 VIOLATION
            "producer": {"tool": "warpline"},
        },
    }
    runtime, _ = _runtime(tmp_path)
    runtime.warpline = WarplineMcpClient(
        invoke=lambda t, a: invalid_meta_envelope, repo="/r"
    )
    pf = call_tool(runtime, "warpline_preflight_get", {"base": "aaa", "head": "bbb"})
    assert pf["structuredContent"]["status"] == "unavailable", (
        "GV-LG-3: a non-empty peer_side_effects must yield unavailable, not checked"
    )


def test_runtime_warpline_referenced_in_no_verdict_path_function():
    # STRUCTURAL (defense-in-depth): runtime.warpline must appear in NO
    # verdict-path / honesty-read source. NOTE inspect.getsource is a SHALLOW text
    # scan — it sees only these named functions, not helpers they call — so this
    # COMPLEMENTS, never replaces, the byte-identity test above.
    #
    # Tool-handler coverage is DERIVED from _TOOL_HANDLERS so that any future
    # handler is covered by construction.  The single legitimate advisory handler
    # (_tool_warpline_preflight_get) is excluded by name — any other handler that
    # starts reading .warpline will cause this test to fail immediately.
    import legis.mcp as mcp
    from legis.service.governance import read_sei_attestations

    # --- derived: every tool handler except the one legitimate advisory handler ---
    _WARPLINE_HANDLER = "_tool_warpline_preflight_get"
    for name, handler in mcp._TOOL_HANDLERS.items():
        if handler.__name__ == _WARPLINE_HANDLER:
            continue
        src = inspect.getsource(handler)
        assert ".warpline" not in src, (
            f"tool handler {handler.__name__!r} (tool={name!r}) references warpline"
        )

    # --- explicit: non-handler verdict internals not in _TOOL_HANDLERS ---
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
        assert ".warpline" not in src, f"{fn.__name__} references warpline"
