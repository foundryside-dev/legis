import pytest
from legis.plainweave_preflight.client import (
    PlainweaveClient,
    PlainweaveError,
    PlainweaveMcpClient,
)

_VALID_BOUNDARY = {
    "local_only": True,
    "live_peer_calls": False,
    "governance_verdicts": False,
    "legis_policy_cells": "external",
}
_KEEP = object()  # sentinel: "use the valid default boundary" — DISTINCT from None (None IS a test case)


def _env(*, boundary=_KEEP, facts=_KEEP, freshness="partial", schema="weft.plainweave.preflight_facts.v1", ok=True):
    data = {
        "producer": {"tool": "plainweave", "version": "1.1.0", "project": "legis"},
        "scope": {"kind": "commit_range", "base": "aaa", "head": "bbb"},
        "generated_at": "2026-06-27T00:00:00+00:00",
        "summary": {"info": 0, "warn": 0, "critical": 0, "facts": 0},
        "warnings": [],
        "provenance": {"producer": "plainweave", "inputs": []},
        "authority_boundary": dict(_VALID_BOUNDARY) if boundary is _KEEP else boundary,
    }
    if freshness is not None:
        data["freshness"] = freshness
    if facts is not _KEEP:
        if facts is not None:
            data["facts"] = facts
    else:
        data["facts"] = []
    return {"schema": schema, "ok": ok, "data": data, "warnings": [], "meta": {}}


def _recorder(responses):
    calls = []

    def invoke(tool, arguments):
        calls.append((tool, arguments))
        return responses.pop(0)

    invoke.calls = calls
    return invoke


def test_protocol_is_runtime_checkable():
    assert isinstance(PlainweaveMcpClient(invoke=_recorder([{}]), repo="/tmp/r"), PlainweaveClient)


def test_preflight_calls_tool_with_commit_range_and_passes_envelope_through():
    e = _env(facts=[])
    inv = _recorder([e])
    out = PlainweaveMcpClient(invoke=inv, repo="/tmp/r").preflight_facts("aaa", "bbb")
    assert out == e
    # NO 'repo' arg — the producer signature is scope_kind/base/head/...
    assert inv.calls[0] == (
        "plainweave_preflight_facts_get",
        {"scope_kind": "commit_range", "base": "aaa", "head": "bbb"},
    )


@pytest.mark.parametrize("bad", [["not", "dict"], "str", 7, None])
def test_non_dict_envelope_is_plainweave_error(bad):
    with pytest.raises(PlainweaveError):
        PlainweaveMcpClient(invoke=_recorder([bad]), repo="/tmp/r").preflight_facts("a", "b")


def test_wrong_schema_or_not_ok_is_plainweave_error():
    wrong = _env(schema="weft.plainweave.error.v1")  # error envelope schema
    with pytest.raises(PlainweaveError, match="schema"):
        PlainweaveMcpClient(invoke=_recorder([wrong]), repo="/tmp/r").preflight_facts("a", "b")
    notok = _env(ok=False)
    with pytest.raises(PlainweaveError, match="ok"):
        PlainweaveMcpClient(invoke=_recorder([notok]), repo="/tmp/r").preflight_facts("a", "b")


def test_gv_lg_3_hostile_or_malformed_boundary_is_refused_fail_closed():
    # A claimed live peer call (a side effect) is refused.
    peer = _env(boundary={"local_only": True, "live_peer_calls": True, "governance_verdicts": False})
    with pytest.raises(PlainweaveError, match="live_peer_calls"):
        PlainweaveMcpClient(invoke=_recorder([peer]), repo="/tmp/r").preflight_facts("a", "b")
    # A producer that claims to emit governance verdicts is refused — the whole
    # point of ADR-006 is that plainweave emits facts only.
    verdict = _env(boundary={"local_only": True, "live_peer_calls": False, "governance_verdicts": True})
    with pytest.raises(PlainweaveError, match="governance_verdicts"):
        PlainweaveMcpClient(invoke=_recorder([verdict]), repo="/tmp/r").preflight_facts("a", "b")
    # local_only false / missing / non-dict boundaries all refuse.
    for bad_boundary in (
        {"local_only": False, "live_peer_calls": False, "governance_verdicts": False},
        {"live_peer_calls": False, "governance_verdicts": False},  # missing local_only
        "not-a-dict",
        None,
        5,
    ):
        em = _env(boundary=bad_boundary)
        with pytest.raises(PlainweaveError):
            PlainweaveMcpClient(invoke=_recorder([em]), repo="/tmp/r").preflight_facts("a", "b")


def test_degraded_envelope_missing_facts_or_freshness_is_plainweave_error():
    # facts omitted -> degraded -> unavailable, not a bare empty 'checked'.
    e = _env(facts=None)
    with pytest.raises(PlainweaveError, match="freshness|facts"):
        PlainweaveMcpClient(invoke=_recorder([e]), repo="/tmp/r").preflight_facts("a", "b")
    # freshness omitted -> degraded.
    e2 = _env(freshness=None)
    with pytest.raises(PlainweaveError, match="freshness|facts"):
        PlainweaveMcpClient(invoke=_recorder([e2]), repo="/tmp/r").preflight_facts("a", "b")


def test_non_dict_data_is_plainweave_error():
    bad = {"schema": "weft.plainweave.preflight_facts.v1", "ok": True, "data": "not-a-dict"}
    with pytest.raises(PlainweaveError, match="data"):
        PlainweaveMcpClient(invoke=_recorder([bad]), repo="/tmp/r").preflight_facts("a", "b")
