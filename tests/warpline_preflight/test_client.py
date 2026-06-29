import pytest
from legis.warpline_preflight.client import WarplineMcpClient, WarplineClient, WarplineError

_VALID_META = {"local_only": True, "peer_side_effects": []}
_KEEP = object()   # sentinel: "use the valid default meta" — DISTINCT from None (None IS a test case)


def _env(schema, data_key, items, *, meta=_KEEP, completeness="FULL"):
    data = {data_key: items, "staleness": {"commits_behind": 0}}
    if completeness is not None:
        data["completeness"] = completeness
    return {"schema": schema, "ok": True, "query": {"rev_range": "aaa..bbb"}, "data": data,
            "warnings": [], "next_actions": {}, "enrichment": {"sei": "present"},
            "meta": dict(_VALID_META) if meta is _KEEP else meta}   # meta=None -> {"meta": None}, a real case


def _recorder(responses):
    calls = []

    def invoke(tool, arguments):
        calls.append((tool, arguments))
        return responses.pop(0)

    invoke.calls = calls
    return invoke


def test_protocol_is_runtime_checkable():
    assert isinstance(WarplineMcpClient(invoke=_recorder([{}]), repo="/tmp/r"), WarplineClient)


def test_impact_radius_calls_tool_with_rev_range_and_passes_envelope_through():
    e = _env("warpline.impact_radius.v1", "affected", [{"sei": "loomweave:eid:" + "a"*32}])
    inv = _recorder([e]); out = WarplineMcpClient(invoke=inv, repo="/tmp/r").impact_radius("aaa", "bbb")
    assert out == e
    assert inv.calls[0] == ("warpline_impact_radius_get", {"repo": "/tmp/r", "rev_range": "aaa..bbb"})


def test_reverify_calls_reverify_tool():
    e = _env("warpline.reverify_worklist.v1", "items", [])
    inv = _recorder([e]); WarplineMcpClient(invoke=inv, repo="/tmp/r").reverify_worklist("a", "b")
    assert inv.calls[0][0] == "warpline_reverify_worklist_get"


@pytest.mark.parametrize("bad", [["not", "dict"], "str", 7, None])
def test_non_dict_envelope_is_warpline_error(bad):
    with pytest.raises(WarplineError):
        WarplineMcpClient(invoke=_recorder([bad]), repo="/tmp/r").impact_radius("a", "b")


def test_wrong_schema_or_not_ok_is_warpline_error():
    wrong = _env("warpline.reverify_worklist.v1", "items", [])  # wrong schema for impact
    with pytest.raises(WarplineError, match="schema"):
        WarplineMcpClient(invoke=_recorder([wrong]), repo="/tmp/r").impact_radius("a", "b")
    notok = _env("warpline.impact_radius.v1", "affected", []); notok["ok"] = False
    with pytest.raises(WarplineError, match="ok"):
        WarplineMcpClient(invoke=_recorder([notok]), repo="/tmp/r").impact_radius("a", "b")


def test_gv_lg_3_hostile_or_malformed_meta_is_refused_fail_closed():
    e = _env("warpline.impact_radius.v1", "affected", []); e["meta"] = {"local_only": True, "peer_side_effects": ["did_a_thing"]}
    with pytest.raises(WarplineError, match="side effect"):
        WarplineMcpClient(invoke=_recorder([e]), repo="/tmp/r").impact_radius("a", "b")
    for bad_meta in ({"local_only": False, "peer_side_effects": []}, {"peer_side_effects": []}, "not-a-dict", None, 5):
        em = _env("warpline.impact_radius.v1", "affected", [], meta=bad_meta)
        with pytest.raises(WarplineError):   # non-dict / missing / False local_only all refuse
            WarplineMcpClient(invoke=_recorder([em]), repo="/tmp/r").impact_radius("a", "b")


def test_degraded_envelope_missing_completeness_is_warpline_error():
    e = _env("warpline.impact_radius.v1", "affected", [], completeness=None)  # completeness omitted
    with pytest.raises(WarplineError, match="completeness"):
        WarplineMcpClient(invoke=_recorder([e]), repo="/tmp/r").impact_radius("a", "b")
