from legis.service.preflight import read_warpline_preflight
from legis.warpline_preflight.client import WarplineError

_IMPACT_ENVELOPE = {
    "schema": "warpline.impact_radius.v1",
    "ok": True,
    "data": {"completeness": "FULL", "affected": [{"sei": "S1", "depth": 1}]},
    "meta": {"local_only": True, "peer_side_effects": []},
}

_REVERIFY_ENVELOPE = {
    "schema": "warpline.reverify_worklist.v1",
    "ok": True,
    "data": {"completeness": "FULL", "items": [{"sei": "S1", "reason": "edited"}]},
    "meta": {"local_only": True, "peer_side_effects": []},
}

_EMPTY_REVERIFY = {
    "schema": "warpline.reverify_worklist.v1",
    "ok": True,
    "data": {"completeness": "FULL", "items": []},
    "meta": {"local_only": True, "peer_side_effects": []},
}

_EMPTY_IMPACT = {
    "schema": "warpline.impact_radius.v1",
    "ok": True,
    "data": {"completeness": "FULL", "affected": []},
    "meta": {"local_only": True, "peer_side_effects": []},
}


class _OkWarpline:
    def impact_radius(self, base, head):
        return _IMPACT_ENVELOPE

    def reverify_worklist(self, base, head):
        return _REVERIFY_ENVELOPE


class _ImpactRaisesWarpline:
    def impact_radius(self, base, head):
        raise WarplineError("boom")

    def reverify_worklist(self, base, head):
        return _EMPTY_REVERIFY


class _WorklistRaisesWarpline:
    def impact_radius(self, base, head):
        return _EMPTY_IMPACT

    def reverify_worklist(self, base, head):
        raise WarplineError("timeout")


def test_checked_when_both_methods_succeed():
    out = read_warpline_preflight(_OkWarpline(), "aaa", "bbb")
    assert out == {
        "status": "checked",
        "impact_radius": _IMPACT_ENVELOPE,
        "reverify_worklist": _REVERIFY_ENVELOPE,
    }


def test_unavailable_when_client_is_none_not_a_silent_empty():
    out = read_warpline_preflight(None, "aaa", "bbb")
    assert out["status"] == "unavailable"
    assert out["unavailable"] == [{"reason": "warpline client not configured"}]
    # ASYMMETRIC: never an empty affected-set that reads as "nothing impacted".
    assert "impact_radius" not in out


def test_unavailable_when_impact_radius_raises_warpline_error():
    out = read_warpline_preflight(_ImpactRaisesWarpline(), "aaa", "bbb")
    assert out["status"] == "unavailable"
    assert out["unavailable"][0]["reason"].startswith("warpline check failed:")


def test_unavailable_when_worklist_raises_warpline_error():
    # Partial advisory context is NOT surfaced as checked — either method failing
    # degrades the WHOLE read to unavailable.
    out = read_warpline_preflight(_WorklistRaisesWarpline(), "aaa", "bbb")
    assert out["status"] == "unavailable"
    assert out["unavailable"][0]["reason"].startswith("warpline check failed:")


def test_warpline_error_never_escapes_as_internal_error():
    # The transport error is caught and converted, never re-raised.
    out = read_warpline_preflight(_ImpactRaisesWarpline(), "aaa", "bbb")
    assert out["status"] == "unavailable"  # no exception propagated
