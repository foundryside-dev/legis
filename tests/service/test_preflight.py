from legis.service.preflight import read_warpline_preflight
from legis.warpline_preflight.client import WarplineError


class _OkWarpline:
    def impact_radius(self, base, head):
        return {"affected": [{"sei": "S1"}], "count": 1}

    def reverify_worklist(self, base, head):
        return {"entries": [{"sei": "S1", "reason": "edited"}], "count": 1}


class _ImpactRaisesWarpline:
    def impact_radius(self, base, head):
        raise WarplineError("boom")

    def reverify_worklist(self, base, head):
        return {"entries": [], "count": 0}


class _WorklistRaisesWarpline:
    def impact_radius(self, base, head):
        return {"affected": [], "count": 0}

    def reverify_worklist(self, base, head):
        raise WarplineError("timeout")


def test_checked_when_both_methods_succeed():
    out = read_warpline_preflight(_OkWarpline(), "aaa", "bbb")
    assert out == {
        "status": "checked",
        "impact_radius": {"affected": [{"sei": "S1"}], "count": 1},
        "reverify_worklist": {"entries": [{"sei": "S1", "reason": "edited"}], "count": 1},
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
