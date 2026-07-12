from legis.plainweave_preflight.client import PlainweaveError
from legis.service.preflight import read_plainweave_preflight, read_warpline_preflight
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


# ---------------------------------------------------------------------------
# read_plainweave_preflight — advisory SIBLING of read_warpline_preflight.
# ---------------------------------------------------------------------------

_PLAINWEAVE_ENVELOPE = {
    "schema": "weft.plainweave.preflight_facts.v1",
    "ok": True,
    "data": {
        "freshness": "partial",
        "facts": [],
        "authority_boundary": {
            "local_only": True,
            "live_peer_calls": False,
            "governance_verdicts": False,
        },
    },
    "warnings": [],
    "meta": {},
}


class _OkPlainweave:
    def preflight_facts(self, base, head):
        return _PLAINWEAVE_ENVELOPE


class _RaisesPlainweave:
    def preflight_facts(self, base, head):
        raise PlainweaveError("boom")


def test_plainweave_checked_when_method_succeeds():
    out = read_plainweave_preflight(_OkPlainweave(), "aaa", "bbb")
    assert out == {
        "status": "checked",
        "preflight_facts": _PLAINWEAVE_ENVELOPE,
    }


def test_plainweave_page_controls_are_forwarded_to_client():
    calls = []

    class _PagedPlainweave:
        def preflight_facts(self, base, head, *, requirement_limit=None, requirement_offset=None):
            calls.append((base, head, requirement_limit, requirement_offset))
            return _PLAINWEAVE_ENVELOPE

    out = read_plainweave_preflight(
        _PagedPlainweave(), "aaa", "bbb", requirement_limit=50, requirement_offset=100
    )

    assert out["status"] == "checked"
    assert calls == [("aaa", "bbb", 50, 100)]


def test_plainweave_legacy_client_degrades_on_continuation_instead_of_internal_error():
    out = read_plainweave_preflight(
        _OkPlainweave(), "aaa", "bbb", requirement_offset=100
    )

    assert out["status"] == "unavailable"
    assert "preflight_facts" not in out
    assert "unexpected keyword" in out["unavailable"][0]["reason"]


def test_plainweave_unavailable_when_client_is_none_not_a_silent_empty():
    out = read_plainweave_preflight(None, "aaa", "bbb")
    assert out["status"] == "unavailable"
    assert out["unavailable"] == [{"reason": "plainweave client not configured"}]
    # ASYMMETRIC: never an empty fact-set that reads as "nothing impacted".
    assert "preflight_facts" not in out


def test_plainweave_unavailable_when_preflight_raises_plainweave_error():
    out = read_plainweave_preflight(_RaisesPlainweave(), "aaa", "bbb")
    assert out["status"] == "unavailable"
    assert out["unavailable"][0]["reason"].startswith("plainweave check failed:")


def test_plainweave_error_never_escapes_as_internal_error():
    # The transport/contract error is caught and converted, never re-raised.
    out = read_plainweave_preflight(_RaisesPlainweave(), "aaa", "bbb")
    assert out["status"] == "unavailable"  # no exception propagated


def test_plainweave_honest_degrade_on_error_envelope_from_uninitialized_project():
    # The most likely real-world degrade: an uninitialized plainweave returns an
    # ok:false error envelope (schema weft.plainweave.error.v1). The consumer's
    # PlainweaveMcpClient._call rejects it -> PlainweaveError -> 'unavailable',
    # NOT 'checked' and NOT a raised INTERNAL_ERROR.
    from legis.plainweave_preflight.client import PlainweaveMcpClient

    error_envelope = {
        "schema": "weft.plainweave.error.v1",
        "ok": False,
        "error": {"code": "not_found", "message": "Plainweave project is not initialized"},
        "warnings": [],
        "meta": {},
    }
    client = PlainweaveMcpClient(invoke=lambda t, a: error_envelope, repo="/r")
    out = read_plainweave_preflight(client, "aaa", "bbb")
    assert out["status"] == "unavailable"
    assert "preflight_facts" not in out
