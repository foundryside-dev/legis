"""Transport-agnostic Wardline scan-routing resolution.

These pin the single governance decision — "is request-side routing allowed,
and is the cell-spec well-formed?" — that both the HTTP and MCP adapters now
delegate to instead of hand-copying (the duplication this resolver removed).
"""

from __future__ import annotations

import pytest

from legis.service.errors import WardlineRoutingError
from legis.service.wardline import resolve_scan_routing
from legis.wardline.governor import WardlineCellPolicy
from legis.wardline.ingest import WardlineSeverity


def _resolve(**overrides):
    base = dict(
        server_cell=None,
        server_cell_by_severity=None,
        request_cell=None,
        request_severity_map=None,
        request_fail_on=None,
        allow_request_routing=False,
    )
    base.update(overrides)
    return resolve_scan_routing(**base)


def test_server_cell_resolves_to_single_policy():
    r = _resolve(server_cell="surface_override")
    assert r.policy is WardlineCellPolicy.SURFACE_OVERRIDE
    assert r.cell_map is None and r.fail_on is None
    assert r.cells == frozenset({WardlineCellPolicy.SURFACE_OVERRIDE})


def test_server_cell_by_severity_resolves_to_cell_map():
    r = _resolve(server_cell_by_severity="CRITICAL=surface_override,INFO=surface_only")
    assert r.policy is None
    assert r.cell_map == {
        WardlineSeverity.CRITICAL: WardlineCellPolicy.SURFACE_OVERRIDE,
        WardlineSeverity.INFO: WardlineCellPolicy.SURFACE_ONLY,
    }


def test_both_server_env_set_is_server_misconfigured():
    with pytest.raises(WardlineRoutingError) as exc:
        _resolve(server_cell="surface_only", server_cell_by_severity="INFO=surface_only")
    assert exc.value.kind == WardlineRoutingError.SERVER_MISCONFIGURED


def test_request_routing_under_server_ownership_is_rejected():
    with pytest.raises(WardlineRoutingError) as exc:
        _resolve(server_cell="surface_only", request_cell="surface_override")
    assert exc.value.kind == WardlineRoutingError.SERVER_OWNED
    assert "server-owned" in str(exc.value)


def test_server_owned_rejection_names_supplied_cell_arg():
    # LEG-3: the SERVER_OWNED message must name which request-side arg ("cell")
    # was supplied/rejected — the "cell trap" — not a generic "server-owned".
    with pytest.raises(WardlineRoutingError) as exc:
        _resolve(server_cell="surface_only", request_cell="surface_override")
    message = str(exc.value)
    assert "server-owned" in message  # preserved literal (existing tests assert it)
    # Pin the echo CLAUSE, not the bare token: "cell" also appears in the static
    # prose "pins the cell", so `"cell" in message` would still pass if the
    # supplied-args echo were stripped to a generic message. This phrase comes
    # only from the supplied_request_args echo.
    assert "arg(s) cell were rejected" in message


def test_server_owned_rejection_names_severity_map_and_fail_on_args():
    with pytest.raises(WardlineRoutingError) as exc:
        _resolve(
            server_cell="surface_only",
            request_severity_map={"ERROR": "surface_override"},
            request_fail_on="ERROR",
        )
    message = str(exc.value)
    assert "server-owned" in message
    assert "severity_map" in message
    assert "fail_on" in message


def test_no_optin_rejection_names_supplied_cell_arg():
    # The not-server-owned-and-flag-off branch also names a supplied request cell.
    with pytest.raises(WardlineRoutingError) as exc:
        _resolve(request_cell="surface_override", allow_request_routing=False)
    message = str(exc.value)
    assert "server-owned" in message
    assert "cell" in message
    assert "LEGIS_WARDLINE_CELL" in message  # existing guidance retained


def test_request_routing_without_optin_is_server_owned():
    with pytest.raises(WardlineRoutingError) as exc:
        _resolve(request_cell="surface_override", allow_request_routing=False)
    assert exc.value.kind == WardlineRoutingError.SERVER_OWNED
    assert "server-owned" in str(exc.value)


def test_request_cell_resolves_when_optedin():
    r = _resolve(request_cell="surface_override", allow_request_routing=True)
    assert r.policy is WardlineCellPolicy.SURFACE_OVERRIDE


def test_request_severity_map_resolves_when_optedin():
    r = _resolve(
        request_severity_map={"CRITICAL": "surface_override"},
        allow_request_routing=True,
    )
    assert r.cell_map == {WardlineSeverity.CRITICAL: WardlineCellPolicy.SURFACE_OVERRIDE}


def test_request_fail_on_with_cell_resolves_and_exposes_surface_only():
    r = _resolve(
        request_cell="surface_override", request_fail_on="ERROR",
        allow_request_routing=True,
    )
    assert r.policy is WardlineCellPolicy.SURFACE_OVERRIDE
    assert r.fail_on is WardlineSeverity.ERROR
    # fail_on resolves per-finding to the gate cell or surface_only, so both may run.
    assert r.cells == frozenset(
        {WardlineCellPolicy.SURFACE_OVERRIDE, WardlineCellPolicy.SURFACE_ONLY}
    )


def test_fail_on_without_cell_is_malformed():
    with pytest.raises(WardlineRoutingError) as exc:
        _resolve(
            request_fail_on="ERROR",
            request_severity_map={"ERROR": "surface_only"},
            allow_request_routing=True,
        )
    assert exc.value.kind == WardlineRoutingError.MALFORMED


def test_both_cell_and_map_is_malformed():
    with pytest.raises(WardlineRoutingError) as exc:
        _resolve(
            request_cell="surface_only",
            request_severity_map={"INFO": "surface_only"},
            allow_request_routing=True,
        )
    assert exc.value.kind == WardlineRoutingError.MALFORMED


def test_neither_cell_nor_map_is_malformed():
    with pytest.raises(WardlineRoutingError) as exc:
        _resolve(allow_request_routing=True)
    assert exc.value.kind == WardlineRoutingError.MALFORMED


def test_empty_request_severity_map_is_malformed():
    # The drift fix: HTTP already rejected an empty cell_by_severity; MCP silently
    # accepted an empty severity_map (routed nothing). The resolver rejects it for
    # both transports.
    with pytest.raises(WardlineRoutingError) as exc:
        _resolve(request_severity_map={}, allow_request_routing=True)
    assert exc.value.kind == WardlineRoutingError.MALFORMED


def test_unknown_cell_is_malformed():
    with pytest.raises(WardlineRoutingError) as exc:
        _resolve(request_cell="not_a_cell", allow_request_routing=True)
    assert exc.value.kind == WardlineRoutingError.MALFORMED


def test_unknown_fail_on_severity_is_malformed():
    with pytest.raises(WardlineRoutingError) as exc:
        _resolve(
            request_cell="surface_only", request_fail_on="SEVERE",
            allow_request_routing=True,
        )
    assert exc.value.kind == WardlineRoutingError.MALFORMED
