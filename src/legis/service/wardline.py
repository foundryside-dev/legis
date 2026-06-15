"""Transport-agnostic Wardline governance routing."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from legis.canonical import content_hash
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.signoff import SignoffGate
from legis.identity.entity_key import EntityKey
from legis.identity.resolver import IdentityResolver
from legis.service.errors import WardlineRoutingError
from legis.service.governance import resolve_for_record
from legis.wardline.governor import WardlineCellPolicy, route_findings
from legis.wardline.ingest import (
    WardlineSeverity,
    active_defects,
    verify_wardline_artifact,
    wardline_artifact_fields,
)
from legis.wardline.policy import resolve_cell


@dataclass(frozen=True)
class ResolvedRouting:
    """The resolved Wardline routing intent for a single scan.

    Exactly one of ``policy`` / ``cell_map`` is set unless ``fail_on`` is given
    (then ``policy`` is the gate cell and per-finding resolution happens inside
    ``route_wardline_scan``). ``cells`` is the set of cells that may actually run
    — an adapter uses it to decide whether the governance engine is needed.
    """

    policy: WardlineCellPolicy | None
    cell_map: dict[WardlineSeverity, WardlineCellPolicy] | None
    fail_on: WardlineSeverity | None
    cells: frozenset[WardlineCellPolicy]


def _parse_cell_map_env(raw: str) -> dict[WardlineSeverity, WardlineCellPolicy]:
    mapping: dict[WardlineSeverity, WardlineCellPolicy] = {}
    for part in raw.split(","):
        if not part.strip():
            continue
        severity_raw, sep, cell_raw = part.partition("=")
        if not sep:
            raise ValueError("cell map entries must be SEVERITY=cell")
        mapping[WardlineSeverity[severity_raw.strip()]] = WardlineCellPolicy(
            cell_raw.strip()
        )
    if not mapping:
        raise ValueError("cell map must not be empty")
    return mapping


def resolve_scan_routing(
    *,
    server_cell: str | None,
    server_cell_by_severity: str | None,
    request_cell: str | None,
    request_severity_map: dict[str, str] | None,
    request_fail_on: str | None,
    allow_request_routing: bool,
) -> ResolvedRouting:
    """Resolve a scan-routing request to a ``ResolvedRouting`` or reject it.

    This is the single home for the governance decision the two transports used
    to hand-copy: *is request-side routing allowed, and is the cell-spec
    well-formed?* The caller passes already-read server-config values (env stays
    in the adapter) plus the normalized request fields; every rejection is a
    ``WardlineRoutingError`` whose ``kind`` the adapter maps to its own taxonomy.

    Routing is server-owned by default: a deployment pins the cell(s) via env and
    callers may not override. ``allow_request_routing`` (the
    ``LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING`` opt-in) is the only path to a
    caller-supplied spec. Check order is part of the contract:
    misconfigured → server-owned → malformed.
    """
    if server_cell is not None and server_cell_by_severity is not None:
        raise WardlineRoutingError(
            WardlineRoutingError.SERVER_MISCONFIGURED,
            "server Wardline routing is misconfigured",
        )
    server_routing = server_cell is not None or server_cell_by_severity is not None
    # Name the request-side routing args the caller actually supplied so the
    # rejection points at the concrete offending knob (the "cell trap"), not a
    # generic "routing is server-owned". Order is the schema order.
    supplied_request_args = [
        name
        for name, value in (
            ("cell", request_cell),
            ("severity_map", request_severity_map),
            ("fail_on", request_fail_on),
        )
        if value is not None
    ]
    request_routing = bool(supplied_request_args)
    if server_routing and request_routing:
        raise WardlineRoutingError(
            WardlineRoutingError.SERVER_OWNED,
            "Wardline routing is server-owned; the server already pins the "
            "cell, so request-side routing arg(s) "
            f"{', '.join(supplied_request_args)} were rejected. (Request-side "
            "routing requires the LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING opt-in.)",
        )
    elif not server_routing:
        if not allow_request_routing:
            supplied_note = (
                " supplied request-side arg(s) "
                f"{', '.join(supplied_request_args)} were rejected;"
                if supplied_request_args
                else ""
            )
            raise WardlineRoutingError(
                WardlineRoutingError.SERVER_OWNED,
                "Wardline routing is server-owned;"
                f"{supplied_note} configure LEGIS_WARDLINE_CELL "
                "or LEGIS_WARDLINE_CELL_BY_SEVERITY",
            )
        if request_fail_on is not None:
            if request_cell is None or request_severity_map is not None:
                raise WardlineRoutingError(
                    WardlineRoutingError.MALFORMED,
                    "fail_on routing requires cell and forbids a per-severity map",
                )
        elif (request_cell is None) == (request_severity_map is None):
            raise WardlineRoutingError(
                WardlineRoutingError.MALFORMED,
                "provide exactly one of cell or a per-severity map",
            )
        if request_severity_map is not None and not request_severity_map:
            raise WardlineRoutingError(
                WardlineRoutingError.MALFORMED, "per-severity map must not be empty"
            )

    policy: WardlineCellPolicy | None = None
    cell_map: dict[WardlineSeverity, WardlineCellPolicy] | None = None
    fail_on: WardlineSeverity | None = None
    try:
        if server_cell_by_severity is not None:
            cell_map = _parse_cell_map_env(server_cell_by_severity)
        elif server_cell is not None:
            policy = WardlineCellPolicy(server_cell)
        elif request_severity_map is not None:
            cell_map = {
                WardlineSeverity[sev]: WardlineCellPolicy(cell)
                for sev, cell in request_severity_map.items()
            }
        else:
            policy = WardlineCellPolicy(request_cell)  # type: ignore[arg-type]
            if request_fail_on is not None:
                fail_on = WardlineSeverity[request_fail_on]
    except (KeyError, ValueError) as exc:
        raise WardlineRoutingError(
            WardlineRoutingError.MALFORMED, f"unknown cell/severity: {exc}"
        ) from exc

    if fail_on is not None:
        cells = {policy, WardlineCellPolicy.SURFACE_ONLY}
    elif cell_map is not None:
        cells = set(cell_map.values())
    else:
        cells = {policy}
    return ResolvedRouting(
        policy=policy,
        cell_map=cell_map,
        fail_on=fail_on,
        cells=frozenset(c for c in cells if c is not None),
    )


@dataclass(frozen=True)
class RoutedScan:
    """The outcome of routing a wardline scan.

    Carries the per-finding ``routed`` records AND the scan-level
    ``artifact_status`` posture (``verified`` / ``dirty`` / ``unverified``), so a
    caller can echo dev-grade-vs-CI-grade at the response root instead of leaving
    it buried in each routed record's provenance — and absent entirely when
    nothing routes (opp #6 / vacuous-green, same class as wardline W2).

    ``artifact_status_reason`` is the honesty surface for the status: a bare
    ``"unverified"`` cannot distinguish key-absent (verification DISABLED) from a
    key that failed to verify, so the reason (``key_absent`` /
    ``dirty_dev_artifact`` / ``signature_verified``) rides at the root too. It is
    always present — no posture without its provenance (PDR-0023).
    """

    routed: list[dict[str, Any]]
    artifact_status: str
    artifact_status_reason: str


def route_wardline_scan(
    scan: Mapping[str, Any],
    *,
    agent_id: str,
    identity: IdentityResolver | None,
    engine: EnforcementEngine | None,
    signoff: SignoffGate | None,
    policy: WardlineCellPolicy | None = None,
    cell_map: dict[WardlineSeverity, WardlineCellPolicy] | None = None,
    fail_on: WardlineSeverity | None = None,
    artifact_key: bytes | None = None,
    allow_dirty: bool = False,
) -> RoutedScan:
    artifact_provenance = verify_wardline_artifact(
        scan, artifact_key, allow_dirty=allow_dirty
    )
    findings = active_defects(scan)

    def resolve(qualname: str | None) -> tuple[EntityKey, dict[str, Any]]:
        if qualname:
            return resolve_for_record(identity, qualname)
        return EntityKey.from_locator("unknown"), {}

    raw_findings = scan.get("findings", [])
    batch_provenance = {
        "scan_digest": f"sha256:{content_hash(wardline_artifact_fields(scan))}",
        "finding_count": len(raw_findings) if isinstance(raw_findings, list) else 0,
        "active_count": len(findings),
        **artifact_provenance,
    }
    if fail_on is not None:
        if policy is None or cell_map is not None:
            raise ValueError("fail_on routing requires policy and forbids cell_map")
        cell_map = {
            f.severity: resolve_cell(f, fail_on=fail_on, gate_cell=policy)
            for f in findings
        }
        policy = None

    routed = route_findings(
        findings,
        policy=policy,
        cell_map=cell_map,
        agent_id=agent_id,
        resolve=resolve,
        engine=engine,
        signoff=signoff,
        batch_provenance=batch_provenance,
    )
    return RoutedScan(
        routed=routed,
        artifact_status=artifact_provenance["artifact_status"],
        artifact_status_reason=artifact_provenance["artifact_status_reason"],
    )
