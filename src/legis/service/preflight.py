"""The warpline advisory preflight read — discriminated checked/unavailable.

SECURITY: warpline is PURELY ADVISORY. This read is a SIBLING of the governance
honesty reads, never embedded in one; a failure here is contained as
``unavailable`` and never escapes as INTERNAL_ERROR, exactly as
``read_identity_gaps`` converts a ``LoomweaveError``. An unreachable/unconfigured
warpline → ``unavailable`` with a reason, never an empty affected-set that reads
as "nothing impacted".
"""

from __future__ import annotations

from typing import Any


def read_warpline_preflight(
    warpline_client: Any | None, base: str, head: str
) -> dict[str, Any]:
    from legis.warpline_preflight.client import WarplineError

    if warpline_client is None:
        return {
            "status": "unavailable",
            "unavailable": [{"reason": "warpline client not configured"}],
        }
    try:
        impact = warpline_client.impact_radius(base, head)
        worklist = warpline_client.reverify_worklist(base, head)
    except WarplineError as exc:
        return {
            "status": "unavailable",
            "unavailable": [{"reason": f"warpline check failed: {exc}"}],
        }
    return {
        "status": "checked",
        "impact_radius": impact,
        "reverify_worklist": worklist,
    }
