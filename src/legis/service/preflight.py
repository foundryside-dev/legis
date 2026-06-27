"""The advisory preflight reads — discriminated checked/unavailable.

SECURITY: warpline and plainweave are PURELY ADVISORY. Each read is a SIBLING of
the governance honesty reads, never embedded in one; a failure here is contained
as ``unavailable`` and never escapes as INTERNAL_ERROR, exactly as
``read_identity_gaps`` converts a ``LoomweaveError``. An unreachable/unconfigured
sibling → ``unavailable`` with a reason, never an empty fact-set that reads as
"nothing impacted". The two reads are independent siblings — neither is merged
into the other, and neither perturbs a governance verdict.
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


def read_plainweave_preflight(
    plainweave_client: Any | None, base: str, head: str
) -> dict[str, Any]:
    """Read Plainweave's ADVISORY preflight facts (envelope
    ``weft.plainweave.preflight_facts.v1``, ADR-006) over base..head.

    Mirrors ``read_warpline_preflight`` exactly: discriminated ``checked`` /
    ``unavailable``. An unconfigured client or ANY contract fault (caught as
    ``PlainweaveError`` — the transport converts every exception to it) degrades
    to ``unavailable`` with a reason, NEVER an INTERNAL_ERROR and NEVER a silent
    empty ``checked`` that reads as "nothing impacted". This is an advisory
    SIBLING; it never changes a Legis policy/governance decision.
    """
    from legis.plainweave_preflight.client import PlainweaveError

    if plainweave_client is None:
        return {
            "status": "unavailable",
            "unavailable": [{"reason": "plainweave client not configured"}],
        }
    try:
        facts = plainweave_client.preflight_facts(base, head)
    except PlainweaveError as exc:
        return {
            "status": "unavailable",
            "unavailable": [{"reason": f"plainweave check failed: {exc}"}],
        }
    return {
        "status": "checked",
        "preflight_facts": facts,
    }
