"""Weft warpline-preflight conformance oracle — Legis as consumer.

Legis reads warpline's ADVISORY preflight surface via
``legis.warpline_preflight.client.WarplineMcpClient`` and
``legis.service.preflight.read_warpline_preflight``. This oracle freezes the two
real envelope shapes warpline emits (``warpline.impact_radius.v1`` /
``warpline.reverify_worklist.v1``, live-captured via MCP) and drives legis's REAL
parse path over the frozen bytes, so a shape change fails CI until legis updates
the consumer.

Three layers, mirroring ``tests/conformance/test_sei_oracle*``:

  * Layer-1 byte-pin (``test_golden_byte_pin``): UNMARKED, default-suite,
    recomputes the git blob sha1 in-process and fails CLOSED on any byte drift.
  * Non-circular consumer oracle (``test_golden_flows_through_the_real_parser``):
    the frozen golden BYTES flow through legis's real ``WarplineMcpClient._call``
    (schema/ok/meta/completeness validation) via a fake invoke replaying the
    golden; assertions are HARDCODED literals, NEVER a re-parse of the golden.
  * Layer-2 source recheck (``test_golden_matches_warpline_source``): compares
    the frozen golden to warpline's MCP contract fixture; SKIPS CLEAN when absent
    and notes the seam.

PROVENANCE: this golden is live-captured from ``warpline-mcp`` (version 1.2.0,
legis repo, HEAD~1..HEAD). See ``fixtures/PROVENANCE.md``.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from legis.service.preflight import read_warpline_preflight
from legis.warpline_preflight.client import WarplineMcpClient

FIX = Path(__file__).parent / "fixtures"
GOLDEN_PATH = FIX / "warpline-preflight-golden.json"

# git blob sha1 of tests/warpline_preflight/fixtures/warpline-preflight-golden.json.
# Frozen to the live-captured warpline.impact_radius.v1 / warpline.reverify_worklist.v1
# envelopes.  Update ONLY after a deliberate re-capture from a live warpline-mcp run;
# re-running warpline-mcp and updating this pin is the trigger for a consumer-contract
# review.  See fixtures/PROVENANCE.md.
GOLDEN_BLOB_SHA = "777b85895076a622f5b0fbf734fa8265d8d49f36"


# ---------------------------------------------------------------------------
# Layer-1: fail-closed byte-pin (UNMARKED — runs in the default suite).
# ---------------------------------------------------------------------------
def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def test_golden_byte_pin():
    data = GOLDEN_PATH.read_bytes()
    assert _git_blob_sha1(data) == GOLDEN_BLOB_SHA, (
        "warpline-preflight golden has drifted from its pinned bytes; update "
        "GOLDEN_BLOB_SHA only after a deliberate re-capture from warpline-mcp "
        "(re-check PROVENANCE.md and re-run `git hash-object` on the new golden)."
    )


# ---------------------------------------------------------------------------
# Machine-readable provenance guard: golden must not be 'pending-live-capture'
# in CI unless the explicit escape env var is set.
# ---------------------------------------------------------------------------
def test_golden_provenance_is_live_captured():
    golden = json.loads(GOLDEN_PATH.read_bytes())
    source = golden.get("_provenance", {}).get("source")
    if source == "pending-live-capture" and not os.environ.get("LEGIS_WARPLINE_GOLDEN_PENDING_OK"):
        pytest.fail(
            "warpline-preflight golden is marked 'pending-live-capture' — "
            "run a live warpline-mcp capture to produce a real golden, or set "
            "LEGIS_WARPLINE_GOLDEN_PENDING_OK=1 only as a temporary escape during "
            "bootstrap.  See fixtures/PROVENANCE.md."
        )


# ---------------------------------------------------------------------------
# Non-circular consumer oracle: golden BYTES -> WarplineMcpClient._call
# (schema/ok/meta/completeness validated). Assertions are HARDCODED literals
# from the frozen golden — NEVER a re-parse of the golden bytes.
# ---------------------------------------------------------------------------

def _dispatch_invoke(golden: dict):
    """Return an invoke that replays frozen envelopes keyed by tool name."""
    def invoke(tool: str, args: dict):
        if tool == "warpline_impact_radius_get":
            return golden["impact_radius"]
        if tool == "warpline_reverify_worklist_get":
            return golden["reverify_worklist"]
        raise AssertionError(f"unexpected tool in oracle: {tool!r}")
    return invoke


def test_golden_flows_through_the_real_parser_with_hardcoded_assertions():
    """Drive the FROZEN golden bytes through WarplineMcpClient._call (the real
    schema/ok/meta/completeness validation), via a fake invoke replaying the bytes.
    Assert HARDCODED values from the golden — NEVER a re-parse of the golden."""
    golden = json.loads(GOLDEN_PATH.read_bytes())

    # --- impact_radius ---
    impact = WarplineMcpClient(
        invoke=lambda t, a: golden["impact_radius"], repo="/r"
    ).impact_radius("b", "h")
    # Hardcoded schema — the real parse gate; any envelope rename breaks here.
    assert impact["schema"] == "warpline.impact_radius.v1"
    assert impact["ok"] is True
    # Hardcoded meta fields validated by _call (GV-LG-3 boundary).
    assert impact["meta"]["local_only"] is True
    assert impact["meta"]["peer_side_effects"] == []
    assert impact["meta"]["producer"]["tool"] == "warpline"
    # Hardcoded data shape — completeness and empty affected from the live capture.
    assert impact["data"]["completeness"] == "NO_SNAPSHOT"
    assert impact["data"]["affected"] == []

    # --- reverify_worklist ---
    reverify = WarplineMcpClient(
        invoke=lambda t, a: golden["reverify_worklist"], repo="/r"
    ).reverify_worklist("b", "h")
    # Hardcoded schema.
    assert reverify["schema"] == "warpline.reverify_worklist.v1"
    assert reverify["ok"] is True
    # Hardcoded meta fields.
    assert reverify["meta"]["local_only"] is True
    assert reverify["meta"]["peer_side_effects"] == []
    assert reverify["meta"]["producer"]["tool"] == "warpline"
    # Hardcoded data shape.
    assert reverify["data"]["completeness"] == "NO_SNAPSHOT"
    assert reverify["data"]["items"] == []


def test_read_warpline_preflight_over_golden_is_checked():
    """The full service read: discriminated 'checked' with both sub-responses,
    parsed through legis's real WarplineMcpClient._call over the frozen golden bytes.
    Assertions are hardcoded — not a re-parse of the golden."""
    golden = json.loads(GOLDEN_PATH.read_bytes())
    client = WarplineMcpClient(invoke=_dispatch_invoke(golden), repo="/r")
    result = read_warpline_preflight(client, "base-sha", "head-sha")

    # Hardcoded status discriminant.
    assert result["status"] == "checked"
    # Hardcoded sub-response schema and meta — the boundary validation was real.
    assert result["impact_radius"]["schema"] == "warpline.impact_radius.v1"
    assert result["impact_radius"]["meta"]["local_only"] is True
    assert result["impact_radius"]["data"]["completeness"] == "NO_SNAPSHOT"
    assert result["impact_radius"]["data"]["affected"] == []
    assert result["reverify_worklist"]["schema"] == "warpline.reverify_worklist.v1"
    assert result["reverify_worklist"]["meta"]["local_only"] is True
    assert result["reverify_worklist"]["data"]["completeness"] == "NO_SNAPSHOT"
    assert result["reverify_worklist"]["data"]["items"] == []


# ---------------------------------------------------------------------------
# Layer-2: drift recheck vs warpline's source MCP contract fixture (skip-clean).
#
# Warpline ships MCP tools with schema warpline.impact_radius.v1 /
# warpline.reverify_worklist.v1 — no flat REST projection.  When warpline vendors
# a canonical contract fixture for these envelopes, point WARPLINE_REPO or place
# a sibling checkout so this check enforces byte-equality automatically.
# ---------------------------------------------------------------------------
def _warpline_source_fixture() -> Path | None:
    candidates: list[Path] = []
    if env := os.environ.get("WARPLINE_REPO"):
        candidates.append(
            Path(env)
            / "tests"
            / "fixtures"
            / "contracts"
            / "warpline"
            / "mcp-preflight-golden.json"
        )
    candidates.append(
        Path(__file__).resolve().parents[3]
        / "warpline"
        / "tests"
        / "fixtures"
        / "contracts"
        / "warpline"
        / "mcp-preflight-golden.json"
    )
    return next((path for path in candidates if path.exists()), None)


def test_golden_matches_warpline_source():
    source = _warpline_source_fixture()
    if source is None:
        pytest.skip(
            "warpline ships no MCP contract fixture (mcp-preflight-golden.json) "
            "at the expected path — the legis golden is live-captured from "
            "warpline-mcp and conforms to the warpline.impact_radius.v1 / "
            "warpline.reverify_worklist.v1 envelope (SEAM 4 §4A + GV-LG-3). "
            "Set WARPLINE_REPO or place a sibling warpline checkout to enable "
            "this drift check.  See fixtures/PROVENANCE.md."
        )
    assert json.loads(GOLDEN_PATH.read_bytes()) == json.loads(
        source.read_text(encoding="utf-8")
    ), "legis warpline-preflight golden drifted from warpline's source MCP contract fixture"
