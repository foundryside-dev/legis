"""Weft plainweave-preflight conformance oracle — Legis as consumer.

Legis reads plainweave's ADVISORY preflight surface via
``legis.plainweave_preflight.client.PlainweaveMcpClient`` and
``legis.service.preflight.read_plainweave_preflight``. This oracle freezes the real
envelope shape plainweave emits (``weft.plainweave.preflight_facts.v1``, ADR-006)
and drives legis's REAL parse path over the frozen bytes, so a shape change fails
CI until legis updates the consumer.

Mirrors ``tests/warpline_preflight/test_warpline_preflight_oracle.py``:

  * Layer-1 byte-pin (``test_golden_byte_pin``): UNMARKED, default-suite,
    recomputes the git blob sha1 in-process and fails CLOSED on any byte drift.
  * Non-circular consumer oracle (``test_golden_flows_through_the_real_parser``):
    the frozen golden BYTES flow through legis's real ``PlainweaveMcpClient._call``
    (schema/ok/authority_boundary/freshness/facts validation) via a fake invoke
    replaying the golden; assertions are HARDCODED literals, NEVER a re-parse.
  * Layer-2 source recheck (``test_golden_matches_plainweave_source``): compares
    the frozen golden to plainweave's contract fixture; SKIPS CLEAN when absent.

PROVENANCE: unlike the warpline golden, this golden is CONSTRUCTED from the frozen
producer contract (ADR-006 + mcp_surface.py), NOT live-captured — the consumer was
built from the hub session whose MCP wiring misroutes plainweave. A live capture is
a flagged, required follow-up in a legis-rooted session. See ``fixtures/PROVENANCE.md``.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from legis.plainweave_preflight.client import PlainweaveMcpClient
from legis.service.preflight import read_plainweave_preflight

FIX = Path(__file__).parent / "fixtures"
GOLDEN_PATH = FIX / "plainweave-preflight-golden.json"

# git blob sha1 of tests/plainweave_preflight/fixtures/plainweave-preflight-golden.json.
# Frozen to the constructed weft.plainweave.preflight_facts.v1 envelope (ADR-006).
# Update ONLY after a deliberate re-construction or a live re-capture from a real
# plainweave-mcp run; re-pinning is the trigger for a consumer-contract review.
# See fixtures/PROVENANCE.md.
GOLDEN_BLOB_SHA = "ed8b8559cafc9bc954b9748777bdd31711acd369"

PREFLIGHT_SCHEMA = "weft.plainweave.preflight_facts.v1"


# ---------------------------------------------------------------------------
# Layer-1: fail-closed byte-pin (UNMARKED — runs in the default suite).
# ---------------------------------------------------------------------------
def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def test_golden_byte_pin():
    data = GOLDEN_PATH.read_bytes()
    assert _git_blob_sha1(data) == GOLDEN_BLOB_SHA, (
        "plainweave-preflight golden has drifted from its pinned bytes; update "
        "GOLDEN_BLOB_SHA only after a deliberate re-construction / re-capture "
        "(re-check PROVENANCE.md and re-run `git hash-object` on the new golden)."
    )


# ---------------------------------------------------------------------------
# Provenance honesty guard: this golden is CONSTRUCTED, not live-captured, and
# must say so — it must NOT falsely claim a live capture it never had. The live
# capture is the flagged follow-up, not a thing we fake (the inverse of the
# warpline oracle, which can force a real capture because warpline routes here).
# ---------------------------------------------------------------------------
def test_golden_provenance_is_constructed_not_live():
    golden = json.loads(GOLDEN_PATH.read_bytes())
    source = golden.get("_provenance", {}).get("source")
    assert source == "constructed-from-frozen-producer-contract", (
        "this golden was built from the frozen ADR-006 producer contract, not a "
        "live plainweave-mcp capture; its provenance must say so honestly."
    )
    assert source != "live-captured", "must not falsely claim a live capture"
    # The follow-up must stay visible until a real legis-rooted capture lands.
    assert "PENDING" in golden["_provenance"]["live_capture_status"]


# ---------------------------------------------------------------------------
# Non-circular consumer oracle: golden BYTES -> PlainweaveMcpClient._call
# (schema/ok/authority_boundary/freshness/facts validated). Assertions are
# HARDCODED literals from the frozen golden — NEVER a re-parse of the golden.
# ---------------------------------------------------------------------------
def _dispatch_invoke(golden: dict):
    """Return an invoke that replays the frozen preflight_facts envelope."""
    def invoke(tool: str, args: dict):
        if tool == "plainweave_preflight_facts_get":
            return golden["preflight_facts"]
        raise AssertionError(f"unexpected tool in oracle: {tool!r}")
    return invoke


def test_consumer_sends_commit_range_scope_with_no_repo_arg():
    """The producer tool takes NO 'repo' arg — its signature is scope_kind/base/
    head/... A blind warpline copy that sent {'repo':..,'rev_range':..} would be
    rejected by the producer. Pin the exact arguments the consumer sends."""
    golden = json.loads(GOLDEN_PATH.read_bytes())
    seen: list[tuple] = []

    def invoke(tool, args):
        seen.append((tool, args))
        return golden["preflight_facts"]

    PlainweaveMcpClient(invoke=invoke, repo="/r").preflight_facts("base-sha", "head-sha")
    assert seen[0] == (
        "plainweave_preflight_facts_get",
        {"scope_kind": "commit_range", "base": "base-sha", "head": "head-sha"},
    )
    assert "repo" not in seen[0][1]
    assert "rev_range" not in seen[0][1]


def test_golden_flows_through_the_real_parser_with_hardcoded_assertions():
    """Drive the FROZEN golden bytes through PlainweaveMcpClient._call (the real
    schema/ok/authority_boundary/freshness/facts validation), via a fake invoke.
    Assert HARDCODED values from the golden — NEVER a re-parse of the golden."""
    golden = json.loads(GOLDEN_PATH.read_bytes())

    env = PlainweaveMcpClient(
        invoke=lambda t, a: golden["preflight_facts"], repo="/r"
    ).preflight_facts("b", "h")

    # Hardcoded schema — the real parse gate; any envelope rename breaks here.
    assert env["schema"] == "weft.plainweave.preflight_facts.v1"
    assert env["ok"] is True
    # Hardcoded authority_boundary fields validated by _call (GV-LG-3 boundary).
    boundary = env["data"]["authority_boundary"]
    assert boundary["local_only"] is True
    assert boundary["live_peer_calls"] is False
    assert boundary["governance_verdicts"] is False
    # Hardcoded data shape — empty facts and the partial freshness from commit_range.
    assert env["data"]["freshness"] == "partial"
    assert env["data"]["facts"] == []
    assert env["data"]["producer"]["tool"] == "plainweave"
    assert env["data"]["scope"]["kind"] == "commit_range"


def test_read_plainweave_preflight_over_golden_is_checked():
    """The full service read: discriminated 'checked' with the facts envelope,
    parsed through legis's real PlainweaveMcpClient._call over the frozen golden.
    Assertions are hardcoded — not a re-parse of the golden."""
    golden = json.loads(GOLDEN_PATH.read_bytes())
    client = PlainweaveMcpClient(invoke=_dispatch_invoke(golden), repo="/r")
    result = read_plainweave_preflight(client, "base-sha", "head-sha")

    # Hardcoded status discriminant.
    assert result["status"] == "checked"
    # Hardcoded sub-response schema and boundary — the validation was real.
    assert result["preflight_facts"]["schema"] == "weft.plainweave.preflight_facts.v1"
    assert result["preflight_facts"]["data"]["authority_boundary"]["local_only"] is True
    assert result["preflight_facts"]["data"]["authority_boundary"]["governance_verdicts"] is False
    assert result["preflight_facts"]["data"]["freshness"] == "partial"
    assert result["preflight_facts"]["data"]["facts"] == []


# ---------------------------------------------------------------------------
# Layer-2: cross-repo CONSUMER conformance vs plainweave's OWN producer golden
# (skip-clean when no sibling plainweave checkout).
#
# Plainweave vendors its own byte-pinned, live-producer-rechecked golden for the
# weft.plainweave.preflight_facts.v1 envelope at
# ``tests/fixtures/contracts/legis/preflight-facts.json``. That golden is the
# producer's ``{"schema": ..., **data}`` payload (NOT the full MCP envelope: no
# ``ok``/``data``/``meta`` wrapper) and exercises the RICH pending_diff scenario
# — all nine fact kinds. This check wraps THAT payload into the full MCP envelope
# and drives it through legis's REAL ``PlainweaveMcpClient._call`` +
# ``read_plainweave_preflight``, asserting the consumer parses plainweave's own
# contract-tested output. If plainweave's producer shape drifts (a fact kind,
# section, or the authority_boundary triad changes) in a way that breaks the
# consumer parse, this reds when a sibling plainweave checkout is present.
# ---------------------------------------------------------------------------
def _plainweave_source_fixture() -> Path | None:
    relative = Path("tests") / "fixtures" / "contracts" / "legis" / "preflight-facts.json"
    candidates: list[Path] = []
    if env := os.environ.get("PLAINWEAVE_REPO"):
        candidates.append(Path(env) / relative)
    candidates.append(Path(__file__).resolve().parents[3] / "plainweave" / relative)
    return next((path for path in candidates if path.exists()), None)


def _envelope_from_producer_payload(payload: dict) -> dict:
    """Reconstruct the full MCP success-envelope from plainweave's vendored
    ``{"schema": ..., **data}`` producer payload (the shape its wire golden pins).
    Mirrors ``plainweave.envelopes.success_envelope`` so the consumer sees exactly
    what the MCP tool would return over the wire."""
    data = {key: value for key, value in payload.items() if key != "schema"}
    return {
        "schema": payload["schema"],
        "ok": True,
        "data": data,
        "warnings": [],
        "meta": {
            "producer": {"tool": "plainweave", "version": data["producer"]["version"]},
            "generated_at": data["generated_at"],
            "project": data["producer"].get("project"),
        },
    }


def test_consumer_parses_plainweave_own_producer_golden():
    source = _plainweave_source_fixture()
    if source is None:
        pytest.skip(
            "no sibling plainweave checkout — plainweave's producer golden lives at "
            "<plainweave>/tests/fixtures/contracts/legis/preflight-facts.json (its own "
            "byte-pinned, live-producer-rechecked fixture). Set PLAINWEAVE_REPO or place "
            "a sibling plainweave checkout to enable this cross-repo consumer-conformance "
            "check.  See fixtures/PROVENANCE.md."
        )
    payload = json.loads(source.read_text(encoding="utf-8"))
    # Sanity: this IS the preflight-facts producer payload (schema+data shape).
    assert payload["schema"] == PREFLIGHT_SCHEMA
    assert "ok" not in payload and "data" not in payload  # flattened, not the full envelope

    envelope = _envelope_from_producer_payload(payload)
    client = PlainweaveMcpClient(invoke=lambda t, a: envelope, repo="/r")
    result = read_plainweave_preflight(client, "main", "WORKTREE")

    # The consumer's REAL parser ACCEPTS plainweave's own contract-tested output:
    # status checked, boundary validated, the rich 9-fact payload passed through.
    assert result["status"] == "checked", (
        "legis's consumer parser rejected plainweave's own producer golden — the "
        "weft.plainweave.preflight_facts.v1 producer shape drifted from what the "
        "consumer validates (schema/ok/authority_boundary/freshness/facts)."
    )
    parsed = result["preflight_facts"]["data"]
    assert parsed["authority_boundary"]["local_only"] is True
    assert parsed["authority_boundary"]["governance_verdicts"] is False
    assert len(parsed["facts"]) == 9  # the rich pending_diff scenario, verbatim
    kinds = {fact["kind"] for fact in parsed["facts"]}
    assert "untraced_change" in kinds and "baseline_drift" in kinds
