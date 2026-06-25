"""Weft warpline-preflight conformance oracle — Legis as consumer.

Legis reads warpline's ADVISORY preflight surface via
``legis.warpline_preflight.client.HttpWarplineClient`` and
``legis.service.preflight.read_warpline_preflight``. This oracle freezes the two
response shapes legis parses and drives legis's REAL parse path over the frozen
bytes, so a shape change fails CI until legis updates the consumer.

Three layers, mirroring ``tests/conformance/test_sei_oracle*``:

  * Layer-1 byte-pin (``test_golden_byte_pin``): UNMARKED, default-suite,
    recomputes the git blob sha1 in-process and fails CLOSED on any byte drift.
  * Non-circular consumer oracle (``test_*_drives_real_legis_parse``): the frozen
    golden BYTES flow through legis's real ``_decode_json_response`` (only the HTTP
    transport is stubbed, never the parse logic) and through the real
    ``read_warpline_preflight``; assertions are on HARDCODED SEIs/counts, never a
    re-parse of the golden.
  * Layer-2 source recheck (``test_golden_matches_warpline_source``): compares the
    frozen golden to warpline's source contract fixture; SKIPS CLEAN when absent
    and names the producer obligation.

PROVENANCE: this golden is frozen to the shape legis's client expects, NOT
vendored from warpline. Warpline ships no producer for these flat REST shapes
today (no HTTP server; its surface is the rich ``warpline.impact_radius.v1`` /
``warpline.reverify_worklist.v1`` envelope). See ``fixtures/PROVENANCE.md``.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from legis.service.preflight import read_warpline_preflight
from legis.warpline_preflight.client import (
    HttpWarplineClient,
    _decode_json_response,
)

GOLDEN_PATH = Path(__file__).parent / "fixtures" / "warpline-preflight-golden.json"

# git blob sha1 of tests/warpline_preflight/fixtures/warpline-preflight-golden.json.
# Frozen to the shape legis's warpline preflight client expects (NOT vendored
# from warpline — warpline ships no producer for these flat REST shapes). Update
# only after confirming the legis consumer contract intentionally changed; if
# warpline later ships a producer fixture, re-vendor byte-identical and re-pin.
GOLDEN_BLOB_SHA = "44bb515d528fdaca5b12703a896f55cd96c2483b"


# ---------------------------------------------------------------------------
# Layer-1: fail-closed byte-pin (UNMARKED — runs in the default suite).
# ---------------------------------------------------------------------------
def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def test_golden_byte_pin():
    data = GOLDEN_PATH.read_bytes()
    assert _git_blob_sha1(data) == GOLDEN_BLOB_SHA, (
        "warpline-preflight golden has drifted from its pinned bytes; update "
        "GOLDEN_BLOB_SHA only after confirming the legis consumer contract change "
        "is intended (and re-check the warpline producer obligation in PROVENANCE.md)."
    )


# ---------------------------------------------------------------------------
# Non-circular consumer oracle: golden BYTES -> legis's real decode -> real
# read_warpline_preflight. Only the HTTP transport is stubbed.
# ---------------------------------------------------------------------------
class _GoldenResp:
    """A minimal urllib-response stand-in carrying the golden bytes for one route."""

    def __init__(self, raw: bytes) -> None:
        self.headers = {"Content-Type": "application/json"}
        self._raw = raw

    def read(self, n: int) -> bytes:
        return self._raw[:n]


def _golden() -> dict:
    # Used ONLY to slice the two route bodies out of the single golden file so
    # each can be re-serialized to bytes and pushed through legis's real decode.
    # Assertions below never read from this — they are hardcoded.
    return json.loads(GOLDEN_PATH.read_bytes())


def _bytes_fetch():
    """An injectable Fetch that serves the golden route bytes through legis's REAL
    ``_decode_json_response`` (parse logic is NOT stubbed — only transport is)."""
    golden = _golden()
    bodies = {
        "/api/impact-radius": json.dumps(golden["impact_radius"]).encode("utf-8"),
        "/api/reverify-worklist": json.dumps(golden["reverify_worklist"]).encode("utf-8"),
    }

    def fetch(method, url, body):
        assert method == "GET" and body is None
        for route, raw in bodies.items():
            if route in url:
                return _decode_json_response(_GoldenResp(raw), f"{method} {url}")
        raise AssertionError(f"unexpected warpline route in oracle: {url}")

    return fetch


def _client() -> HttpWarplineClient:
    return HttpWarplineClient("http://localhost:9100", fetch=_bytes_fetch())


def test_impact_radius_drives_real_legis_parse():
    out = _client().impact_radius("base-sha", "head-sha")
    assert out["count"] == 2
    assert [a["sei"] for a in out["affected"]] == [
        "loomweave:eid:0123456789abcdef0123456789abcdef",
        "loomweave:eid:fedcba9876543210fedcba9876543210",
    ]


def test_reverify_worklist_drives_real_legis_parse():
    out = _client().reverify_worklist("base-sha", "head-sha")
    assert out["count"] == 1
    assert [e["sei"] for e in out["entries"]] == [
        "loomweave:eid:0123456789abcdef0123456789abcdef"
    ]


def test_read_warpline_preflight_over_golden_is_checked_with_real_shapes():
    # The full service read: discriminated 'checked' with both sub-responses,
    # parsed through legis's real client + decode over the frozen golden bytes.
    result = read_warpline_preflight(_client(), "base-sha", "head-sha")
    assert result["status"] == "checked"
    assert result["impact_radius"]["count"] == 2
    assert [a["sei"] for a in result["impact_radius"]["affected"]] == [
        "loomweave:eid:0123456789abcdef0123456789abcdef",
        "loomweave:eid:fedcba9876543210fedcba9876543210",
    ]
    assert result["reverify_worklist"]["count"] == 1
    assert [e["sei"] for e in result["reverify_worklist"]["entries"]] == [
        "loomweave:eid:0123456789abcdef0123456789abcdef"
    ]


# ---------------------------------------------------------------------------
# Layer-2: drift recheck vs warpline's source contract fixture (skip-clean).
#
# Warpline ships NO producer for these flat REST shapes today (no HTTP server;
# its real surface is the rich warpline.impact_radius.v1 / .reverify_worklist.v1
# envelope, where the affected set is nested under data.affected / data.items and
# there is no top-level count). So this recheck SKIPS CLEAN and names the
# producer obligation. It activates byte-equality enforcement automatically the
# day warpline ships a flat-shape contract fixture at the path below.
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
            / "preflight-rest-golden.json"
        )
    candidates.append(
        Path(__file__).resolve().parents[3]
        / "warpline"
        / "tests"
        / "fixtures"
        / "contracts"
        / "warpline"
        / "preflight-rest-golden.json"
    )
    return next((path for path in candidates if path.exists()), None)


def test_golden_matches_warpline_source():
    source = _warpline_source_fixture()
    if source is None:
        pytest.skip(
            "warpline ships no flat-REST preflight contract fixture "
            "(preflight-rest-golden.json) — its surface is the rich "
            "warpline.impact_radius.v1 / .reverify_worklist.v1 envelope, not the "
            "flat {affected/entries, count} shape legis consumes. PRODUCER "
            "OBLIGATION: warpline must ship GET /api/impact-radius + "
            "GET /api/reverify-worklist (or an equivalent flat projection) and "
            "vendor that fixture; set WARPLINE_REPO or place a sibling warpline "
            "checkout to enable this drift check. See fixtures/PROVENANCE.md."
        )
    assert json.loads(GOLDEN_PATH.read_bytes()) == json.loads(
        source.read_text(encoding="utf-8")
    ), "legis warpline-preflight golden drifted from warpline's source contract fixture"
