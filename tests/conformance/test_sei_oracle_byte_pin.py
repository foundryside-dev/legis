"""Weft SEI §8 conformance oracle — Layer-1 fail-closed byte-pin.

The vendored ``sei-conformance-oracle.json`` is byte-identical to Loomweave's
authoritative fixture. ``test_sei_oracle.py`` already carries a Layer-2 source
recheck (``test_vendored_oracle_matches_loomweave_source``), but that recheck
*skips clean* when no Loomweave checkout is present — so on its own it cannot
catch a corrupted or edited vendored fixture in the default CI suite.

This module is the complementary Layer-1 pin: it recomputes the git blob sha1
of the vendored fixture in-process and asserts it against a hard-coded constant.
It is UNMARKED, takes no environment dependency, and therefore runs in the
DEFAULT suite and fails CLOSED on any byte drift of the vendored fixture.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

# git blob sha1 of legis's vendored tests/conformance/fixtures/sei-conformance-oracle.json.
# Byte-identical to Loomweave's authoritative docs/federation/fixtures fixture.
VENDORED_BLOB_SHA = "0ea577025d94c028a0f682b7d29765079455718c"

ORACLE_PATH = Path(__file__).parent / "fixtures" / "sei-conformance-oracle.json"


def _git_blob_sha1(data: bytes) -> str:
    # git's blob object hash: sha1 over "blob <len>\0" + content.
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def test_vendored_oracle_byte_pin():
    data = ORACLE_PATH.read_bytes()
    assert _git_blob_sha1(data) == VENDORED_BLOB_SHA, (
        "Vendored SEI conformance oracle has drifted from its pinned bytes; "
        "re-vendor from Loomweave's docs/federation/fixtures/sei-conformance-oracle.json "
        "and update VENDORED_BLOB_SHA only after confirming the change is intended."
    )
