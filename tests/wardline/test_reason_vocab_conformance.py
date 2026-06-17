"""Weft canonical reason-vocabulary conformance test (G1) for legis.

Source of truth: /home/john/weft/contracts/weft-reason-vocab.json — the closed
set of 11 ``reason_class`` values plus the carrier rule (every NON-clean result
carries ``reason_class`` + ``cause`` + ``fix``; a ``clean`` result omits
``cause`` + ``fix``).

legis's shipped reason surface is the DOMAIN enum ``ArtifactStatusReason``
({key_absent, dirty_dev_artifact, signature_verified}) on the wire field
``artifact_status_reason``. Those are NOT canonical reason_classes. legis conforms
ADDITIVELY: ``ARTIFACT_STATUS_REASON_TO_CANONICAL`` maps each domain term to a
canonical reason_class, emitted alongside the untouched shipped field.

This test LOCKS the conformance: it fails if legis ever drifts —
  * emits a ``reason_class`` outside the canonical 11,
  * adds an ``ArtifactStatusReason`` member with no canonical mapping,
  * violates the carrier rule (non-clean missing cause/fix, or clean carrying them).

It reads the canonical contract from the weft hub repo when present (the live
source of truth); if that path is absent (member repo checked out standalone) it
falls back to an in-test copy of the closed 11, so the test still locks legis's
own surface as a subset.
"""

from __future__ import annotations

import json
from pathlib import Path

from legis.wardline.ingest import (
    ARTIFACT_STATUS_REASON_TO_CANONICAL,
    ArtifactStatusReason,
    canonical_reason_carrier,
)

# The canonical contract, by path (see module docstring). Read it if the hub repo
# is checked out alongside; otherwise fall back to the pinned closed set.
_CANONICAL_CONTRACT_PATH = Path("/home/john/weft/contracts/weft-reason-vocab.json")
_FALLBACK_CANONICAL = frozenset(
    {
        "clean",
        "disabled",
        "unresolved_input",
        "rejected",
        "dead_path",
        "unreachable",
        "misrouted",
        "error",
        "scheme_mismatch",
        "stale",
        "partial",
    }
)


def _canonical_classes() -> frozenset[str]:
    if _CANONICAL_CONTRACT_PATH.is_file():
        contract = json.loads(_CANONICAL_CONTRACT_PATH.read_text(encoding="utf-8"))
        classes = frozenset(contract["reason_classes"].keys())
        # The pinned fallback must not silently diverge from the live contract.
        assert classes == _FALLBACK_CANONICAL, (
            "the in-test fallback canonical set has drifted from "
            f"{_CANONICAL_CONTRACT_PATH}: {classes ^ _FALLBACK_CANONICAL}"
        )
        return classes
    return _FALLBACK_CANONICAL


CANONICAL = _canonical_classes()


def test_every_domain_reason_has_a_canonical_mapping():
    """No ArtifactStatusReason member may go unmapped — drift would otherwise emit
    a status with no canonical reason_class."""
    mapped = set(ARTIFACT_STATUS_REASON_TO_CANONICAL)
    members = set(ArtifactStatusReason)
    assert mapped == members, (
        "ArtifactStatusReason members without a canonical mapping: "
        f"{members - mapped}"
    )


def test_emitted_reason_classes_are_a_subset_of_the_canonical_11():
    """The whole point of G1: legis's reason vocabulary stays inside the closed
    canonical set. A non-canonical reason_class fails here."""
    emitted = set(ARTIFACT_STATUS_REASON_TO_CANONICAL.values())
    assert emitted <= CANONICAL, f"non-canonical reason_class(es): {emitted - CANONICAL}"


def test_carrier_rule_holds_for_every_reason():
    """Carrier rule: non-clean carries reason_class + cause + fix (fix MANDATORY);
    clean carries only reason_class (omits cause + fix)."""
    for reason in ArtifactStatusReason:
        carrier = canonical_reason_carrier(reason)
        reason_class = carrier["reason_class"]
        assert reason_class in CANONICAL
        if reason_class == "clean":
            assert "cause" not in carrier, f"{reason}: clean must omit cause"
            assert "fix" not in carrier, f"{reason}: clean must omit fix"
        else:
            assert carrier.get("cause"), f"{reason}: non-clean must carry cause"
            assert carrier.get("fix"), f"{reason}: non-clean must carry fix (MANDATORY)"


def test_canonical_mapping_is_the_documented_justified_set():
    """Pin the exact justified mapping so a silent re-map is caught in review."""
    assert {k.value: v for k, v in ARTIFACT_STATUS_REASON_TO_CANONICAL.items()} == {
        "key_absent": "disabled",
        "dirty_dev_artifact": "stale",
        "signature_verified": "clean",
    }
