"""Shared Weft conformance test: the Wardline->legis signed scan-artifact contract.

This is the CONSUMER half of the cross-member conformance vector described in
``vectors/README.md``. It loads ``vectors/wardline_scan_artifact.v1.json`` — the
SAME bytes Wardline's producer CI loads — and drives every vector case through
legis's real signer (``enforcement.signing.sign``) and real ingest
(``wardline.ingest.active_defects``).

Why this file exists (Weft incident 2026-06-10, root cause #2): the findings
payload, the kind vocabulary, and the HMAC formula were hand-copied on both sides
with no shared test, so a rename on either side re-signed cleanly and broke the
other side invisibly. G1 (absent ``findings`` key -> silent zero-route under a
green status) is the realised case. A contract fix without its vector just
re-creates the drift; this vector + loader is how the fix is real. The byte-exact
signature pin doubles as the canonicalization-drift detector: if either side's
canonical-JSON+HMAC formula diverges, ``expected_signature`` stops reproducing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from legis.enforcement.signing import sign
from legis.wardline.ingest import (
    DEFECT_KIND,
    FINDINGS_KEY,
    KNOWN_KINDS,
    SKIPPED_DIRTY_TREE,
    WardlineDirtyTreeError,
    WardlinePayloadError,
    active_defects,
    verify_wardline_artifact,
    wardline_artifact_fields,
)

VECTOR_PATH = Path(__file__).parent / "vectors" / "wardline_scan_artifact.v1.json"
DIRTY_VECTOR_PATH = Path(__file__).parent / "vectors" / "wardline_dirty_scan_artifact.v1.json"
VECTOR = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
DIRTY_VECTOR = json.loads(DIRTY_VECTOR_PATH.read_text(encoding="utf-8"))
_KEY = VECTOR["signing"]["key_utf8"].encode("utf-8")
_DIRTY_KEY = DIRTY_VECTOR["signing"]["key_utf8"].encode("utf-8")


def _ids(cases: list[dict]) -> list[str]:
    return [c["name"] for c in cases]


def test_vector_self_describes_the_constants_legis_enforces():
    # The vector's declared anchors MUST match the constants legis ships, or the
    # shared file and the consumer have silently diverged.
    assert VECTOR["contract"] == "weft/wardline-scan-artifact"
    assert VECTOR["findings_key"] == FINDINGS_KEY
    assert VECTOR["defect_kind"] == DEFECT_KIND
    assert set(VECTOR["known_kinds"]) == set(KNOWN_KINDS)


def test_dirty_vector_self_describes_the_dirty_key_legis_consumes():
    assert DIRTY_VECTOR["contract"] == "weft/wardline-dirty-scan-artifact"
    assert DIRTY_VECTOR["dirty_key"] == "dirty"
    assert DIRTY_VECTOR["signature_key"] == "artifact_signature"


@pytest.mark.parametrize("case", VECTOR["valid"], ids=_ids(VECTOR["valid"]))
def test_valid_vectors_ingest_as_specified(case):
    artifact = case["artifact"]
    # Signature pin (cross-impl canonicalization-drift detector) where present.
    if "expected_signature" in case:
        assert sign(wardline_artifact_fields(artifact), _KEY) == case["expected_signature"]
    # Gate-population pin.
    got = [f.fingerprint for f in active_defects(artifact)]
    assert got == case["expected_active_fingerprints"]


@pytest.mark.parametrize("case", VECTOR["invalid"], ids=_ids(VECTOR["invalid"]))
def test_invalid_vectors_are_rejected_loudly(case):
    # Every malformed/drifted wire shape must raise — never read as zero defects
    # under a green status (the G1 class). The match string anchors WHICH guard.
    with pytest.raises(WardlinePayloadError, match=case["reject_match"]):
        active_defects(case["artifact"])


@pytest.mark.parametrize("case", DIRTY_VECTOR["valid"], ids=_ids(DIRTY_VECTOR["valid"]))
def test_dirty_vector_governs_keyless_as_dirty(case):
    prov = verify_wardline_artifact(case["artifact"], artifact_key=None)
    assert prov["artifact_status"] == case["expected_keyless_artifact_status"]
    assert prov["commit_sha"] == case["artifact"]["commit_sha"]
    # STRIKE D (PDR-0023): the posture must carry a machine-readable reason so a
    # keyless-dirty pass is distinguishable from a keyless-clean unverified one.
    assert prov["artifact_status_reason"] == "dirty_dev_artifact"


@pytest.mark.parametrize("case", DIRTY_VECTOR["valid"], ids=_ids(DIRTY_VECTOR["valid"]))
def test_dirty_vector_is_typed_skip_in_ci_posture(case):
    with pytest.raises(WardlineDirtyTreeError) as exc:
        verify_wardline_artifact(case["artifact"], artifact_key=_DIRTY_KEY, allow_dirty=False)
    assert exc.value.reason == case["expected_ci_reject_reason"] == SKIPPED_DIRTY_TREE


@pytest.mark.parametrize("case", DIRTY_VECTOR["valid"], ids=_ids(DIRTY_VECTOR["valid"]))
def test_dirty_vector_governs_under_explicit_devmode(case):
    prov = verify_wardline_artifact(case["artifact"], artifact_key=_DIRTY_KEY, allow_dirty=True)
    assert prov["artifact_status"] == case["expected_ci_allow_dirty_artifact_status"]
    assert "artifact_signature" not in prov
