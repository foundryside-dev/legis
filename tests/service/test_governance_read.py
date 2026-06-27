"""Task 2 tests: read_governance_for_sei, read_governance_for_sei_gate,
governance_read_unavailable.

TDD red→green.  All imports of the new names happen inside the test bodies or
at module level — either way the ImportError on a missing symbol is "the right
failure reason" for Step 2 of the TDD cycle.
"""

import pytest

from legis.clock import FixedClock
from legis.enforcement.protected import ProtectedGate
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.identity.entity_key import EntityKey
from legis.service.errors import AuditIntegrityError, ProtectedKeyRequiredError
from legis.service.governance import (
    governance_read_unavailable,
    read_governance_for_sei,
    read_governance_for_sei_gate,
)
from legis.store.audit_store import AuditStore

# ── shared fixtures ──────────────────────────────────────────────────────────

_SEI = "loomweave:eid:test-sei"
_CLOCK = FixedClock("2026-06-02T12:00:00+00:00")


class _AcceptJudge:
    def evaluate(self, record):
        return JudgeOpinion(verdict=Verdict.ACCEPTED, model="judge@1", rationale="ok")


def _stable_key(sei=_SEI):
    return EntityKey(value=sei, identity_stable=True)


def _operator_override_gate(tmp_path, *, sei=_SEI, content_hash="ch:override-content"):
    """Build a genuine ProtectedGate, submit an operator_override, return (gate, store, result)."""
    store = AuditStore(f"sqlite:///{tmp_path}/gov.db")
    gate = ProtectedGate(store, _CLOCK, judge=_AcceptJudge(), key=b"protected-key")
    result = gate.operator_override(
        policy="protected.x",
        entity_key=_stable_key(sei),
        rationale="operator clears",
        operator_id="operator-1",
        file_fingerprint="sha256:ff",
        ast_path="ap",
        extensions={"loomweave": {"content_hash": content_hash}},
    )
    return gate, store, result


# ── positive projection: operator_override ───────────────────────────────────


def test_projects_override_to_clearance_record(tmp_path):
    """A genuine signed operator_override maps to the 7-field clearance record.

    posture must be "protected_override" (the provable mechanism).
    Coupling note: read_sei_attestations admits the record whose
    judge_verdict == Verdict.OVERRIDDEN_BY_OPERATOR.value; the posture map
    key is "operator_override" (the kind string, not the enum constant).
    """
    _, store, _ = _operator_override_gate(tmp_path, content_hash="ch:override-content")
    out = read_governance_for_sei(store.read_all(), _SEI)
    assert out["status"] == "checked"
    assert out["sei"] == _SEI
    assert len(out["records"]) == 1
    rec = out["records"][0]
    assert rec == {
        "sei": _SEI,
        "disposition": "cleared",
        "posture": "protected_override",
        "authority": "operator",
        "as_of": "2026-06-02T12:00:00+00:00",
        "reasons": ["operator_override"],
        "content_hash": "ch:override-content",
    }


# ── positive projection: signoff_cleared (monkeypatched) ────────────────────


def test_signoff_projection_full_dict(monkeypatch):
    """Monkeypatch read_sei_attestations to a signoff_cleared attestation; assert
    all 7 clearance record fields (disposition/posture/authority/as_of/reasons/content_hash).
    Patching legis.service.governance.read_sei_attestations — the call-site namespace.
    """
    fake_attestations = {
        "status": "checked",
        "sei": _SEI,
        "attestations": [
            {
                "kind": "signoff_cleared",
                "content_hash": "ch:signoff-content",
                "recorded_at": "2026-06-02T12:00:00+00:00",
                "seq": 2,
                "signoff_seq": 1,
            }
        ],
    }
    monkeypatch.setattr(
        "legis.service.governance.read_sei_attestations",
        lambda records, sei: fake_attestations,
    )
    out = read_governance_for_sei([], _SEI)
    assert out["status"] == "checked"
    assert len(out["records"]) == 1
    rec = out["records"][0]
    assert rec == {
        "sei": _SEI,
        "disposition": "cleared",
        "posture": "operator_signoff",
        "authority": "operator",
        "as_of": "2026-06-02T12:00:00+00:00",
        "reasons": ["signoff_cleared"],
        "content_hash": "ch:signoff-content",
    }


# ── honest absence: verified trail, no clearance ────────────────────────────


def test_verified_but_no_clearance_is_checked_empty():
    """An empty (or non-matching) verified trail → status:'checked', records:[] (NOT unavailable)."""
    out = read_governance_for_sei([], _SEI)
    assert out == {"status": "checked", "sei": _SEI, "records": []}


# ── as_of guard: omit records with absent or non-RFC3339 timestamp ───────────


def test_as_of_none_is_omitted(monkeypatch):
    """An attestation with recorded_at: None must be OMITTED, not emitted with as_of:null."""
    fake = {
        "status": "checked",
        "sei": _SEI,
        "attestations": [
            {
                "kind": "operator_override",
                "content_hash": "ch:x",
                "recorded_at": None,
                "seq": 1,
            }
        ],
    }
    monkeypatch.setattr(
        "legis.service.governance.read_sei_attestations",
        lambda records, sei: fake,
    )
    out = read_governance_for_sei([], _SEI)
    assert out["records"] == []


def test_as_of_non_rfc3339_is_omitted(monkeypatch):
    """An attestation with a garbage recorded_at string must be OMITTED."""
    fake = {
        "status": "checked",
        "sei": _SEI,
        "attestations": [
            {
                "kind": "operator_override",
                "content_hash": "ch:x",
                "recorded_at": "garbage",
                "seq": 1,
            }
        ],
    }
    monkeypatch.setattr(
        "legis.service.governance.read_sei_attestations",
        lambda records, sei: fake,
    )
    out = read_governance_for_sei([], _SEI)
    assert out["records"] == []


# ── unknown kind: omit, never crash ─────────────────────────────────────────


def test_unknown_kind_is_omitted(monkeypatch):
    """An attestation with an unrecognised kind must be OMITTED, not raise KeyError."""
    fake = {
        "status": "checked",
        "sei": _SEI,
        "attestations": [
            {
                "kind": "future_kind",  # _POSTURE_BY_KIND.get returns None → omit
                "content_hash": "ch:x",
                "recorded_at": "2026-06-02T12:00:00+00:00",
                "seq": 1,
            }
        ],
    }
    monkeypatch.setattr(
        "legis.service.governance.read_sei_attestations",
        lambda records, sei: fake,
    )
    out = read_governance_for_sei([], _SEI)
    assert out["records"] == []


# ── status propagation guard ─────────────────────────────────────────────────


def test_status_propagated_not_hardcoded(monkeypatch):
    """Happy path: read_sei_attestations status='checked' propagates through.
    Guard path: a non-'checked' status raises AuditIntegrityError rather than
    being silently relabelled 'checked'.  Both branches must be exercised so the
    guard is actually covered.
    """
    # Happy path: checked propagates
    fake_checked = {"status": "checked", "sei": _SEI, "attestations": []}
    monkeypatch.setattr(
        "legis.service.governance.read_sei_attestations",
        lambda records, sei: fake_checked,
    )
    out = read_governance_for_sei([], _SEI)
    assert out["status"] == "checked"

    # Guard path: a future non-checked status must not be silently relabelled
    fake_other = {"status": "unavailable", "sei": _SEI, "attestations": []}
    monkeypatch.setattr(
        "legis.service.governance.read_sei_attestations",
        lambda records, sei: fake_other,
    )
    with pytest.raises(AuditIntegrityError, match="unexpected status"):
        read_governance_for_sei([], _SEI)


# ── gate: signature tamper → AuditIntegrityError ────────────────────────────


def test_gate_raises_on_signature_tamper(tmp_path):
    """FORGE-A: mutate a signed field (judge_verdict) after the gate writes the
    signature → TrailVerifier.verify raises TamperError → service gate wraps it
    in AuditIntegrityError.  Tests the service-gate wrapper, NOT a hand-rolled
    TrailVerifier call (Constraint 6).
    """
    _, store, _ = _operator_override_gate(tmp_path)
    records = store.read_all()
    # Corrupt the signed verdict field (FORGE-A pattern from test_governance.py)
    records[0].payload["extensions"]["judge_verdict"] = "BLOCKED"

    with pytest.raises(AuditIntegrityError):
        read_governance_for_sei_gate(
            records,
            _SEI,
            hmac_key="protected-key",
            protected_policies=frozenset({"protected.x"}),
        )


# ── gate: no key for protected records → ProtectedKeyRequiredError ───────────


def test_gate_requires_key_for_protected(tmp_path):
    """A protected record (protected_cell:True + judge_metadata_signature) present
    without hmac_key → ProtectedKeyRequiredError, even when protected_policies is
    empty (the discriminator fires on the signature marker, not the policy name).
    """
    _, store, _ = _operator_override_gate(tmp_path)
    records = store.read_all()
    with pytest.raises(ProtectedKeyRequiredError):
        read_governance_for_sei_gate(
            records,
            _SEI,
            hmac_key=None,
            protected_policies=frozenset(),
        )


# ── unavailable helper shape ─────────────────────────────────────────────────


def test_unavailable_helper_shape():
    """governance_read_unavailable builds the discriminated unavailable envelope."""
    out = governance_read_unavailable(_SEI, "trail not verifiable")
    assert out == {
        "status": "unavailable",
        "sei": _SEI,
        "records": [],
        "unavailable": [{"reason": "trail not verifiable"}],
    }
