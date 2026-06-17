from legis.clock import FixedClock
from legis.enforcement.signoff import SignoffGate
from legis.canonical import content_hash
from legis.identity.entity_key import EntityKey
from legis.store.audit_store import AuditStore


def gate(tmp_path, signer=None, key=None):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    g = SignoffGate(
        store, FixedClock("2026-06-02T12:00:00+00:00"), signer=signer, key=key
    )
    return g, store


def test_request_does_not_clear_until_signed(tmp_path):
    g, store = gate(tmp_path)
    req = g.request(
        policy="prod-deploy",
        entity_key=EntityKey.from_locator("svc/api"),
        rationale="ship hotfix",
        agent_id="agent-3",
    )
    assert req.cleared is False
    assert g.is_cleared(req.seq) is False
    assert (
        store.read_all()[0].payload["extensions"]["signoff_state"]
        == "PENDING_SIGNOFF"
    )


def test_operator_signoff_clears_the_gate_and_is_recorded(tmp_path):
    g, store = gate(tmp_path)
    req = g.request(
        policy="prod-deploy",
        entity_key=EntityKey.from_locator("svc/api"),
        rationale="ship hotfix",
        agent_id="agent-3",
    )
    result = g.sign_off(
        request_seq=req.seq, operator_id="op-release-mgr", rationale="verified rollback"
    )
    assert result.cleared is True
    assert g.is_cleared(req.seq) is True
    signoff = store.read_all()[1].payload
    assert signoff["extensions"]["signoff_state"] == "SIGNED_OFF"
    assert signoff["extensions"]["request_seq"] == req.seq
    assert signoff["agent_id"] == "op-release-mgr"


def test_no_llm_is_invoked_on_the_structured_path(tmp_path):
    # SignoffGate has no judge dependency at all — structurally guaranteed.
    g, _ = gate(tmp_path)
    assert not hasattr(g, "_judge")


def test_protected_signoff_is_tamper_bound(tmp_path):
    # With a signer + key, the SIGNED_OFF record carries an HMAC signature.
    g, store = gate(tmp_path, signer=True, key=b"k")
    req = g.request(
        policy="prod-deploy",
        entity_key=EntityKey.from_locator("svc/api"),
        rationale="ship",
        agent_id="agent-3",
    )
    g.sign_off(request_seq=req.seq, operator_id="op-1", rationale="ok")
    ext = store.read_all()[1].payload["extensions"]
    assert ext["signoff_signature"].startswith("hmac-sha256:v3:")


def test_protected_signoff_binds_the_original_request_payload(tmp_path):
    g, store = gate(tmp_path, signer=True, key=b"k")
    req = g.request(
        policy="prod-deploy",
        entity_key=EntityKey.from_sei("loomweave:eid:x"),
        rationale="ship",
        agent_id="agent-3",
        extensions={
            "loomweave": {
                "alive": True,
                "content_hash": "source-hash",
                "lineage_snapshot": {"length": 1, "hash": "lineage-hash"},
            }
        },
    )
    request_payload = store.read_all()[0].payload

    g.sign_off(request_seq=req.seq, operator_id="op-1", rationale="ok")

    signoff = store.read_all()[1].payload
    assert signoff["extensions"]["request_payload_hash"] == content_hash(request_payload)
    assert signoff["extensions"]["signoff_signature"].startswith("hmac-sha256:v3:")


def test_signoff_index_bounds_validation(tmp_path):
    g, _ = gate(tmp_path)
    import pytest

    # Out of bounds request_seq
    with pytest.raises(ValueError):
        g.sign_off(request_seq=0, operator_id="op-1")
    with pytest.raises(ValueError):
        g.sign_off(request_seq=-1, operator_id="op-1")
    with pytest.raises(ValueError):
        g.sign_off(request_seq=999, operator_id="op-1")

    # request_record checks
    assert g.request_record(0) is None
    assert g.request_record(-5) is None
    assert g.request_record(999) is None


def test_signoff_duplicate_signoff_rejected(tmp_path):
    g, _ = gate(tmp_path)
    import pytest

    req = g.request(
        policy="prod-deploy",
        entity_key=EntityKey.from_locator("svc/api"),
        rationale="ship",
        agent_id="agent-3",
    )
    g.sign_off(request_seq=req.seq, operator_id="op-1")

    # Second signoff should be rejected
    with pytest.raises(ValueError) as excinfo:
        g.sign_off(request_seq=req.seq, operator_id="op-2")
    assert "already been signed off" in str(excinfo.value)
