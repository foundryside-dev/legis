import pytest
import sqlite3

from legis.clock import FixedClock
from legis.crypto.signing import sign
from legis.governance.binding_ledger import (
    BindingError,
    BindingLedger,
    binding_signing_fields,
)
from legis.identity.entity_key import EntityKey
from legis.store.audit_store import AuditStore

KEY = b"binding-key-1"


def _ledger(tmp_path):
    store = AuditStore(f"sqlite:///{tmp_path / 'bind.db'}")
    return BindingLedger(store, FixedClock("2026-06-02T12:00:00+00:00"), key=KEY), store


def test_record_then_get_round_trips_the_binding(tmp_path):
    ledger, _ = _ledger(tmp_path)
    seq = ledger.record(signoff_seq=7, issue_id="ISSUE-1",
                        entity_key=EntityKey.from_sei("loomweave:eid:abc"), content_hash="h")
    assert seq == 1
    got = ledger.get(7)
    assert got["signoff_seq"] == 7
    assert got["issue_id"] == "ISSUE-1"
    assert got["entity_key"] == {"value": "loomweave:eid:abc", "identity_stable": True}
    assert got["content_hash"] == "h"
    assert got["binding_signature"].startswith("hmac-sha256:v2:")


def test_verify_passes_for_a_legit_record(tmp_path):
    ledger, _ = _ledger(tmp_path)
    ledger.record(signoff_seq=1, issue_id="I", entity_key=EntityKey.from_sei("loomweave:eid:x"),
                  content_hash="h")
    ledger.verify()  # does not raise


def test_unknown_signoff_seq_returns_none(tmp_path):
    ledger, _ = _ledger(tmp_path)
    ledger.record(signoff_seq=1, issue_id="I", entity_key=EntityKey.from_sei("loomweave:eid:x"),
                  content_hash="h")
    assert ledger.get(99) is None


def test_forged_signature_is_rejected(tmp_path):
    ledger, store = _ledger(tmp_path)
    store.append({"kind": "issue_binding", "signoff_seq": 1, "issue_id": "I",
                  "entity_key": {"value": "loomweave:eid:x", "identity_stable": True},
                  "content_hash": "h", "recorded_at": "t",
                  "binding_signature": "hmac-sha256:v1:deadbeef"})
    with pytest.raises(BindingError):
        ledger.verify()
    with pytest.raises(BindingError):
        ledger.get(1)


def _signed_payload(**overrides):
    payload = {"kind": "issue_binding", "signoff_seq": 1, "issue_id": "I",
               "entity_key": {"value": "loomweave:eid:x", "identity_stable": True},
               "content_hash": "h", "recorded_at": "t"}
    payload["binding_signature"] = sign(binding_signing_fields(payload), KEY)
    payload.update(overrides)
    return payload


def test_tampering_a_signed_field_is_rejected(tmp_path):
    # Copy a legit signature onto a record whose now-signed fields were mutated:
    # flip entity_key.identity_stable and backdate recorded_at. Proves both are
    # in the signed set.
    ledger, store = _ledger(tmp_path)
    store.append(_signed_payload(
        entity_key={"value": "loomweave:eid:x", "identity_stable": False},
        recorded_at="2020-01-01T00:00:00+00:00",
    ))
    with pytest.raises(BindingError):
        ledger.verify()


def test_tampering_content_hash_is_rejected(tmp_path):
    ledger, store = _ledger(tmp_path)
    store.append(_signed_payload(content_hash="TAMPERED"))
    with pytest.raises(BindingError):
        ledger.verify()


def test_missing_signature_is_rejected(tmp_path):
    ledger, store = _ledger(tmp_path)
    store.append({"kind": "issue_binding", "signoff_seq": 1, "issue_id": "I",
                  "entity_key": {"value": "loomweave:eid:x", "identity_stable": True},
                  "content_hash": "h", "recorded_at": "t"})
    with pytest.raises(BindingError):
        ledger.verify()


def test_malformed_binding_record_is_rejected(tmp_path):
    ledger, store = _ledger(tmp_path)
    store.append({"kind": "issue_binding", "signoff_seq": 1,
                  "binding_signature": "hmac-sha256:v1:whatever"})
    with pytest.raises(BindingError):
        ledger.verify()


def test_broken_append_only_hash_chain_is_rejected(tmp_path):
    ledger, store = _ledger(tmp_path)
    ledger.record(signoff_seq=1, issue_id="I-1",
                  entity_key=EntityKey.from_sei("loomweave:eid:x"), content_hash="h1")
    ledger.record(signoff_seq=2, issue_id="I-2",
                  entity_key=EntityKey.from_sei("loomweave:eid:y"), content_hash="h2")
    con = sqlite3.connect(tmp_path / "bind.db")
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
    con.execute("DELETE FROM audit_log WHERE seq=1")
    con.commit()
    con.close()
    assert store.verify_integrity() is False

    with pytest.raises(BindingError, match="hash chain"):
        ledger.verify()
    with pytest.raises(BindingError, match="hash chain"):
        ledger.get(2)


def test_get_by_issue_id_returns_verified_record(tmp_path):
    ledger, _ = _ledger(tmp_path)
    ledger.record(signoff_seq=7, issue_id="ISSUE-7",
                  entity_key=EntityKey.from_sei("loomweave:eid:abc"), content_hash="h7")
    got = ledger.get_by_issue_id("ISSUE-7")
    assert got is not None
    assert got["issue_id"] == "ISSUE-7"
    assert got["signoff_seq"] == 7
    assert got["content_hash"] == "h7"


def test_get_by_issue_id_returns_none_when_absent(tmp_path):
    ledger, _ = _ledger(tmp_path)
    ledger.record(signoff_seq=7, issue_id="ISSUE-7",
                  entity_key=EntityKey.from_sei("loomweave:eid:abc"), content_hash="h7")
    assert ledger.get_by_issue_id("ISSUE-MISSING") is None


def test_get_by_issue_id_raises_on_tampered_ledger(tmp_path):
    ledger, store = _ledger(tmp_path)
    # Record a legitimate ISSUE-7 binding first
    ledger.record(signoff_seq=7, issue_id="ISSUE-7",
                  entity_key=EntityKey.from_sei("loomweave:eid:abc"), content_hash="h7")
    # Then append a forged binding record (bad signature) — poisons the whole ledger
    store.append({"kind": "issue_binding", "signoff_seq": 8, "issue_id": "ISSUE-7",
                  "entity_key": {"value": "loomweave:eid:abc", "identity_stable": True},
                  "content_hash": "h7", "recorded_at": "t",
                  "binding_signature": "hmac-sha256:v1:deadbeef"})
    # Fail-closed: must raise rather than return the real record from a poisoned ledger
    with pytest.raises(BindingError):
        ledger.get_by_issue_id("ISSUE-7")


def test_get_by_issue_id_returns_last_binding_for_issue(tmp_path):
    # Insertion order and signoff_seq order DISAGREE: the second-inserted record
    # has a LOWER signoff_seq. This rules out an accidental "max signoff_seq wins"
    # implementation — last-inserted must win, not highest seq.
    ledger, _ = _ledger(tmp_path)
    ledger.record(signoff_seq=5, issue_id="ISSUE-7",
                  entity_key=EntityKey.from_sei("loomweave:eid:abc"), content_hash="hash-first")
    ledger.record(signoff_seq=1, issue_id="ISSUE-7",
                  entity_key=EntityKey.from_sei("loomweave:eid:abc"), content_hash="hash-second")
    got = ledger.get_by_issue_id("ISSUE-7")
    assert got is not None
    assert got["signoff_seq"] == 1
    assert got["content_hash"] == "hash-second"
