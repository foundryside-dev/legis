"""Phase 1 / Task 1.2 — PostureLedger wrapping AuditStore.

Fail-closed rule for this phase: absent ledger -> read_floor() reports "no
ledger" (None) and callers fall back to ``structured``, never ``chill``.

All unit tests construct the store with an explicit absolute sqlite URL
(matching tests/store/test_audit_store.py), never via posture_db_url().
"""

from __future__ import annotations

import hashlib

import pytest

from legis.enforcement import signing as enf_signing
from legis.posture.ledger import PostureLedger
from legis.posture.records import KIND_KEY_RESET


def _url(tmp_path):
    return f"sqlite:///{tmp_path}/posture.db"


class _MemSigner:
    """In-memory test signer: holds a key, signs canonical fields at v3."""

    def __init__(self, key: bytes):
        self._key = key

    def fingerprint(self) -> str:
        return hashlib.sha256(self._key).hexdigest()

    def sign(self, fields: dict) -> str:
        return enf_signing.sign(fields, self._key, version="v3")


def test_genesis_writes_chill_floor(tmp_path):
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    ledger.genesis(key_fingerprint="ab" * 32, agent_id="installer", recorded_at="t0")
    records = ledger.store.read_all()
    assert len(records) == 1
    assert records[0].payload["kind"] == "GENESIS"
    assert records[0].payload["floor"] == "chill"
    assert ledger.read_floor() == "chill"


def test_read_floor_missing_ledger_returns_none(tmp_path):
    # No DB file written. initialize=False so we don't create it.
    ledger = PostureLedger(_url(tmp_path), initialize=False)
    assert ledger.read_floor() is None
    assert ledger.read_floor() != "chill"


def test_read_floor_is_last_record(tmp_path):
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    key = b"k" * 32
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    ledger.transition(
        "structured",
        signer=_MemSigner(key),
        session_id="sess-1",
        key_fingerprint=fp,
        agent_id="op",
        rationale="tighten",
        recorded_at="t1",
    )
    assert ledger.read_floor() == "structured"


def test_read_floor_uses_tail_read(tmp_path, monkeypatch):
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    ledger.genesis(key_fingerprint="ab" * 32, agent_id="installer", recorded_at="t0")

    def _boom():
        raise AssertionError("read_floor must not call read_all (hot path)")

    monkeypatch.setattr(ledger.store, "read_all", _boom)
    assert ledger.read_floor() == "chill"


def test_chain_integrity(tmp_path):
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    key = b"k" * 32
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    ledger.transition(
        "coached",
        signer=_MemSigner(key),
        session_id="sess-1",
        key_fingerprint=fp,
        agent_id="op",
        rationale="r",
        recorded_at="t1",
    )
    assert ledger.store.verify_integrity() is True


def test_idempotent_open(tmp_path):
    url = _url(tmp_path)
    ledger = PostureLedger(url, initialize=True)
    ledger.genesis(key_fingerprint="ab" * 32, agent_id="installer", recorded_at="t0")
    # Re-open over the existing DB; a second genesis must not append.
    ledger2 = PostureLedger(url, initialize=True)
    ledger2.genesis(key_fingerprint="ab" * 32, agent_id="installer", recorded_at="t0")
    assert len(ledger2.store.read_all()) == 1


def test_genesis_blocked_after_key_reset(tmp_path):
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    # Simulate a KEY_RESET tail (no GENESIS re-needed) by appending one directly.
    from legis.posture.records import PostureRecord

    reset = PostureRecord(
        kind=KIND_KEY_RESET,
        floor="chill",
        key_fingerprint="cd" * 32,
        agent_id="op",
        recorded_at="t0",
        rationale="lost key",
    )
    ledger.store.append(reset.to_payload())
    before = len(ledger.store.read_all())
    ledger.genesis(key_fingerprint="ef" * 32, agent_id="installer", recorded_at="t1")
    assert len(ledger.store.read_all()) == before  # no second genesis


def test_transition_record_signed_binds_seq(tmp_path):
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    key = b"secret-key-bytes-32-..........!!"
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    ledger.transition(
        "structured",
        signer=_MemSigner(key),
        session_id="sess-1",
        key_fingerprint=fp,
        agent_id="op",
        rationale="r",
        recorded_at="t1",
    )
    rec = ledger.store.read_by_seq(2)
    assert rec is not None
    sig = rec.payload["operator_sig"]
    assert sig is not None
    # Reconstruct the signed fields: the record content minus the signature,
    # plus chain_seq=seq (the v3 position binding).
    fields = {k: v for k, v in rec.payload.items() if k != "operator_sig"}
    fields["chain_seq"] = rec.seq
    assert enf_signing.verify(fields, sig, key) is True
    # And it does NOT verify at the wrong position (seq binding holds).
    wrong = dict(fields)
    wrong["chain_seq"] = 99
    assert enf_signing.verify(wrong, sig, key) is False


def test_transition_fingerprint_mismatch_refused(tmp_path):
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    key = b"k" * 32
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    wrong_signer = _MemSigner(b"other-key-bytes-................")
    with pytest.raises(Exception):
        ledger.transition(
            "structured",
            signer=wrong_signer,
            session_id="sess-1",
            key_fingerprint=fp,
            agent_id="op",
            rationale="r",
            recorded_at="t1",
        )
    # Fail-closed: no half-written record.
    assert len(ledger.store.read_all()) == 1


def test_no_read_inside_transition_batch(tmp_path):
    """transition() must resolve any tail read BEFORE entering append_signed (Q-M5).

    append_signed() acquires its own connection via ``self._engine.begin()`` and
    never sets the thread-local batch handle, so ``in_batch()`` is False
    throughout the build() callback — an ``if store.in_batch(): raise`` guard can
    never fire (it is a structural false-green). Instead we bind to the path the
    build callback actually uses: monkeypatch the three store read methods to
    raise UNCONDITIONALLY for the duration of transition(), and assert
    transition() still succeeds. That proves the build callback issues NO
    fresh-connection read (any read would surface our RuntimeError and fail the
    call); the caller must have resolved every read before entering the batch.

    Mutation check: injecting ``self.store.read_all()`` inside build() (or any of
    these reads) makes transition() raise here, turning this test RED.
    """
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    key = b"k" * 32
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")

    store = ledger.store
    calls: dict[str, int] = {
        "get_latest_sequence_and_hash": 0,
        "read_all": 0,
        "read_by_seq": 0,
    }

    def forbid(name):
        def wrapped(*a, **k):
            calls[name] += 1
            raise RuntimeError(
                f"{name} must not be called during transition() — all reads "
                "must be resolved before entering the append_signed batch (Q-M5)"
            )

        return wrapped

    store.get_latest_sequence_and_hash = forbid("get_latest_sequence_and_hash")  # type: ignore[method-assign]
    store.read_all = forbid("read_all")  # type: ignore[method-assign]
    store.read_by_seq = forbid("read_by_seq")  # type: ignore[method-assign]

    # transition() must complete without ever touching those reads. (The caller
    # resolved key_fingerprint above and passes it in; the build callback issues
    # no read.) If any read fires, the forbid() RuntimeError propagates out of
    # append_signed and this call raises — failing the test.
    ledger.transition(
        "structured",
        signer=_MemSigner(key),
        session_id="sess-1",
        key_fingerprint=fp,
        agent_id="op",
        rationale="r",
        recorded_at="t1",
    )

    assert calls == {
        "get_latest_sequence_and_hash": 0,
        "read_all": 0,
        "read_by_seq": 0,
    }

    # The TRANSITION was actually persisted: reopen a fresh ledger (whose store
    # has the real, unpatched read methods) and confirm the floor moved.
    reopened = PostureLedger(_url(tmp_path), initialize=False)
    assert reopened.read_floor() == "structured"
