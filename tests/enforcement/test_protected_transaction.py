import sqlite3

import pytest

from legis.clock import FixedClock
from legis.enforcement.protected import ProtectedGate
from legis.enforcement.verdict import Verdict
from legis.identity.entity_key import EntityKey
from legis.store.audit_store import AuditStore
from legis.store.head_anchor import AnchorError, HeadAnchor

KEY = b"k" * 32
CLOCK = "2026-06-26T12:00:00+00:00"


class _UnusedJudge:
    """operator_override bypasses the judge; if it is consulted, fail loudly."""

    def evaluate(self, record):  # pragma: no cover - must never be called
        raise AssertionError("judge must not be consulted on operator_override")


def _anchored_gate(tmp_path):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    anchor = HeadAnchor(str(tmp_path / "gov.anchor"), KEY)
    gate = ProtectedGate(store, FixedClock(CLOCK), _UnusedJudge(), KEY, anchor=anchor)
    return store, anchor, gate


def _override(gate, rationale):
    return gate.operator_override(
        policy="protected/secrets",
        entity_key=EntityKey.from_locator("m.f"),
        rationale=rationale,
        operator_id="op",
        file_fingerprint="fp",
        ast_path="m.f",
    )


def _truncate_to(db_path, keep_seq):
    """Raw out-of-band tail truncation (drops the append-only triggers first).

    # No survivor re-chain needed: AnchorError fires on the head_seq comparison
    # before chain_hash is checked.
    """
    con = sqlite3.connect(db_path)
    try:
        con.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
        con.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
        con.execute("DELETE FROM audit_log WHERE seq > ?", (keep_seq,))
        con.commit()
    finally:
        con.close()


def test_protected_transaction_advances_anchor_so_truncation_is_detected(tmp_path):
    """A protected append batched through ProtectedGate.transaction() advances the
    HeadAnchor after commit, so a later tail-truncation back to the pre-batch head
    is DETECTED (parity with SignoffGate.transaction()). legis-0c310712a7.
    """
    store, anchor, gate = _anchored_gate(tmp_path)
    # A pre-batch protected append (outside any batch -> anchor advances normally).
    _override(gate, "pre-batch")
    pre_seq, _ = store.get_latest_sequence_and_hash()

    # Batch a protected append through the NEW owned transaction API.
    with gate.transaction():
        _override(gate, "in-batch")

    # The transaction() advanced the anchor to the in-batch record's head.
    head_seq, _ = store.get_latest_sequence_and_hash()
    assert head_seq == pre_seq + 1

    # Truncate the in-batch record out of band, back to the pre-batch head.
    _truncate_to(str(tmp_path / "gov.db"), pre_seq)

    # The anchor remembers the higher head -> truncation is detected.
    with pytest.raises(AnchorError):
        anchor.check(store.read_all())


def test_protected_transaction_is_safe_without_an_anchor(tmp_path):
    """Production default: anchor=None. transaction() still batches atomically;
    the if-anchor guard is a no-op, not a crash."""
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    gate = ProtectedGate(store, FixedClock(CLOCK), _UnusedJudge(), KEY)  # no anchor=
    with gate.transaction():
        _override(gate, "in-batch")
    assert len(store.read_all()) == 1
    assert store.verify_integrity() is True


def test_protected_transaction_no_overshoot_on_rollback(tmp_path):
    """AUD-1 no-overshoot: an exception inside gate.transaction() rolls back the
    append AND the anchor update, so the anchor never advances past a rolled-back
    head. legis-0c310712a7."""
    store, anchor, gate = _anchored_gate(tmp_path)
    # Pre-batch append: anchor lands at a known head.
    _override(gate, "pre-rollback")
    pre_batch_count = len(store.read_all())

    with pytest.raises(RuntimeError):
        with gate.transaction():
            _override(gate, "will-be-rolled-back")
            raise RuntimeError("simulated failure inside batch")

    # Rollback dropped the in-batch row; anchor update never ran.
    assert len(store.read_all()) == pre_batch_count
    # Anchor still at the pre-batch head -> does not raise.
    anchor.check(store.read_all())


def test_raw_store_transaction_bypasses_anchor_advance_documented_residual(tmp_path):
    """DOCUMENTS the parity limit (not a defense): a protected append inside a RAW
    store.transaction() — bypassing gate.transaction() — defers the anchor advance
    (in_batch() is true) and nothing re-advances it, so a truncation back to the
    pre-batch head is NOT detected. The supported safe path is gate.transaction()
    (Task 1); a caller that owns a raw batch must advance the anchor itself,
    identically to SignoffGate. If a future change closes this (e.g. an after-commit
    hook on AuditStore.transaction), update this test deliberately. legis-0c310712a7.
    """
    store, anchor, gate = _anchored_gate(tmp_path)
    _override(gate, "pre-batch")
    pre_seq, _ = store.get_latest_sequence_and_hash()

    # RAW batch (NOT gate.transaction()): the append's anchor advance is deferred
    # and never re-applied.
    with store.transaction():
        _override(gate, "in-raw-batch")

    # LANDING ASSERTION: proves the in-raw-batch append actually landed (the
    # in_batch()-deferred branch was taken). If this fails, the raw batch silently
    # no-op'd and the residual test cannot be trusted. Do NOT silence by weakening
    # the assertion.
    assert store.get_latest_sequence_and_hash()[0] == pre_seq + 1

    # The anchor is STALE at the pre-batch head (the residual).
    _truncate_to(str(tmp_path / "gov.db"), pre_seq)

    # Stale anchor == truncated DB head -> truncation is NOT detected.
    anchor.check(store.read_all())  # does not raise: asserts the DOCUMENTED residual
