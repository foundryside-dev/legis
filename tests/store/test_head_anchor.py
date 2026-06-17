"""Out-of-band head anchor — the tail-truncation half of the AUD-1 defence.

seq-binding (v3) + contiguity catch interior delete and reorder, but they
*cannot* catch tail-truncation: lopping the last N records off leaves a chain
that is contiguous (1..N-k), internally consistent, and whose every surviving
signature still verifies — the truncated head was legitimately last. Only an
out-of-band memory of "the head used to be higher" sees it. That memory is the
HeadAnchor: a small, HMAC-signed sidecar file holding the last (seq, chain_hash).
"""

import json
import os
import sqlite3

import pytest

from legis.canonical import content_hash
from legis.store.audit_store import GENESIS, AuditStore, _chain
from legis.store.head_anchor import AnchorError, HeadAnchor

KEY = b"anchor-key-1"


def _store(tmp_path):
    return AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")


def _anchored(tmp_path, n=3):
    """A store with *n* appended records and an anchor advanced to the head."""
    store = _store(tmp_path)
    anchor = HeadAnchor(str(tmp_path / "gov.anchor"), KEY)
    for i in range(n):
        store.append({"k": i})
        seq, chain = store.get_latest_sequence_and_hash()
        anchor.update(seq, chain)
    return store, anchor


def _truncate_tail(tmp_path, keep):
    # Delete every row above `keep` out of band and re-chain the survivors —
    # exactly what file-write tail truncation looks like to the store.
    con = sqlite3.connect(tmp_path / "gov.db")
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
    con.execute("DELETE FROM audit_log WHERE seq > ?", (keep,))
    rows = con.execute("SELECT seq, payload FROM audit_log ORDER BY seq ASC").fetchall()
    prev = GENESIS
    for seq, payload in rows:
        c = content_hash(json.loads(payload))
        ch = _chain(prev, c)
        con.execute(
            "UPDATE audit_log SET content_hash=?, prev_hash=?, chain_hash=? WHERE seq=?",
            (c, prev, ch, seq),
        )
        prev = ch
    con.commit()
    con.close()


def test_anchor_passes_on_an_untampered_trail(tmp_path):
    store, anchor = _anchored(tmp_path)
    anchor.check(store.read_all())  # no raise


def test_anchor_detects_tail_truncation(tmp_path):
    # THE anchor test: truncate the tail. The survivors form a clean chain —
    # verify_integrity() is True — but the anchor remembers a higher head.
    store, anchor = _anchored(tmp_path, n=3)
    _truncate_tail(tmp_path, keep=2)
    assert store.verify_integrity() is True  # contiguous + consistent survivors
    with pytest.raises(AnchorError):
        anchor.check(store.read_all())


def test_anchor_missing_file_fails_closed(tmp_path):
    # An attacker who truncates the DB and then deletes the anchor must not
    # thereby disarm the check: a missing anchor on an anchored store is tamper.
    store, anchor = _anchored(tmp_path, n=2)
    os.remove(tmp_path / "gov.anchor")
    with pytest.raises(AnchorError):
        anchor.check(store.read_all())


def test_anchor_forged_signature_rejected(tmp_path):
    # Rewriting the anchor to match a truncated DB requires the key.
    store, _ = _anchored(tmp_path, n=3)
    forged = {"head_seq": 2, "head_chain_hash": "deadbeef",
              "anchor_signature": "hmac-sha256:v3:" + "0" * 64}
    (tmp_path / "gov.anchor").write_text(json.dumps(forged))
    with pytest.raises(AnchorError):
        HeadAnchor(str(tmp_path / "gov.anchor"), KEY).check(store.read_all())


def test_anchor_detects_truncate_then_reappend_forgery(tmp_path):
    # Truncate to seq=2, then re-append a fresh record to seq=3 to restore the
    # head count. The anchor's chain_hash at seq=3 no longer matches: the
    # attacker cannot reproduce the original keyed content signature.
    store, anchor = _anchored(tmp_path, n=3)
    _truncate_tail(tmp_path, keep=2)
    store.append({"k": "attacker-substitute"})  # back to head seq=3, different chain
    assert store.verify_integrity() is True
    with pytest.raises(AnchorError):
        anchor.check(store.read_all())


def test_anchor_with_empty_path_is_a_noop(tmp_path):
    # Path-less / :memory: stores cannot be anchored; update + check no-op.
    anchor = HeadAnchor("", KEY)
    anchor.update(5, "abc")  # no file written, no raise
    anchor.check([])  # no raise


def test_anchor_replay_is_a_known_unclosed_limitation(tmp_path):
    # KNOWN LIMITATION (red-team, AUD-1): the anchor signature stops forgery but
    # NOT replay. An attacker who snapshots a genuinely-signed earlier anchor
    # (head=1), lets the trail grow, then truncates the DB back to seq=1 and
    # restores the saved anchor, goes UNDETECTED — the restored anchor is real,
    # its seq + chain_hash are consistent with the truncated DB. This is inherent
    # to a local mutable sidecar (nothing on disk the file-write attacker cannot
    # also roll back); full rollback resistance needs append-only/remote storage
    # for the anchor. This test pins that boundary so it is honest and
    # version-controlled — if a future change claims to close replay, it must
    # delete this test deliberately, not let the over-claim drift back in.
    store = _store(tmp_path)
    anchor = HeadAnchor(str(tmp_path / "gov.anchor"), KEY)
    store.append({"k": 0})
    seq, chain = store.get_latest_sequence_and_hash()
    anchor.update(seq, chain)
    saved = (tmp_path / "gov.anchor").read_bytes()  # the attacker snapshots it
    for i in (1, 2):
        store.append({"k": i})
        anchor.update(*store.get_latest_sequence_and_hash())

    _truncate_tail(tmp_path, keep=1)
    (tmp_path / "gov.anchor").write_bytes(saved)  # replay the stale-but-genuine anchor

    assert store.verify_integrity() is True
    # The replayed anchor verifies — the rollback is NOT caught locally.
    anchor.check(store.read_all())  # no raise: documents the residual
