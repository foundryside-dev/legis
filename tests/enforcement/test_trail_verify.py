import json
import sqlite3

from legis.canonical import canonical_json, content_hash
from legis.clock import FixedClock
from legis.enforcement.protected import (
    ProtectedGate,
    TamperError,
    TrailVerifier,
)
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.identity.entity_key import EntityKey
from legis.store.audit_store import GENESIS, AuditStore, _chain


class ScriptedJudge:
    def __init__(self, opinion):
        self.opinion = opinion

    def evaluate(self, record):
        return self.opinion


KEY = b"protected-key-1"
PROTECTED = frozenset({"no-eval"})


def _gate(db):
    store = AuditStore(f"sqlite:///{db}")
    g = ProtectedGate(
        store,
        FixedClock("2026-06-02T12:00:00+00:00"),
        judge=ScriptedJudge(JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")),
        key=KEY,
    )
    return g, store


def _submit(g):
    g.submit(
        policy="no-eval",
        entity_key=EntityKey.from_locator("e"),
        rationale="original",
        agent_id="a",
        file_fingerprint="fp",
        ast_path="ap",
    )


def test_clean_protected_trail_verifies(tmp_path):
    g, store = _gate(tmp_path / "gov.db")
    _submit(g)
    TrailVerifier(KEY, PROTECTED).verify(store.read_all())  # no raise


def test_missing_signature_on_protected_policy_is_tampering(tmp_path):
    g, store = _gate(tmp_path / "gov.db")
    _submit(g)
    _strip_signature_and_rechain(tmp_path / "gov.db")
    assert store.verify_integrity() is True  # Sprint 0 unkeyed chain fooled
    try:
        TrailVerifier(KEY, PROTECTED).verify(store.read_all())
        raise AssertionError("expected TamperError on missing signature")
    except TamperError:
        pass


def test_hmac_catches_a_fully_rechained_edit(tmp_path):
    # THE discriminating test: edit a protected record's rationale, recompute the
    # content/chain hashes for it and every successor so verify_integrity()==True,
    # then assert the keyed HMAC still rejects it.
    g, store = _gate(tmp_path / "gov.db")
    _submit(g)
    _edit_rationale_and_rechain(tmp_path / "gov.db", "FORGED")
    assert store.verify_integrity() is True  # unkeyed chain fooled
    try:
        TrailVerifier(KEY, PROTECTED).verify(store.read_all())
        raise AssertionError("expected TamperError on forged rationale")
    except TamperError:
        pass


def test_hmac_catches_rechained_agent_attribution_edit(tmp_path):
    g, store = _gate(tmp_path / "gov.db")
    _submit(g)
    _edit_payload_and_rechain(tmp_path / "gov.db", lambda p: p.update({"agent_id": "forged-agent"}))
    assert store.verify_integrity() is True
    try:
        TrailVerifier(KEY, PROTECTED).verify(store.read_all())
        raise AssertionError("expected TamperError on forged agent_id")
    except TamperError:
        pass


def test_protected_gate_record_verifies_even_with_empty_protected_policy_set(tmp_path):
    g, store = _gate(tmp_path / "gov.db")
    _submit(g)
    _edit_payload_and_rechain(tmp_path / "gov.db", lambda p: p.update({"agent_id": "forged-agent"}))
    assert store.verify_integrity() is True
    try:
        TrailVerifier(KEY, frozenset()).verify(store.read_all())
        raise AssertionError("expected TamperError on protected gate record despite empty policy config")
    except TamperError:
        pass


def test_hmac_catches_rechained_judge_rationale_edit(tmp_path):
    g, store = _gate(tmp_path / "gov.db")
    _submit(g)
    _edit_payload_and_rechain(
        tmp_path / "gov.db",
        lambda p: p["extensions"].update({"judge_rationale": "forged rationale"}),
    )
    assert store.verify_integrity() is True
    try:
        TrailVerifier(KEY, PROTECTED).verify(store.read_all())
        raise AssertionError("expected TamperError on forged judge rationale")
    except TamperError:
        pass


def test_missing_entity_key_on_protected_policy_is_tampering(tmp_path):
    g, store = _gate(tmp_path / "gov.db")
    _submit(g)
    _edit_payload_and_rechain(
        tmp_path / "gov.db",
        lambda p: (p.pop("entity_key", None), p["extensions"].pop("judge_metadata_signature", None)),
    )
    assert store.verify_integrity() is True
    try:
        TrailVerifier(KEY, PROTECTED).verify(store.read_all())
        raise AssertionError("expected TamperError on missing entity_key")
    except TamperError:
        pass


def test_hmac_catches_interior_delete_and_renumber(tmp_path):
    # AUD-1 (THE seq-binding test): an attacker with file access deletes an
    # interior protected record and renumbers its successor down to close the
    # seq gap, then re-chains. This defeats BOTH the chain walk (re-chained
    # consistently) AND the contiguity check (seq stays 1..N, no gap) — so
    # verify_integrity() returns True. Only binding the seq into the per-record
    # HMAC (v3) catches it: the renumbered record's signature bound its ORIGINAL
    # seq, which no longer matches the column.
    g, store = _gate(tmp_path / "gov.db")
    for r in ("first", "second", "third"):
        g.submit(
            policy="no-eval",
            entity_key=EntityKey.from_locator("e"),
            rationale=r,
            agent_id="a",
            file_fingerprint="fp",
            ast_path="ap",
        )
    _delete_interior_and_renumber(tmp_path / "gov.db")
    # Chain walk + contiguity are both fooled — the structural layer cannot see it.
    assert store.verify_integrity() is True
    try:
        TrailVerifier(KEY, PROTECTED).verify(store.read_all())
        raise AssertionError("expected TamperError on renumbered protected record")
    except TamperError:
        pass


def test_anchored_verifier_catches_tail_truncation_that_signatures_cannot(tmp_path):
    # AUD-1 (THE anchor test, end to end): an anchored gate records the head as
    # it grows. Truncating the tail leaves survivors that are contiguous,
    # chain-consistent, and individually signed — so the signature + chain pass
    # is blind to it. Only the out-of-band anchor sees the head shrank.
    from legis.store.head_anchor import HeadAnchor

    db = tmp_path / "gov.db"
    anchor = HeadAnchor(str(tmp_path / "gov.anchor"), KEY)
    store = AuditStore(f"sqlite:///{db}")
    g = ProtectedGate(
        store,
        FixedClock("2026-06-02T12:00:00+00:00"),
        judge=ScriptedJudge(JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")),
        key=KEY,
        anchor=anchor,
    )
    for r in ("first", "second", "third"):
        g.submit(
            policy="no-eval",
            entity_key=EntityKey.from_locator("e"),
            rationale=r,
            agent_id="a",
            file_fingerprint="fp",
            ast_path="ap",
        )
    _truncate_tail(db, keep=2)
    assert store.verify_integrity() is True  # survivors are a clean chain

    # Without the anchor, the truncation is invisible — the survivors verify.
    TrailVerifier(KEY, PROTECTED).verify(store.read_all())

    # With the anchor wired in, the shrunk head is caught.
    try:
        TrailVerifier(KEY, PROTECTED, anchor=anchor).verify(store.read_all())
        raise AssertionError("expected TamperError on tail truncation")
    except TamperError:
        pass


def test_protected_signoff_signature_covers_loomweave_metadata(tmp_path):
    from legis.enforcement.signoff import SignoffGate

    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    gate = SignoffGate(
        store,
        FixedClock("2026-06-02T12:00:00+00:00"),
        signer=True,
        key=KEY,
    )
    gate.request(
        policy="no-eval",
        entity_key=EntityKey.from_sei("loomweave:eid:x"),
        rationale="needs review",
        agent_id="agent-1",
        extensions={"loomweave": {"alive": True, "content_hash": "original", "lineage_snapshot": {"length": 1, "hash": "h"}}},
    )
    _edit_payload_and_rechain(
        tmp_path / "gov.db",
        lambda p: p["extensions"]["loomweave"].update({"content_hash": "forged"}),
    )
    assert store.verify_integrity() is True
    try:
        TrailVerifier(KEY, PROTECTED).verify(store.read_all())
        raise AssertionError("expected TamperError on forged signoff loomweave metadata")
    except TamperError:
        pass


# --- raw-sqlite tamper helpers (out-of-band edits the store API forbids) ---


def _open_unlocked(db):
    con = sqlite3.connect(db)
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
    return con


def _rechain(con):
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


def _truncate_tail(db, keep):
    # Lop every row above `keep` and re-chain the survivors — file-write tail
    # truncation. Survivors stay contiguous + consistent + individually signed.
    con = _open_unlocked(db)
    con.execute("DELETE FROM audit_log WHERE seq > ?", (keep,))
    _rechain(con)
    con.close()


def _delete_interior_and_renumber(db):
    # Delete seq=2 and slide seq=3 down into the gap, then re-chain — the
    # delete-and-rechain that leaves a consistent, gap-free chain.
    con = _open_unlocked(db)
    con.execute("DELETE FROM audit_log WHERE seq = 2")
    con.execute("UPDATE audit_log SET seq = 2 WHERE seq = 3")
    _rechain(con)
    con.close()


def _edit_rationale_and_rechain(db, new_rationale):
    _edit_payload_and_rechain(db, lambda p: p.update({"rationale": new_rationale}))


def _edit_payload_and_rechain(db, mutate):
    con = _open_unlocked(db)
    seq, payload = con.execute(
        "SELECT seq, payload FROM audit_log ORDER BY seq ASC LIMIT 1"
    ).fetchone()
    p = json.loads(payload)
    mutate(p)
    con.execute("UPDATE audit_log SET payload=? WHERE seq=?", (canonical_json(p), seq))
    _rechain(con)
    con.close()


def _strip_signature_and_rechain(db):
    con = _open_unlocked(db)
    seq, payload = con.execute(
        "SELECT seq, payload FROM audit_log ORDER BY seq ASC LIMIT 1"
    ).fetchone()
    p = json.loads(payload)
    p["extensions"].pop("judge_metadata_signature", None)
    con.execute("UPDATE audit_log SET payload=? WHERE seq=?", (canonical_json(p), seq))
    _rechain(con)
    con.close()
