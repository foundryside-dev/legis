"""Phase 10 — doctor reconciliation for the posture ledger.

Tasks 10.1 (chain + genesis presence), 10.2 (unacknowledged KEY_RESET ->
non-zero exit, with D6 new-epoch signature verification), and 10.3 (operator-key
accessibility).

All fixtures point the doctor at a tmp posture DB via the ``LEGIS_POSTURE_DB``
override (which ``_store_url`` honours verbatim, matching config precedence).
No fixture touches the real ``.weft/legis/`` store dir.
"""

from __future__ import annotations

import sqlite3

import pytest

from legis.crypto import signing as enf_signing
from legis.posture.ledger import PostureLedger
from legis.posture.records import (
    KIND_KEY_RESET,
    KIND_TRANSITION,
    PostureRecord,
)
from legis.posture.signing import key_fingerprint, mint_key


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


class _MemSigner:
    """An in-memory signer holding raw key bytes (mirrors tests/posture)."""

    def __init__(self, key: bytes) -> None:
        self._key = key

    def fingerprint(self) -> str:
        from hashlib import sha256

        return sha256(self._key).hexdigest()

    def sign(self, fields: dict) -> str:
        return enf_signing.sign(fields, self._key, version="v3")


def _url(tmp_path) -> str:
    return "sqlite:///" + str(tmp_path / "posture.db")


@pytest.fixture
def posture_env(tmp_path, monkeypatch):
    """Point the doctor's posture store URL at a tmp DB."""
    url = _url(tmp_path)
    monkeypatch.setenv("LEGIS_POSTURE_DB", url)
    monkeypatch.delenv("LEGIS_OPERATOR_KEY", raising=False)
    return url


def _open(url: str) -> PostureLedger:
    return PostureLedger(url, initialize=True)


def _append_key_reset(ledger: PostureLedger, *, new_fp: str, agent_id: str, recorded_at: str) -> None:
    """Chain a KEY_RESET onto existing history (rekey lands in Phase 11; the
    doctor tests construct the record directly so they don't depend on it)."""
    record = PostureRecord(
        kind=KIND_KEY_RESET,
        floor=ledger.read_floor() or "structured",
        key_fingerprint=new_fp,
        agent_id=agent_id,
        recorded_at=recorded_at,
        rationale="rekey",
        operator_sig=None,
        session_id=None,
    )
    ledger.store.append(record.to_payload())


# ---------------------------------------------------------------------------
# Task 10.1 — chain + genesis presence
# ---------------------------------------------------------------------------


def test_posture_chain_ok(posture_env):
    from legis.doctor import check_posture_chain

    ledger = _open(posture_env)
    ledger.genesis(key_fingerprint="ab" * 32, agent_id="installer", recorded_at="t0")

    c = check_posture_chain(_root := __import__("pathlib").Path("."))
    assert c.id == "store.posture_chain"
    assert c.status == "ok"
    assert c.repairable is False


def test_posture_chain_missing_is_ok(tmp_path, monkeypatch):
    from legis.doctor import check_posture_chain

    url = "sqlite:///" + str(tmp_path / "nope.db")
    monkeypatch.setenv("LEGIS_POSTURE_DB", url)

    c = check_posture_chain(__import__("pathlib").Path("."))
    assert c.status == "ok"
    assert "no ledger" in (c.message or "").lower()
    # No-leak: must NOT create the DB file.
    assert not (tmp_path / "nope.db").exists()


def test_posture_chain_tampered_errors(posture_env, tmp_path):
    from legis.doctor import check_posture_chain

    ledger = _open(posture_env)
    ledger.genesis(key_fingerprint="ab" * 32, agent_id="installer", recorded_at="t0")
    # Tamper a payload out of band so the chain hash no longer matches. Drop the
    # append-only triggers first (a real file-tamper has no such guard).
    db = tmp_path / "posture.db"
    con = sqlite3.connect(db)
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
    con.execute("UPDATE audit_log SET payload = REPLACE(payload, 'chill', 'protected')")
    con.commit()
    con.close()

    c = check_posture_chain(__import__("pathlib").Path("."))
    assert c.status == "error"


def test_posture_store_exists_no_genesis_warns(posture_env):
    from legis.doctor import check_posture_ledger

    # Schema created (AuditStore __init__) but ZERO rows — no genesis.
    _open(posture_env)

    c = check_posture_ledger(__import__("pathlib").Path("."))
    assert c.id == "store.posture_ledger"
    assert c.status == "warn"
    assert "genesis" in (c.message or "").lower()


def test_posture_ledger_genesis_present_is_ok(posture_env):
    from legis.doctor import check_posture_ledger

    ledger = _open(posture_env)
    ledger.genesis(key_fingerprint="ab" * 32, agent_id="installer", recorded_at="t0")

    c = check_posture_ledger(__import__("pathlib").Path("."))
    assert c.status == "ok"
    # Reports the standing floor.
    assert "chill" in (c.message or "").lower()


def test_posture_ledger_missing_is_ok(tmp_path, monkeypatch):
    from legis.doctor import check_posture_ledger

    monkeypatch.setenv("LEGIS_POSTURE_DB", "sqlite:///" + str(tmp_path / "nope.db"))
    c = check_posture_ledger(__import__("pathlib").Path("."))
    assert c.status == "ok"
    assert not (tmp_path / "nope.db").exists()


# ---------------------------------------------------------------------------
# Task 10.2 — unacknowledged KEY_RESET -> non-zero exit (D6)
# ---------------------------------------------------------------------------


def _genesis_then_rekey(url: str):
    """Genesis under epoch-1 key, then a KEY_RESET introducing epoch-2.

    Returns ``(ledger, key2_hex, fp2)`` so the caller can sign an acknowledging
    transition under the NEW epoch.
    """
    ledger = _open(url)
    key1 = mint_key()
    fp1 = key_fingerprint(key1)
    ledger.genesis(key_fingerprint=fp1, agent_id="installer", recorded_at="t0")
    key2 = mint_key()
    fp2 = key_fingerprint(key2)
    _append_key_reset(ledger, new_fp=fp2, agent_id="alice", recorded_at="2026-06-16T00:00:00Z")
    return ledger, key2, fp2


def test_key_reset_unacknowledged_errors(posture_env):
    from legis.doctor import check_posture_key_reset, collect_checks, run_doctor

    _genesis_then_rekey(posture_env)

    c = check_posture_key_reset(__import__("pathlib").Path("."))
    assert c.status == "error"
    assert c.ok is False
    assert c.repairable is False

    # run_doctor returns non-zero because a check is not ok.
    rc = run_doctor(__import__("pathlib").Path("."), repair=False, fmt="json")
    assert rc == 1
    # And it is wired into collect_checks.
    ids = {ck.id for ck in collect_checks(__import__("pathlib").Path("."), repair=False)}
    assert "store.posture_key_reset" in ids


def test_key_reset_acknowledged_ok(posture_env, monkeypatch):
    from legis.doctor import check_posture_key_reset

    ledger, key2, fp2 = _genesis_then_rekey(posture_env)
    # An acknowledging TRANSITION signed under the NEW epoch key (fp2).
    ledger.transition(
        "structured",
        signer=_MemSigner(bytes.fromhex(key2)),
        session_id="sess-ack",
        key_fingerprint=fp2,
        agent_id="alice",
        rationale="re-raise after rekey",
        recorded_at="2026-06-16T01:00:00Z",
    )
    # The doctor obtains the new-epoch key from the env backend to verify.
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", key2)

    c = check_posture_key_reset(__import__("pathlib").Path("."))
    assert c.status == "ok"
    assert c.ok is True


def test_key_reset_acknowledged_with_age_file_backend(posture_env, monkeypatch, tmp_path):
    from pathlib import Path

    from legis.config import operator_age_path
    from legis.doctor import check_posture_key_reset
    from legis.posture.signing import AgeFileSigner, wrap_key

    monkeypatch.chdir(tmp_path)
    ledger, key2, fp2 = _genesis_then_rekey(posture_env)
    passphrase = "correct horse"
    monkeypatch.setenv("LEGIS_OPERATOR_KEY_AGE_PASSPHRASE", passphrase)
    monkeypatch.delenv("LEGIS_OPERATOR_KEY", raising=False)
    age_path = operator_age_path()
    age_path.parent.mkdir(parents=True, exist_ok=True)
    age_path.write_bytes(wrap_key(key2, passphrase))

    ledger.transition(
        "structured",
        signer=AgeFileSigner(blob=age_path.read_bytes(), passphrase_cb=lambda: passphrase),
        session_id="sess-ack",
        key_fingerprint=fp2,
        agent_id="alice",
        rationale="re-raise after rekey",
        recorded_at="2026-06-16T01:00:00Z",
    )

    c = check_posture_key_reset(Path("."))
    assert c.status == "ok"
    assert c.ok is True


def test_key_reset_acknowledged_with_age_file_backend_uses_doctor_root(
    posture_env, monkeypatch, tmp_path
):
    from legis.doctor import check_posture_key_reset
    from legis.posture.signing import AgeFileSigner, wrap_key

    repo = tmp_path / "repo"
    other_cwd = tmp_path / "other"
    repo.mkdir()
    other_cwd.mkdir()
    ledger, key2, fp2 = _genesis_then_rekey(posture_env)
    passphrase = "correct horse"
    monkeypatch.setenv("LEGIS_OPERATOR_KEY_AGE_PASSPHRASE", passphrase)
    monkeypatch.delenv("LEGIS_OPERATOR_KEY", raising=False)
    age_path = repo / ".weft" / "legis" / "operator.age"
    age_path.parent.mkdir(parents=True, exist_ok=True)
    age_path.write_bytes(wrap_key(key2, passphrase))

    ledger.transition(
        "structured",
        signer=AgeFileSigner(blob=age_path.read_bytes(), passphrase_cb=lambda: passphrase),
        session_id="sess-ack",
        key_fingerprint=fp2,
        agent_id="alice",
        rationale="re-raise after rekey",
        recorded_at="2026-06-16T01:00:00Z",
    )

    monkeypatch.chdir(other_cwd)
    c = check_posture_key_reset(repo)
    assert c.status == "ok"
    assert c.ok is True


def test_key_reset_acknowledged_requires_new_epoch_fingerprint(posture_env, monkeypatch):
    """A TRANSITION signed under the OLD epoch key does NOT acknowledge (D6)."""
    from legis.doctor import check_posture_key_reset

    ledger = _open(posture_env)
    key1 = mint_key()
    fp1 = key_fingerprint(key1)
    ledger.genesis(key_fingerprint=fp1, agent_id="installer", recorded_at="t0")
    key2 = mint_key()
    fp2 = key_fingerprint(key2)
    _append_key_reset(ledger, new_fp=fp2, agent_id="alice", recorded_at="2026-06-16T00:00:00Z")

    # Append a TRANSITION but sign it with the OLD key (key1), while the record's
    # key_fingerprint field still claims the new epoch fp2. Record-kind presence
    # alone would (wrongly) treat this as acknowledged; signature verification
    # against fp2 must reject it.
    def build(seq, prev_hash):
        rec = PostureRecord(
            kind=KIND_TRANSITION,
            floor="structured",
            key_fingerprint=fp2,
            agent_id="attacker",
            recorded_at="2026-06-16T02:00:00Z",
            rationale="forged ack",
            operator_sig=None,
            session_id="sess-x",
        )
        payload = rec.to_payload()
        fields = {k: v for k, v in payload.items() if k != "operator_sig"}
        fields["chain_seq"] = seq
        # Sign with the OLD epoch key — wrong key for fp2.
        payload["operator_sig"] = enf_signing.sign(fields, bytes.fromhex(key1), version="v3")
        return payload

    ledger.store.append_signed(build)

    # The doctor is handed the genuine new-epoch key, but the transition's sig
    # was made with the old key, so verification against fp2 fails.
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", key2)

    c = check_posture_key_reset(__import__("pathlib").Path("."))
    assert c.status == "error"
    assert c.ok is False


def test_key_reset_message_attributed(posture_env):
    from legis.doctor import check_posture_key_reset

    _genesis_then_rekey(posture_env)
    c = check_posture_key_reset(__import__("pathlib").Path("."))
    msg = (c.message or "")
    assert "alice" in msg  # agent_id attribution
    assert "2026-06-16" in msg  # reset date


def test_key_reset_absent_is_ok(posture_env):
    """A normal GENESIS-only ledger (no rekey) is acknowledged-by-default."""
    from legis.doctor import check_posture_key_reset

    ledger = _open(posture_env)
    ledger.genesis(key_fingerprint="ab" * 32, agent_id="installer", recorded_at="t0")
    c = check_posture_key_reset(__import__("pathlib").Path("."))
    assert c.status == "ok"


def test_key_reset_missing_ledger_is_ok(tmp_path, monkeypatch):
    from legis.doctor import check_posture_key_reset

    monkeypatch.setenv("LEGIS_POSTURE_DB", "sqlite:///" + str(tmp_path / "nope.db"))
    monkeypatch.delenv("LEGIS_OPERATOR_KEY", raising=False)
    c = check_posture_key_reset(__import__("pathlib").Path("."))
    assert c.status == "ok"
    assert not (tmp_path / "nope.db").exists()


# ---------------------------------------------------------------------------
# Task 10.3 — operator-key accessibility
# ---------------------------------------------------------------------------


def test_operator_key_reachable_ok(posture_env, monkeypatch):
    from legis.doctor import check_operator_key_accessible

    ledger = _open(posture_env)
    key = mint_key()
    fp = key_fingerprint(key)
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    # A backend can produce the expected fingerprint (env path, with the warning
    # note — but reachability itself is ok).
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", key)

    c = check_operator_key_accessible(__import__("pathlib").Path("."))
    assert c.id == "runtime.operator_key"
    # env-present produces a warn (plaintext-in-env honesty); reachability holds.
    assert c.status == "warn"
    assert c.ok is True


def test_operator_key_lost_warns(posture_env, monkeypatch):
    from legis.doctor import check_operator_key_accessible

    ledger = _open(posture_env)
    ledger.genesis(key_fingerprint="ab" * 32, agent_id="installer", recorded_at="t0")
    # No backend can produce the stored fingerprint (no env key, no age file).
    monkeypatch.delenv("LEGIS_OPERATOR_KEY", raising=False)

    c = check_operator_key_accessible(__import__("pathlib").Path("."))
    assert c.status == "warn"
    assert "not reachable" in (c.message or "").lower()
    assert c.ok is True  # report-only warn, never blocks


def test_operator_key_env_present_warns(posture_env, monkeypatch):
    from legis.doctor import check_operator_key_accessible

    ledger = _open(posture_env)
    key = mint_key()
    fp = key_fingerprint(key)
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", key)

    c = check_operator_key_accessible(__import__("pathlib").Path("."))
    assert c.status == "warn"
    assert "env" in (c.message or "").lower()


def test_operator_key_age_file_reachable_uses_doctor_root(posture_env, monkeypatch, tmp_path):
    from legis.doctor import check_operator_key_accessible
    from legis.posture.signing import wrap_key

    repo = tmp_path / "repo"
    other_cwd = tmp_path / "other"
    repo.mkdir()
    other_cwd.mkdir()
    ledger = _open(posture_env)
    key = mint_key()
    fp = key_fingerprint(key)
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    passphrase = "correct horse"
    monkeypatch.setenv("LEGIS_OPERATOR_KEY_AGE_PASSPHRASE", passphrase)
    monkeypatch.delenv("LEGIS_OPERATOR_KEY", raising=False)
    age_path = repo / ".weft" / "legis" / "operator.age"
    age_path.parent.mkdir(parents=True, exist_ok=True)
    age_path.write_bytes(wrap_key(key, passphrase))

    monkeypatch.chdir(other_cwd)
    c = check_operator_key_accessible(repo)
    assert c.status == "ok"
    assert "reachable" in (c.message or "").lower()


def test_operator_key_env_mismatch_is_not_reported_usable(posture_env, monkeypatch):
    from legis.doctor import check_operator_key_accessible

    ledger = _open(posture_env)
    key = mint_key()
    fp = key_fingerprint(key)
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", mint_key())

    c = check_operator_key_accessible(__import__("pathlib").Path("."))
    assert c.status == "warn"
    msg = (c.message or "").lower()
    assert "does not match" in msg
    assert "usable" not in msg


def test_operator_key_no_ledger_is_ok(tmp_path, monkeypatch):
    from legis.doctor import check_operator_key_accessible

    monkeypatch.setenv("LEGIS_POSTURE_DB", "sqlite:///" + str(tmp_path / "nope.db"))
    monkeypatch.delenv("LEGIS_OPERATOR_KEY", raising=False)
    c = check_operator_key_accessible(__import__("pathlib").Path("."))
    assert c.status == "ok"
    assert not (tmp_path / "nope.db").exists()


def test_no_key_material_in_any_posture_check_message(posture_env, monkeypatch):
    """Honesty: no posture doctor check ever renders the raw key."""
    from legis.doctor import (
        check_operator_key_accessible,
        check_posture_chain,
        check_posture_key_reset,
        check_posture_ledger,
    )

    ledger, key2, fp2 = _genesis_then_rekey(posture_env)
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", key2)

    root = __import__("pathlib").Path(".")
    for check in (
        check_posture_chain,
        check_posture_ledger,
        check_posture_key_reset,
        check_operator_key_accessible,
    ):
        msg = check(root).message or ""
        assert key2 not in msg
