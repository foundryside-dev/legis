"""Task 5 tests: legis governance-read <sei> CLI subcommand.

TDD red→green. Cases:
  (a) LEGIS_HMAC_KEY set + verifiable store with a clearance → exit 0, JSON {status:checked, records:[…]}
  (b) NO LEGIS_HMAC_KEY → exit 0, JSON {status:unavailable,…}
  (c) CHAIN-tampered store (delete a non-protected record, creating a seq gap) →
      exit nonzero, "audit integrity" in stderr.
      CRITICAL: this test must be RED if verify_integrity() is omitted. Only
      verify_integrity() detects a seq gap; TrailVerifier.verify is a no-op
      on non-protected records, so a CLI that skips verify_integrity() would
      return exit 0 / {status:checked, records:[]} (false-green).
  (d) Signature-tampered protected store (key mismatch) → exit nonzero,
      "verification failed" in stderr.
  (e) Missing/relocated DB (key set) → exit 0, JSON {status:unavailable,…},
      NOT a silent {status:checked, records:[]} from an auto-created empty DB.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from legis.cli import main
from legis.clock import FixedClock
from legis.enforcement.protected import ProtectedGate
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.identity.entity_key import EntityKey
from legis.store.audit_store import AuditStore

_SEI = "loomweave:eid:cli-governance-read-test"
_CLOCK = FixedClock("2026-06-03T10:00:00+00:00")
_KEY = b"cli-governance-key"
_KEY_STR = "cli-governance-key"
_POLICY = "protected.cli-test"


class _AcceptJudge:
    def evaluate(self, record):  # noqa: ANN001
        return JudgeOpinion(verdict=Verdict.ACCEPTED, model="judge@1", rationale="ok")


def _db_url(db_path) -> str:
    return f"sqlite:///{db_path}"


def _write_clearance(db_path) -> None:
    """Write a genuine protected operator_override clearance to the store."""
    store = AuditStore(_db_url(db_path))
    gate = ProtectedGate(store, _CLOCK, judge=_AcceptJudge(), key=_KEY)
    gate.operator_override(
        policy=_POLICY,
        entity_key=EntityKey(value=_SEI, identity_stable=True),
        rationale="operator clears",
        operator_id="operator-1",
        file_fingerprint="sha256:ff",
        ast_path="Module.Call",
        extensions={"loomweave": {"content_hash": "ch:test-content"}},
    )


# --------------------------------------------------------------------------- #
# (a) LEGIS_HMAC_KEY set + verifiable store with clearance → checked          #
# --------------------------------------------------------------------------- #


def test_cli_governance_read_checked_with_clearance(tmp_path, monkeypatch, capsys):
    """Verifiable protected store + LEGIS_HMAC_KEY → exit 0, status:checked with records."""
    db_path = tmp_path / "gov.db"
    _write_clearance(db_path)
    monkeypatch.setenv("LEGIS_HMAC_KEY", _KEY_STR)
    monkeypatch.setenv("LEGIS_PROTECTED_POLICIES", _POLICY)

    rc = main(["governance-read", "--db", _db_url(db_path), _SEI])
    assert rc == 0
    out, err = capsys.readouterr()
    assert not err, f"unexpected stderr: {err!r}"
    envelope = json.loads(out)
    assert envelope["status"] == "checked"
    assert envelope["sei"] == _SEI
    assert len(envelope["records"]) == 1
    rec = envelope["records"][0]
    assert rec["disposition"] == "cleared"
    assert rec["posture"] == "protected_override"
    assert rec["authority"] == "operator"
    assert rec["content_hash"] == "ch:test-content"
    assert rec["reasons"] == ["operator_override"]
    assert rec["as_of"] == "2026-06-03T10:00:00+00:00"


# --------------------------------------------------------------------------- #
# (b) NO LEGIS_HMAC_KEY → unavailable (can't verify sigs)                    #
# --------------------------------------------------------------------------- #


def test_cli_governance_read_no_key_is_unavailable(tmp_path, monkeypatch, capsys):
    """Without LEGIS_HMAC_KEY, signatures are unverifiable → unavailable (NOT silent checked/[])."""
    db_path = tmp_path / "gov.db"
    _write_clearance(db_path)
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)

    rc = main(["governance-read", "--db", _db_url(db_path), _SEI])
    assert rc == 0
    out, err = capsys.readouterr()
    assert not err, f"unexpected stderr: {err!r}"
    envelope = json.loads(out)
    assert envelope["status"] == "unavailable"
    assert envelope["sei"] == _SEI
    assert envelope["records"] == []
    reasons = envelope.get("unavailable", [])
    assert reasons and "reason" in reasons[0]
    assert "LEGIS_HMAC_KEY" in reasons[0]["reason"]


# --------------------------------------------------------------------------- #
# (c) CHAIN-tampered store: seq gap in non-protected records → exit nonzero   #
# CRITICAL: this test must be RED if verify_integrity() is omitted from the   #
# CLI helper. TrailVerifier.verify is a no-op on non-protected records;       #
# only verify_integrity() detects the seq contiguity gap.                     #
# --------------------------------------------------------------------------- #


def test_cli_governance_read_chain_tamper_exits_nonzero(tmp_path, monkeypatch, capsys):
    """Seq-gap (non-protected records, trigger-bypassed delete) → exit 1, 'audit integrity' in stderr.

    If verify_integrity() is omitted, the CLI would return exit 0 / {status:checked, records:[]}
    (false-green) because TrailVerifier.verify passes silently on non-protected records.
    """
    db_path = tmp_path / "gov.db"
    store = AuditStore(_db_url(db_path))
    # Plain (non-protected) records so TrailVerifier is a no-op on them.
    store.append({"event": "PLAIN_1"})
    store.append({"event": "PLAIN_2"})
    store.append({"event": "PLAIN_3"})

    # Bypass the append-only triggers and delete the middle record, creating
    # a seq gap (seq: 1, 3) that verify_integrity() detects.
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
        conn.execute("DELETE FROM audit_log WHERE seq = 2")
        conn.commit()
    finally:
        conn.close()

    monkeypatch.setenv("LEGIS_HMAC_KEY", _KEY_STR)

    rc = main(["governance-read", "--db", _db_url(db_path), _SEI])
    assert rc != 0
    out, err = capsys.readouterr()
    # Must report the integrity failure on stderr with "audit integrity"
    assert "audit integrity" in err.lower(), f"stderr was: {err!r}"
    # Must NOT print a false-green JSON envelope on stdout
    assert not out.strip() or "checked" not in out


# --------------------------------------------------------------------------- #
# (d) Signature-tampered protected store via key mismatch → exit nonzero      #
# --------------------------------------------------------------------------- #


def test_cli_governance_read_sig_tamper_exits_nonzero(tmp_path, monkeypatch, capsys):
    """Protected store signed with _KEY; CLI uses a different key.

    The SHA hash chain is consistent (verify_integrity passes); TrailVerifier with
    the wrong key detects the HMAC mismatch → AuditIntegrityError → exit 1.
    """
    db_path = tmp_path / "gov.db"
    _write_clearance(db_path)  # signed with _KEY = b"cli-governance-key"

    # Wrong key — signatures cannot verify
    monkeypatch.setenv("LEGIS_HMAC_KEY", "wrong-key-does-not-match")
    monkeypatch.setenv("LEGIS_PROTECTED_POLICIES", _POLICY)

    rc = main(["governance-read", "--db", _db_url(db_path), _SEI])
    assert rc != 0
    out, err = capsys.readouterr()
    # The AuditIntegrityError message is "Protected audit trail verification failed: …"
    assert "verification failed" in err.lower(), f"stderr was: {err!r}"


# --------------------------------------------------------------------------- #
# (e) Missing/relocated DB (with key set) → unavailable, NOT a false-green    #
# --------------------------------------------------------------------------- #


def test_cli_governance_read_missing_db_is_unavailable(tmp_path, monkeypatch, capsys):
    """Missing DB → {status:unavailable}, exit 0.

    Must NOT auto-create an empty DB and return {status:checked, records:[]}.
    LEGIS_HMAC_KEY must be set so the no-key early-return (case b) does not
    fire before the missing-DB check is reached.
    """
    nonexistent = tmp_path / "not_there.db"
    assert not nonexistent.exists()
    monkeypatch.setenv("LEGIS_HMAC_KEY", _KEY_STR)

    rc = main(["governance-read", "--db", _db_url(nonexistent), _SEI])
    assert rc == 0
    out, err = capsys.readouterr()
    assert not err, f"unexpected stderr: {err!r}"
    envelope = json.loads(out)
    assert envelope["status"] == "unavailable"
    assert envelope["sei"] == _SEI
    assert envelope["records"] == []
    reasons = envelope.get("unavailable", [])
    assert reasons and "governance store not found" in reasons[0]["reason"]
    # DB must not have been auto-created
    assert not nonexistent.exists()
