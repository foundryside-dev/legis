"""Phase 1 / Task 1.2 — PostureLedger edge behaviors.

Pins the genuinely-reachable branches the happy-path ledger tests don't hit:
the SQLite-URL path parser, missing-file detection on an absolute URL, and the
Phase 3.2 / Phase 11 method signatures that are stubbed in Phase 1.
"""

from __future__ import annotations

from legis.posture.ledger import PostureLedger, _sqlite_file


def test_sqlite_file_relative_form():
    # sqlite:///relative/x.db -> a relative path (resolved against cwd).
    p = _sqlite_file("sqlite:///relative/x.db")
    assert p is not None
    assert not p.is_absolute()
    assert p.as_posix() == "relative/x.db"


def test_sqlite_file_absolute_form():
    # sqlite:////abs/x.db -> the leading-slash absolute path is preserved.
    p = _sqlite_file("sqlite:////tmp/abs/x.db")
    assert p is not None
    assert p.is_absolute()
    assert p.as_posix() == "/tmp/abs/x.db"


def test_sqlite_file_non_sqlite_url_is_none():
    assert _sqlite_file("postgresql://localhost/x") is None


def test_read_floor_absent_absolute_file_is_none(tmp_path):
    # Absolute URL whose backing file does not exist -> None (fail-closed).
    url = f"sqlite:////{tmp_path.as_posix().lstrip('/')}/missing.db"
    ledger = PostureLedger(url, initialize=False)
    assert ledger.read_floor() is None


def test_read_floor_empty_initialized_store_is_none(tmp_path):
    # File exists (initialize=True created it) but no records -> None, not chill.
    ledger = PostureLedger(f"sqlite:///{tmp_path}/posture.db", initialize=True)
    assert ledger.read_floor() is None


# -- unprovisioned ledger: a file with no audit_log table ---------------------
# Production reads open the ledger initialize=False (mcp.py: build_runtime), so a
# pre-posture / unprovisioned DB has NO audit_log table. Such a read must degrade
# to the same fail-closed "no ledger" state (None / False) as a missing file, not
# crash with OperationalError("no such table: audit_log"). (dogfood: legis-5fd3b257c3)


def test_read_floor_empty_file_no_table_is_none(tmp_path):
    # A 0-byte / no-table DB opened initialize=False must read as None, not raise.
    db = tmp_path / "empty-posture.db"
    db.touch()
    ledger = PostureLedger(f"sqlite:///{db}", initialize=False)
    assert ledger.read_floor() is None


def test_epoch_reset_unacknowledged_no_table_is_false(tmp_path):
    # epoch_reset_unacknowledged() reads via read_all() with no existence guard;
    # an unprovisioned (empty-file) ledger must report False, not raise.
    db = tmp_path / "empty-posture.db"
    db.touch()
    ledger = PostureLedger(f"sqlite:///{db}", initialize=False)
    assert ledger.epoch_reset_unacknowledged() is False


def test_epoch_reset_unacknowledged_missing_file_is_false(tmp_path):
    # Missing file (no path.exists guard inside read_all) must also degrade.
    url = f"sqlite:////{tmp_path.as_posix().lstrip('/')}/missing.db"
    ledger = PostureLedger(url, initialize=False)
    assert ledger.epoch_reset_unacknowledged() is False


def test_current_epoch_fingerprint_no_table_is_none(tmp_path):
    # The change-gate epoch read must also tolerate an unprovisioned ledger.
    db = tmp_path / "empty-posture.db"
    db.touch()
    ledger = PostureLedger(f"sqlite:///{db}", initialize=False)
    assert ledger.current_epoch_fingerprint() is None


def test_session_opened_implemented_in_phase3(tmp_path):
    # Phase 3.2 supersedes the Phase 1 stub: session_opened now appends a
    # keyless OPERATOR_SESSION_OPENED record (full coverage in test_session.py).
    ledger = PostureLedger(f"sqlite:///{tmp_path}/posture.db", initialize=True)
    ledger.session_opened(
        operator_id="alice",
        enabled_at="2026-06-16T14:02:00Z",
        ttl=300,
        keychain_auth_ref=None,
        session_id="sess-1",
    )
    assert ledger.store.read_all()[-1].payload["kind"] == "OPERATOR_SESSION_OPENED"


def test_rekey_implemented_in_phase11(tmp_path):
    # Phase 11 supersedes the Phase 1 stub: rekey() mints a fresh epoch, keeps
    # the standing floor, and chains a keyless KEY_RESET onto preserved history
    # (full coverage in test_rekey.py).
    ledger = PostureLedger(f"sqlite:///{tmp_path}/posture.db", initialize=True)
    ledger.genesis(
        key_fingerprint="ab" * 32, agent_id="installer", recorded_at="t0"
    )
    handed: list[tuple[str, str]] = []
    new_fp = ledger.rekey(
        agent_id="op",
        recorded_at="t1",
        key_sink=lambda key_hex, backend: handed.append((key_hex, backend)),
        backend="age-file",
    )
    assert ledger.read_floor() == "chill"
    assert ledger.store.read_all()[-1].payload["kind"] == "KEY_RESET"
    assert new_fp == ledger.current_epoch_fingerprint() != "ab" * 32
    assert len(handed) == 1
