import logging
import sqlite3

import pytest

from legis.store.audit_store import (
    GENESIS,
    AuditStore,
    _apply_sqlite_pragmas,
    _chain,
)


def db_path(tmp_path):
    return tmp_path / "audit.db"


def make_store(tmp_path):
    return AuditStore(f"sqlite:///{db_path(tmp_path)}")


def raw_conn(tmp_path):
    return sqlite3.connect(db_path(tmp_path))


def test_append_returns_monotonic_seq(tmp_path):
    s = make_store(tmp_path)
    assert s.append({"k": "a"}) == 1
    assert s.append({"k": "b"}) == 2


def test_read_all_is_ordered_and_decodes_payload(tmp_path):
    s = make_store(tmp_path)
    s.append({"k": "a"})
    s.append({"k": "b"})
    recs = s.read_all()
    assert [r.seq for r in recs] == [1, 2]
    assert recs[0].payload == {"k": "a"}


def test_store_exposes_no_mutation_api(tmp_path):
    s = make_store(tmp_path)
    assert not hasattr(s, "update")
    assert not hasattr(s, "delete")


def test_trigger_rejects_update(tmp_path):
    s = make_store(tmp_path)
    s.append({"k": "a"})
    conn = raw_conn(tmp_path)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE audit_log SET payload = '{}' WHERE seq = 1")
            conn.commit()
    finally:
        conn.close()


def test_trigger_rejects_delete(tmp_path):
    s = make_store(tmp_path)
    s.append({"k": "a"})
    conn = raw_conn(tmp_path)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM audit_log WHERE seq = 1")
            conn.commit()
    finally:
        conn.close()


def test_verify_integrity_passes_on_clean_chain(tmp_path):
    s = make_store(tmp_path)
    s.append({"k": "a"})
    s.append({"k": "b"})
    assert s.verify_integrity() is True


def test_verify_integrity_detects_out_of_band_tamper(tmp_path, caplog):
    s = make_store(tmp_path)
    s.append({"k": "a"})
    s.append({"k": "b"})
    # Tamper directly, bypassing the app API and the append-only triggers:
    conn = raw_conn(tmp_path)
    try:
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute(
            "UPDATE audit_log SET payload = :p WHERE seq = 1",
            {"p": '{"k":"EVIL"}'},
        )
        conn.commit()
    finally:
        conn.close()
    with caplog.at_level(logging.ERROR, logger="legis.store.audit_store"):
        assert s.verify_integrity() is False
    # An investigator needs the offending seq, not a bare False.
    assert "integrity check failed at seq=1" in caplog.text


def test_verify_integrity_handles_malformed_json_as_integrity_failure(tmp_path, caplog):
    s = make_store(tmp_path)
    s.append({"k": "a"})
    conn = raw_conn(tmp_path)
    try:
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute(
            "UPDATE audit_log SET payload = :p WHERE seq = 1",
            {"p": "{not-json"},
        )
        conn.commit()
    finally:
        conn.close()

    with caplog.at_level(logging.ERROR, logger="legis.store.audit_store"):
        assert s.verify_integrity() is False
    assert "integrity check failed" in caplog.text


def test_audit_store_concurrent_writes(tmp_path):
    import threading
    s = make_store(tmp_path)

    errors = []
    def run_appends(tid, count):
        try:
            for i in range(count):
                s.append({"thread": tid, "idx": i})
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=run_appends, args=(t, 20)) for t in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors, f"Concurrent appends failed with errors: {errors}"
    recs = s.read_all()
    assert len(recs) == 100
    assert s.verify_integrity() is True


def test_pragma_wal_actually_applied_on_file(tmp_path):
    # The connect listener must put the on-disk DB into WAL mode. journal_mode is
    # a persistent file-header property, so an *external* connection that never
    # ran our listener still observes it — proof WAL truly applied to the file.
    make_store(tmp_path)
    conn = raw_conn(tmp_path)
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()
    assert mode.lower() == "wal"


def test_pragma_synchronous_is_full_for_durability(tmp_path):
    # AUD-3: an audit-integrity store must not lose committed appends on a
    # power-cut. Under WAL, synchronous=NORMAL only fsyncs the WAL at a
    # checkpoint, so committed-but-unsynced records vanish on power loss,
    # leaving a consistent, contiguous, valid-looking SHORTENED trail. FULL (2)
    # fsyncs every commit, so a committed governance record is durable. (0=OFF,
    # 1=NORMAL, 2=FULL, 3=EXTRA.) Read on a connection that went through the
    # listener — synchronous is per-connection, not a persistent file property.
    s = make_store(tmp_path)
    with s._engine.connect() as conn:
        level = conn.exec_driver_sql("PRAGMA synchronous").scalar()
    assert level == 2  # FULL


def test_pragma_busy_timeout_set_on_listener_connection(tmp_path):
    # busy_timeout is per-connection (not persistent), so it must be read on a
    # connection that went through the listener — i.e. one from the store engine.
    s = make_store(tmp_path)
    with s._engine.connect() as conn:
        timeout = conn.exec_driver_sql("PRAGMA busy_timeout").scalar()
    assert timeout == 5000


class _FakeCursor:
    def __init__(self, journal_mode):
        self._journal_mode = journal_mode
        self.closed = False

    def execute(self, _sql):
        return self

    def fetchone(self):
        return (self._journal_mode,)

    def close(self):
        self.closed = True


class _FakeConn:
    def __init__(self, journal_mode):
        self.cursor_obj = _FakeCursor(journal_mode)

    def cursor(self):
        return self.cursor_obj


class _RaisingCursor:
    def __init__(self):
        self.closed = False

    def execute(self, _sql):
        raise sqlite3.OperationalError("PRAGMA rejected")

    def close(self):
        self.closed = True


class _RaisingConn:
    def __init__(self):
        self.cursor_obj = _RaisingCursor()

    def cursor(self):
        return self.cursor_obj


def test_apply_pragmas_warns_when_wal_not_applied(caplog):
    # The silent failure the bare `except` never caught: PRAGMA journal_mode=WAL
    # does NOT raise when WAL is unavailable — it returns the mode actually in
    # force (e.g. 'delete'/'memory'). That must surface as a warning.
    conn = _FakeConn("delete")
    with caplog.at_level(logging.WARNING, logger="legis.store.audit_store"):
        _apply_sqlite_pragmas(conn, "sqlite:///some.db")
    assert any(
        "wal" in r.getMessage().lower() for r in caplog.records
    ), f"expected a WAL-not-applied warning; got {[r.getMessage() for r in caplog.records]}"
    assert conn.cursor_obj.closed is True


def test_apply_pragmas_warns_with_exc_info_on_pragma_exception(caplog):
    # A PRAGMA that genuinely raises must be logged (with exc_info), not swallowed,
    # and the connection setup must still complete (cursor closed, no re-raise).
    conn = _RaisingConn()
    with caplog.at_level(logging.WARNING, logger="legis.store.audit_store"):
        _apply_sqlite_pragmas(conn, "sqlite:///some.db")
    assert caplog.records, "expected a warning when PRAGMA application raises"
    rec = caplog.records[-1]
    assert rec.levelno >= logging.WARNING
    assert rec.exc_info is not None
    assert conn.cursor_obj.closed is True


def test_verify_integrity_detects_interior_delete_with_gap(tmp_path, caplog):
    # AUD-1: an attacker with file-write access deletes an interior record and
    # re-chains the survivors. The plain SHA chain is recomputable without the
    # HMAC key, so every surviving *link* stays internally consistent — the
    # old chain walk passed. But the seq column now skips the deleted row, and
    # that gap is the structural tell a contiguity check catches.
    s = make_store(tmp_path)
    s.append({"k": "a"})
    s.append({"k": "b"})
    s.append({"k": "c"})
    conn = raw_conn(tmp_path)
    try:
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute("DROP TRIGGER audit_log_no_delete")
        conn.execute("DELETE FROM audit_log WHERE seq = 2")
        # Re-chain the survivors (seq 1, 3) so the link walk stays consistent.
        rows = conn.execute(
            "SELECT seq, content_hash FROM audit_log ORDER BY seq ASC"
        ).fetchall()
        prev = GENESIS
        for seq, c in rows:
            ch = _chain(prev, c)
            conn.execute(
                "UPDATE audit_log SET prev_hash=?, chain_hash=? WHERE seq=?",
                (prev, ch, seq),
            )
            prev = ch
        conn.commit()
    finally:
        conn.close()
    with caplog.at_level(logging.ERROR, logger="legis.store.audit_store"):
        assert s.verify_integrity() is False
    assert "seq=3" in caplog.text


def test_verify_integrity_handles_non_finite_float_as_integrity_failure(tmp_path):
    # json.loads accepts Infinity/NaN, so the payload survives read_all's
    # decode guard, but content_hash -> canonical_json(allow_nan=False) raises
    # ValueError. verify_integrity must report tamper as False, not crash
    # (Q-M3 / audit M6).
    s = make_store(tmp_path)
    s.append({"k": "a"})
    conn = raw_conn(tmp_path)
    try:
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute(
            "UPDATE audit_log SET payload = :p WHERE seq = 1",
            {"p": '{"k": Infinity}'},
        )
        conn.commit()
    finally:
        conn.close()

    assert s.verify_integrity() is False
