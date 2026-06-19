"""Append-only audit store.

Record-agnostic: persists opaque dict payloads as canonical JSON in an ordered,
hash-chained, append-only table. It knows nothing about override records or any
other schema layered on top (those serialize to dict and hand bytes here).

Two integrity layers, complementary:
  * **Triggers** reject UPDATE/DELETE at the DB level — mutation is *rejected,
    not discouraged*, and there is no mutation method on this class.
  * **Hash chain** lets ``verify_integrity`` detect any out-of-band edit or
    reordering that bypasses the triggers (e.g. direct file tampering). This is
    the seed of the protected cell's tamper-evidence story (Sprint 3).
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    Table,
    Text,
    create_engine,
    insert,
    inspect,
    select,
    text,
)
from sqlalchemy.pool import NullPool

from legis.canonical import canonical_json, content_hash

logger = logging.getLogger(__name__)

GENESIS = "0" * 64

# A signer that, given the chain position a record will occupy (seq, prev_hash),
# returns the fully-built, signed payload. Used by ``append_signed`` to bind seq
# into the v3 HMAC (AUD-1).
BuildSignedPayload = Callable[[int, str], dict[str, Any]]


def _apply_sqlite_pragmas(dbapi_connection: Any, url: str) -> None:
    """Apply the durability/concurrency PRAGMAs to a freshly-opened connection.

    Best-effort: a PRAGMA failure must not break connection setup (the store is
    still usable without WAL), but it must NOT vanish silently either. Two
    distinct failure channels are surfaced:

    * An exception while issuing a PRAGMA → logged with ``exc_info``.
    * WAL silently not taking effect → ``PRAGMA journal_mode=WAL`` does *not*
      raise when WAL is unavailable (read-only mount, some network filesystems,
      in-memory DBs); it returns the journal mode actually in force. The old
      ``except Exception: pass`` never caught this most-likely case, so the
      connection ran without WAL and the symptom surfaced much later as an
      opaque "database is locked" under concurrency. Detect and log it here.

    Durability is ``synchronous=FULL``, NOT the throughput-favouring ``NORMAL``
    (AUD-3). Under WAL, ``NORMAL`` fsyncs the WAL only at a checkpoint, so a
    committed-but-not-yet-checkpointed append is lost on a power-cut — and the
    survivors form a consistent, contiguous, fully-signed chain, i.e. a
    valid-looking *shortened* trail indistinguishable from "nothing more was
    written". For an audit-integrity store that silent tail-loss is the harm,
    so each commit is fsynced (``FULL``); throughput is the right thing to
    trade. This is the prevention half; AUD-1's out-of-band head anchor is the
    detection half (it flags a trail that shrank below its recorded head). The
    floor is intentionally not configurable — an audit store's durability must
    not be lowerable back to the bug.
    """
    cursor = dbapi_connection.cursor()
    try:
        journal_row = cursor.execute("PRAGMA journal_mode=WAL").fetchone()
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.execute("PRAGMA busy_timeout=5000")
        journal_mode = journal_row[0] if journal_row else None
        if journal_mode is not None and str(journal_mode).lower() != "wal":
            logger.warning(
                "audit store SQLite did not enter WAL mode (journal_mode=%r, "
                "url=%s); concurrent appends may surface as opaque 'database is "
                "locked' errors instead of waiting",
                journal_mode,
                url,
            )
    except Exception:  # noqa: BLE001  (PRAGMA failure must not break connect)
        logger.warning(
            "audit store failed to apply SQLite PRAGMAs (url=%s); connection "
            "falls back to defaults (no WAL / default busy_timeout)",
            url,
            exc_info=True,
        )
    finally:
        cursor.close()


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    payload: dict[str, Any]
    content_hash: str
    prev_hash: str
    chain_hash: str


def _chain(prev_hash: str, c_hash: str) -> str:
    return hashlib.sha256((prev_hash + c_hash).encode("utf-8")).hexdigest()


class AuditStore:
    def __init__(
        self,
        url: str,
        *,
        initialize: bool = True,
        apply_pragmas: bool = True,
    ) -> None:
        # The federated store subtree (.weft/legis) is created lazily, here at
        # open time — SQLite makes the .db file but never its parent directory.
        from legis.config import ensure_sqlite_parent

        if initialize:
            ensure_sqlite_parent(url)
        # NullPool: hold no connection between operations — an append-only
        # audit store wants no lingering locks and clean resource lifecycle.
        self._engine = create_engine(url, future=True, poolclass=NullPool)
        # Ambient connection for an in-progress multi-append transaction. Stored
        # thread-locally so a batch on one thread never leaks its open
        # connection into another thread's append (Q-M5). When unset, append()
        # opens its own per-call transaction as before.
        self._txn = threading.local()

        from sqlalchemy import event
        if apply_pragmas:
            @event.listens_for(self._engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                if "sqlite" in url:
                    _apply_sqlite_pragmas(dbapi_connection, url)

        self._md = MetaData()
        self._log = Table(
            "audit_log",
            self._md,
            Column("seq", Integer, primary_key=True, autoincrement=True),
            Column("payload", Text, nullable=False),
            Column("content_hash", Text, nullable=False),
            Column("prev_hash", Text, nullable=False),
            Column("chain_hash", Text, nullable=False),
        )
        if initialize:
            self._md.create_all(self._engine)
            self._install_append_only_triggers()

    def _install_append_only_triggers(self) -> None:
        if self._engine.dialect.name == "sqlite":
            with self._engine.begin() as conn:
                conn.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS audit_log_no_update "
                        "BEFORE UPDATE ON audit_log BEGIN "
                        "SELECT RAISE(ABORT, 'audit_log is append-only'); END;"
                    )
                )
                conn.execute(
                    text(
                        "CREATE TRIGGER IF NOT EXISTS audit_log_no_delete "
                        "BEFORE DELETE ON audit_log BEGIN "
                        "SELECT RAISE(ABORT, 'audit_log is append-only'); END;"
                    )
                )

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Group appends into one all-or-nothing transaction (Q-M5).

        Every ``append`` issued inside this context shares a single connection
        and commits together on clean exit; any exception rolls back the whole
        batch, so a mid-loop failure cannot leave earlier appends persisted.
        Re-entrancy and cross-thread bleed are avoided by stashing the ambient
        connection thread-locally; nested ``transaction()`` calls reuse the
        outer one.

        Appends only, and now *enforced*: ``read_all`` / ``read_by_seq`` /
        ``verify_integrity`` / ``get_latest_sequence_and_hash`` open their own
        connection via ``self._engine.begin()``, so a read issued inside this
        context would not see the batch's uncommitted appends and on SQLite would
        hit ``SQLITE_BUSY`` against the held ``BEGIN IMMEDIATE`` write lock. Each
        guards on the thread-local and raises ``RuntimeError`` rather than
        contending silently (``_assert_no_batch_in_progress``). Do all reads
        before entering the context (as ``wardline.governor`` does: it resolves
        every entity before opening the batch). Only ``append``'s own chain-head
        read is safe here, because it runs on the ambient connection.
        """
        if getattr(self._txn, "conn", None) is not None:
            # Already inside a batch on this thread — reuse it (nested no-op).
            yield
            return
        with self._engine.begin() as conn:
            if conn.dialect.name == "sqlite":
                conn.execute(text("BEGIN IMMEDIATE"))
            self._txn.conn = conn
            try:
                yield
            finally:
                self._txn.conn = None

    def in_batch(self) -> bool:
        """Whether a ``transaction()`` batch is held on this thread's connection.

        Lets a caller skip a fresh-connection read (forbidden mid-batch, see
        ``_assert_no_batch_in_progress``) and defer it until the batch commits —
        e.g. a head-anchor advance that must run after the lock is released."""
        return getattr(self._txn, "conn", None) is not None

    def _assert_no_batch_in_progress(self, method: str) -> None:
        """Fail loudly if a fresh-connection read runs inside a held batch (Q-M5).

        ``transaction()`` holds a ``BEGIN IMMEDIATE`` write lock on the ambient
        thread-local connection. Every public read opens its OWN connection, so
        a read issued while the batch is held would (a) contend with that lock
        (``SQLITE_BUSY`` on SQLite, and possibly no error on other backends) and
        (b) miss the batch's uncommitted appends. The original contract relied on
        callers never doing this; this guard *enforces* it, turning a silent,
        backend-dependent contention into an explicit, deterministic error so a
        future in-batch read in a gate append path fails its tests immediately.
        """
        if getattr(self._txn, "conn", None) is not None:
            raise RuntimeError(
                f"AuditStore.{method}() called inside an active transaction() batch "
                "on this thread. Fresh-connection reads contend with the batch's "
                "held BEGIN IMMEDIATE write lock and cannot see its uncommitted "
                "appends — resolve all reads before opening the batch (Q-M5)."
            )

    def _head(self, conn: Any) -> tuple[int, str]:
        """The current chain head as (last_seq, prev_hash) under the open conn.

        Read once and reused by both insert paths so the seq a signer binds
        (AUD-1 / v3) is exactly the seq the row receives.
        """
        row = conn.execute(
            select(self._log.c.seq, self._log.c.chain_hash)
            .order_by(self._log.c.seq.desc())
            .limit(1)
        ).first()
        if row is None:
            return 0, GENESIS
        return row.seq, row.chain_hash

    def _write(self, conn: Any, seq: int, payload: dict[str, Any], prev_hash: str) -> int:
        c_hash = content_hash(payload)
        conn.execute(
            insert(self._log).values(
                seq=seq,
                payload=canonical_json(payload),
                content_hash=c_hash,
                prev_hash=prev_hash,
                chain_hash=_chain(prev_hash, c_hash),
            )
        )
        return seq

    def _insert(self, conn: Any, payload: dict[str, Any]) -> int:
        last_seq, prev_hash = self._head(conn)
        return self._write(conn, last_seq + 1, payload, prev_hash)

    def _insert_signed(
        self, conn: Any, build_payload: BuildSignedPayload
    ) -> int:
        # AUD-1: hand the signer its own chain position so it can bind seq into
        # the HMAC (v3). seq is the explicit max+1 computed here under the held
        # write lock — never autoincrement — so the value the signer commits to
        # is provably the value the row gets, with no read-then-insert race.
        last_seq, prev_hash = self._head(conn)
        seq = last_seq + 1
        payload = build_payload(seq, prev_hash)
        return self._write(conn, seq, payload, prev_hash)

    def append(self, payload: dict[str, Any]) -> int:
        ambient = getattr(self._txn, "conn", None)
        if ambient is not None:
            # Inside a transaction(): read-your-writes on the shared connection
            # keeps the hash chain valid mid-batch; the context owns commit.
            return self._insert(ambient, payload)
        with self._engine.begin() as conn:
            if conn.dialect.name == "sqlite":
                conn.execute(text("BEGIN IMMEDIATE"))
            return self._insert(conn, payload)

    def append_signed(self, build_payload: BuildSignedPayload) -> int:
        """Append a record that binds its own chain position into its signature.

        ``build_payload(seq, prev_hash)`` is called with the position this record
        will occupy and must return the fully-built, signed payload (the gate
        folds ``seq`` into the v3 signed field set). The whole reserve-sign-insert
        runs under one ``BEGIN IMMEDIATE`` lock, so a concurrent append cannot
        steal the seq the signer committed to.
        """
        ambient = getattr(self._txn, "conn", None)
        if ambient is not None:
            return self._insert_signed(ambient, build_payload)
        with self._engine.begin() as conn:
            if conn.dialect.name == "sqlite":
                conn.execute(text("BEGIN IMMEDIATE"))
            return self._insert_signed(conn, build_payload)

    def _has_log_table(self, conn) -> bool:
        """True iff the ``audit_log`` table exists on this connection.

        An ``initialize=False`` handle opened against an unprovisioned DB (a
        missing or empty/no-table file) has no table; reads then treat the store
        as empty rather than raising ``OperationalError("no such table")``
        (fail-closed: callers map an empty store to their safe default). DDL only
        ever runs under ``initialize=True``, so a read can never create it.
        """
        return inspect(conn).has_table("audit_log")

    def read_all(self) -> list[AuditRecord]:
        self._assert_no_batch_in_progress("read_all")
        with self._engine.begin() as conn:
            if not self._has_log_table(conn):
                return []
            rows = conn.execute(
                select(self._log).order_by(self._log.c.seq.asc())
            ).all()
        return [
            AuditRecord(
                seq=r.seq,
                payload=json.loads(r.payload),
                content_hash=r.content_hash,
                prev_hash=r.prev_hash,
                chain_hash=r.chain_hash,
            )
            for r in rows
        ]

    def read_by_seq(self, seq: int) -> AuditRecord | None:
        self._assert_no_batch_in_progress("read_by_seq")
        with self._engine.begin() as conn:
            if not self._has_log_table(conn):
                return None
            row = conn.execute(
                select(self._log).where(self._log.c.seq == seq)
            ).first()
        if row is None:
            return None
        return AuditRecord(
            seq=row.seq,
            payload=json.loads(row.payload),
            content_hash=row.content_hash,
            prev_hash=row.prev_hash,
            chain_hash=row.chain_hash,
        )

    def verify_integrity(self) -> bool:
        # O(N) by design: a full chain re-hash is the only way to detect
        # out-of-band tampering of an arbitrary record (the hash chain gives O(1)
        # verification of *appends*, never of a mutated prefix). Callers on
        # interactive read paths (service.verified_records) pay this deliberately;
        # see that function's cost note (rc4 review #7) for why it is not narrowed.
        self._assert_no_batch_in_progress("verify_integrity")
        prev_hash = GENESIS
        expected_seq = 1
        try:
            records = self.read_all()
        except (json.JSONDecodeError, TypeError, ValueError):
            # No seq survives a decode failure of the whole read; name the
            # failure mode so an investigator knows the trail is unreadable
            # rather than merely mismatched.
            logger.error(
                "audit trail integrity check failed: a record payload did not "
                "decode as JSON",
                exc_info=True,
            )
            return False
        for rec in records:
            # Contiguity (AUD-1): the chain walk below only verifies that each
            # *link* points at its predecessor's hash, which an attacker with
            # file access can recompute (the chain is plain SHA, keyless). What
            # they cannot hide is the seq column skipping a deleted row. seq is
            # assigned strictly contiguously at append (1..N, no gaps — appends
            # never reuse or skip), so any gap or reorder is out-of-band
            # deletion. This is the always-on half of the delete-and-rechain
            # defence; binding seq into the per-record HMAC (v3) is the other.
            if rec.seq != expected_seq:
                logger.error(
                    "audit trail integrity check failed at seq=%s: non-contiguous "
                    "sequence (expected seq=%s) — a record was deleted or reordered "
                    "out of band",
                    rec.seq,
                    expected_seq,
                )
                return False
            expected_seq += 1
            # json.loads accepts Infinity/NaN, so a directly-tampered payload
            # survives read_all's decode but makes canonical_json(allow_nan=
            # False) raise out of content_hash. Treat that as tamper, not a
            # crash (Q-M3 / audit M6).
            try:
                computed = content_hash(rec.payload)
            except (ValueError, TypeError):
                logger.error(
                    "audit trail integrity check failed at seq=%s: payload is "
                    "not canonicalizable (tamper)",
                    rec.seq,
                    exc_info=True,
                )
                return False
            if computed != rec.content_hash:
                logger.error(
                    "audit trail integrity check failed at seq=%s: content hash "
                    "mismatch (recorded %s, recomputed %s)",
                    rec.seq,
                    rec.content_hash,
                    computed,
                )
                return False
            if rec.prev_hash != prev_hash:
                logger.error(
                    "audit trail integrity check failed at seq=%s: broken chain "
                    "link (prev_hash %s != expected %s)",
                    rec.seq,
                    rec.prev_hash,
                    prev_hash,
                )
                return False
            if rec.chain_hash != _chain(rec.prev_hash, rec.content_hash):
                logger.error(
                    "audit trail integrity check failed at seq=%s: chain hash "
                    "does not match prev+content",
                    rec.seq,
                )
                return False
            prev_hash = rec.chain_hash
        return True

    def get_latest_sequence_and_hash(self) -> tuple[int, str]:
        self._assert_no_batch_in_progress("get_latest_sequence_and_hash")
        with self._engine.begin() as conn:
            if not self._has_log_table(conn):
                return 0, GENESIS
            row = conn.execute(
                select(self._log.c.seq, self._log.c.chain_hash)
                .order_by(self._log.c.seq.desc())
                .limit(1)
            ).first()
        if row is None:
            return 0, GENESIS
        return row.seq, row.chain_hash
