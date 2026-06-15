"""Store protocols consumed by governance core modules."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from typing import Any, Protocol


class AuditRecordLike(Protocol):
    @property
    def seq(self) -> int: ...

    @property
    def payload(self) -> dict[str, Any]: ...

    @property
    def content_hash(self) -> str: ...

    @property
    def prev_hash(self) -> str: ...


class AppendOnlyStore(Protocol):
    def append(self, payload: dict[str, Any]) -> int: ...

    def append_signed(
        self, build_payload: Callable[[int, str], dict[str, Any]]
    ) -> int:
        """Append a record that binds its own chain position into its signature.

        The builder is called with ``(seq, prev_hash)`` — the position this
        record will occupy — and returns the fully-signed payload, so a signer
        can fold ``seq`` into the v3 signed field set (AUD-1). Reserve, sign and
        insert run under one write lock; no read-then-insert race.
        """
        ...

    def read_all(self) -> Sequence[AuditRecordLike]: ...

    def read_by_seq(self, seq: int) -> AuditRecordLike | None: ...

    def verify_integrity(self) -> bool: ...

    def get_latest_sequence_and_hash(self) -> tuple[int, str]:
        """The current chain head as ``(seq, chain_hash)`` — ``(0, GENESIS)`` if
        empty. Used to advance an out-of-band head anchor after an append."""
        ...

    def in_batch(self) -> bool:
        """Whether a ``transaction()`` batch is currently held on this thread.

        Lets an anchor-advancing caller defer the (batch-forbidden) head read
        until the batch commits, rather than reading it per-append."""
        ...

    def transaction(self) -> AbstractContextManager[None]:
        """Group appends into one all-or-nothing transaction.

        Appends only. A read issued inside this context (``read_all``,
        ``read_by_seq``, ``verify_integrity``) is NOT guaranteed to observe
        uncommitted appends from the same batch — it sees a pre-batch snapshot
        — and on a single-connection backend (SQLite) may contend with the
        held write transaction. Resolve all reads before opening the batch. The
        SQLite implementation (``AuditStore``) *enforces* this: an in-batch read
        on the same thread raises ``RuntimeError`` instead of contending.
        """
        ...
