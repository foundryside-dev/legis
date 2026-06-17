"""Out-of-band head anchor — the tail-truncation half of the AUD-1 defence.

Binding ``seq`` into the per-record HMAC (v3) plus the contiguity check close
interior deletion and reordering: a deleted interior row leaves a seq gap, and
renumbering to hide it breaks the seq-bound signature. Neither can see a *tail*
truncation, though — lopping the last N records off leaves a chain that is
contiguous, internally consistent, and whose every surviving signature still
verifies, because the new head was legitimately the head at some earlier moment.

The only way to catch that is an out-of-band memory that the head used to be
higher. ``HeadAnchor`` is that memory: a small sidecar file, written next to the
DB, holding the last ``(head_seq, head_chain_hash)`` and HMAC-signed with the
same key as the records. The signature is load-bearing — without it an attacker
with file access would simply rewrite the anchor to match the truncated DB.

This is conceded-capability hardening (it assumes the file-write the core forgery
guarantee already excludes), so it is **opt-in**: a store is anchored only when a
deployment wires one. But once a store *is* anchored, a missing anchor fails
closed — an attacker must not be able to disarm the check by deleting the file.

Scope, stated honestly:
  * The anchor lags the DB by design — it is updated *after* the append commits,
    so a crash in between leaves it one record behind. That is the safe
    direction: the check only alarms when the DB head is *below* the anchor, so
    a lagging anchor yields false-negatives (never false alarms), and the next
    successful append re-advances it.
  * What it catches: forgery (no key → no valid anchor), and truncation/rollback
    by an attacker who does *not* hold a genuine earlier anchor — i.e. one who
    arrives after the head has grown, or who never retained an old copy. It
    reports that removal happened; it cannot reconstruct what was removed.
  * REPLAY LIMITATION (red-team, AUD-1): the signature stops forgery but not
    replay. The anchor is a single mutable file; *any* genuinely-signed earlier
    version of it is a valid "the head was once this low" statement. An attacker
    who is continuously present (or who snapshots the anchor file) can save the
    anchor while the head is low, let the trail grow, then truncate the DB back
    to that low head and restore the saved anchor — it verifies (real signature,
    consistent seq + chain_hash), so the rollback is undetected. This is
    inherent to local same-filesystem storage: there is nothing on disk the
    file-write attacker cannot also roll back, so no purely-local check (no
    counter, timestamp, or extra copy) closes it — a stale-but-genuine anchor is
    indistinguishable from a current one without external memory. Closing replay
    requires storing the anchor where the attacker cannot roll it back —
    append-only/WORM or remote storage — or an external monitor that tracks the
    anchored head's monotonicity (head_seq only ever rises). Point ``path`` at
    such storage for full rollback resistance; on a local sidecar the anchor
    still raises the bar (forgery- and late-attacker-truncation-resistant) but
    does not, and cannot, defeat a snapshotting attacker.
"""

from __future__ import annotations

import json
import os
from typing import Any

from legis.enforcement.signing import verify
from legis.enforcement.signing import sign as _sign

ANCHOR_VERSION = "v3"


class AnchorError(RuntimeError):
    """The DB head diverged from the out-of-band anchor — truncation or rollback."""


def _anchor_fields(head_seq: int, head_chain_hash: str) -> dict[str, Any]:
    return {"head_seq": head_seq, "head_chain_hash": head_chain_hash}


class HeadAnchor:
    def __init__(self, path: str, key: bytes) -> None:
        self._path = path
        self._key = key

    def update(self, head_seq: int, head_chain_hash: str) -> None:
        """Advance the anchor to a new committed head. Atomic (temp + replace).

        Call this *after* the append commits. ``:memory:`` / path-less stores can
        pass an empty path to make this a no-op (no file to anchor).
        """
        if not self._path:
            return
        fields = _anchor_fields(head_seq, head_chain_hash)
        body = {
            **fields,
            "anchor_signature": _sign(fields, self._key, version=ANCHOR_VERSION),
        }
        tmp = f"{self._path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(body, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._path)

    def check(self, records: list) -> None:
        """Raise ``AnchorError`` if *records* fall short of the anchored head.

        *records* is the store's full ``read_all()`` (already chain-verified by
        the caller). The anchor file MUST exist and MUST carry a valid signature;
        a missing or forged anchor on an anchored store is itself a tamper signal.
        """
        if not self._path:
            return
        try:
            with open(self._path, encoding="utf-8") as fh:
                body = json.load(fh)
        except FileNotFoundError as exc:
            raise AnchorError(
                f"head anchor {self._path} is missing — an anchored trail cannot "
                "be verified without it (possible truncation + anchor deletion)"
            ) from exc
        except (json.JSONDecodeError, ValueError) as exc:
            raise AnchorError(f"head anchor {self._path} is unreadable: {exc}") from exc

        sig = body.get("anchor_signature")
        anchored_seq = body.get("head_seq")
        anchored_chain = body.get("head_chain_hash")
        if not sig or anchored_seq is None or anchored_chain is None:
            raise AnchorError(f"head anchor {self._path} is structurally malformed")
        if not verify(_anchor_fields(anchored_seq, anchored_chain), sig, self._key):
            raise AnchorError(f"head anchor {self._path} signature does not verify")

        db_head_seq = records[-1].seq if records else 0
        if db_head_seq < anchored_seq:
            raise AnchorError(
                f"audit trail head seq={db_head_seq} is below the anchored head "
                f"seq={anchored_seq} — records were truncated out of band"
            )
        # The anchored chain_hash must still appear at the anchored seq. This
        # transitively validates the whole prefix: a re-appended forgery up to
        # the same seq would land a different chain_hash here (the attacker
        # cannot reproduce the keyed content signatures of the originals).
        at_anchor = next((r for r in records if r.seq == anchored_seq), None)
        if at_anchor is None:
            raise AnchorError(
                f"audit trail is missing seq={anchored_seq} recorded by the anchor"
            )
        if at_anchor.chain_hash != anchored_chain:
            raise AnchorError(
                f"audit trail chain_hash at seq={anchored_seq} diverges from the "
                "anchored value — the trail was rewritten out of band"
            )
