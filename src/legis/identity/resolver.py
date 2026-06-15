"""Resolve a locator to an SEI-keyed (or honestly-degraded) EntityKey.

This is the WP-5.1 swap point: governance records key on SEI when Loomweave proves
a stable, alive identity, and on the locator (``identity_stable=False``) in every
other case — capability absent, no client, locator not alive, or transport error.
The resolver never parses an SEI and never guesses. It also captures the REQ-L-01
append-only lineage snapshot at the moment of the governance decision.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from legis.canonical import content_hash
from legis.identity.loomweave_client import LoomweaveIdentity
from legis.identity.entity_key import EntityKey

logger = logging.getLogger(__name__)

# A long-lived resolver re-probes the Loomweave sei capability at most once per
# this window. Without it a positive latch is permanent: a Loomweave that loses
# the capability mid-life would be trusted forever (Q-L6).
_DEFAULT_CAPABILITY_TTL_SECONDS = 300.0


class IdentityResolutionStatus(str, Enum):
    """The identity axis verdict (str,Enum — serializes as the bare string).

    ``INVALID`` is produced only by the SEI backfill path (it keys raw dicts,
    not :class:`IdentityResolution`); the resolver itself emits only the other
    three.
    """

    RESOLVED = "resolved"
    NOT_ALIVE = "not_alive"
    UNAVAILABLE = "unavailable"
    INVALID = "invalid"


class LineageSnapshotStatus(str, Enum):
    """The REQ-L-01 lineage-snapshot verdict (str,Enum — bare-string wire)."""

    VERIFIED = "verified"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class IdentityResolution:
    entity_key: EntityKey
    alive: bool | None          # identity axis; None when no capability/decision
    content_hash: str | None    # content axis; None when unavailable
    lineage_snapshot: dict[str, Any] | None  # {"length": N, "hash": ...} or None
    identity_resolution_status: IdentityResolutionStatus
    lineage_snapshot_status: LineageSnapshotStatus

    def __post_init__(self) -> None:
        # The identity axis and its status are two views of one fact — keep them
        # from contradicting each other at construction. A "resolved" record with
        # alive=False (or any other crossed pair) was representable before this
        # guard; the invariant lived only in the construction sites. The bijection
        # is exactly the three shapes the resolver actually builds.
        #
        # ``alive`` must be exactly None/False/True by identity: a bare ``in`` /
        # dict lookup would alias ints (1 == True, 0 == False) and a non-bool
        # would surface as a KeyError, not this guard's ValueError.
        if not any(self.alive is v for v in (None, False, True)):
            raise ValueError(
                f"IdentityResolution.alive must be None/False/True, got {self.alive!r}"
            )
        expected = {
            None: IdentityResolutionStatus.UNAVAILABLE,
            False: IdentityResolutionStatus.NOT_ALIVE,
            True: IdentityResolutionStatus.RESOLVED,
        }[self.alive]
        if self.identity_resolution_status is not expected:
            raise ValueError(
                f"contradictory IdentityResolution: alive={self.alive!r} "
                f"requires identity_resolution_status="
                f"{expected.value!r}, got {self.identity_resolution_status.value!r}"
            )
        # The lineage axis is the record's other half: a snapshot is present iff
        # the status is VERIFIED (the resolver pairs them so — VERIFIED carries a
        # snapshot; UNAVAILABLE/NOT_APPLICABLE carry None). Keep that pairing from
        # contradicting itself too, so the whole record — not just the identity
        # axis — is impossible to construct in a self-contradictory state.
        snapshot_present = self.lineage_snapshot is not None
        verified = self.lineage_snapshot_status is LineageSnapshotStatus.VERIFIED
        if snapshot_present != verified:
            raise ValueError(
                f"contradictory IdentityResolution: lineage_snapshot "
                f"{'present' if snapshot_present else 'absent'} requires "
                f"lineage_snapshot_status"
                f"{'==' if snapshot_present else '!='} VERIFIED, got "
                f"{self.lineage_snapshot_status.value!r}"
            )


class IdentityResolver:
    def __init__(
        self,
        client: LoomweaveIdentity | None,
        *,
        capability_ttl: float = _DEFAULT_CAPABILITY_TTL_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._capable: bool | None = None  # cached probe result; None = unknown
        self._capable_checked_at: float | None = None
        self._capability_ttl = capability_ttl
        self._monotonic = monotonic

    @property
    def client(self) -> LoomweaveIdentity | None:
        """The underlying read client (None when legis runs standalone)."""
        return self._client

    def _capability(self) -> bool:
        if self._client is None:
            return False
        now = self._monotonic()
        checked_at = self._capable_checked_at
        # The latch (positive OR negative) is fresh only while within the TTL.
        # The original code latched the first result for the resolver's whole
        # life, so a capability lost (or gained) upstream was never noticed by a
        # long-lived resolver (Q-L6).
        fresh = (
            self._capable is not None
            and checked_at is not None
            and now - checked_at < self._capability_ttl
        )
        if not fresh:
            try:
                self._capable = bool(self._client.capability())
            except Exception:
                # Honest transient degrade — clear the latch so the next resolve
                # retries rather than trusting a stale value. Log it: the typed
                # return is indistinguishable from a Loomweave that genuinely has
                # no sei capability, so the warning is the only operator signal
                # that the integration is broken rather than absent.
                logger.warning(
                    "Loomweave sei-capability probe failed; degrading to locator keys",
                    exc_info=True,
                )
                self._capable = None
                self._capable_checked_at = None
                return False
            self._capable_checked_at = now
        return self._capable if self._capable is not None else False

    def _snapshot(
        self, sei: str
    ) -> tuple[dict[str, Any] | None, LineageSnapshotStatus]:
        try:
            lineage = self._client.lineage(sei)  # type: ignore[union-attr]
        except Exception:
            logger.warning(
                "Loomweave lineage snapshot failed; recording lineage as unavailable",
                exc_info=True,
            )
            return None, LineageSnapshotStatus.UNAVAILABLE
        return (
            {"length": len(lineage), "hash": content_hash(lineage)},
            LineageSnapshotStatus.VERIFIED,
        )

    def resolve_supplied_sei(self, sei: str) -> IdentityResolution | None:
        """Verify an agent-supplied SEI is alive, keying directly on it (L1).

        The weft SEI-on-entry path: the agent already holds a stable identity and
        binds it at the point of entry, rather than handing legis a locator to
        resolve (L2, :meth:`resolve`). Returns an ``IdentityResolution`` keyed on
        the SEI when Loomweave confirms it alive, or ``None`` when it cannot be
        confirmed (no capability/client, transport error, dead, or malformed
        response). ``None`` means "do not record" — the caller raises
        ``unresolved_input`` and creates nothing, never a locator-keyed record
        for what the agent asserted was an SEI (that would silently demote an L1
        bind to an off-spine locator). The resolver never parses the SEI.
        """
        if not self._capability():
            return None
        try:
            res = self._client.resolve_sei(sei)  # type: ignore[union-attr]
        except Exception:
            logger.warning(
                "Loomweave resolve_sei failed; cannot confirm supplied SEI",
                exc_info=True,
            )
            return None
        if not isinstance(res, dict) or res.get("alive") is not True:
            # ID-SEI-2: require a real boolean True (mirrors resolve()): a non-bool
            # truthy value from a buggy/hostile Loomweave must NOT promote a dead or
            # unknown SEI to a recorded stable identity. Fail closed → None.
            return None
        snapshot, snapshot_status = self._snapshot(sei)
        raw_content_hash = res.get("content_hash")
        content_hash_value = raw_content_hash if isinstance(raw_content_hash, str) else None
        return IdentityResolution(
            EntityKey.from_sei(sei),
            True,
            content_hash_value,
            snapshot,
            IdentityResolutionStatus.RESOLVED,
            snapshot_status,
        )

    def resolve(self, locator: str) -> IdentityResolution:
        degraded = IdentityResolution(
            EntityKey.from_locator(locator),
            None,
            None,
            None,
            IdentityResolutionStatus.UNAVAILABLE,
            LineageSnapshotStatus.NOT_APPLICABLE,
        )
        if not self._capability():
            return degraded
        try:
            res = self._client.resolve_locator(locator)  # type: ignore[union-attr]
        except Exception:
            logger.warning(
                "Loomweave locator resolve failed; degrading to locator key",
                exc_info=True,
            )
            return degraded
        if not isinstance(res, dict):
            return degraded
        if res.get("alive") is not True:
            # Capability present but this locator has no alive SEI — honest: no
            # stable identity, and we know it (alive recorded False, not None).
            # ID-SEI-2: require a real boolean True — a non-bool truthy value
            # (e.g. the string "false", or 1) from a buggy/hostile Loomweave must
            # NOT be read as alive and promoted to a stable identity. Fail closed.
            return IdentityResolution(
                EntityKey.from_locator(locator),
                False,
                None,
                None,
                IdentityResolutionStatus.NOT_ALIVE,
                LineageSnapshotStatus.NOT_APPLICABLE,
            )
        sei = res.get("sei")
        if not isinstance(sei, str) or not sei:
            return degraded
        snapshot, snapshot_status = self._snapshot(sei)
        # content_hash is carried verbatim into the governance record; trust only
        # a string. A non-string from a buggy/hostile Loomweave degrades to None
        # rather than polluting the typed content axis (Q-L6).
        raw_content_hash = res.get("content_hash")
        content_hash_value = raw_content_hash if isinstance(raw_content_hash, str) else None
        return IdentityResolution(
            EntityKey.from_sei(sei),
            True,
            content_hash_value,
            snapshot,
            IdentityResolutionStatus.RESOLVED,
            snapshot_status,
        )
