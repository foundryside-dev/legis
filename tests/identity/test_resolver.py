import logging

import pytest

from legis.canonical import content_hash
from legis.identity.entity_key import EntityKey
from legis.identity.resolver import (
    IdentityResolution,
    IdentityResolutionStatus,
    IdentityResolver,
    LineageSnapshotStatus,
)


class FakeClient:
    def __init__(
        self,
        *,
        capable=True,
        resolve=None,
        lineage=None,
        boom=False,
        lineage_boom=False,
        resolve_boom=False,
        resolve_sei=None,
        resolve_sei_boom=False,
    ):
        self._capable = capable
        self._resolve = resolve or {"alive": False}
        self._lineage = lineage or []
        self._boom = boom
        self._lineage_boom = lineage_boom
        self._resolve_boom = resolve_boom
        self._resolve_sei = resolve_sei
        self._resolve_sei_boom = resolve_sei_boom

    def capability(self):
        if self._boom:
            raise RuntimeError("loomweave down")
        return self._capable

    def resolve_locator(self, locator):
        if self._resolve_boom:
            raise RuntimeError("resolve_locator down")
        return self._resolve

    def resolve_sei(self, sei):
        if self._resolve_sei_boom:
            raise RuntimeError("resolve_sei down")
        # Default: echo the supplied SEI back as alive (the happy path).
        if self._resolve_sei is None:
            return {"alive": True, "content_hash": "blake3hash"}
        return self._resolve_sei

    def lineage(self, sei):
        if self._lineage_boom:
            raise RuntimeError("lineage down")
        return self._lineage


ALIVE = {"sei": "loomweave:eid:deadbeef", "current_locator": "python:function:m.f",
         "content_hash": "blake3hash", "alive": True}


def test_alive_sei_is_keyed_opaquely_with_two_axes():
    r = IdentityResolver(FakeClient(resolve=ALIVE, lineage=[{"event": "born"}]))
    res = r.resolve("python:function:m.f")
    assert res.entity_key.value == "loomweave:eid:deadbeef"      # the SEI, verbatim
    assert res.entity_key.identity_stable is True
    assert res.entity_key.value.startswith("loomweave:eid:")     # opaque, not parsed
    assert res.entity_key.value != "python:function:m.f"       # not the locator
    assert res.alive is True                                    # identity axis
    assert res.content_hash == "blake3hash"                     # content axis
    assert res.lineage_snapshot == {"length": 1, "hash": content_hash([{"event": "born"}])}
    assert res.identity_resolution_status == "resolved"
    assert res.lineage_snapshot_status == "verified"


# --- the str,Enum axes + the IdentityResolution construction invariant ---


def test_status_axes_are_str_enums_serializing_to_bare_strings():
    # str,Enum members ARE their wire string — comparison and serialization
    # are byte-identical to the old bare strings (the whole compat argument).
    assert IdentityResolutionStatus.RESOLVED == "resolved"
    assert LineageSnapshotStatus.NOT_APPLICABLE == "not_applicable"
    assert content_hash({"s": IdentityResolutionStatus.NOT_ALIVE}) == content_hash(
        {"s": "not_alive"}
    )


def test_identity_resolution_rejects_contradictory_status_alive():
    # The sharpest case: a frozen record claiming "resolved" while alive is False
    # is self-contradictory and must be unrepresentable at construction.
    ek = EntityKey.from_locator("python:function:m.f")
    with pytest.raises(ValueError):
        IdentityResolution(
            ek,
            False,
            None,
            None,
            IdentityResolutionStatus.RESOLVED,
            LineageSnapshotStatus.NOT_APPLICABLE,
        )
    with pytest.raises(ValueError):
        IdentityResolution(
            ek,
            None,
            None,
            None,
            IdentityResolutionStatus.NOT_ALIVE,
            LineageSnapshotStatus.NOT_APPLICABLE,
        )
    with pytest.raises(ValueError):
        IdentityResolution(
            ek,
            True,
            None,
            None,
            IdentityResolutionStatus.UNAVAILABLE,
            LineageSnapshotStatus.NOT_APPLICABLE,
        )


def test_identity_resolution_accepts_the_three_consistent_shapes():
    ek = EntityKey.from_locator("python:function:m.f")
    # alive None ↔ UNAVAILABLE, False ↔ NOT_ALIVE, True ↔ RESOLVED
    IdentityResolution(
        ek, None, None, None,
        IdentityResolutionStatus.UNAVAILABLE, LineageSnapshotStatus.NOT_APPLICABLE,
    )
    IdentityResolution(
        ek, False, None, None,
        IdentityResolutionStatus.NOT_ALIVE, LineageSnapshotStatus.NOT_APPLICABLE,
    )
    IdentityResolution(
        ek, True, "h", {"length": 1, "hash": "x"},
        IdentityResolutionStatus.RESOLVED, LineageSnapshotStatus.VERIFIED,
    )


def test_identity_resolution_rejects_contradictory_lineage_axis():
    # The lineage axis is the other half of the record: a snapshot is present
    # iff the status is VERIFIED. Any crossed pair is self-contradictory.
    ek = EntityKey.from_locator("python:function:m.f")
    # VERIFIED but no snapshot.
    with pytest.raises(ValueError):
        IdentityResolution(
            ek, True, "h", None,
            IdentityResolutionStatus.RESOLVED, LineageSnapshotStatus.VERIFIED,
        )
    # Snapshot present but status NOT_APPLICABLE.
    with pytest.raises(ValueError):
        IdentityResolution(
            ek, False, None, {"length": 1, "hash": "x"},
            IdentityResolutionStatus.NOT_ALIVE, LineageSnapshotStatus.NOT_APPLICABLE,
        )
    # Snapshot present but status UNAVAILABLE.
    with pytest.raises(ValueError):
        IdentityResolution(
            ek, True, "h", {"length": 1, "hash": "x"},
            IdentityResolutionStatus.RESOLVED, LineageSnapshotStatus.UNAVAILABLE,
        )


def test_identity_resolution_accepts_resolved_with_unavailable_lineage():
    # A real producer shape: RESOLVED identity but the lineage probe failed —
    # snapshot None, status UNAVAILABLE. Must construct.
    ek = EntityKey.from_locator("python:function:m.f")
    IdentityResolution(
        ek, True, "h", None,
        IdentityResolutionStatus.RESOLVED, LineageSnapshotStatus.UNAVAILABLE,
    )


def test_identity_resolution_rejects_non_bool_alive_as_value_error():
    # A non-bool alive (and int aliases like 1/0 that collide with True/False)
    # must raise the guard's own ValueError, not a KeyError.
    ek = EntityKey.from_locator("python:function:m.f")
    with pytest.raises(ValueError):
        IdentityResolution(
            ek, "yes", None, None,  # type: ignore[arg-type]
            IdentityResolutionStatus.RESOLVED, LineageSnapshotStatus.VERIFIED,
        )
    with pytest.raises(ValueError):
        IdentityResolution(
            ek, 1, None, None,  # type: ignore[arg-type]
            IdentityResolutionStatus.RESOLVED, LineageSnapshotStatus.VERIFIED,
        )


def test_capability_absent_degrades_to_locator():
    r = IdentityResolver(FakeClient(capable=False))
    res = r.resolve("python:function:m.f")
    assert res.entity_key.value == "python:function:m.f"
    assert res.entity_key.identity_stable is False
    assert res.alive is None and res.content_hash is None and res.lineage_snapshot is None


def test_no_client_degrades_to_locator():
    res = IdentityResolver(None).resolve("python:function:m.f")
    assert res.entity_key.identity_stable is False


def test_locator_with_no_alive_sei_degrades_but_records_alive_false():
    r = IdentityResolver(FakeClient(resolve={"alive": False}))
    res = r.resolve("python:function:gone")
    assert res.entity_key.identity_stable is False
    assert res.alive is False        # capability present, but no stable identity → honest


def test_non_bool_alive_does_not_promote_to_stable_identity():
    # ID-SEI-2: a buggy/hostile Loomweave returning a non-bool truthy `alive`
    # (the string "false", or 1) must NOT be read as alive and promoted to a
    # stable SEI binding — `alive` is checked with `is True`, fail-closed.
    for bad_alive in ("false", "true", 1, "yes"):
        r = IdentityResolver(
            FakeClient(resolve={"alive": bad_alive, "sei": "loomweave:eid:x",
                                "content_hash": "h"})
        )
        res = r.resolve("python:function:m.f")
        assert res.entity_key.identity_stable is False, bad_alive
        assert res.alive is False, bad_alive


def test_transport_error_degrades_never_raises():
    r = IdentityResolver(FakeClient(boom=True))
    res = r.resolve("python:function:m.f")
    assert res.entity_key.identity_stable is False


def test_transient_capability_error_is_retried():
    class FlakyCapabilityClient(FakeClient):
        def __init__(self):
            super().__init__(resolve=ALIVE, lineage=[{"event": "born"}])
            self.calls = 0

        def capability(self):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("loomweave temporarily down")
            return True

    client = FlakyCapabilityClient()
    r = IdentityResolver(client)
    assert r.resolve("python:function:m.f").entity_key.identity_stable is False

    res = r.resolve("python:function:m.f")

    assert res.entity_key.value == "loomweave:eid:deadbeef"
    assert client.calls == 2


def test_alive_response_missing_sei_degrades_instead_of_raw_key_error():
    r = IdentityResolver(FakeClient(resolve={"alive": True, "content_hash": "h"}))
    res = r.resolve("python:function:m.f")
    assert res.entity_key.identity_stable is False
    assert res.alive is None


def test_alive_sei_with_lineage_failure_records_unavailable_status():
    r = IdentityResolver(FakeClient(resolve=ALIVE, lineage_boom=True))
    res = r.resolve("python:function:m.f")
    assert res.entity_key.value == "loomweave:eid:deadbeef"
    assert res.alive is True
    assert res.lineage_snapshot is None
    assert res.identity_resolution_status == "resolved"
    assert res.lineage_snapshot_status == "unavailable"


# --- each degrade path must leave an operator-visible trail. A broken Loomweave
# (auth/network/HMAC failure) returns the SAME typed-degraded record as a genuine
# "no SEI" — so when governance shows `unavailable` en masse, the WARNING is the
# only thing telling an operator "integration broken" from "nothing to resolve".
# One test per except block, each needing a differently-configured fake. ---


def test_capability_probe_failure_is_logged_with_exc_info(caplog):
    r = IdentityResolver(FakeClient(boom=True))
    with caplog.at_level(logging.WARNING, logger="legis.identity.resolver"):
        res = r.resolve("python:function:m.f")
    assert res.entity_key.identity_stable is False  # typed return unchanged
    assert caplog.records, "expected a warning when capability() raises"
    rec = caplog.records[-1]
    assert rec.levelno >= logging.WARNING
    assert rec.exc_info is not None


def test_resolve_locator_failure_is_logged_with_exc_info(caplog):
    r = IdentityResolver(FakeClient(resolve_boom=True))
    with caplog.at_level(logging.WARNING, logger="legis.identity.resolver"):
        res = r.resolve("python:function:m.f")
    assert res.entity_key.identity_stable is False  # typed return unchanged
    assert caplog.records, "expected a warning when resolve_locator() raises"
    rec = caplog.records[-1]
    assert rec.levelno >= logging.WARNING
    assert rec.exc_info is not None


def test_lineage_snapshot_failure_is_logged_with_exc_info(caplog):
    r = IdentityResolver(FakeClient(resolve=ALIVE, lineage_boom=True))
    with caplog.at_level(logging.WARNING, logger="legis.identity.resolver"):
        res = r.resolve("python:function:m.f")
    # The resolution still succeeds; only the lineage axis degrades — but the
    # failure must still surface.
    assert res.alive is True
    assert res.lineage_snapshot_status == "unavailable"
    assert caplog.records, "expected a warning when lineage() raises"
    rec = caplog.records[-1]
    assert rec.levelno >= logging.WARNING
    assert rec.exc_info is not None


# --- Q-L6: the capability latch must revalidate (TTL), and content_hash must be
# type-checked, not trusted verbatim from the Loomweave response. ---


class _Probe(FakeClient):
    """A client whose capability can be flipped, counting probes."""

    def __init__(self, *, capable=True, resolve=None, lineage=None):
        super().__init__(capable=capable, resolve=resolve, lineage=lineage)
        self.probes = 0

    def capability(self):
        self.probes += 1
        return self._capable


def test_capability_is_cached_within_ttl():
    # Within the TTL window the positive latch is reused — one probe across many
    # resolves (the caching the original code intended).
    clock = {"t": 1000.0}
    client = _Probe(resolve=ALIVE, lineage=[{"event": "born"}])
    r = IdentityResolver(client, capability_ttl=300.0, monotonic=lambda: clock["t"])
    for _ in range(5):
        assert r.resolve("python:function:m.f").entity_key.identity_stable is True
    assert client.probes == 1


def test_capability_latch_revalidates_after_ttl():
    # A Loomweave that LOSES the sei capability mid-life must not be treated as
    # capable forever by a long-lived resolver. After the TTL elapses the latch
    # is re-probed and the resolver honestly degrades.
    clock = {"t": 1000.0}
    client = _Probe(resolve=ALIVE, lineage=[{"event": "born"}])
    r = IdentityResolver(client, capability_ttl=300.0, monotonic=lambda: clock["t"])

    assert r.resolve("python:function:m.f").entity_key.identity_stable is True
    assert client.probes == 1

    client._capable = False           # capability revoked upstream
    clock["t"] += 299.0               # still within TTL → stale latch reused
    assert r.resolve("python:function:m.f").entity_key.identity_stable is True
    assert client.probes == 1

    clock["t"] += 2.0                 # now past TTL → re-probe, sees the loss
    assert r.resolve("python:function:m.f").entity_key.identity_stable is False
    assert client.probes == 2


def test_capability_regained_after_ttl_is_noticed():
    # Symmetric to revocation: a negative latch must also age out, so a Loomweave
    # that GAINS the capability is eventually picked up.
    clock = {"t": 0.0}
    client = _Probe(capable=False, resolve=ALIVE, lineage=[{"event": "born"}])
    r = IdentityResolver(client, capability_ttl=300.0, monotonic=lambda: clock["t"])

    assert r.resolve("python:function:m.f").entity_key.identity_stable is False
    client._capable = True
    clock["t"] += 301.0
    assert r.resolve("python:function:m.f").entity_key.identity_stable is True


def test_non_string_content_hash_is_dropped():
    # content_hash is carried verbatim into the record; a non-string value from a
    # buggy/hostile Loomweave must not land in the typed str|None field.
    for bad in (12345, {"nested": "obj"}, ["list"], 3.14):
        resolve = {**ALIVE, "content_hash": bad}
        r = IdentityResolver(FakeClient(resolve=resolve, lineage=[{"event": "born"}]))
        res = r.resolve("python:function:m.f")
        assert res.entity_key.value == "loomweave:eid:deadbeef"
        assert res.content_hash is None


# --- weft SEI-on-entry (L1): resolve_supplied_sei verifies an agent-supplied SEI
# is alive and keys directly on it, or returns None ("do not record"). ---


def test_supplied_sei_alive_is_keyed_directly():
    r = IdentityResolver(
        FakeClient(
            resolve_sei={"alive": True, "content_hash": "h"},
            lineage=[{"event": "born"}],
        )
    )
    res = r.resolve_supplied_sei("loomweave:eid:deadbeef")
    assert res is not None
    assert res.entity_key.value == "loomweave:eid:deadbeef"  # the SEI, verbatim
    assert res.entity_key.identity_stable is True
    assert res.alive is True
    assert res.content_hash == "h"
    assert res.identity_resolution_status == "resolved"
    assert res.lineage_snapshot_status == "verified"


def test_supplied_sei_no_capability_returns_none():
    # No SEI capability → cannot confirm alive → do-not-record (None), never a
    # locator-keyed record masquerading as the asserted SEI.
    r = IdentityResolver(FakeClient(capable=False))
    assert r.resolve_supplied_sei("loomweave:eid:x") is None


def test_supplied_sei_dead_returns_none():
    r = IdentityResolver(FakeClient(resolve_sei={"alive": False}))
    assert r.resolve_supplied_sei("loomweave:eid:gone") is None


def test_supplied_sei_non_bool_alive_returns_none():
    # ID-SEI-2 parity with resolve(): a non-bool truthy `alive` must not promote.
    for bad_alive in ("false", "true", 1, "yes"):
        r = IdentityResolver(FakeClient(resolve_sei={"alive": bad_alive}))
        assert r.resolve_supplied_sei("loomweave:eid:x") is None, bad_alive


def test_supplied_sei_transport_error_returns_none_never_raises():
    r = IdentityResolver(FakeClient(resolve_sei_boom=True))
    assert r.resolve_supplied_sei("loomweave:eid:x") is None


def test_supplied_sei_lineage_failure_still_resolves_unavailable():
    r = IdentityResolver(
        FakeClient(resolve_sei={"alive": True, "content_hash": "h"}, lineage_boom=True)
    )
    res = r.resolve_supplied_sei("loomweave:eid:deadbeef")
    assert res is not None
    assert res.alive is True
    assert res.lineage_snapshot is None
    assert res.lineage_snapshot_status == "unavailable"


def test_supplied_sei_non_string_content_hash_dropped():
    r = IdentityResolver(
        FakeClient(resolve_sei={"alive": True, "content_hash": 123}, lineage=[])
    )
    res = r.resolve_supplied_sei("loomweave:eid:deadbeef")
    assert res is not None
    assert res.content_hash is None
