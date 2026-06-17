"""Weft SEI §8 conformance oracle — Legis as consumer.

The scenario list is loaded from the vendored ``sei-conformance-oracle.json``
fixture, copied from Loomweave's authoritative fixture. Each scenario id is
claimed by one consumer assertion so a fixture change fails CI until Legis
updates the corresponding behavior check. The live-Loomweave integration run is
a separate, environment-gated check.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

import pytest

from legis.governance.gaps import find_orphan_gaps
from legis.identity.resolver import IdentityResolver
from legis.store.audit_store import AuditStore

ORACLE_PATH = Path(__file__).parent / "fixtures" / "sei-conformance-oracle.json"


@lru_cache(maxsize=1)
def _load_oracle() -> dict:
    # Read+parse once per run: _scenario() calls this ~8x and the fixture is
    # immutable for the session.
    return json.loads(ORACLE_PATH.read_text(encoding="utf-8"))


def _scenario(scenario_id: str) -> dict:
    for item in _load_oracle()["scenarios"]:
        if item["id"] == scenario_id:
            return item
    raise AssertionError(f"missing SEI oracle scenario {scenario_id!r}")


def _loomweave_oracle_source() -> Path | None:
    candidates: list[Path] = []
    if env := os.environ.get("LOOMWEAVE_REPO"):
        candidates.append(Path(env) / "docs" / "federation" / "fixtures" / "sei-conformance-oracle.json")
    candidates.append(
        Path(__file__).resolve().parents[3]
        / "loomweave"
        / "docs"
        / "federation"
        / "fixtures"
        / "sei-conformance-oracle.json"
    )
    return next((path for path in candidates if path.exists()), None)


COVERED_SCENARIOS = {
    "identity_round_trip_and_opacity",
    "rename",
    "move",
    "ambiguous",
    "delete",
    "capability_absent",
}


class FakeLoomweave:
    def __init__(self, *, capable=True, resolve=None, sei=None, lineage=None):
        self._capable = capable
        self._resolve = resolve or {}      # {locator: response}
        self._sei = sei or {}              # {sei: response}
        self._lineage = lineage or {}      # {sei: [events]}

    def capability(self):
        return self._capable

    def resolve_locator(self, locator):
        return self._resolve.get(locator, {"alive": False})

    def resolve_sei(self, sei):
        return self._sei.get(sei, {"sei": sei, "alive": False, "lineage": []})

    def lineage(self, sei):
        return self._lineage.get(sei, [])


def test_vendored_oracle_matches_loomweave_source():
    source = _loomweave_oracle_source()
    if source is None:
        pytest.skip("Loomweave repo not found; set LOOMWEAVE_REPO to enable drift check")
    assert _load_oracle() == json.loads(source.read_text(encoding="utf-8"))


def test_every_oracle_scenario_is_covered():
    fixture_ids = {item["id"] for item in _load_oracle()["scenarios"]}
    assert fixture_ids == COVERED_SCENARIOS


def test_identity_round_trip_and_opacity():
    scenario = _scenario("identity_round_trip_and_opacity")
    loc = "python:function:m.f"
    client = FakeLoomweave(resolve={loc: {"sei": "loomweave:eid:rt", "current_locator": loc,
                                        "content_hash": "h", "alive": True}})
    res = IdentityResolver(client).resolve(loc)
    assert scenario["expect"]["resolve_locator"]["alive"] is True
    assert res.entity_key.identity_stable is True
    assert res.entity_key.value.startswith("loomweave:eid:")   # opaque, carries prefix
    assert res.entity_key.value != loc                       # not the locator
    assert res.alive is True and res.content_hash == "h"


def _attest(tmp_path, sei):
    store = AuditStore(f"sqlite:///{tmp_path / 'g.db'}")
    store.append({"entity_key": {"value": sei, "identity_stable": True},
                  "identity_stable": True, "extensions": {}})
    return store


def test_rename_carries_sei_record_survives(tmp_path):
    scenario = _scenario("rename")
    # The record was keyed on the SEI; after rename the SEI still resolves alive
    # at the NEW locator. legis's consumer behaviour: NOT orphaned — carried.
    sei = "loomweave:eid:ren"
    store = _attest(tmp_path, sei)
    client = FakeLoomweave(sei={sei: {"sei": sei, "current_locator": "python:function:new.f",
                                    "content_hash": "h", "alive": True}})
    assert scenario["expect"]["carry"] is True
    assert find_orphan_gaps(store.read_all(), client) == []   # carried, not orphaned


def test_move_carries_sei(tmp_path):
    scenario = _scenario("move")
    sei = "loomweave:eid:mov"
    store = _attest(tmp_path, sei)
    client = FakeLoomweave(sei={sei: {"sei": sei, "current_locator": "python:function:b.f",
                                    "content_hash": "h", "alive": True}})
    assert scenario["expect"]["carry"] is True
    assert find_orphan_gaps(store.read_all(), client) == []   # carried, not orphaned


def test_ambiguous_old_sei_orphaned_surfaces_gap(tmp_path):
    scenario = _scenario("ambiguous")
    sei = "loomweave:eid:amb"
    store = AuditStore(f"sqlite:///{tmp_path / 'g.db'}")
    store.append({"entity_key": {"value": sei, "identity_stable": True},
                  "identity_stable": True, "extensions": {}})
    client = FakeLoomweave(sei={sei: {"sei": sei, "alive": False,
                                    "lineage": [{"event": "orphaned"}]}})
    gaps = find_orphan_gaps(store.read_all(), client)
    assert scenario["expect"]["carry"] is False
    assert [g.sei for g in gaps] == [sei]   # fail-closed: surfaced, never carried


def test_delete_old_sei_orphaned_surfaces_gap(tmp_path):
    scenario = _scenario("delete")
    sei = "loomweave:eid:del"
    store = AuditStore(f"sqlite:///{tmp_path / 'g.db'}")
    store.append({"entity_key": {"value": sei, "identity_stable": True},
                  "identity_stable": True, "extensions": {}})
    client = FakeLoomweave(sei={sei: {"sei": sei, "alive": False,
                                    "lineage": [{"event": "orphaned"}]}})
    assert scenario["expect"]["resolve_sei(old_sei)"]["alive"] is False
    assert [g.sei for g in find_orphan_gaps(store.read_all(), client)] == [sei]


def test_capability_absent_degrades_gracefully():
    scenario = _scenario("capability_absent")
    client = FakeLoomweave(capable=False)
    res = IdentityResolver(client).resolve("python:function:any")
    assert scenario["expect"]["resolve_locator(any)"]["alive"] is False
    assert res.entity_key.identity_stable is False   # honest 'identity unavailable'
    assert res.entity_key.value == "python:function:any"   # keeps working on locators
