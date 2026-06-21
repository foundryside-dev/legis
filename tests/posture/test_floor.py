"""Phase 4 / Task 4.1 — FlooredRegistry subclass + tier max().

Fail-closed rule (design §4, D0/D1): read_floor() returning None (missing
ledger) maps to an effective floor of ``structured``, NEVER ``chill``. The
floor only ever *raises* the effective cell above the matched rule's cell; it
never lowers it. ``rule_for`` is inherited unchanged so ``matched_rule``
reports the raw rule the agent matched.
"""

from __future__ import annotations

import itertools

from legis.policy.cells import (
    CELL_TIER_ORDER,
    PolicyCellRegistry,
    PolicyCellRule,
)
from legis.posture.floor import FlooredRegistry, floored_registry


def _max_by_tier(a: str, b: str) -> str:
    return CELL_TIER_ORDER[
        max(CELL_TIER_ORDER.index(a), CELL_TIER_ORDER.index(b))
    ]


def test_max_respects_tier_order():
    # For all 16 (floor x registry-cell) combos, cell_for == max_by_tier via
    # index lookup in CELL_TIER_ORDER, not string compare.
    for floor, regcell in itertools.product(CELL_TIER_ORDER, CELL_TIER_ORDER):
        inner = PolicyCellRegistry(
            default_cell="chill",
            rules=[PolicyCellRule(pattern="p", cell=regcell)],
        )
        floored = FlooredRegistry(inner, floor=floor)
        assert floored.cell_for("p") == _max_by_tier(floor, regcell)


def test_floor_only_raises():
    inner = PolicyCellRegistry(
        default_cell="chill",
        rules=[
            PolicyCellRule(pattern="chillp", cell="chill"),
            PolicyCellRule(pattern="protp", cell="protected"),
        ],
    )
    # registry chill + floor structured -> structured (raised).
    assert FlooredRegistry(inner, floor="structured").cell_for("chillp") == "structured"
    # registry protected + floor chill -> protected (floor never lowers).
    assert FlooredRegistry(inner, floor="chill").cell_for("protp") == "protected"


def test_missing_floor_fails_closed_structured():
    # An absent/empty/deleted ledger means no signed posture evidence is
    # available. That is a fail-closed condition: it raises even a chill registry
    # to structured instead of deferring to registry defaults.
    class _NoLedger:
        def read_floor(self):
            return None

    dev = floored_registry(PolicyCellRegistry(default_cell="chill"), _NoLedger())
    assert dev.floor == "structured"
    assert dev.cell_for("anything") == "structured"

    prod = floored_registry(
        PolicyCellRegistry(default_cell="structured"), _NoLedger()
    )
    assert prod.floor == "structured"
    assert prod.cell_for("anything") == "structured"


def test_default_cell_floored():
    inner = PolicyCellRegistry(default_cell="chill")
    floored = FlooredRegistry(inner, floor="structured")
    assert floored.default_cell == "structured"
    # An unmatched policy routes by the floored default.
    assert floored.cell_for("unconfigured") == "structured"


def test_rule_for_reports_raw_pattern():
    inner = PolicyCellRegistry(
        default_cell="chill",
        rules=[PolicyCellRule(pattern="chillp", cell="chill")],
    )
    floored = FlooredRegistry(inner, floor="structured")
    rule = floored.rule_for("chillp")
    assert rule is not None
    # The raw matched rule is preserved (pattern + raw cell); only the
    # *effective* cell from cell_for is raised.
    assert rule.pattern == "chillp"
    assert rule.cell == "chill"
    assert floored.cell_for("chillp") == "structured"


def test_is_policy_cell_registry_subclass():
    inner = PolicyCellRegistry(default_cell="chill")
    floored = FlooredRegistry(inner, floor="structured")
    assert isinstance(floored, PolicyCellRegistry)


def test_floored_registry_reads_floor_at_call_time():
    inner = PolicyCellRegistry(default_cell="chill")

    class _Mutable:
        def __init__(self):
            self.value = "chill"

        def read_floor(self):
            return self.value

    ledger = _Mutable()
    first = floored_registry(inner, ledger)
    assert first.cell_for("p") == "chill"
    ledger.value = "structured"
    second = floored_registry(inner, ledger)
    assert second.cell_for("p") == "structured"
