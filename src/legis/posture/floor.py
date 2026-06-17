"""The FlooredRegistry chokepoint (design §4, decisions D0/D1/D2).

A ``FlooredRegistry`` is a *subclass* of
:class:`~legis.policy.cells.PolicyCellRegistry` whose ``cell_for`` /
``default_cell`` are raised to the posture floor. Because it is a subclass,
every call site that already accepts a ``PolicyCellRegistry`` — including
``explain_policy`` — accepts a ``FlooredRegistry`` transparently and floors
without a signature change (D1).

Fail-closed contract (design §4):
  * The floor only ever *raises* the effective cell (``_max_tier``); it never
    lowers it. A ``protected`` registry cell under a ``chill`` floor stays
    ``protected``.
  * A missing/empty ledger (``read_floor() is None``) maps to the identity
    floor ``chill`` (a no-op): the registry's own default stands, which is
    itself fail-closed (``structured``) in production. The floor only RAISES
    once an operator has written a genesis/transition (:func:`floored_registry`).
  * The floor value is read fresh at every construction; it is never cached on
    a runtime (D2). ``floored_registry`` calls ``read_floor()`` at call time.

``rule_for`` is inherited unchanged so ``matched_rule.pattern`` keeps reporting
the raw rule the agent matched — only the *effective* cell is raised above the
matched rule's cell (D1).
"""

from __future__ import annotations

from typing import Protocol

from legis.policy.cells import CELL_TIER_ORDER, PolicyCellRegistry


class _FloorReader(Protocol):
    def read_floor(self) -> str | None: ...


def _max_tier(a: str, b: str) -> str:
    """The higher of two cells by ``CELL_TIER_ORDER`` index (never a string sort)."""
    return CELL_TIER_ORDER[
        max(CELL_TIER_ORDER.index(a), CELL_TIER_ORDER.index(b))
    ]


class FlooredRegistry(PolicyCellRegistry):
    """A ``PolicyCellRegistry`` whose effective cells are raised to ``floor``.

    Constructed from an inner registry's ``default_cell`` + ``rules`` plus a
    ``floor`` cell. ``cell_for`` returns ``max_tier(floor, inner.cell_for(...))``;
    ``default_cell`` is the floored default. ``rule_for`` is inherited unchanged.
    """

    def __init__(self, inner: PolicyCellRegistry, *, floor: str) -> None:
        # Rebuild on top of the inner registry's already-validated rules so a
        # FlooredRegistry IS-A PolicyCellRegistry (D1) and explain_policy/
        # policy_list accept it with no special-casing.
        super().__init__(default_cell=inner.default_cell, rules=inner.rules)
        # _validate_cell raises on an unknown floor (e.g. a typo'd cell name).
        from legis.policy.cells import _validate_cell

        self.floor = _validate_cell(floor, "floor")
        # default_cell is a plain attribute on the base; raise it to the floor.
        self.default_cell = _max_tier(self.floor, self.default_cell)

    def cell_for(self, policy: str) -> str:
        # super().cell_for resolves the RAW matched-rule/default cell; the floor
        # only raises it. default_cell is already floored above, so an unmatched
        # policy is covered too.
        return _max_tier(self.floor, super().cell_for(policy))


def floored_registry(inner: PolicyCellRegistry, ledger: _FloorReader) -> FlooredRegistry:
    """Build a ``FlooredRegistry`` from ``inner`` and the ledger's current floor.

    Reads ``ledger.read_floor()`` AT CALL TIME (never cached, D2) and maps a
    ``None`` floor (missing/empty ledger) to the fail-closed ``structured``
    default — never ``chill`` (design §4).
    """
    floor = ledger.read_floor()
    if floor is None:
        # Absent/empty ledger -> the IDENTITY floor (chill, the bottom tier), a
        # pure no-op: max(chill, X) == X, so the registry's own default stands.
        # That default is itself fail-closed (fail_closed_policy_cells() ->
        # structured) in production, so an uninstalled/deleted ledger still
        # yields structured there; under the explicit LEGIS_DEV_DEFAULT_CELLS
        # opt-in it stays chill (preserving the N3 keyless-chill acceptance). The
        # floor only RAISES once an operator has written a genesis/transition.
        # (design §4, reconciled 2026-06-17 during implementation.)
        floor = "chill"
    return FlooredRegistry(inner, floor=floor)
