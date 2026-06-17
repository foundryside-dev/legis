"""Policy-to-cell registry for the agent-facing MCP surface.

The registry is deliberately declarative and stdlib-only. Agents submit opaque
policy names; the server maps them to governance cells and reports the mapping
back through ``policy_explain`` and ``override_submit``.
"""

from __future__ import annotations

import fnmatch
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


# Canonical governance cells in tier order (simple → complex). This ordered
# sequence is the single source of truth for cell *membership*; ``VALID_CELLS``
# is derived from it so the two cannot desync. Consumers that need a stable
# display/iteration order (e.g. the MCP ``policy_list`` cells block) import
# ``CELL_TIER_ORDER`` rather than re-hardcoding the membership.
CELL_TIER_ORDER = ("chill", "coached", "structured", "protected")
VALID_CELLS = frozenset(CELL_TIER_ORDER)


@dataclass(frozen=True)
class PolicyCellRule:
    pattern: str
    cell: str


class PolicyCellRegistry:
    def __init__(
        self, default_cell: str, rules: Iterable[PolicyCellRule] = ()
    ) -> None:
        self.default_cell = _validate_cell(default_cell, "default_cell")
        self._rules = tuple(_validate_rule(i, rule) for i, rule in enumerate(rules))

    @property
    def rules(self) -> tuple[PolicyCellRule, ...]:
        """Read-only view of the configured rules, in declared order."""
        return self._rules

    def rule_for(self, policy: str) -> PolicyCellRule | None:
        """Return the rule that governs ``policy``, or ``None`` on fall-through.

        Precedence matches ``cell_for``: an exact (non-glob) pattern wins over a
        glob. ``None`` means no rule matched and the policy is routed by
        ``default_cell``.
        """
        for rule in self._rules:
            if not _has_glob(rule.pattern) and rule.pattern == policy:
                return rule
        for rule in self._rules:
            if _has_glob(rule.pattern) and fnmatch.fnmatchcase(policy, rule.pattern):
                return rule
        return None

    def cell_for(self, policy: str) -> str:
        rule = self.rule_for(policy)
        return rule.cell if rule is not None else self.default_cell


def default_policy_cells() -> PolicyCellRegistry:
    """Dev/test default: unlisted policies land in the chill self-clear cell.

    Convenient for local work, but NOT a safe production default — see
    ``fail_closed_policy_cells``. Production composition roots must only select
    this under an explicit dev opt-in (Q-M7 / audit H6).
    """
    return PolicyCellRegistry(default_cell="chill")


def fail_closed_policy_cells() -> PolicyCellRegistry:
    """Production fail-closed default for absent configuration.

    An unlisted policy escalates to a human operator (``structured`` /
    block+escalate) instead of silently self-clearing (``chill``), so a typo,
    a missing registry entry, or an incomplete deployment cannot downgrade
    governance to self-clear (Q-M7 / audit H6).
    """
    return PolicyCellRegistry(default_cell="structured")


def load_policy_cells(path: str | Path) -> PolicyCellRegistry:
    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    default_cell = data.get("default_cell")
    if not isinstance(default_cell, str) or not default_cell.strip():
        raise ValueError("missing/empty default_cell")

    raw_rules = data.get("policy", [])
    if not isinstance(raw_rules, list):
        raise ValueError(
            "policy table must be an array of tables ([[policy]]), "
            f"got {type(raw_rules).__name__!r}"
        )

    rules: list[PolicyCellRule] = []
    for i, entry in enumerate(raw_rules):
        if not isinstance(entry, dict):
            raise ValueError(
                f"policy[{i}] is malformed: expected a table ([[policy]]), "
                f"got {type(entry).__name__!r}"
            )
        pattern = entry.get("pattern")
        cell = entry.get("cell")
        if not isinstance(pattern, str) or not pattern.strip():
            raise ValueError(f"policy[{i}] is malformed: missing/empty pattern")
        if not isinstance(cell, str) or not cell.strip():
            raise ValueError(f"policy[{i}] is malformed: missing/empty cell")
        rules.append(PolicyCellRule(pattern=pattern, cell=cell))

    return PolicyCellRegistry(default_cell=default_cell, rules=rules)


def _validate_rule(index: int, rule: PolicyCellRule) -> PolicyCellRule:
    pattern = rule.pattern.strip()
    if not pattern:
        raise ValueError(f"policy[{index}] is malformed: missing/empty pattern")
    return PolicyCellRule(
        pattern=pattern,
        cell=_validate_cell(rule.cell, f"policy[{index}].cell"),
    )


def _validate_cell(raw: str, location: str) -> str:
    cell = raw.strip()
    if cell not in VALID_CELLS:
        allowed = ", ".join(sorted(VALID_CELLS))
        raise ValueError(f"{location} has unknown cell {cell!r}; expected one of: {allowed}")
    return cell


def _has_glob(pattern: str) -> bool:
    return any(char in pattern for char in "*?[")
