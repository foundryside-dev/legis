"""The policy grammar — one shared contract, an open agent-authored instance set.

The grammar defines what a policy boundary *is* (a ``BoundaryType`` that, given a
target, returns CLEAR / VIOLATION / UNKNOWN) and what fail-closed means. Boundary
types are registered: builtins as defaults, agents adding their own with zero
human config. Soundness is inherited, not waived — anything the engine cannot
prove (an unregistered policy, a boundary that returns UNKNOWN, or one that
raises / returns garbage) yields UNKNOWN with a provenance gap, never a
false-green. Same seam shape as Wardline's ``TaintSourceProvider`` and Loomweave's
``Transport``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class PolicyResult(str, Enum):
    CLEAR = "CLEAR"          # boundary proven satisfied
    VIOLATION = "VIOLATION"  # boundary proven violated — a policy fires
    UNKNOWN = "UNKNOWN"      # cannot prove either way — honest gap, fail-closed


@dataclass(frozen=True)
class PolicyEvaluation:
    policy: str
    result: PolicyResult
    detail: str
    provenance_gap: bool


@runtime_checkable
class BoundaryType(Protocol):
    name: str

    def evaluate(self, target: Mapping[str, Any]) -> tuple[PolicyResult, str]: ...


class PolicyConflictError(RuntimeError):
    """A registration would shadow an already-registered boundary type."""


class PolicyGrammar:
    def __init__(self) -> None:
        self._boundaries: dict[str, BoundaryType] = {}

    def register(self, boundary: BoundaryType) -> None:
        name = boundary.name
        if name in self._boundaries:
            raise PolicyConflictError(
                f"policy {name!r} is already registered; boundaries are immutable "
                "(an agent may not shadow a builtin or another boundary)"
            )
        self._boundaries[name] = boundary

    def registered(self) -> frozenset[str]:
        return frozenset(self._boundaries)

    def evaluate(self, policy: str, target: Mapping[str, Any]) -> PolicyEvaluation:
        boundary = self._boundaries.get(policy)
        if boundary is None:
            return PolicyEvaluation(
                policy,
                PolicyResult.UNKNOWN,
                f"no boundary type registered for policy {policy!r}",
                True,
            )
        try:
            raw = boundary.evaluate(target)
            result, detail = raw  # may raise if the boundary returned garbage
            if not isinstance(result, PolicyResult):
                raise TypeError(f"boundary returned non-PolicyResult: {result!r}")
        except Exception as exc:  # untrusted in-process code — fail closed
            return PolicyEvaluation(
                policy,
                PolicyResult.UNKNOWN,
                f"boundary could not prove policy {policy!r}: {exc}",
                True,
            )
        return PolicyEvaluation(
            policy, result, str(detail), result is PolicyResult.UNKNOWN
        )


class AllowlistBoundary:
    """Builtin: CLEAR iff ``target['value']`` is allowlisted; missing value → UNKNOWN."""

    def __init__(self, name: str, allowed: frozenset[str]) -> None:
        self.name = name
        self._allowed = allowed

    def evaluate(self, target: Mapping[str, Any]) -> tuple[PolicyResult, str]:
        if "value" not in target:
            return (PolicyResult.UNKNOWN, "target has no 'value' to evaluate")
        value = target["value"]
        if value in self._allowed:
            return (PolicyResult.CLEAR, f"{value!r} is allowlisted")
        return (PolicyResult.VIOLATION, f"{value!r} is not allowlisted")


def default_grammar() -> PolicyGrammar:
    """A grammar preloaded with builtin boundary types (the defaults)."""
    g = PolicyGrammar()
    g.register(AllowlistBoundary("import-allowlist", frozenset({"json", "os", "sys"})))
    return g
