"""Service-level discovery contract for the MCP ``policy_explain`` tool."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from legis.enforcement.engine import EnforcementEngine
from legis.policy.cells import PolicyCellRegistry


@dataclass(frozen=True)
class RequiredInput:
    field: str
    how: str

    def to_payload(self) -> dict[str, str]:
        return {"field": self.field, "how": self.how}


@dataclass(frozen=True)
class PolicyExplanation:
    cell: str
    judge_inline: bool
    self_clearable: bool
    human_in_loop: bool
    enabled: bool
    available_moves: tuple[str, ...]
    required_inputs: tuple[RequiredInput, ...]
    # The registry rule pattern that routed this policy, or None when the policy
    # fell through to default_cell. Distinguishes a configured-but-disabled cell
    # from a hallucinated/unconfigured policy name (matched_rule is None).
    matched_rule: str | None = None
    # N-9: the explicit boolean form of the same distinction — True iff a
    # registry rule matched the policy name; False means the name may be
    # unrecognized/hallucinated (it was routed by default_cell). None on
    # cell-level explanations (policy_list), where there is no policy referent;
    # the key is then omitted from the payload so a per-cell row can never
    # carry a misleading policy_known:false.
    policy_known: bool | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "cell": self.cell,
            "judge_inline": self.judge_inline,
            "self_clearable": self.self_clearable,
            "human_in_loop": self.human_in_loop,
            "enabled": self.enabled,
            "available_moves": list(self.available_moves),
            "required_inputs": [
                item.to_payload() for item in self.required_inputs
            ],
            "matched_rule": self.matched_rule,
        }
        if self.policy_known is not None:
            payload["policy_known"] = self.policy_known
        return payload


_PROTECTED_INPUTS = (
    RequiredInput(
        field="file_fingerprint",
        how="sha256 of the target file contents",
    ),
    RequiredInput(
        field="ast_path",
        how="dotted path to the AST node",
    ),
)


def explain_policy(
    registry: PolicyCellRegistry,
    *,
    policy: str,
    entity: str,
    engine: EnforcementEngine | None,
    protected_gate: object | None,
    signoff_gate: object | None,
) -> PolicyExplanation:
    """Explain the governing cell and legal moves for a policy/entity pair.

    ``entity`` is accepted now because it is part of the ratified tool contract.
    The v1 registry routes by policy only, so the value is not used for routing.
    """
    del entity
    rule = registry.rule_for(policy)
    # Derive the effective cell from cell_for, NOT rule.cell: when registry is a
    # FlooredRegistry (posture floor), cell_for raises the matched-rule/default
    # cell to the floor (D0/D1). rule_for stays the raw matched rule so
    # matched_rule/policy_known below still report which rule the agent matched.
    cell = registry.cell_for(policy)
    explanation = explain_cell(
        cell,
        engine=engine,
        protected_gate=protected_gate,
        signoff_gate=signoff_gate,
    )
    # matched_rule distinguishes a configured policy (reports its pattern) from an
    # unconfigured name routed by default_cell (None) — closing "real-but-disabled
    # vs hallucinated". policy_known is the explicit boolean form of the same
    # signal (N-9), always set on this path. Neither affects cell/enabled: an
    # unmatched name still legitimately routes to default_cell, never an error.
    return replace(
        explanation,
        matched_rule=rule.pattern if rule is not None else None,
        policy_known=rule is not None,
    )


def explain_cell(
    cell: str,
    *,
    engine: EnforcementEngine | None,
    protected_gate: object | None,
    signoff_gate: object | None,
) -> PolicyExplanation:
    """Explain a governance cell's posture and enablement on this deployment.

    The single source of truth for per-cell ``enabled`` / ``judge_inline`` /
    ``self_clearable`` / ``human_in_loop`` and the legal moves. ``policy_list``
    and ``policy_explain`` both route through here so they can never disagree.
    The returned ``matched_rule`` / ``policy_known`` are always ``None`` here;
    ``explain_policy`` fills them after routing.
    """
    if cell == "chill":
        enabled = engine is not None and not engine.has_judge
        return PolicyExplanation(
            cell="chill",
            judge_inline=False,
            self_clearable=True,
            human_in_loop=False,
            enabled=enabled,
            available_moves=("override_submit",) if enabled else (),
            required_inputs=(),
        )
    if cell == "coached":
        enabled = engine is not None and engine.has_judge
        return PolicyExplanation(
            cell="coached",
            judge_inline=True,
            self_clearable=False,
            human_in_loop=False,
            enabled=enabled,
            available_moves=("override_submit",) if enabled else (),
            required_inputs=(),
        )
    if cell == "structured":
        enabled = signoff_gate is not None
        return PolicyExplanation(
            cell="structured",
            judge_inline=False,
            self_clearable=False,
            human_in_loop=True,
            enabled=enabled,
            available_moves=(
                "override_submit",
                "signoff_status_get",
            )
            if enabled
            else (),
            required_inputs=(),
        )
    if cell == "protected":
        enabled = protected_gate is not None
        return PolicyExplanation(
            cell="protected",
            judge_inline=True,
            self_clearable=False,
            human_in_loop=False,
            enabled=enabled,
            available_moves=("override_submit",) if enabled else (),
            required_inputs=_PROTECTED_INPUTS,
        )
    raise AssertionError(f"unknown policy cell {cell!r}")
