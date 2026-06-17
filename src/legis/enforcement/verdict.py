"""Judge verdict value types — shared by the judge and the engine.

A ``str`` enum so verdicts serialize to plain JSON in the audit trail and on the
HTTP surface (same discipline as ``CheckOutcome``).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    ACCEPTED = "ACCEPTED"
    BLOCKED = "BLOCKED"
    OVERRIDDEN_BY_OPERATOR = "OVERRIDDEN_BY_OPERATOR"

    @classmethod
    def model_emittable(cls) -> frozenset[Verdict]:
        """Verdicts an LLM judge may legitimately emit (JUDGE-3).

        OVERRIDDEN_BY_OPERATOR is an operator-authority verdict produced only by
        ``operator_override``; a model must never be able to emit it, so the
        judge parser rejects anything outside this set as unparseable (the caller
        then fail-closes to BLOCKED). Single source of truth — do not re-inline.
        """
        return frozenset({cls.ACCEPTED, cls.BLOCKED})

    @classmethod
    def accepting(cls) -> frozenset[Verdict]:
        """Verdicts that count as accepted — i.e. clear a gate / suppress.

        Single source of truth for "this verdict cleared". Note this is NOT the
        protected-cell clear condition: the protected gate additionally requires
        ACCEPTED *and* validator confirmation (the JUDGE-3 downgrade guard), so
        membership here is necessary but not sufficient there.
        """
        return frozenset({cls.ACCEPTED, cls.OVERRIDDEN_BY_OPERATOR})


class SignoffState(str, Enum):
    PENDING = "PENDING_SIGNOFF"
    SIGNED_OFF = "SIGNED_OFF"


@dataclass(frozen=True)
class JudgeOpinion:
    verdict: Verdict
    model: str
    rationale: str
