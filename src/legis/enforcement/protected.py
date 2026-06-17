"""Protected cell — tamper-bound, judge-gated verdicts + load-time verification.

Layered over the coached cell: every verdict is bound to the inspected source
(``file_fingerprint`` + ``ast_path``) and HMAC-signed. ``signing_fields`` is the
single source of the signed dict — both the gate (write) and ``TrailVerifier``
(read) call it, so they cannot drift. The signed dict binds entity + policy in
addition to the roadmap's six fields, so a valid signed verdict cannot be
transplanted onto a different entity.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from legis.clock import Clock
from legis.enforcement.judge import Judge
from legis.enforcement.signing import SIG_PREFIX_V3, sign, verify
from legis.enforcement.signoff import signoff_signing_fields
from legis.enforcement.verdict import Verdict
from legis.identity.entity_key import EntityKey
from legis.records.override_record import OverrideRecord
from legis.store.head_anchor import AnchorError, HeadAnchor
from legis.store.protocol import AppendOnlyStore

logger = logging.getLogger(__name__)


class TamperError(RuntimeError):
    """A protected record failed load-time signature verification."""


@dataclass(frozen=True)
class ProtectedResult:
    accepted: bool
    seq: int
    verdict: Verdict
    judge_model: str | None
    judge_rationale: str | None
    signature: str


def signing_fields(
    payload: dict[str, Any], *, seq: int | None = None
) -> dict[str, Any]:
    """The exact dict that is HMAC-signed — reconstructable from a stored payload.

    Binds entity + policy in addition to the roadmap's six fields, so a signed
    verdict cannot be transplanted to another entity.

    When *seq* is given (AUD-1 / v3), the record's chain position is folded in,
    binding the verdict not just to its content but to *where* it sits in the
    trail — closing the delete-and-rechain forgery. At verify time *seq* MUST be
    the seq column of the stored row, never a payload field (which an attacker
    controls identically), or the binding is theatre.
    """
    ext = payload.get("extensions") or {}
    clar = ext.get("loomweave") or {}
    snap = clar.get("lineage_snapshot") or {}
    fields = {
        "policy": payload.get("policy"),
        "entity": payload.get("entity_key"),
        "verdict": ext.get("judge_verdict"),
        "model": ext.get("judge_model"),
        "recorded_at": payload.get("recorded_at"),
        "rationale": payload.get("rationale"),
        "agent_id": payload.get("agent_id"),
        "protected_cell": ext.get("protected_cell") is True,
        "file_fingerprint": ext.get("file_fingerprint"),
        "ast_path": ext.get("ast_path"),
        "judge_rationale": ext.get("judge_rationale"),
        "loomweave_content_hash": clar.get("content_hash"),
        "loomweave_lineage_hash": snap.get("hash"),
        "loomweave_lineage_len": snap.get("length"),
    }
    source_binding = ext.get("source_binding")
    if isinstance(source_binding, dict) and source_binding:
        fields.update(
            {
                "source_binding_status": source_binding.get("status"),
                "source_binding_reason": source_binding.get("reason"),
                "source_binding_source_path": source_binding.get("source_path"),
                "source_binding_current_fingerprint": source_binding.get(
                    "current_fingerprint"
                ),
            }
        )
    if seq is not None:
        fields["chain_seq"] = seq
    return fields


class TrailVerifier:
    """Load-time signature check. A record whose policy is protected MUST carry a
    valid signature; a missing or mismatched signature is tampering.

    Scope of the guarantee (honest after the 2026-06-09 review, finding F1).
    v3 ``chain_seq``-binding + contiguity catch in-place EDIT, REORDER, and
    RENUMBER of records that remain protected — a mutated or repositioned signed
    record fails to verify at its position. What is NOT caught here: a holder of
    raw write access to the DB file can rewrite a damning record's ``policy`` to a
    non-protected value AND strip its protected-cell markers ("modify-to-unsigned"),
    or simply truncate the tail, so ``_requires_verification`` no longer selects
    it and both ``verify_integrity()`` and ``verify()`` pass. Those are residuals
    of the conceded raw-file-write threat tier (the same tier as the AUD-1
    deletion residual), mitigated only by the opt-in ``HeadAnchor`` — and even
    then with the documented anchor-replay caveat. The verification requirement
    is currently derived from in-record fields, so it cannot, by itself, defend
    against an actor who can rewrite those fields; hardening it (a
    config/identity-derived requirement, or signing every append so "unsigned" is
    itself whole-trail tamper) is tracked post-1.0.
    """

    def __init__(
        self,
        key: bytes,
        protected_policies: frozenset[str],
        *,
        anchor: HeadAnchor | None = None,
    ) -> None:
        self._key = key
        self._protected = protected_policies
        # Opt-in (AUD-1): an out-of-band head anchor that catches tail-truncation,
        # which seq-binding + contiguity structurally cannot. None → not anchored.
        self._anchor = anchor

    @property
    def protected_policies(self) -> frozenset[str]:
        return self._protected

    def _requires_verification(self, payload: dict[str, Any]) -> bool:
        ext = payload.get("extensions", {}) or {}
        return (
            payload.get("policy") in self._protected
            or ext.get("protected_cell") is True
            or "judge_metadata_signature" in ext
            or "signoff_signature" in ext
            or "file_fingerprint" in ext
            or "ast_path" in ext
        )

    def verify(self, records) -> None:
        records = list(records)
        # Tail-truncation check first (AUD-1): the per-record signature pass
        # below cannot see records that are simply gone. The anchor can.
        if self._anchor is not None:
            try:
                self._anchor.check(records)
            except AnchorError as exc:
                raise TamperError(str(exc)) from exc
        for rec in records:
            if not self._requires_verification(rec.payload):
                continue
            if "entity_key" not in rec.payload:
                raise TamperError(
                    f"protected record seq={rec.seq} is missing entity_key"
                )
            ext = rec.payload.get("extensions", {})
            if "signoff_state" in ext:
                sig = ext.get("signoff_signature")
                if not sig:
                    raise TamperError(
                        f"protected sign-off record seq={rec.seq} is missing its signature"
                    )
                if sig.startswith(SIG_PREFIX_V3):
                    fields = signoff_signing_fields(rec.payload, seq=rec.seq)
                else:
                    fields = signoff_signing_fields(rec.payload)
                if not verify(fields, sig, self._key):
                    raise TamperError(
                        f"protected sign-off record seq={rec.seq} signature does not verify"
                    )
            else:
                sig = ext.get("judge_metadata_signature")
                if not sig:
                    raise TamperError(
                        f"protected override record seq={rec.seq} is missing its signature"
                    )
                try:
                    # v3 (AUD-1) binds the chain position: reconstruct from the
                    # seq COLUMN (rec.seq), never a payload field, so a renumbered
                    # record fails to verify at its new position. v2 records
                    # (legacy / pre-AUD-1) carry no position binding.
                    if sig.startswith(SIG_PREFIX_V3):
                        fields = signing_fields(rec.payload, seq=rec.seq)
                    else:
                        fields = signing_fields(rec.payload)
                except (KeyError, AttributeError, TypeError) as exc:
                    raise TamperError(
                        f"protected record seq={rec.seq} is structurally malformed: {exc}"
                    ) from exc
                if not verify(fields, sig, self._key):
                    raise TamperError(
                        f"protected record seq={rec.seq} signature does not verify"
                    )


# A deterministic, non-LLM check that an ACCEPTED override on a protected policy
# is actually justified. Returns True to confirm the model's ACCEPTED, False to
# veto it. Receives the proposed record (its rationale is data, never executed).
ProtectedValidator = Callable[[OverrideRecord], bool]


class ProtectedGate:
    def __init__(
        self,
        store: AppendOnlyStore,
        clock: Clock,
        judge: Judge,
        key: bytes,
        *,
        protected_policies: frozenset[str] = frozenset(),
        validator: ProtectedValidator | None = None,
        anchor: HeadAnchor | None = None,
    ) -> None:
        self._store = store
        self._clock = clock
        self._judge = judge
        self._key = key
        # Opt-in (AUD-1): advanced to the committed head after each append so a
        # later tail-truncation is detectable. None → not anchored (default).
        self._anchor = anchor
        # The LLM judge is ADVISORY in the protected cell (Q-H3): a model
        # ACCEPTED does not clear the gate on the model's word. A prompt-injected
        # rationale that fools the judge into ACCEPTED would otherwise be
        # HMAC-signed as authoritative evidence. ACCEPTED stands only if a
        # non-LLM deterministic ``validator`` confirms it; otherwise it is
        # downgraded to BLOCKED and the agent must obtain operator sign-off
        # (operator_override). This downgrade is UNCONDITIONAL within the cell
        # (finding JUDGE-3): ``protected_policies`` no longer gates it — a policy
        # is protected by virtue of being routed to this cell, not by separate
        # membership (cell routing is glob-capable and can diverge from the
        # exact-match set). The set now only drives a config-hygiene warning for
        # an undeclared protected-cell policy, plus the TrailVerifier read-side
        # signature requirement.
        self._protected_policies = protected_policies
        self._validator = validator

    def _record_signed(
        self,
        *,
        policy: str,
        entity_key: EntityKey,
        rationale: str,
        actor_id: str,
        verdict: Verdict,
        model: str | None,
        judge_rationale: str | None,
        file_fingerprint: str,
        ast_path: str,
        extensions: dict[str, Any] | None = None,
    ) -> ProtectedResult:
        ext: dict[str, Any] = {
            **(extensions or {}),
            "protected_cell": True,
            "judge_verdict": verdict.value,
            "judge_model": model,
            "judge_rationale": judge_rationale,
            "file_fingerprint": file_fingerprint,
            "ast_path": ast_path,
        }
        base = OverrideRecord(
            policy=policy,
            entity_key=entity_key,
            rationale=rationale,
            agent_id=actor_id,
            recorded_at=self._clock.now_iso(),
            extensions=ext,
        )
        captured: dict[str, str] = {}

        def build(seq: int, _prev_hash: str) -> dict[str, Any]:
            # AUD-1 / v3: the store hands us our own chain position so the
            # signature binds seq. A renumber-to-hide-a-deletion then fails to
            # verify at the new position.
            payload = base.to_payload()
            signature = sign(
                signing_fields(payload, seq=seq), self._key, version="v3"
            )
            payload["extensions"]["judge_metadata_signature"] = signature
            captured["signature"] = signature
            return payload

        seq = self._store.append_signed(build)
        # Never read the head mid-batch: it is a batch-forbidden fresh-connection
        # read (Q-M5). The protected gate is not itself a batch owner, but it
        # shares the governance store with the sign-off gate, so guard defensively
        # — the next non-batch append re-advances the anchor (AUD-1 lag contract).
        if self._anchor is not None and not self._store.in_batch():
            self._anchor.update(*self._store.get_latest_sequence_and_hash())
        signature = captured["signature"]
        return ProtectedResult(
            accepted=verdict in Verdict.accepting(),
            seq=seq,
            verdict=verdict,
            judge_model=model,
            judge_rationale=judge_rationale,
            signature=signature,
        )

    def submit(
        self,
        *,
        policy: str,
        entity_key: EntityKey,
        rationale: str,
        agent_id: str,
        file_fingerprint: str,
        ast_path: str,
        extensions: dict[str, Any] | None = None,
    ) -> ProtectedResult:
        proposed_ext = {
            **(extensions or {}),
            "file_fingerprint": file_fingerprint,
            "ast_path": ast_path,
        }
        proposed = OverrideRecord(
            policy=policy,
            entity_key=entity_key,
            rationale=rationale,
            agent_id=agent_id,
            recorded_at=self._clock.now_iso(),
            extensions=proposed_ext,
        )
        opinion = self._judge.evaluate(proposed)
        verdict = opinion.verdict
        record_ext = dict(extensions or {})
        # Protected cell: the LLM judge is ADVISORY (Q-H3). The gate clears ONLY
        # on a judge ACCEPTED that a deterministic, non-LLM validator confirms.
        # EVERY other judge-origin verdict is downgraded to BLOCKED so the agent
        # must escalate to operator sign-off. This is UNCONDITIONAL within the
        # cell — a policy is protected by virtue of being routed here, not by
        # separate protected_policies membership (finding JUDGE-3: cell routing is
        # glob-capable and diverges from the exact-match set, so gating on
        # membership left a silent fail-open). Crucially the downgrade must cover
        # the WHOLE accepted-set, not just ACCEPTED: a fooled/injected model that
        # emits OVERRIDDEN_BY_OPERATOR (which _record_signed also treats as
        # accepted) must not clear the gate either. OVERRIDDEN_BY_OPERATOR is
        # produced only by operator_override(), which bypasses this method; the
        # judge parser additionally rejects it at the source.
        # The validator only changes the outcome on the ACCEPTED path — every other
        # verdict is downgraded to BLOCKED regardless — so it runs ONLY there. This
        # also keeps an operator-supplied validator off submits it was never written
        # to handle (e.g. ones the judge already BLOCKED). It is fail-CLOSED: if the
        # validator raises on an unexpected record shape, that exception is a veto
        # (-> BLOCKED), never an unhandled error that would surface as a
        # fail-open-shaped 500 in a gate whose premise is fail-closed.
        validator_confirms = False
        if verdict is Verdict.ACCEPTED and self._validator is not None:
            try:
                validator_confirms = bool(self._validator(proposed))
            except Exception:
                logger.warning(
                    "protected-cell validator raised for policy %r; treating as a "
                    "veto (fail-closed -> BLOCKED).",
                    policy,
                    exc_info=True,
                )
                validator_confirms = False
        if not (verdict is Verdict.ACCEPTED and validator_confirms):
            if verdict is not Verdict.BLOCKED:
                # Record the model's advisory opinion for audit, then block.
                record_ext["judge_advisory_verdict"] = verdict.value
                if policy not in self._protected_policies:
                    logger.warning(
                        "protected-cell override for policy %r is not declared in "
                        "protected_policies; downgrading the advisory %s "
                        "fail-closed. Add it to LEGIS_PROTECTED_POLICIES to make "
                        "the protection explicit and silence this warning.",
                        policy,
                        verdict.value,
                    )
            verdict = Verdict.BLOCKED
        return self._record_signed(
            policy=policy,
            entity_key=entity_key,
            rationale=rationale,
            actor_id=agent_id,
            verdict=verdict,
            model=opinion.model,
            judge_rationale=opinion.rationale,
            file_fingerprint=file_fingerprint,
            ast_path=ast_path,
            extensions=record_ext,
        )

    def operator_override(
        self,
        *,
        policy: str,
        entity_key: EntityKey,
        rationale: str,
        operator_id: str,
        file_fingerprint: str,
        ast_path: str,
        extensions: dict[str, Any] | None = None,
    ) -> ProtectedResult:
        # A human uses authority to bypass the judge. No model is consulted; the
        # verdict is the distinct OVERRIDDEN_BY_OPERATOR signal, still tamper-bound.
        return self._record_signed(
            policy=policy,
            entity_key=entity_key,
            rationale=rationale,
            actor_id=operator_id,
            verdict=Verdict.OVERRIDDEN_BY_OPERATOR,
            model=None,
            judge_rationale=None,
            file_fingerprint=file_fingerprint,
            ast_path=ast_path,
            extensions=extensions,
        )

    def records(self):
        """The governance trail this gate writes to — for verified reads."""
        return self._store.read_all()

    def verify_integrity(self) -> bool:
        """Verify the underlying append-only hash chain before HMAC checks."""
        return self._store.verify_integrity()
