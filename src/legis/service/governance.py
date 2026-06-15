"""Extracted governance decision logic — transport-agnostic.

Functions added here take their dependencies explicitly (no closures, no
globals) and, when they signal failure, raise ``ServiceError`` subclasses —
never a transport error. (``resolve_for_record`` itself propagates no errors.)
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from legis.enforcement.engine import EnforcementEngine, EnforcementResult
from legis.enforcement.lifecycle import evaluate_override_rate
from legis.enforcement.protected import (
    ProtectedGate,
    ProtectedResult,
    TamperError,
    TrailVerifier,
)
from legis.enforcement.signoff import SignoffGate, SignoffResult
from legis.governance import params
from legis.identity.entity_key import EntityKey
from legis.identity.resolver import IdentityResolver
from legis.policy.grammar import PolicyEvaluation, PolicyGrammar, PolicyResult
from legis.service.errors import (
    AuditIntegrityError,
    BindingUnavailableError,
    NoSuchRequestError,
    NotClearedError,
    NotEnabledError,
    ProtectedKeyRequiredError,
    UnresolvedInputError,
)
from legis.service.source_binding import (
    require_verified_source_binding,
    verify_current_source_binding,
)


def resolve_for_record(
    identity: IdentityResolver | None, locator: str
) -> tuple[EntityKey, dict]:
    """The one resolve-then-key boundary.

    Keys on the SEI when Loomweave proves a stable identity, on the locator
    otherwise. When no resolver is wired legis runs standalone (locator-keyed).
    The ``loomweave`` extension carries the two distinct axes (identity: ``alive``,
    content: ``content_hash``) plus the REQ-L-01 lineage snapshot, never
    collapsed — present only when a resolution decision was actually made.
    """
    if identity is None:
        return EntityKey.from_locator(locator), {}
    res = identity.resolve(locator)
    ext: dict = {}
    if res.alive is not None:
        # Both status axes are mandatory str,Enum fields on IdentityResolution now,
        # so read them directly — the old getattr fallbacks guarded a shape the
        # type no longer permits. The members serialize as their bare strings.
        ext["loomweave"] = {
            "alive": res.alive,
            "content_hash": res.content_hash,
            "lineage_snapshot": res.lineage_snapshot,
            "identity_resolution_status": res.identity_resolution_status,
            "lineage_snapshot_status": res.lineage_snapshot_status,
        }
    return res.entity_key, ext


def resolve_for_entry(
    identity: IdentityResolver | None,
    *,
    entity: str,
    entity_sei: str | None,
) -> tuple[EntityKey, dict]:
    """The SEI-on-entry resolve boundary for the authoring surfaces (weft doctrine).

    Two mutually exclusive inputs select the resolution path:

    * ``entity_sei`` (L1, inline bind) — the agent already holds a stable SEI and
      binds it at the point of entry. legis verifies it is alive through the
      Loomweave ``resolve_sei`` transport and keys directly on it. A non-resolving
      SEI raises :class:`UnresolvedInputError` (weft-reason ``unresolved_input``)
      and the caller records NOTHING — never a locator-keyed record masquerading
      as a stable bind.
    * ``entity`` alone (L2, locator/symbol) — the pre-existing path: legis resolves
      the locator to an SEI when it can and degrades to a locator key otherwise
      (:func:`resolve_for_record`). Unchanged for every existing caller.

    Keeping both axes here means the engine/gate layer below stays
    transport-agnostic and only ever sees a resolved :class:`EntityKey`.
    """
    if entity_sei is None:
        return resolve_for_record(identity, entity)
    if identity is None:
        # No resolve transport wired: an SEI the agent asserts cannot be confirmed
        # alive, and recording it unverified would be exactly the unbound-but-looks-
        # bound record the doctrine forbids. Fail closed with the operator fix.
        raise UnresolvedInputError(
            cause=(
                f"entity_sei {entity_sei!r} was supplied but Loomweave identity is "
                "not wired, so legis cannot confirm the SEI is alive"
            ),
            fix=(
                "Ask the operator to set LOOMWEAVE_API_URL out-of-band and relaunch, "
                "or submit the entity as a locator/symbol (entity) instead and let "
                "legis resolve it."
            ),
        )
    resolution = identity.resolve_supplied_sei(entity_sei)
    if resolution is None:
        raise UnresolvedInputError(
            cause=(
                f"entity_sei {entity_sei!r} did not resolve to a live, stable "
                "identity in Loomweave"
            ),
            fix=(
                "Confirm the SEI exists and is alive (the entity may have been "
                "deleted, or Loomweave is degraded), or submit the entity as a "
                "locator/symbol (entity) for legis to resolve."
            ),
        )
    ext: dict = {}
    if resolution.alive is not None:
        ext["loomweave"] = {
            "alive": resolution.alive,
            "content_hash": resolution.content_hash,
            "lineage_snapshot": resolution.lineage_snapshot,
            "identity_resolution_status": resolution.identity_resolution_status,
            "lineage_snapshot_status": resolution.lineage_snapshot_status,
        }
    return resolution.entity_key, ext


def verified_records(
    trail_owner,
    trail_verifier,
    engine_records: Callable[[], list],
):
    """The verified governance trail.

    ``trail_owner`` is whichever gate owns the trail being read: the protected
    gate for the governance trail, or the sign-off gate for the sign-off trail
    (the API ``bind-issue`` path passes the latter). When no owner is wired the
    simple-tier engine owns it instead (read lazily via ``engine_records`` so a
    protected deployment never initialises the engine store). Never mix the two
    stores. Verification is fail-closed and applies to EVERY consumer of the
    trail, so a tampered record is an honest integrity error
    (``AuditIntegrityError``), never silently read or scored.

    ``trail_owner`` and ``trail_verifier`` are intentionally left duck-typed (an
    owner exposing ``records()`` / ``verify_integrity()`` and a verifier
    exposing ``verify()``) so the service layer is not coupled to the
    enforcement concrete types.

    Cost note (rc4 review #7): this verifies the *whole* trail on every call —
    ``verify_integrity()`` re-hashes the chain (O(N)) and ``trail_verifier.verify``
    re-checks signatures (O(N)) — including on interactive paths (the keyed
    override-submit idempotency check and every override-rate read). That cost is
    the tamper-evidence property, not an oversight: there is no load-time or
    open-time verification anywhere (``AuditStore.__init__`` only creates the
    schema), so this path is the only thing standing between a tampered record and
    an interactive read. Two tempting optimizations are deliberately NOT taken:
    reserving full verification for the explicit governance-gate would leave every
    interactive read unverified (a silent tamper window); and incremental
    verification (trusting a cached last-verified prefix and re-hashing only the
    new tail) cannot detect out-of-band tampering of an already-verified record —
    exactly what the hash chain exists to catch — and still would not reach O(1),
    because the signature pass is O(N) regardless. If trail size ever makes this
    latency-bound, the honest lever is trail retention/compaction, not narrowing
    what each read verifies.
    """
    if trail_owner is not None:
        records = trail_owner.records()
        verify_integrity = getattr(trail_owner, "verify_integrity", None)
        if verify_integrity is not None and not verify_integrity():
            raise AuditIntegrityError("audit integrity failure: database hash chain verification failed")
        if trail_verifier is not None:
            try:
                trail_verifier.verify(records)
            except TamperError as exc:
                raise AuditIntegrityError(f"audit integrity failure: {exc}") from exc
        return records
    return engine_records()


def compute_override_rate(records: list):
    """Evaluate the override-rate gate against the policy constants.

    Threshold/window/floor come from ADR-0002 constants — NOT caller input — so
    the gate an agent is measured against cannot be tuned by it.
    """
    return evaluate_override_rate(
        records,
        threshold=params.OVERRIDE_RATE_THRESHOLD,
        window=params.OVERRIDE_RATE_WINDOW,
        min_sample=params.OVERRIDE_RATE_MIN_SAMPLE,
    )


def _requires_protected_verification(payload: dict[str, Any], protected_policies) -> bool:
    """Gate-local protected-detection for the KEYLESS branch of the override-rate
    gate: would refusing to score this record be right because it genuinely needs
    a signature we have no key to check?

    The discriminator is *status-claim vs incidental metadata*. The markers kept
    below — ``protected_cell`` and the signature keys — are a record purporting to
    BE protected, so failing closed on them in a keyless deployment is correct
    even if injected. ``file_fingerprint`` / ``ast_path`` carry no such claim:
    they are ordinary metadata, and the simple-tier engine accepts an arbitrary
    ``extensions`` dict, so they can ride on a never-signed chill/coached record —
    flagging them would fail-close a non-protected deployment on a record that has
    nothing to verify. That over-reach is why those two sniffs are dropped here.

    Intentionally NARROWER than ``TrailVerifier._requires_verification`` (the
    verify path, which must stay over-inclusive): the two answer different
    questions — keyless "must I refuse to score this?" vs with-key "must this be
    signed?" — so do NOT re-merge them.
    """
    ext = payload.get("extensions", {}) or {}
    return (
        payload.get("policy") in protected_policies
        or ext.get("protected_cell") is True
        or "judge_metadata_signature" in ext
        or "signoff_signature" in ext
    )


def evaluate_override_rate_gate(
    records: list,
    *,
    hmac_key: str | None,
    protected_policies,
):
    """Content-driven override-rate gate: the single decision path for the cli.

    Detect protected records, require an HMAC key for them (fail closed — a
    protected trail cannot be scored unverified, 07cf54e), verify the protected
    trail, then score the override rate. This is the canonical implementation;
    the cli gate calls it rather than re-deriving the same decision (Q-H2).
    """
    protected_present = any(
        _requires_protected_verification(rec.payload, protected_policies) for rec in records
    )
    if protected_present and not hmac_key:
        raise ProtectedKeyRequiredError(
            "Protected audit records require LEGIS_HMAC_KEY for verification"
        )
    if hmac_key:
        verifier = TrailVerifier(hmac_key.encode("utf-8"), protected_policies)
        try:
            verifier.verify(records)
        except TamperError as exc:
            raise AuditIntegrityError(
                f"Protected audit trail verification failed: {exc}"
            ) from exc
    return compute_override_rate(records)


def submit_override(
    engine: EnforcementEngine,
    *,
    identity: IdentityResolver | None,
    policy: str,
    entity: str,
    rationale: str,
    agent_id: str,
    extra_extensions: dict[str, Any] | None = None,
    entity_sei: str | None = None,
) -> EnforcementResult:
    """Resolve-then-key, then submit the override to the simple-tier engine.

    Cell semantics live in the engine: judge absent → chill (always accepted);
    judge present → coached (ACCEPTED records, BLOCKED records the attempt). The
    adapter maps ``EnforcementResult.accepted`` to its transport's success/blocked
    signal (HTTP 201/409; MCP ACCEPTED_*/BLOCKED).

    Keyword-only after ``engine`` so the five same-typed fields cannot be
    transposed at the call site; this is the seam the MCP adapter (WP-M3) calls
    directly, alongside the existing ``POST /overrides`` handler.
    """
    entity_key, ext = resolve_for_entry(identity, entity=entity, entity_sei=entity_sei)
    return engine.submit_override(
        policy=policy,
        entity_key=entity_key,
        rationale=rationale,
        agent_id=agent_id,
        extensions={**ext, **(extra_extensions or {})},
    )


def submit_protected_override(
    protected_gate: ProtectedGate | None,
    *,
    identity: IdentityResolver | None,
    policy: str,
    entity: str,
    rationale: str,
    agent_id: str,
    file_fingerprint: str,
    ast_path: str,
    source_root: str | Path | None = None,
    extra_extensions: dict[str, Any] | None = None,
    entity_sei: str | None = None,
) -> ProtectedResult:
    """Submit a protected-cell override using transport-bound agent identity.

    ``entity_sei`` (when supplied) is the weft L1 identity bind: the record keys
    on that verified SEI. ``entity`` remains the source-path/symbol used for the
    current-source fingerprint binding — an opaque SEI has no local bytes, so the
    source binding records an honest ``unverified`` status (the pre-existing
    non-path-entity behaviour), while identity is still rename-stable.
    """
    if protected_gate is None:
        # LEG-2: the message names the operator knob (C-8: operator action).
        raise NotEnabledError(
            "protected cell not enabled: ask the operator to set "
            "LEGIS_HMAC_KEY (out-of-band) and relaunch"
        )
    entity_key, ext = resolve_for_entry(identity, entity=entity, entity_sei=entity_sei)
    source_binding = verify_current_source_binding(
        entity=entity,
        file_fingerprint=file_fingerprint,
        source_root=source_root,
    )
    require_verified_source_binding(entity, source_binding)
    return protected_gate.submit(
        policy=policy,
        entity_key=entity_key,
        rationale=rationale,
        agent_id=agent_id,
        file_fingerprint=file_fingerprint,
        ast_path=ast_path,
        extensions={**ext, "source_binding": source_binding, **(extra_extensions or {})},
    )


def submit_operator_override(
    protected_gate: ProtectedGate | None,
    *,
    identity: IdentityResolver | None,
    policy: str,
    entity: str,
    rationale: str,
    operator_id: str,
    file_fingerprint: str,
    ast_path: str,
    source_root: str | Path | None = None,
    entity_sei: str | None = None,
) -> ProtectedResult:
    """Submit a protected-cell operator override with current-source binding."""
    if protected_gate is None:
        # LEG-2: the message names the operator knob (C-8: operator action).
        raise NotEnabledError(
            "protected cell not enabled: ask the operator to set "
            "LEGIS_HMAC_KEY (out-of-band) and relaunch"
        )
    entity_key, ext = resolve_for_entry(identity, entity=entity, entity_sei=entity_sei)
    source_binding = verify_current_source_binding(
        entity=entity,
        file_fingerprint=file_fingerprint,
        source_root=source_root,
    )
    require_verified_source_binding(entity, source_binding)
    return protected_gate.operator_override(
        policy=policy,
        entity_key=entity_key,
        rationale=rationale,
        operator_id=operator_id,
        file_fingerprint=file_fingerprint,
        ast_path=ast_path,
        extensions={**ext, "source_binding": source_binding},
    )


def request_signoff(
    signoff_gate: SignoffGate | None,
    *,
    identity: IdentityResolver | None,
    policy: str,
    entity: str,
    rationale: str,
    agent_id: str,
    extra_extensions: dict[str, Any] | None = None,
    entity_sei: str | None = None,
) -> SignoffResult:
    """Open a structured sign-off request for a launch-bound agent."""
    if signoff_gate is None:
        # LEG-2: the message names the operator knob (C-8: operator action).
        raise NotEnabledError(
            "structured cell not enabled: ask the operator to set "
            "LEGIS_HMAC_KEY (out-of-band) and relaunch"
        )
    entity_key, ext = resolve_for_entry(identity, entity=entity, entity_sei=entity_sei)
    return signoff_gate.request(
        policy=policy,
        entity_key=entity_key,
        rationale=rationale,
        agent_id=agent_id,
        extensions={**ext, **(extra_extensions or {})},
    )


def read_identity_gaps(
    identity: IdentityResolver | None,
    records: Callable[[], list],
) -> dict[str, Any]:
    """The identity-gap read: which attestations' SEIs does Loomweave report dead?

    GOV-2 honesty: a bare ``[]`` when Loomweave is unwired would read as an
    all-clear on exactly the condition this read exists to catch, so the
    payload always discriminates ``status: "unavailable"`` (could not check,
    with reasons) from ``status: "checked"`` (checked, possibly zero gaps).
    ``records`` is called only when a check can actually run.
    """
    from legis.governance.gaps import find_orphan_gaps

    if identity is None or identity.client is None:
        return {
            "status": "unavailable",
            "gaps": [],
            "unavailable": [{"reason": "loomweave client not configured"}],
        }
    gaps = find_orphan_gaps(records(), identity.client)
    return {
        "status": "checked",
        "gaps": [
            {"sei": g.sei, "reason": g.reason, "lineage": g.lineage}
            for g in gaps
        ],
    }


def read_lineage_integrity(
    identity: IdentityResolver | None,
    records: Callable[[], list],
) -> dict[str, Any]:
    """The lineage-integrity read: do recorded snapshots still prefix lineage?

    GOV-1 honesty: three-way status with ``diverged > unverified > verified``
    precedence — a divergence is never masked by an unavailable sibling, and an
    unverifiable lineage is never reported verified. Same unwired discipline as
    ``read_identity_gaps``.
    """
    from legis.governance.gaps import find_lineage_integrity

    if identity is None or identity.client is None:
        return {
            "status": "unavailable",
            "divergences": [],
            "unavailable": [{"reason": "loomweave client not configured"}],
        }
    integrity = find_lineage_integrity(records(), identity.client)
    return {
        "status": (
            "diverged" if integrity.divergences
            else "unverified" if integrity.unavailable
            else "verified"
        ),
        "divergences": [
            {"sei": d.sei, "recorded_length": d.recorded_length,
             "current_length": d.current_length} for d in integrity.divergences
        ],
        "unavailable": [
            {"sei": u.sei, "reason": u.reason} for u in integrity.unavailable
        ],
    }


def _binding_entity_from_backfill(
    records: list[Any], original_seq: int
) -> tuple[EntityKey, str] | None:
    """ADR-0003 recovery: resolve a locator-keyed request through SEI_BACKFILL.

    Walks the verified trail newest-first for a ``SEI_BACKFILL`` event that
    re-keys ``original_seq`` onto a stable SEI; returns the backfilled key and
    content hash, or ``None`` when no usable backfill exists.
    """
    for rec in reversed(records):
        payload = rec.payload
        if payload.get("event") != "SEI_BACKFILL":
            continue
        if payload.get("original_seq") != original_seq:
            continue
        try:
            entity_key = EntityKey.from_dict(payload["entity_key"])
        except (KeyError, TypeError, ValueError):
            continue
        if not entity_key.identity_stable:
            continue
        content_hash = payload.get("extensions", {}).get("loomweave", {}).get(
            "content_hash"
        ) or ""
        return entity_key, content_hash
    return None


def bind_signoff_issue(
    signoff_gate: SignoffGate | None,
    trail_verifier,
    filigree,
    *,
    issue_id: str,
    request_seq: int,
    key: bytes | None = None,
    ledger=None,
) -> dict[str, Any]:
    """Bind a CLEARED structured sign-off to a Filigree issue.

    The single bind decision both adapters drive (Q-H2): fail-closed trail
    verification first, then a recorded and cleared request, then the SEI and
    content hash sourced from the recorded request — never the caller — with
    the ADR-0003 ``SEI_BACKFILL`` recovery for locator-keyed requests, then the
    attach + ledger record via ``bind_signoff_to_issue``.
    """
    from legis.governance.signoff_binding import bind_signoff_to_issue

    if filigree is None:
        # LEG-2: the message names the operator knob (C-8: operator action).
        raise NotEnabledError(
            "filigree binding not enabled: ask the operator to set "
            "FILIGREE_API_URL (out-of-band) and relaunch"
        )
    if signoff_gate is None:
        raise NotEnabledError(
            "structured cell not enabled: ask the operator to set "
            "LEGIS_HMAC_KEY (out-of-band) and relaunch"
        )
    records = verified_records(signoff_gate, trail_verifier, lambda: [])
    request = signoff_gate.request_record(request_seq)
    if request is None:
        raise NoSuchRequestError(f"no sign-off request at seq {request_seq}")
    if not signoff_gate.is_cleared(request_seq):
        raise NotClearedError("sign-off not cleared")
    entity_key = EntityKey.from_dict(request["entity_key"])
    content_hash = request.get("extensions", {}).get("loomweave", {}).get(
        "content_hash"
    ) or ""
    if not entity_key.identity_stable:
        backfilled = _binding_entity_from_backfill(records, request_seq)
        if backfilled is not None:
            entity_key, content_hash = backfilled
    try:
        return bind_signoff_to_issue(
            filigree,
            issue_id=issue_id,
            entity_key=entity_key,
            content_hash=content_hash,
            signoff_seq=request_seq,
            key=key,
            ledger=ledger,
        )
    except ValueError as exc:
        # ADR-0003 fail-closed: a locator-keyed (non-SEI) sign-off cannot be
        # rename-stably bound; the sign-off stands, only the pointer waits.
        raise BindingUnavailableError(str(exc)) from exc


def sign_off(
    signoff_gate: SignoffGate | None,
    *,
    request_seq: int,
    operator_id: str,
    rationale: str = "",
) -> SignoffResult:
    """Operator sign-off on a pending structured request.

    The single service path for clearing a sign-off, so the HTTP route no longer
    reaches past the service layer to the gate (Q-H2).
    """
    if signoff_gate is None:
        # LEG-2: the message names the operator knob (C-8: operator action).
        raise NotEnabledError(
            "structured cell not enabled: ask the operator to set "
            "LEGIS_HMAC_KEY (out-of-band) and relaunch"
        )
    return signoff_gate.sign_off(
        request_seq=request_seq,
        operator_id=operator_id,
        rationale=rationale,
    )


def evaluate_policy(
    grammar: PolicyGrammar,
    *,
    engine: EnforcementEngine | None,
    policy: str,
    target: dict[str, Any],
) -> PolicyEvaluation:
    """Evaluate policy grammar and optionally record UNKNOWN provenance gaps."""
    ev = grammar.evaluate(policy, target)
    if ev.result is PolicyResult.UNKNOWN and engine is not None:
        engine.record_event(
            {
                "event": "UNKNOWN_POLICY",
                "policy": ev.policy,
                "detail": ev.detail,
                "provenance_gap": True,
            }
        )
    return ev
