"""Extracted governance decision logic — transport-agnostic.

Functions added here take their dependencies explicitly (no closures, no
globals) and, when they signal failure, raise ``ServiceError`` subclasses —
never a transport error. (``resolve_for_record`` itself propagates no errors.)
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
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
from legis.enforcement.verdict import SignoffState, Verdict
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
      Loomweave ``resolve_sei`` transport, resolves the submitted ``entity``
      locator, and records only when both resolve to the same live SEI. A
      non-resolving or unbound SEI raises :class:`UnresolvedInputError`
      (weft-reason ``unresolved_input``) and the caller records NOTHING — never
      a locator-keyed record masquerading as a stable bind or evidence on an
      unrelated stable identity.
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
    locator_resolution = identity.resolve(entity)
    if (
        locator_resolution.alive is not True
        or not locator_resolution.entity_key.identity_stable
        or locator_resolution.entity_key != resolution.entity_key
    ):
        locator_value = locator_resolution.entity_key.value
        raise UnresolvedInputError(
            cause=(
                f"entity_sei {entity_sei!r} resolved live but does not match "
                f"entity {entity!r}; entity resolved to {locator_value!r}"
            ),
            fix=(
                "Submit the SEI that Loomweave resolves for the supplied entity, "
                "or omit entity_sei and submit the entity as a locator/symbol so "
                "legis can bind it itself."
            ),
        )
    ext: dict = {}
    if locator_resolution.alive is not None:
        ext["loomweave"] = {
            "alive": locator_resolution.alive,
            "content_hash": locator_resolution.content_hash,
            "lineage_snapshot": locator_resolution.lineage_snapshot,
            "identity_resolution_status": locator_resolution.identity_resolution_status,
            "lineage_snapshot_status": locator_resolution.lineage_snapshot_status,
        }
    return locator_resolution.entity_key, ext


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


def read_sei_attestations(verified_runtime_records: list, sei: str) -> dict[str, Any]:
    """Per-SEI human-cleared attestation facts from the VERIFIED governance trail.

    ASYMMETRIC ERROR RULE: a FALSE "attested" lets warpline skip reverify on
    un-cleared code (security hole); an OMITTED attestation only wastes work
    (safe). Every ambiguous/failure case therefore resolves toward "not attested"
    — omit the record, never surface it. ``verified_runtime_records`` MUST already
    have come through ``verified_records`` — the handler guarantees this via the
    protected-gate + trail-verifier pre-gate, and a tampered protected trail has
    already raised AuditIntegrityError before this function is called. The
    parameter is named for that contract: a future caller passing raw
    ``_engine(runtime).records`` is then a self-documenting mistake. This function
    takes a MATERIALIZED list (not a callable) — a bare list cannot carry the
    verified/unverified distinction, so the gate decision lives in the handler.

    THE FORGE-PROOF DISCRIMINATOR (Task 8, owner-ratified). Two kinds are admitted,
    and ONLY when every distinguishing/content field is COVERED BY A SIGNATURE — so
    membership in the verified set actually proves the field is authentic:

    * ``operator_override`` — a protected operator-override verdict. Admit only when
      ``judge_metadata_signature`` is present on the candidate (the marker that
      proves THIS record was in the verified selection — a marker-less injected
      record rides through ``_requires_verification`` UNVERIFIED, so keying on the
      bare ``judge_verdict`` is forgeable), ``judge_verdict == OVERRIDDEN_BY_OPERATOR``
      (signed at signing_fields["verdict"], protected.py — FORGE-A is closed:
      mutating it breaks the signature and fails closed upstream), ``protected_cell
      is True`` (signed), the inline ``loomweave.content_hash`` is non-empty
      (signed), and entity_key.value == sei AND entity_key.identity_stable
      (the SIGNED entity dict — never the unsigned top-level identity_stable dup).
    * ``signoff_cleared`` — a SIGNED_OFF record carrying a ``signoff_signature``
      (the verified-selection marker), whose joined PENDING request (by the signed
      ``request_seq``) is INTEGRITY-BOUND: recompute ``content_hash`` over the FULL
      stored PENDING payload and require it == the signed ``request_payload_hash``
      (FORGE-B: a pointer is not integrity; mutating the PENDING's content_hash
      breaks this match). The surfaced content_hash is the PENDING's
      ``loomweave.content_hash`` (the SIGNED_OFF carries none of its own), required
      non-empty, and the entity is read from the SIGNED entity dict == sei AND
      identity_stable.

    OMITTED: chill/coached self-clears, unsigned/procedural sign-offs, BLOCKED
    verdicts, empty content_hash, cross-SEI, identity_stable False. WHEN IN DOUBT,
    OMIT. The classifier never re-verifies signatures (the pre-gate already did);
    it ONLY keys off fields inside signing_fields/signoff_signing_fields and
    independently integrity-checks the sign-off join (which crosses a signature
    boundary the SIGNED_OFF's own signature covers only via request_payload_hash).

    Returns status='checked' with the admitted attestations (possibly empty — an
    empty result here is HONEST: the trail WAS verified, the SEI simply has no
    human clearance). The handler owns the status='unavailable' pre-gate for the
    no-key / engine-only case (an unverifiable trail must not be read here).
    """
    from legis.canonical import content_hash as _content_hash

    records = list(verified_runtime_records)
    attestations: list[dict[str, Any]] = []

    for rec in records:
        payload = rec.payload
        ext = payload.get("extensions", {}) or {}

        # Entity must be the SIGNED entity_key dict (value + identity_stable both
        # inside signing_fields["entity"]); the top-level payload["identity_stable"]
        # is an unsigned duplicate — never read it.
        entity = payload.get("entity_key")
        if not isinstance(entity, dict):
            continue
        if entity.get("value") != sei or entity.get("identity_stable") is not True:
            continue

        # --- operator_override -------------------------------------------------
        # PRECONDITION 1: the signature marker proves this record verified.
        if "judge_metadata_signature" in ext and "signoff_state" not in ext:
            if ext.get("judge_verdict") != Verdict.OVERRIDDEN_BY_OPERATOR.value:
                continue  # BLOCKED / ACCEPTED protected verdicts are not clearances
            if ext.get("protected_cell") is not True:
                continue
            content = (ext.get("loomweave", {}) or {}).get("content_hash") or ""
            if not content:
                continue
            attestations.append(
                {
                    "kind": "operator_override",
                    "content_hash": content,
                    "recorded_at": payload.get("recorded_at"),
                    "seq": rec.seq,
                }
            )
            continue

        # --- signoff_cleared ---------------------------------------------------
        # PRECONDITION 1: signoff_signature marker proves this record verified.
        if "signoff_signature" in ext and ext.get("signoff_state") == SignoffState.SIGNED_OFF.value:
            request_seq = ext.get("request_seq")
            signed_request_hash = ext.get("request_payload_hash")
            if request_seq is None or not signed_request_hash:
                continue
            # FORGE-B: join the PENDING by its seq COLUMN, then recompute the hash
            # over the FULL stored PENDING payload and require it == the signed
            # request_payload_hash. A pointer alone is not integrity.
            pending_payload = None
            for cand in records:
                cand_ext = cand.payload.get("extensions", {}) or {}
                if (
                    cand.seq == request_seq
                    and cand_ext.get("signoff_state") == SignoffState.PENDING.value
                ):
                    pending_payload = cand.payload
                    break
            if pending_payload is None:
                continue
            if _content_hash(pending_payload) != signed_request_hash:
                continue  # PENDING content_hash mutated -> hash no longer matches
            content = (
                (pending_payload.get("extensions", {}) or {}).get("loomweave", {}) or {}
            ).get("content_hash") or ""
            if not content:
                continue
            attestations.append(
                {
                    "kind": "signoff_cleared",
                    "content_hash": content,
                    "recorded_at": payload.get("recorded_at"),
                    "seq": rec.seq,
                    "signoff_seq": request_seq,
                }
            )

    return {"status": "checked", "sei": sei, "attestations": attestations}


_POSTURE_BY_KIND = {
    "operator_override": "protected_override",   # provable: protected_cell + OVERRIDDEN_BY_OPERATOR signed
    "signoff_cleared": "operator_signoff",       # provable: SIGNED_OFF + integrity-bound request
}
# Three coupled points: read_sei_attestations' admitted kinds, these map keys, and the schema's
# `posture` enum. A new clearance kind must update all three. reasons = clearance-kind code (WHAT
# happened); posture = provable mechanism (HOW) — distinct axes, 1:1 in v1.


def _is_rfc3339(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def read_governance_for_sei(verified_runtime_records: list, sei: str) -> dict[str, Any]:
    """Per-SEI VERIFIED GOVERNANCE CLEARANCES as the ``governance_read.v1`` envelope.

    A pure PROJECTION of ``read_sei_attestations`` (the forge-proof admitted set) — adds NO admission
    logic and reads NO unsigned field, inheriting the signature-coverage/asymmetric-error guarantees.
    A clearance whose ``recorded_at`` is absent or non-RFC3339, or whose ``kind`` has no known
    posture, is OMITTED (asymmetric-error: a missing clearance only wastes warpline work; a malformed
    one is the unsafe direction). The caller owns the ``status:"unavailable"`` pre-gate via
    ``governance_read_unavailable`` for the no-key / unverifiable-trail case.
    """
    att = read_sei_attestations(verified_runtime_records, sei)
    if att.get("status") != "checked":
        # read_sei_attestations is contracted to return "checked" here (the handler owns the
        # unavailable pre-gate). If that ever changes, fail loud rather than relabel it "checked".
        raise AuditIntegrityError(
            f"read_sei_attestations returned unexpected status {att.get('status')!r}"
        )
    records: list[dict[str, Any]] = []
    for a in att["attestations"]:
        posture = _POSTURE_BY_KIND.get(a["kind"])
        if posture is None:
            continue  # unknown kind -> omit, never fabricate a posture
        if not _is_rfc3339(a.get("recorded_at")):
            continue  # missing / malformed timestamp -> omit, never ship as_of:null
        records.append(
            {
                "sei": sei,
                "disposition": "cleared",
                "posture": posture,
                "authority": "operator",
                "as_of": a["recorded_at"],
                "reasons": [a["kind"]],
                "content_hash": a["content_hash"],
            }
        )
    return {"status": "checked", "sei": sei, "records": records}


def read_governance_for_sei_gate(
    records: list, sei: str, *, hmac_key: str | None, protected_policies
) -> dict[str, Any]:
    """Verified governance read for the CLI/batch path: detect protected -> require key -> verify
    signatures (fail closed) -> project. Mirrors ``evaluate_override_rate_gate`` exactly, so the CLI
    measures the same trust the HTTP/MCP paths do (Constraint 6). The store-level hash-chain check
    (``verify_integrity``) is the CALLER's responsibility BEFORE this call (as in
    ``_check_override_rate``) — both halves are mandatory (Constraint 1).
    """
    protected_present = any(
        _requires_protected_verification(r.payload, protected_policies) for r in records
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
    return read_governance_for_sei(records, sei)


def governance_read_unavailable(sei: str, reason: str) -> dict[str, Any]:
    """The shared ``governance_read.v1`` unavailable envelope (one shape across all 3 adapters).
    NEVER a silent ``checked``/``[]`` — an unverifiable trail reads as "could not check" (GOV-2)."""
    return {"status": "unavailable", "sei": sei, "records": [], "unavailable": [{"reason": reason}]}


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
    from legis.identity.loomweave_client import LoomweaveError

    if identity is None or identity.client is None:
        return {
            "status": "unavailable",
            "gaps": [],
            "unavailable": [{"reason": "loomweave client not configured"}],
        }
    try:
        gaps = find_orphan_gaps(records(), identity.client)
    except LoomweaveError as exc:
        # Loomweave is wired but a check failed mid-flight (outage, timeout,
        # malformed response). The read distinguishes "could not check" from a
        # checked-empty list (GOV-2): degrade to unavailable rather than letting
        # the transport error escape as an INTERNAL_ERROR / 500, which would read
        # as a hard fault on a recoverable condition.
        return {
            "status": "unavailable",
            "gaps": [],
            "unavailable": [{"reason": f"loomweave check failed: {exc}"}],
        }
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
