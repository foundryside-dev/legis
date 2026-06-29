"""Ingest a Wardline scan result — select the gate population, carry the tiers.

legis does not call Wardline (Wardline has no HTTP); the agent hands legis the
MCP scan response. legis never re-analyzes — it reads findings and governs. The
trust tiers are Wardline's, carried verbatim as the one suite vocabulary.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from legis.crypto.signing import verify

# The shared trust vocabulary (Wardline taints.py) — carried, never re-derived.
TRUST_TIERS: frozenset[str] = frozenset({
    "INTEGRAL", "ASSURED", "GUARDED", "EXTERNAL_RAW",
    "UNKNOWN_RAW", "UNKNOWN_GUARDED", "UNKNOWN_ASSURED", "MIXED_RAW",
})
SUPPRESSION_PROOF_KEYS: frozenset[str] = frozenset({
    "suppression_proof",
    "suppression_ticket",
    "suppression_reason",
})
MAX_FINDINGS = 500
# The batch key carrying the findings list. A shared constant (not a bare string
# scattered across producer + consumer) is the cross-impl contract anchor: a
# silent producer rename leaves this key ABSENT, which `active_defects` rejects
# as malformed rather than reading as zero defects under a green status (G1).
FINDINGS_KEY = "findings"
# The defect-class kind token: the gate population is exactly the findings whose
# ``kind`` equals this value.
DEFECT_KIND = "defect"
# Wardline's finding-kind vocabulary (wardline core/finding.py ``Kind``), carried
# verbatim like ``TRUST_TIERS`` — never re-derived. ``active_defects`` gates on
# ``DEFECT_KIND``; the OTHER known kinds are legitimately not-a-defect and skipped.
# A kind OUTSIDE this set is drift/tamper — e.g. a producer rename of the
# ``"defect"`` token (``defect`` -> ``vulnerability``), re-signed HMAC-clean — and
# is rejected LOUDLY, never silently skipped out of the gate population under a
# green status (G1 twin, the value axis of the absent-``findings``-key G1; the
# signature proves authenticity, not vocabulary conformance).
KNOWN_KINDS: frozenset[str] = frozenset({
    "defect", "fact", "classification", "metric", "suggestion",
})
ARTIFACT_SIGNATURE_FIELD = "artifact_signature"
ARTIFACT_PROVENANCE_FIELDS: tuple[str, ...] = (
    "scanner_identity",
    "rule_set_version",
    "commit_sha",
    "tree_sha",
)


class WardlineSeverity(str, Enum):
    rank: int

    CRITICAL = ("CRITICAL", 4)
    ERROR = ("ERROR", 3)
    WARN = ("WARN", 2)
    INFO = ("INFO", 1)
    NONE = ("NONE", 0)

    def __new__(cls, value: str, rank: int) -> "WardlineSeverity":
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj.rank = rank
        return obj


class WardlinePayloadError(ValueError):
    """A Wardline scan payload is not shaped like the trusted wire contract."""


class ArtifactStatus(str, Enum):
    """How far the Wardline artifact's provenance verified (str,Enum — the member
    IS its bare-string wire value, so records serialize byte-identically)."""

    VERIFIED = "verified"
    DIRTY = "dirty"
    UNVERIFIED = "unverified"


class ArtifactStatusReason(str, Enum):
    """The machine-readable *why* behind an ``artifact_status`` (str,Enum —
    bare-string wire), the honesty surface for the wardline->legis attest seam.

    The defect this kills (PDR-0023): an ``"unverified"`` posture is otherwise
    byte-indistinguishable between "unverified because nobody configured a
    verification key" (a DISABLED/not-configured state) and "unverified because
    a present key failed to verify" (tamper/mismatch). A bare ``"unverified"``
    confesses degradation without saying which — a confident-degraded answer
    masquerading as a normal state. Every status now carries its reason so an
    agent/operator can distinguish the cases without re-deriving them.

    Note that with the current code path ``KEY_ABSENT`` is the ONLY route to
    ``UNVERIFIED`` — an actually-present key that fails to verify raises
    :class:`WardlinePayloadError` (a loud red), never a quiet ``"unverified"``.
    The reason makes that contract legible on the wire instead of implicit in
    the control flow: a downstream consumer reading ``key_absent`` knows the
    posture is "verification is DISABLED on this server", not "verification ran
    and failed". The remaining members are emitted so the field is never absent
    (no status without its provenance — the lead-summary discipline)."""

    # UNVERIFIED: no LEGIS_WARDLINE_ARTIFACT_KEY configured — verification is
    # DISABLED, not failed. This is the recruiting signal legis doctor ambers on.
    KEY_ABSENT = "key_absent"
    # DIRTY: an unsigned dirty-tree dev artifact, governed unsigned.
    DIRTY_DEV_ARTIFACT = "dirty_dev_artifact"
    # VERIFIED: a configured key verified the signed provenance.
    SIGNATURE_VERIFIED = "signature_verified"


# --- Weft canonical reason vocabulary (G1) -------------------------------------
# Source of truth: /home/john/weft/contracts/weft-reason-vocab.json (the closed
# 11 reason_classes + the carrier rule). ``ArtifactStatusReason`` values above are
# DOMAIN terms (the shipped wire field ``artifact_status_reason``), NOT canonical.
# This map adds a canonical ``reason_class`` ALONGSIDE the domain term — additive,
# never renaming or dropping the shipped field. The domain term stays in
# ``cause`` so no information is lost. Mappings (justified):
#   key_absent          -> disabled  (verification capability not configured / off)
#   dirty_dev_artifact  -> stale     (a real-but-degraded dev artifact, governed
#                                      unsigned: accepted yet older/looser than the
#                                      clean-tree signed anchor — qualified trust)
#   signature_verified  -> clean     (earned, complete true-negative; carrier omits
#                                      cause + fix)
# A subset-conformance test (tests/wardline/test_reason_vocab_conformance.py)
# asserts this map's range stays within the canonical 11 and covers every
# ArtifactStatusReason member, and that the carrier rule holds.
ARTIFACT_STATUS_REASON_TO_CANONICAL: Mapping[ArtifactStatusReason, str] = {
    ArtifactStatusReason.KEY_ABSENT: "disabled",
    ArtifactStatusReason.DIRTY_DEV_ARTIFACT: "stale",
    ArtifactStatusReason.SIGNATURE_VERIFIED: "clean",
}

# The carrier (cause + fix) for each non-clean canonical reason_class. The domain
# term lives in ``cause``; ``fix`` is MANDATORY on every non-clean carrier and
# omitted only for ``clean`` (``signature_verified``).
_REASON_CARRIER: Mapping[ArtifactStatusReason, dict[str, str]] = {
    ArtifactStatusReason.KEY_ABSENT: {
        "cause": "key_absent: no LEGIS_WARDLINE_ARTIFACT_KEY configured — "
        "artifact verification is disabled, not failed.",
        "fix": "Configure LEGIS_WARDLINE_ARTIFACT_KEY to enable signed-artifact "
        "verification (operator, out-of-band).",
    },
    ArtifactStatusReason.DIRTY_DEV_ARTIFACT: {
        "cause": "dirty_dev_artifact: an unsigned dirty-tree dev artifact, "
        "governed unsigned — degraded relative to a clean-tree signed anchor.",
        "fix": "Commit your working tree for a signed Wardline artifact "
        "(signing is clean-tree-only).",
    },
}


def canonical_reason_carrier(reason: ArtifactStatusReason) -> dict[str, str]:
    """The Weft-canonical carrier for an ``artifact_status_reason``.

    Returns ``{"reason_class": <one of the canonical 11>}`` for a ``clean`` result
    (carrier omits ``cause`` + ``fix``), and
    ``{"reason_class", "cause", "fix"}`` for every non-clean result (``fix`` is
    MANDATORY). This is ADDITIVE: callers merge it alongside the shipped
    ``artifact_status_reason`` field; the domain term is preserved in ``cause``.
    """
    reason_class = ARTIFACT_STATUS_REASON_TO_CANONICAL[reason]
    carrier: dict[str, str] = {"reason_class": reason_class}
    if reason_class != "clean":
        carrier.update(_REASON_CARRIER[reason])
    return carrier


class ScanOutcome(str, Enum):
    """The ``scan_route`` boundary outcome (str,Enum — bare-string wire).

    ``ROUTED`` — findings were governed into the configured cell. A dirty working
    tree is not a malformed payload — it is "the dev environment is not ready for
    a signed artifact yet". wardline emits an UNSIGNED, ``dirty: true`` dev
    artifact for this case (signing stays clean-tree-only); legis classifies it
    as the typed amber ``SKIPPED_DIRTY_TREE`` state, NOT a generic red, so a
    harness can tell "commit first" apart from "legis/the scan is broken".
    """

    ROUTED = "ROUTED"
    SKIPPED_DIRTY_TREE = "SKIPPED_DIRTY_TREE"


# Back-compat alias for the bare-string constant callers/tests imported before the
# enum existed; ``== "SKIPPED_DIRTY_TREE"`` still holds (str,Enum).
SKIPPED_DIRTY_TREE = ScanOutcome.SKIPPED_DIRTY_TREE


class WardlineDirtyTreeError(Exception):
    """A dirty-tree dev artifact arrived where signed CI provenance is required.

    Deliberately NOT a ``WardlinePayloadError`` (which boundaries map to a
    generic red — HTTP 422 / MCP ``INVALID_ARGUMENT``): the whole point is that
    this amber/skipped state is *distinguishable* from a malformed-or-tampered
    payload. Raised only in the CI posture (artifact key configured) when the
    dirty dev artifact is unsigned and the dev-mode opt-in is off. Boundaries
    catch it and surface a typed ``SKIPPED_DIRTY_TREE`` outcome.
    """

    # A ScanOutcome member (via the alias). Boundaries serialize the whole
    # ``to_payload()`` shape; ``reason`` resolves both as a class attribute
    # (legacy ``WardlineDirtyTreeError.reason == "SKIPPED_DIRTY_TREE"`` checks)
    # and on the instance, as the bare ``"SKIPPED_DIRTY_TREE"`` string.
    reason = SKIPPED_DIRTY_TREE

    # Stable wire vocabulary (enum-like once published; do not casually rename).
    DEFAULT_POSTURE = "ci_artifact_key_configured"
    DEFAULT_CAUSE = "dirty_unsigned_artifact"
    DEFAULT_REMEDIATION = (
        "Commit your working tree for a signed Wardline artifact "
        "(signing is clean-tree-only).",
        "Or set LEGIS_WARDLINE_ALLOW_DIRTY=1 (operator, out-of-band) to govern "
        "the unsigned dirty artifact in dev — recorded as 'dirty', never 'verified'.",
    )

    def __init__(
        self,
        message: str,
        *,
        posture: str = DEFAULT_POSTURE,
        cause: str = DEFAULT_CAUSE,
        remediation: tuple[str, ...] | None = None,
    ) -> None:
        super().__init__(message)
        # Shadow the class attribute on the instance so ``exc.reason`` holds even
        # if a subclass forgets it; the value is identical.
        self.reason = SKIPPED_DIRTY_TREE
        self.posture = posture
        self.cause = cause
        self.remediation: list[str] = list(
            remediation if remediation is not None else self.DEFAULT_REMEDIATION
        )

    def to_payload(self) -> dict[str, Any]:
        """The single source of the SKIPPED_DIRTY_TREE response both transports
        serialize (MCP structuredContent + HTTP body), so they cannot drift.

        Honest + actionable (C-10(d)): names the posture, the cause, and what to
        do — while governing nothing (``routed == []``). It is RESPONSE CONTENT
        only; it adds no call argument and grants no authority.
        """
        return {
            "outcome": self.reason,
            "routed": [],
            "reason": self.reason,
            "posture": self.posture,
            "cause": self.cause,
            "remediation": list(self.remediation),
            "detail": str(self),
        }


def wardline_artifact_fields(scan: Mapping[str, Any]) -> dict[str, Any]:
    """The Wardline artifact payload covered by ``artifact_signature``."""
    if not isinstance(scan, Mapping):
        raise WardlinePayloadError("scan must be an object")
    return {
        str(key): value
        for key, value in scan.items()
        if key != ARTIFACT_SIGNATURE_FIELD
    }


def verify_wardline_artifact(
    scan: Mapping[str, Any],
    artifact_key: bytes | None,
    *,
    allow_dirty: bool = False,
) -> dict[str, Any]:
    """Validate optional server-required artifact authentication.

    When ``artifact_key`` is configured, the scan must carry signed scanner,
    rule-set, commit, and tree provenance. Without a configured key we still
    record any supplied metadata, but mark it explicitly unverified.

    Dirty-tree dev artifacts (``dirty: true`` + no signature — wardline
    ``--allow-dirty``) are a typed amber case, never a generic red:

    * keyless dev posture — already permissive; the scan governs, but the
      dirty marker is recorded honestly (``artifact_status == "dirty"``) so a
      dirty dev scan is distinguishable from a clean unsigned one.
    * CI posture (``artifact_key`` configured) — by default a dirty dev
      artifact raises :class:`WardlineDirtyTreeError` (the boundary surfaces a
      typed ``SKIPPED_DIRTY_TREE`` outcome). ``allow_dirty`` is the explicit
      server-side dev-mode opt-in that lets legis govern it UNSIGNED, recorded
      as ``"dirty"`` (never ``"verified"``).

    The relaxation is scoped to exactly ``dirty is True AND no signature``: a
    signed payload still verifies normally (so a forged signature stays red),
    and a clean unsigned payload still requires a signature (``allow_dirty``
    relaxes only the dirty case, not "any unsigned"). ``dirty`` is checked as
    strict boolean ``True`` because the scan dict is caller-controlled.
    """
    fields = wardline_artifact_fields(scan)
    provenance: dict[str, Any] = {
        "artifact_status": ArtifactStatus.UNVERIFIED,
        # The honesty surface: a bare "unverified" cannot distinguish
        # key-absent (verification DISABLED) from a key that failed to verify.
        # KEY_ABSENT is the only route to UNVERIFIED here (a present-but-bad key
        # raises WardlinePayloadError), so name it explicitly on the wire.
        "artifact_status_reason": ArtifactStatusReason.KEY_ABSENT,
        # Weft-canonical reason_class ALONGSIDE the domain term (G1, additive).
        **canonical_reason_carrier(ArtifactStatusReason.KEY_ABSENT),
    }
    for key in ARTIFACT_PROVENANCE_FIELDS:
        value = scan.get(key)
        if isinstance(value, str) and value:
            provenance[key] = value

    signature_present = isinstance(scan.get(ARTIFACT_SIGNATURE_FIELD), str) and bool(
        scan.get(ARTIFACT_SIGNATURE_FIELD)
    )
    is_dirty_dev_artifact = scan.get("dirty") is True and not signature_present

    if artifact_key is None:
        if is_dirty_dev_artifact:
            provenance["artifact_status"] = ArtifactStatus.DIRTY
            provenance["artifact_status_reason"] = (
                ArtifactStatusReason.DIRTY_DEV_ARTIFACT
            )
            # Re-derive the canonical carrier for the new reason (key_absent ->
            # dirty_dev_artifact: disabled -> stale, with its own cause + fix).
            provenance.update(
                canonical_reason_carrier(ArtifactStatusReason.DIRTY_DEV_ARTIFACT)
            )
        return provenance

    if is_dirty_dev_artifact:
        if not allow_dirty:
            raise WardlineDirtyTreeError(
                "wardline emitted an unsigned dirty-tree dev artifact "
                "(dirty: true); signing is clean-tree-only. Commit for a "
                "signed artifact, or set LEGIS_WARDLINE_ALLOW_DIRTY=1 to "
                "govern it unsigned in dev."
            )
        return {
            "artifact_status": ArtifactStatus.DIRTY,
            "artifact_status_reason": ArtifactStatusReason.DIRTY_DEV_ARTIFACT,
            **canonical_reason_carrier(ArtifactStatusReason.DIRTY_DEV_ARTIFACT),
            **{key: value for key in ARTIFACT_PROVENANCE_FIELDS
               if isinstance(value := scan.get(key), str) and value},
        }

    missing = [
        key for key in ARTIFACT_PROVENANCE_FIELDS
        if not isinstance(scan.get(key), str) or not scan[key]
    ]
    if missing:
        raise WardlinePayloadError(
            f"Wardline artifact missing required field(s): {', '.join(missing)}"
        )

    signature = scan.get(ARTIFACT_SIGNATURE_FIELD)
    if not isinstance(signature, str) or not signature:
        raise WardlinePayloadError("Wardline artifact signature is required")
    if not verify(fields, signature, artifact_key):
        raise WardlinePayloadError("Wardline artifact signature does not verify")
    return {
        "artifact_status": ArtifactStatus.VERIFIED,
        "artifact_status_reason": ArtifactStatusReason.SIGNATURE_VERIFIED,
        # clean: the carrier is just reason_class (omits cause + fix).
        **canonical_reason_carrier(ArtifactStatusReason.SIGNATURE_VERIFIED),
        **{key: scan[key] for key in ARTIFACT_PROVENANCE_FIELDS},
        "artifact_signature": signature,
    }


@dataclass(frozen=True)
class WardlineFinding:
    rule_id: str
    message: str
    severity: WardlineSeverity
    kind: str
    fingerprint: str
    qualname: str | None
    properties: Mapping[str, Any]
    suppression_state: str

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "WardlineFinding":
        missing = [
            key
            for key in ("rule_id", "message", "severity", "kind", "fingerprint")
            if key not in d
        ]
        if missing:
            raise WardlinePayloadError(
                f"finding missing required field(s): {', '.join(missing)}"
            )
        severity_raw = d["severity"]
        if not isinstance(severity_raw, str):
            raise WardlinePayloadError("finding severity must be a string")
        try:
            severity = WardlineSeverity[severity_raw]
        except KeyError as exc:
            raise WardlinePayloadError(f"unknown Wardline severity: {severity_raw}") from exc
        properties = d.get("properties", {})
        if not isinstance(properties, Mapping):
            raise WardlinePayloadError("finding properties must be an object")
        # Properties are write-only evidence (carried verbatim into the record,
        # never acted on) — they may hold trust tiers AND diagnostics (sink,
        # callee, markers). legis does not constrain the values to the tier
        # vocabulary; that would reject realistic scans for no governance gain.
        qualname = d.get("qualname")
        if qualname is not None and not isinstance(qualname, str):
            raise WardlinePayloadError("finding qualname must be a string or null")
        # W3 (weft-ef79348eb2): Wardline renamed this per-finding key
        # ``suppressed`` -> ``suppression_state`` across all surfaces incl. the
        # SIGNED artifact. legis reads the new key. The missing-key default stays
        # ``"active"`` — a clean break: a stale finding (old key only) reads as
        # active and OVER-gates (fail-safe; never silently drops a real defect).
        suppression_state = d.get("suppression_state", "active")
        if not isinstance(suppression_state, str):
            raise WardlinePayloadError("finding suppression_state must be a string")
        for key in ("rule_id", "message", "kind", "fingerprint"):
            if not isinstance(d[key], str) or not d[key]:
                raise WardlinePayloadError(f"finding {key} must be a non-empty string")
        return cls(
            rule_id=d["rule_id"],
            message=d["message"],
            severity=severity,
            kind=d["kind"],
            fingerprint=d["fingerprint"],
            qualname=qualname,
            properties=dict(properties),
            suppression_state=suppression_state,
        )


# Suppression states. ``active`` defects are the gate population. Agent-initiated
# suppressions (``waived`` / ``suppressed``) must carry proof — an agent must not
# be able to silently dismiss a defect. Non-agent suppressions
# (``baselined`` / ``judged``) are simply not active and carry no proof. Any
# other state is malformed and rejected.
class Suppressed(str, Enum):
    """The finding suppression-state vocabulary (str,Enum — bare-string wire).

    The ``suppression_state`` field stays ``str`` on the wire-facing dataclass so
    the validation timing is unchanged (any string is accepted off the wire; only
    a *defect* with an out-of-vocabulary state is rejected, in ``active_defects``).
    This enum is the single source of truth for the vocabulary — members compare
    and hash equal to their strings, so the frozensets below match the bare
    ``suppression_state`` strings carried verbatim from the scan. (W3 renamed the
    KEY ``suppressed`` -> ``suppression_state``; these VALUES are unchanged.)
    """

    ACTIVE = "active"
    WAIVED = "waived"
    SUPPRESSED = "suppressed"
    BASELINED = "baselined"
    JUDGED = "judged"


AGENT_SUPPRESSED: frozenset[Suppressed] = frozenset({Suppressed.WAIVED, Suppressed.SUPPRESSED})
NON_AGENT_SUPPRESSED: frozenset[Suppressed] = frozenset(
    {Suppressed.BASELINED, Suppressed.JUDGED}
)


def _has_suppression_proof(finding: Mapping[str, Any]) -> bool:
    """True if suppression proof is present — top-level OR inside ``properties``.

    Wardline keeps ``suppression_reason`` at the finding's top level; other
    producers may nest it in ``properties``. legis accepts proof in either
    location (it carries the value as evidence; it does not interpret it).
    """
    nested = finding.get("properties", {})
    if not isinstance(nested, Mapping):
        nested = {}

    def _present(source: Mapping[str, Any]) -> bool:
        return any(
            isinstance(source.get(key), str) and bool(source[key].strip())
            for key in SUPPRESSION_PROOF_KEYS
        )

    return _present(finding) or _present(nested)


def active_defects(scan: Mapping[str, Any]) -> list[WardlineFinding]:
    """The gate population: active (non-suppressed) DEFECT findings."""
    if not isinstance(scan, Mapping):
        raise WardlinePayloadError("scan must be an object")
    # Presence is required, not defaulted: an ABSENT key is drift/tamper (e.g. a
    # producer rename ``findings`` -> ``findings_list``, re-signed HMAC-clean) and
    # must be loud, never a silent empty gate population under a green status (G1).
    # A genuinely clean scan still carries ``findings: []`` (key present, empty).
    if FINDINGS_KEY not in scan:
        raise WardlinePayloadError(
            f"scan is missing the required '{FINDINGS_KEY}' key "
            "(a renamed or dropped findings key must not read as zero defects)"
        )
    raw_findings = scan[FINDINGS_KEY]
    if not isinstance(raw_findings, list):
        raise WardlinePayloadError("scan findings must be a list")
    if len(raw_findings) > MAX_FINDINGS:
        raise WardlinePayloadError(f"scan findings exceeds maximum batch size {MAX_FINDINGS}")
    out: list[WardlineFinding] = []
    for raw in raw_findings:
        if not isinstance(raw, Mapping):
            raise WardlinePayloadError("each finding must be an object")
        f = WardlineFinding.from_wire(raw)
        # G1 twin (value axis): an unknown kind is drift/tamper, not a finding to
        # silently skip. A defect whose kind token drifted out of Wardline's
        # vocabulary (re-signed HMAC-clean) would otherwise fall through the
        # ``!= DEFECT_KIND`` skip and vanish from the gate population under a green
        # status. Reject it loudly; only then treat KNOWN non-defect kinds as the
        # legitimately-excluded population.
        if f.kind not in KNOWN_KINDS:
            raise WardlinePayloadError(
                f"finding has unknown kind {f.kind!r} "
                "(not in the Wardline kind vocabulary; a renamed or unknown kind "
                "must not silently drop a defect from the gate population)"
            )
        if f.kind != DEFECT_KIND:
            continue
        if f.suppression_state == Suppressed.ACTIVE:
            out.append(f)
            continue
        if f.suppression_state in AGENT_SUPPRESSED:
            if not _has_suppression_proof(raw):
                raise WardlinePayloadError(
                    "suppressed defect must carry suppression proof"
                )
            continue
        if f.suppression_state in NON_AGENT_SUPPRESSED:
            continue
        raise WardlinePayloadError(
            f"unsupported suppression state for defect: {f.suppression_state}"
        )
    return out
