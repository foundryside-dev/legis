"""Weft seam conformance oracle — legis (PRODUCER) -> warpline (CONSUMER).

SEAM: legis produces per-SEI governance ATTESTATIONS that warpline reads to
decide whether a verification can be skipped (an ``attestation_get``-style read).
The PRODUCER wire is the legis MCP tool ``attestation_get`` (mcp.py
``_tool_attestation_get`` -> ``legis.service.governance.read_sei_attestations``).
There is NO HTTP attestation route (api/app.py serves none); the MCP tool is the
served surface.

This module freezes a shared GOLDEN of legis's per-SEI attestation response and
rechecks the REAL serializer + the REAL MCP wire against it, so a legis-side
rename of an attestation field (``kind``/``content_hash``/``recorded_at``/
``seq``/``signoff_seq``/``status``) — or a change to the ``checked``/
``unavailable`` discriminant — reds here.

RENAME-STABILITY (the property warpline relies on): the attestation is keyed on
the opaque SEI (``entity_key.value`` inside ``signing_fields["entity"]``), NOT on
a locator. After a rename/move the SEI is unchanged, so the attestation still
resolves under the same key — that is exactly why warpline keys its governance
read on ``sei`` (contract.md "Keying"; federation.LegisClient.governance_for_sei).

GOLDEN PROVENANCE (non-circular): the golden was frozen ONCE from the real wire
(SignoffGate + ProtectedGate writing genuine signed records into a real
AuditStore, then call_tool("attestation_get")). The rechecks below load the
golden from the FILE and compare LIVE serializer/wire output to it — they never
regenerate it. Frozen bytes do not move when the serializer changes, so a field
rename in the producer is caught. See fixtures/PROVENANCE.md.

Layered freshness defence (mirrors test_sei_oracle*.py):
  * Layer-1 byte-pin (``test_attestation_golden_byte_pin``): UNMARKED, default
    suite, recomputes the git blob sha1 of the golden file and fails CLOSED on
    any byte drift — even when the producer source is unchanged.
  * Producer-source recheck (``test_*_reproduces_golden``): drives the real
    legis serializer/wire to reproduce the golden's shape AND values.
  * Layer-2 consumer recheck (``test_warpline_consumer_field_names_*``):
    skip-clean against warpline's source/contract — see the HONEST-GAP note.
"""
from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path

import pytest

from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.protected import ProtectedGate, TrailVerifier
from legis.enforcement.signoff import SignoffGate
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.identity.entity_key import EntityKey
from legis.mcp import McpRuntime, call_tool
from legis.service.governance import read_sei_attestations
from legis.store.audit_store import AuditStore

GOLDEN_PATH = (
    Path(__file__).parent / "fixtures" / "legis-warpline-attestation-get.golden.json"
)

# git blob sha1 of the vendored golden. Layer-1 fail-closed pin (UNMARKED).
GOLDEN_BLOB_SHA = "ad894cc0d93cb9e8f5631bfccacbdeacbbae4994"

# Fixed inputs the golden was frozen with — reused by the source recheck so the
# LIVE wire reproduces the SAME bytes. A FixedClock makes recorded_at stable;
# a fresh append-only store makes the seqs (1 PENDING, 2 SIGNED_OFF, 3 OVERRIDE)
# deterministic; the golden EXCLUDES the HMAC signature, so it is key-independent.
_CLOCK_ISO = "2026-06-02T12:00:00+00:00"
_KEY = b"weft-seam-conformance-key"
_POLICY = "protected.attestation"
# Opaque SEI (rename-stable key). Both a signoff_cleared and an operator_override
# attestation are keyed on this one SEI so a single response pins both kinds.
_SEI = "loomweave:eid:0000000000000000000000000000aaaa"


@lru_cache(maxsize=1)
def _load_golden() -> dict:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


class _AdvisoryJudge:
    """Protected-cell judge is advisory; operator_override bypasses it entirely."""

    def evaluate(self, record):  # noqa: ANN001
        return JudgeOpinion(Verdict.BLOCKED, "judge@1", "advisory only")


def _build_attested_store(tmp_path) -> AuditStore:
    """Write a genuine signoff_cleared + operator_override attestation, both keyed
    on ``_SEI``, into a real AuditStore through the real legis write path.

    This is the SAME path the golden was frozen from. It exercises:
      * SignoffGate.request/sign_off -> a real signed SIGNED_OFF record whose
        PENDING join is integrity-bound (read_sei_attestations FORGE-B).
      * ProtectedGate.operator_override -> a real signed OVERRIDDEN_BY_OPERATOR
        record (read_sei_attestations FORGE-A).
    """
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    clock = FixedClock(_CLOCK_ISO)

    signoff = SignoffGate(store, clock, signer=True, key=_KEY)
    req = signoff.request(
        policy=_POLICY,
        entity_key=EntityKey(value=_SEI, identity_stable=True),
        rationale="review",
        agent_id="agent-1",
        extensions={"loomweave": {"content_hash": "blake3:signoff-cleared"}},
    )
    signoff.sign_off(request_seq=req.seq, operator_id="op-1", rationale="ok")

    protected = ProtectedGate(
        store,
        clock,
        judge=_AdvisoryJudge(),
        key=_KEY,
        protected_policies=frozenset({_POLICY}),
    )
    protected.operator_override(
        policy=_POLICY,
        entity_key=EntityKey(value=_SEI, identity_stable=True),
        rationale="release exception approved by security lead",
        operator_id="op-sec-lead",
        file_fingerprint="sha256:abc",
        ast_path="Module/Call[eval]",
        extensions={"loomweave": {"content_hash": "blake3:operator-override"}},
    )
    return store


def _wired_runtime(store: AuditStore) -> McpRuntime:
    """A runtime with BOTH a protected gate and a trail verifier wired, so the
    attestation_get fail-closed pre-gate passes and the verified trail is read."""
    engine = EnforcementEngine(store, FixedClock(_CLOCK_ISO))
    gate = ProtectedGate(
        store,
        FixedClock(_CLOCK_ISO),
        judge=_AdvisoryJudge(),
        key=_KEY,
        protected_policies=frozenset({_POLICY}),
    )
    return McpRuntime(
        agent_id="agent-launch",
        initialized=True,
        engine=engine,
        protected_gate=gate,
        trail_verifier=TrailVerifier(_KEY, frozenset({_POLICY})),
    )


# --- Layer-1: byte-pin (UNMARKED, default suite, fails CLOSED on byte drift) ---
def test_attestation_golden_byte_pin():
    data = GOLDEN_PATH.read_bytes()
    assert _git_blob_sha1(data) == GOLDEN_BLOB_SHA, (
        "legis<->warpline attestation golden drifted from its pinned bytes; "
        "re-freeze it from the real attestation_get wire and update "
        "GOLDEN_BLOB_SHA only after confirming the change is intended (and that "
        "warpline's consumer still reads the new shape)."
    )


# --- Producer-source recheck (non-circular): real serializer reproduces golden -
def test_serializer_reproduces_golden(tmp_path):
    # Field-name pin: drive the REAL read_sei_attestations over the REAL verified
    # records. A rename of any attestation field (kind/content_hash/recorded_at/
    # seq/signoff_seq/status/sei) reds here against the frozen golden.
    store = _build_attested_store(tmp_path)
    live = read_sei_attestations(store.read_all(), _SEI)
    assert live == _load_golden()


def test_mcp_wire_reproduces_golden(tmp_path):
    # Wire pin: the FULL served surface warpline reads — call_tool -> the
    # structuredContent dict. Equals the serializer dict by construction, and
    # additionally exercises the fail-closed verified-trail pre-gate.
    store = _build_attested_store(tmp_path)
    runtime = _wired_runtime(store)
    result = call_tool(runtime, "attestation_get", {"sei": _SEI})
    assert not result.get("isError")
    assert result["structuredContent"] == _load_golden()


def test_both_attestation_kinds_are_pinned():
    # Guard against a one-kind golden silently leaving the other branch's `kind`
    # value un-pinned: the frozen golden MUST carry both producer branches.
    kinds = {a["kind"] for a in _load_golden()["attestations"]}
    assert kinds == {"signoff_cleared", "operator_override"}


def test_attestation_golden_is_keyed_on_sei():
    # RENAME-STABILITY: the golden's `sei` is the opaque loomweave SEI, never a
    # locator. This is the property warpline relies on (it keys its governance
    # read on `sei`), so the seam survives a rename/move on the legis side.
    golden = _load_golden()
    assert golden["status"] == "checked"
    assert golden["sei"] == _SEI
    assert golden["sei"].startswith("loomweave:eid:")


def test_unavailable_discriminant_is_distinct_from_empty_checked(tmp_path):
    # The consumer MUST distinguish 'unavailable' (trail not verifiable -> reverify)
    # from a 'checked' empty list (honestly never attested). A wired-but-absent
    # gate yields the unavailable discriminant the golden's `status` field anchors.
    store = _build_attested_store(tmp_path)
    engine = EnforcementEngine(store, FixedClock(_CLOCK_ISO))
    unwired = McpRuntime(agent_id="x", initialized=True, engine=engine)
    sc = call_tool(unwired, "attestation_get", {"sei": _SEI})["structuredContent"]
    assert sc["status"] == "unavailable"
    assert sc["attestations"] == []
    assert sc["status"] != _load_golden()["status"]


# --- Layer-2: consumer recheck against warpline (HONEST-GAP, skip by default) ---
def _warpline_repo() -> Path | None:
    # OPT-IN ONLY: resolve to a warpline checkout *exclusively* via WARPLINE_REPO.
    # We deliberately do NOT auto-discover the sibling `/home/john/warpline`,
    # because warpline's consumer half is mid-flight (the verification-freshness
    # rework lives in `federation.py`); auto-running source-string assertions
    # against an in-flight branch would couple the default legis suite to warpline
    # churn. So the default suite SKIPS this honest-gap with a clear reason; an
    # operator who wants the recheck points WARPLINE_REPO at a checkout explicitly.
    env = os.environ.get("WARPLINE_REPO")
    if not env:
        return None
    repo = Path(env)
    return repo if (repo / "src" / "warpline").exists() else None


def test_warpline_consumer_field_names_honest_gap():
    # HONEST-GAP (consumer half not yet wired). warpline main defines the seam
    # PROTOCOL — federation.LegisClient.governance_for_sei(sei) -> list[dict] —
    # but the transport is NOT wired: _consult_legis reports the read "disabled"
    # with a recruiting fix that NAMES "the legis MCP governance read". There are
    # therefore NO attestation field-name literals (kind/content_hash/recorded_at/
    # seq/signoff_seq) in warpline to assert against yet, so a field-granularity
    # Layer-2 pin is not feasible without fabricating one.
    #
    # SKIP BY DEFAULT (opt-in via WARPLINE_REPO): when a checkout is supplied we
    # pin the one load-bearing property that IS present — the consumer seam is
    # keyed on the SEI (rename-stable), the property the producer golden
    # guarantees — and that its recruiting fix points back at THIS producer's MCP
    # read. When warpline wires governance_for_sei over attestation_get and starts
    # reading the `kind`/`content_hash` fields, replace this with a real
    # field-name recheck against warpline's consumer source to close the seam
    # two-sided.
    repo = _warpline_repo()
    if repo is None:
        pytest.skip(
            "warpline consumer recheck is opt-in (set WARPLINE_REPO); the consumer "
            "half is unwired/in-flight, so this is an honest-gap, not a satisfied pin"
        )
    federation = (repo / "src" / "warpline" / "federation.py").read_text(encoding="utf-8")
    # The seam is keyed on the SEI (rename-stable) — the producer-side guarantee.
    assert "def governance_for_sei(self, sei: str)" in federation
    # The recruiting fix points the consumer at the legis MCP governance read —
    # i.e. THIS producer's attestation_get wire.
    assert "legis MCP governance read" in federation
