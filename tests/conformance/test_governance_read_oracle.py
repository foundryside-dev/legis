"""Weft seam conformance oracle — legis governance_read (FROZEN GOLDEN).

SEAM: legis produces per-SEI governance CLEARANCES via the ``governance_read``
MCP tool (``_tool_governance_read`` -> ``legis.service.governance.read_governance_for_sei``).
This module freezes a GOLDEN of legis's governance_read response and rechecks
the REAL serializer + the REAL MCP wire against it, so a legis-side field rename
or projection change reds here.

GOLDEN PROVENANCE (non-circular): the golden was frozen ONCE from the real wire
(ProtectedGate + SignoffGate writing genuine signed records into a real AuditStore,
then call_tool("governance_read")). The rechecks below load the golden from the
FILE and compare LIVE serializer/wire output to it — they never regenerate it.

Mirrors test_warpline_attestation_oracle.py exactly. Key differences:
  - tool is ``governance_read`` (not ``attestation_get``)
  - golden field set is the clearance_record (sei/disposition/posture/authority/
    as_of/reasons/content_hash), NOT attestation fields (kind/content_hash/seq)
  - uses the same _build_attested_store / _SEI / _CLOCK_ISO / _KEY as the
    attestation oracle so content_hashes are cross-checkable

CONTENT_HASH CROSS-CHECK (test_content_hashes_match_attestation_golden): the
clearance records' content_hash values must match the attestation golden's
attestations' content_hash values (same records, different projection).

Layered freshness defence:
  * Layer-1 byte-pin (``test_governance_read_golden_byte_pin``): UNMARKED, recomputes
    the git blob sha1 and fails CLOSED on any byte drift.
  * Producer recheck (``test_mcp_wire_reproduces_golden``): drives real call_tool.
  * Kind-coverage guard (``test_both_clearance_kinds_are_pinned``): golden must
    carry both posture values.
"""
from __future__ import annotations

import hashlib
import json
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

# Reuse the SAME SEI, clock, key, and policy as the attestation oracle so that
# content_hashes are identical between the two goldens (cross-check in test below).
# If this oracle is run against the attestation oracle's store, the projection
# must produce the SAME content_hash values.
_CLOCK_ISO = "2026-06-02T12:00:00+00:00"
_KEY = b"weft-seam-conformance-key"
_POLICY = "protected.attestation"
_SEI = "loomweave:eid:0000000000000000000000000000aaaa"

GOLDEN_PATH = (
    Path(__file__).parent / "fixtures" / "legis-governance-read.golden.json"
)

# git blob sha1 of the committed golden. Layer-1 fail-closed pin (UNMARKED).
GOLDEN_BLOB_SHA = "898fd1a8c159cd717b0b976a5488b5c0c65a86a6"


@lru_cache(maxsize=1)
def _load_golden() -> dict:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


class _AdvisoryJudge:
    """Protected-cell judge is advisory; operator_override bypasses it entirely."""

    def evaluate(self, record):  # noqa: ANN001
        return JudgeOpinion(Verdict.BLOCKED, "judge@1", "advisory only")


def _build_attested_store(tmp_path) -> "AuditStore":  # noqa: F821
    """Write a genuine signoff_cleared + operator_override record, both keyed on _SEI.

    IDENTICAL to test_warpline_attestation_oracle._build_attested_store (same
    parameters, same key, same clock, same policy, same SEI) so the content_hash
    values in the governance_read golden match the attestation golden.
    """
    from legis.store.audit_store import AuditStore

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


def _wired_runtime(store) -> McpRuntime:
    """A runtime with BOTH a protected gate and a trail verifier wired."""
    from legis.store.audit_store import AuditStore  # noqa: F401

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


# --- Layer-1: byte-pin (UNMARKED, default suite) ---

def test_governance_read_golden_byte_pin():
    data = GOLDEN_PATH.read_bytes()
    assert _git_blob_sha1(data) == GOLDEN_BLOB_SHA, (
        "legis governance_read golden drifted from its pinned bytes; "
        "re-freeze it from the real governance_read wire and update "
        "GOLDEN_BLOB_SHA only after confirming the change is intended."
    )


# --- Producer recheck: real wire reproduces golden ---

def test_mcp_wire_reproduces_golden(tmp_path):
    """Drive the REAL call_tool wire. A rename of any clearance_record field
    (sei/disposition/posture/authority/as_of/reasons/content_hash/status) reds here."""
    store = _build_attested_store(tmp_path)
    runtime = _wired_runtime(store)
    result = call_tool(runtime, "governance_read", {"sei": _SEI})
    assert not result.get("isError"), result
    assert result["structuredContent"] == _load_golden()


# --- Kind-coverage guard ---

def test_both_clearance_kinds_are_pinned():
    """The golden MUST carry both clearance postures (operator_signoff +
    protected_override). A one-kind golden leaves the other projection branch
    un-pinned and a rename there would not red here."""
    postures = {r["posture"] for r in _load_golden()["records"]}
    assert postures == {"operator_signoff", "protected_override"}


# --- Content-hash cross-check with the attestation golden ---

def test_content_hashes_match_attestation_golden():
    """The governance_read golden's content_hash values must match the attestation
    golden's content_hash values (same signed records, different projection).
    If either golden is refreshed independently, this cross-check catches drift."""
    att_golden_path = Path(__file__).parent / "fixtures" / "legis-warpline-attestation-get.golden.json"
    att_golden = json.loads(att_golden_path.read_text(encoding="utf-8"))
    att_hashes = {a["content_hash"] for a in att_golden["attestations"]}

    gov_golden = _load_golden()
    gov_hashes = {r["content_hash"] for r in gov_golden["records"]}

    assert gov_hashes == att_hashes, (
        "governance_read golden content_hashes don't match attestation golden — "
        "they are built from the same store, so they must agree"
    )


# --- Rename-stability ---

def test_governance_read_golden_is_keyed_on_sei():
    golden = _load_golden()
    assert golden["status"] == "checked"
    assert golden["sei"] == _SEI
    assert golden["sei"].startswith("loomweave:eid:")


# --- Unavailable discriminant ---

def test_unavailable_discriminant_is_distinct_from_empty_checked(tmp_path):
    """Unwired gateway yields 'unavailable', not 'checked'/[] — the consumer
    MUST distinguish these two statuses."""
    store = _build_attested_store(tmp_path)
    engine = EnforcementEngine(store, FixedClock(_CLOCK_ISO))
    unwired = McpRuntime(agent_id="x", initialized=True, engine=engine)
    sc = call_tool(unwired, "governance_read", {"sei": _SEI})["structuredContent"]
    assert sc["status"] == "unavailable"
    assert sc["records"] == []
    assert sc["status"] != _load_golden()["status"]
