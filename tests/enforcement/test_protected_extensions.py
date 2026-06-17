import pytest

from legis.clock import FixedClock
from legis.enforcement.protected import (
    ProtectedGate,
    TamperError,
    TrailVerifier,
    signing_fields,
)
from legis.enforcement.signing import verify
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.identity.entity_key import EntityKey
from legis.store.audit_store import AuditStore

KEY = b"protected-key-1"
LOOMWEAVE = {"loomweave": {"alive": True, "content_hash": "blake3h",
                       "lineage_snapshot": {"length": 1, "hash": "lh"}}}


class ScriptedJudge:
    def __init__(self, opinion):
        self.opinion = opinion

    def evaluate(self, record):
        return self.opinion


def _gate(tmp_path):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    # JUDGE-3: the protected cell is fail-closed — a judge ACCEPTED only clears
    # when a deterministic validator confirms it. These tests exercise the
    # accepted-record mechanics (loomweave block, fixed-field binding), so wire a
    # confirming validator to reach the cleared state.
    g = ProtectedGate(store, FixedClock("2026-06-02T12:00:00+00:00"),
                      judge=ScriptedJudge(JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")),
                      key=KEY, validator=lambda record: True)
    return g, store


def test_submit_carries_loomweave_block(tmp_path):
    g, store = _gate(tmp_path)
    g.submit(policy="no-eval", entity_key=EntityKey.from_sei("loomweave:eid:abc"),
             rationale="r", agent_id="a", file_fingerprint="fp", ast_path="ap",
             extensions=LOOMWEAVE)
    ext = store.read_all()[0].payload["extensions"]
    assert ext["loomweave"] == LOOMWEAVE["loomweave"]
    # Fixed signed fields are untouched by the caller's extensions.
    assert ext["judge_verdict"] == "ACCEPTED"
    assert ext["file_fingerprint"] == "fp"


def test_loomweave_block_does_not_break_the_signature(tmp_path):
    g, store = _gate(tmp_path)
    g.submit(policy="no-eval", entity_key=EntityKey.from_sei("loomweave:eid:abc"),
             rationale="r", agent_id="a", file_fingerprint="fp", ast_path="ap",
             extensions=LOOMWEAVE)
    rec = store.read_all()[0]
    payload = rec.payload
    sig = payload["extensions"]["judge_metadata_signature"]
    assert verify(signing_fields(payload, seq=rec.seq), sig, KEY) is True


def test_mutating_loomweave_block_invalidates_the_signature(tmp_path):
    # Discriminating regression lock for WP-A1/L-05: the loomweave block must be bound
    # to the signed field set. Mutating it after signing MUST break the signature.
    g, store = _gate(tmp_path)
    g.submit(policy="no-eval", entity_key=EntityKey.from_sei("loomweave:eid:abc"),
             rationale="r", agent_id="a", file_fingerprint="fp", ast_path="ap",
             extensions=LOOMWEAVE)
    record = store.read_all()[0]
    payload = record.payload
    payload["extensions"]["loomweave"]["content_hash"] = "TAMPERED"
    payload["extensions"]["loomweave"]["lineage_snapshot"] = {"length": 99, "hash": "x"}
    sig = payload["extensions"]["judge_metadata_signature"]
    # Reconstruct v3-correctly (seq from the column) so this is False purely
    # because the loomweave content was mutated, not a version/field mismatch.
    assert verify(signing_fields(payload, seq=record.seq), sig, KEY) is False
    # The protected-tier load-time verifier likewise rejects the mutated record.
    with pytest.raises(TamperError):
        TrailVerifier(KEY, frozenset({"no-eval"})).verify([record])



def test_operator_override_carries_loomweave_block(tmp_path):
    g, store = _gate(tmp_path)
    g.operator_override(policy="no-eval", entity_key=EntityKey.from_sei("loomweave:eid:abc"),
                        rationale="r", operator_id="op", file_fingerprint="fp", ast_path="ap",
                        extensions=LOOMWEAVE)
    ext = store.read_all()[0].payload["extensions"]
    assert ext["loomweave"] == LOOMWEAVE["loomweave"]
    assert ext["judge_verdict"] == "OVERRIDDEN_BY_OPERATOR"


def test_caller_extensions_cannot_override_fixed_fields(tmp_path):
    g, store = _gate(tmp_path)
    g.submit(policy="no-eval", entity_key=EntityKey.from_sei("loomweave:eid:abc"),
             rationale="r", agent_id="a", file_fingerprint="fp", ast_path="ap",
             extensions={"judge_verdict": "TAMPERED", "file_fingerprint": "evil"})
    ext = store.read_all()[0].payload["extensions"]
    assert ext["judge_verdict"] == "ACCEPTED"   # gate wins
    assert ext["file_fingerprint"] == "fp"
