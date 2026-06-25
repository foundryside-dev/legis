import pytest

from legis.clock import SystemClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.lifecycle import GateStatus
from legis.enforcement.protected import ProtectedGate, TamperError
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.identity.entity_key import EntityKey
from legis.identity.resolver import IdentityResolutionStatus, LineageSnapshotStatus
from legis.service.errors import (
    AuditIntegrityError,
    InvalidArgumentError,
    UnresolvedInputError,
)
from legis.service.governance import (
    compute_override_rate,
    resolve_for_entry,
    resolve_for_record,
    submit_override,
    submit_protected_override,
    verified_records,
)
from legis.store.audit_store import AuditStore


class _FakeResult:
    # Mirrors IdentityResolution, including the two mandatory str,Enum status
    # axes. Defaults derive from ``alive`` via the same bijection the real type
    # now enforces in __post_init__, so a contradictory fake can't sneak through.
    def __init__(self, entity_key, alive, content_hash, lineage_snapshot):
        self.entity_key = entity_key
        self.alive = alive
        self.content_hash = content_hash
        self.lineage_snapshot = lineage_snapshot
        self.identity_resolution_status = {
            True: IdentityResolutionStatus.RESOLVED,
            False: IdentityResolutionStatus.NOT_ALIVE,
            None: IdentityResolutionStatus.UNAVAILABLE,
        }[alive]
        if alive:
            self.lineage_snapshot_status = (
                LineageSnapshotStatus.VERIFIED
                if lineage_snapshot is not None
                else LineageSnapshotStatus.UNAVAILABLE
            )
        else:
            self.lineage_snapshot_status = LineageSnapshotStatus.NOT_APPLICABLE


class _FakeIdentity:
    def __init__(self, result, *, sei_result="unset"):
        self._result = result
        # sei_result: the IdentityResolution (or None) returned for a supplied SEI.
        # "unset" → fall back to the locator result so existing tests are unaffected.
        self._sei_result = result if sei_result == "unset" else sei_result

    def resolve(self, locator):
        return self._result

    def resolve_supplied_sei(self, sei):
        return self._sei_result


def test_no_identity_keys_on_locator_with_empty_extensions():
    key, ext = resolve_for_record(None, "src/foo.py:bar")
    assert key == EntityKey.from_locator("src/foo.py:bar")
    assert ext == {}


def test_identity_resolution_carries_loomweave_extension_when_alive_known():
    resolved_key = EntityKey.from_locator("resolved")
    identity = _FakeIdentity(
        _FakeResult(resolved_key, alive=True, content_hash="abc", lineage_snapshot=["e1"])
    )
    key, ext = resolve_for_record(identity, "src/foo.py:bar")
    assert key == resolved_key
    assert ext["loomweave"] == {
        "alive": True,
        "content_hash": "abc",
        "lineage_snapshot": ["e1"],
        "identity_resolution_status": "resolved",
        "lineage_snapshot_status": "verified",
    }


def test_alive_false_records_loomweave_extension_with_alive_false():
    resolved_key = EntityKey.from_locator("src/foo.py:bar")
    identity = _FakeIdentity(
        _FakeResult(resolved_key, alive=False, content_hash=None, lineage_snapshot=None)
    )
    key, ext = resolve_for_record(identity, "src/foo.py:bar")
    assert key == resolved_key
    assert ext["loomweave"] == {
        "alive": False,
        "content_hash": None,
        "lineage_snapshot": None,
        "identity_resolution_status": "not_alive",
        "lineage_snapshot_status": "not_applicable",
    }


def test_identity_with_unknown_alive_omits_loomweave_extension():
    resolved_key = EntityKey.from_locator("resolved")
    identity = _FakeIdentity(
        _FakeResult(resolved_key, alive=None, content_hash=None, lineage_snapshot=None)
    )
    key, ext = resolve_for_record(identity, "x")
    assert key == resolved_key
    assert ext == {}


# --- weft SEI-on-entry (L1): resolve_for_entry with an inline entity_sei ---


def test_resolve_for_entry_without_sei_is_the_locator_path():
    # entity_sei absent → identical to resolve_for_record (existing callers
    # unaffected). The fake's locator result is returned, not the SEI path.
    resolved_key = EntityKey.from_locator("resolved")
    identity = _FakeIdentity(
        _FakeResult(resolved_key, alive=True, content_hash="abc", lineage_snapshot=["e1"])
    )
    key, ext = resolve_for_entry(identity, entity="src/foo.py:bar", entity_sei=None)
    assert key == resolved_key
    assert ext["loomweave"]["alive"] is True


def test_resolve_for_entry_with_sei_keys_directly_on_verified_sei():
    sei_key = EntityKey.from_sei("loomweave:eid:deadbeef")
    identity = _FakeIdentity(
        _FakeResult(sei_key, alive=True, content_hash="h",
                    lineage_snapshot=["born"]),
        sei_result=_FakeResult(sei_key, alive=True, content_hash="h",
                               lineage_snapshot=["born"]),
    )
    key, ext = resolve_for_entry(
        identity, entity="src/foo.py:bar", entity_sei="loomweave:eid:deadbeef"
    )
    assert key == sei_key
    assert key.identity_stable is True
    assert ext["loomweave"]["alive"] is True
    assert ext["loomweave"]["content_hash"] == "h"


def test_resolve_for_entry_rejects_sei_for_unrelated_locator():
    locator_key = EntityKey.from_sei("loomweave:eid:locator-target")
    supplied_key = EntityKey.from_sei("loomweave:eid:supplied")
    identity = _FakeIdentity(
        _FakeResult(locator_key, alive=True, content_hash="locator-h",
                    lineage_snapshot=["born"]),
        sei_result=_FakeResult(supplied_key, alive=True, content_hash="supplied-h",
                               lineage_snapshot=["other"]),
    )

    with pytest.raises(UnresolvedInputError) as ei:
        resolve_for_entry(
            identity,
            entity="src/foo.py:bar",
            entity_sei="loomweave:eid:supplied",
        )

    assert "does not match" in ei.value.cause
    assert "entity" in ei.value.fix


def test_resolve_for_entry_unresolvable_sei_raises_and_records_nothing():
    # The fake reports the supplied SEI does not resolve (None) → fail-closed.
    identity = _FakeIdentity(
        _FakeResult(EntityKey.from_locator("x"), alive=None,
                    content_hash=None, lineage_snapshot=None),
        sei_result=None,
    )
    with pytest.raises(UnresolvedInputError) as ei:
        resolve_for_entry(identity, entity="src/foo.py:bar", entity_sei="loomweave:eid:gone")
    assert ei.value.cause and ei.value.fix
    assert "loomweave:eid:gone" in ei.value.cause


def test_resolve_for_entry_sei_without_resolver_raises_unresolved():
    # No resolve transport wired: an asserted SEI cannot be confirmed alive, so
    # recording it would be an unbound-but-looks-bound record. Fail closed.
    with pytest.raises(UnresolvedInputError) as ei:
        resolve_for_entry(None, entity="src/foo.py:bar", entity_sei="loomweave:eid:x")
    assert "LOOMWEAVE_API_URL" in ei.value.fix


def test_submit_override_with_entity_sei_records_on_the_sei(tmp_path):
    sei_key = EntityKey.from_sei("loomweave:eid:abc")
    identity = _FakeIdentity(
        _FakeResult(sei_key, alive=True, content_hash="h", lineage_snapshot=[]),
        sei_result=_FakeResult(sei_key, alive=True, content_hash="h", lineage_snapshot=[]),
    )
    engine = EnforcementEngine(AuditStore(f"sqlite:///{tmp_path / 'gov.db'}"), SystemClock())
    result = submit_override(
        engine,
        identity=identity,
        policy="some.policy",
        entity="src/foo.py:bar",
        rationale="because",
        agent_id="agent-x",
        entity_sei="loomweave:eid:abc",
    )
    record = next(r for r in engine.records() if r.seq == result.seq)
    assert record.payload["entity_key"] == sei_key.to_dict()
    assert record.payload["identity_stable"] is True


def test_submit_override_with_unresolvable_sei_records_nothing(tmp_path):
    identity = _FakeIdentity(
        _FakeResult(EntityKey.from_locator("loc"), alive=None,
                    content_hash=None, lineage_snapshot=None),
        sei_result=None,
    )
    engine = EnforcementEngine(AuditStore(f"sqlite:///{tmp_path / 'gov.db'}"), SystemClock())
    with pytest.raises(UnresolvedInputError):
        submit_override(
            engine,
            identity=identity,
            policy="some.policy",
            entity="src/foo.py:bar",
            rationale="because",
            agent_id="agent-x",
            entity_sei="loomweave:eid:gone",
        )
    assert engine.records() == []  # NOTHING recorded — the whole point


class _FakeProtectedGate:
    def __init__(self, records):
        self._records = records

    def records(self):
        return self._records


class _IntegrityFailGate(_FakeProtectedGate):
    def verify_integrity(self):
        return False


class _OkVerifier:
    def verify(self, records):
        return None


class _TamperVerifier:
    def verify(self, records):
        raise TamperError("record 4 hash mismatch")


def _boom():
    raise AssertionError("engine fallback must not be called when a protected gate is wired")


def test_verified_records_uses_engine_store_when_no_protected_gate():
    assert verified_records(None, None, lambda: ["r1", "r2"]) == ["r1", "r2"]


def test_verified_records_uses_protected_store_and_skips_engine_fallback():
    gate = _FakeProtectedGate(["protected"])
    assert verified_records(gate, _OkVerifier(), _boom) == ["protected"]


def test_verified_records_skips_verification_when_no_verifier():
    gate = _FakeProtectedGate(["protected"])
    assert verified_records(gate, None, _boom) == ["protected"]


def test_verified_records_raises_audit_integrity_error_on_tamper():
    gate = _FakeProtectedGate(["bad"])
    with pytest.raises(AuditIntegrityError) as exc_info:
        verified_records(gate, _TamperVerifier(), _boom)
    # the `from exc` chain must be preserved
    assert isinstance(exc_info.value.__cause__, TamperError)


def test_verified_records_uses_public_gate_integrity_hook():
    gate = _IntegrityFailGate(["bad"])
    with pytest.raises(AuditIntegrityError, match="hash chain"):
        verified_records(gate, None, _boom)


def test_compute_override_rate_returns_status_rate_sample_below_min_sample():
    # An empty trail is below min-sample → the gate is not FAIL; rate is 0.
    res = compute_override_rate([])
    assert res.status == GateStatus.PASS_WITH_NOTICE
    assert res.rate == 0.0
    assert res.sample_size == 0


def _sqlite_engine(tmp_path):
    # file-backed sqlite store, no judge → chill cell
    return EnforcementEngine(AuditStore(f"sqlite:///{tmp_path / 'gov.db'}"), SystemClock())


def test_submit_override_chill_records_and_accepts(tmp_path):
    engine = _sqlite_engine(tmp_path)
    result = submit_override(
        engine,
        identity=None,
        policy="no-direct-push",
        entity="src/foo.py:bar",
        rationale="generated file; lint N/A",
        agent_id="agent-7",
    )
    assert result.accepted is True
    # a fresh append-only store assigns seq 1 to its first record
    assert result.seq == 1
    trail = engine.trail()
    assert len(trail) == 1
    assert trail[0]["agent_id"] == "agent-7"
    assert trail[0]["policy"] == "no-direct-push"


class _BlockingJudge:
    model_id = "stub-judge"

    def evaluate(self, record):
        return JudgeOpinion(
            verdict=Verdict.BLOCKED, model="stub-judge", rationale="rationale insufficient"
        )


class _AcceptingJudge:
    def evaluate(self, record):
        return JudgeOpinion(verdict=Verdict.ACCEPTED, model="stub-judge", rationale="ok")


def test_submit_override_coached_blocks_on_negative_verdict(tmp_path):
    engine = EnforcementEngine(
        AuditStore(f"sqlite:///{tmp_path}/gov.db"), SystemClock(), judge=_BlockingJudge()
    )
    result = submit_override(
        engine,
        identity=None,
        policy="no-direct-push",
        entity="src/foo.py:bar",
        rationale="trust me",
        agent_id="agent-7",
    )
    assert result.accepted is False
    assert result.verdict is Verdict.BLOCKED
    assert result.judge_model == "stub-judge"
    # the BLOCKED attempt is still recorded (no silent path)
    assert len(engine.trail()) == 1


def test_submit_protected_override_rejects_unverified_source_binding_before_signing(tmp_path):
    store = AuditStore(f"sqlite:///{tmp_path}/protected.db")
    gate = ProtectedGate(store, SystemClock(), judge=_AcceptingJudge(), key=b"k")

    with pytest.raises(InvalidArgumentError, match="source binding could not be verified"):
        submit_protected_override(
            gate,
            identity=None,
            policy="no-eval",
            entity="src/missing.py:f",
            rationale="sandboxed",
            agent_id="agent-7",
            file_fingerprint="sha256:" + "0" * 64,
            ast_path="Module/FunctionDef[f]",
            source_root=tmp_path,
        )

    assert store.read_all() == []


# --- Q-H2: the override-rate gate decision lives in the service layer ---

def _protected_gate_with_record(tmp_path, db_name="gov.db"):
    from legis.clock import FixedClock

    class _AcceptJudge:
        def evaluate(self, record):
            return JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")

    db = f"sqlite:///{tmp_path / db_name}"
    gate = ProtectedGate(AuditStore(db), FixedClock("2026-06-02T12:00:00+00:00"),
                         judge=_AcceptJudge(), key=b"protected-key")
    gate.submit(
        policy="no-eval",
        entity_key=EntityKey.from_locator("src/x.py:f"),
        rationale="approved",
        agent_id="agent-1",
        file_fingerprint="sha256:abc",
        ast_path="Module/Call[eval]",
    )
    return db


def test_evaluate_override_rate_gate_fails_closed_without_key(tmp_path):
    from legis.service.errors import ProtectedKeyRequiredError
    from legis.service.governance import evaluate_override_rate_gate

    db = _protected_gate_with_record(tmp_path)
    records = AuditStore(db).read_all()
    with pytest.raises(ProtectedKeyRequiredError):
        evaluate_override_rate_gate(records, hmac_key=None, protected_policies=frozenset())


def test_evaluate_override_rate_gate_scores_with_key(tmp_path):
    from legis.service.governance import evaluate_override_rate_gate

    db = _protected_gate_with_record(tmp_path)
    records = AuditStore(db).read_all()
    res = evaluate_override_rate_gate(
        records, hmac_key="protected-key", protected_policies=frozenset({"no-eval"})
    )
    assert res.status in {GateStatus.PASS, GateStatus.PASS_WITH_NOTICE, GateStatus.FAIL}


def test_evaluate_override_rate_gate_ignores_soft_sniffs_on_simple_records(tmp_path):
    # A chill/coached record can carry an arbitrary extra_extensions dict through
    # the simple-tier engine. Such a record holding file_fingerprint/ast_path is
    # NOT protected (the engine never writes protected_cell or a signature), so a
    # keyless, non-protected deployment must score it rather than fail closed.
    from legis.service.governance import evaluate_override_rate_gate

    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    engine = EnforcementEngine(store, SystemClock())  # chill: no judge
    engine.submit_override(
        policy="some-policy",
        entity_key=EntityKey.from_locator("src/x.py:f"),
        rationale="r",
        agent_id="a",
        extensions={"file_fingerprint": "fp", "ast_path": "ap"},
    )
    records = store.read_all()
    res = evaluate_override_rate_gate(records, hmac_key=None, protected_policies=frozenset())
    assert res.status in {GateStatus.PASS, GateStatus.PASS_WITH_NOTICE, GateStatus.FAIL}


def test_sign_off_raises_not_enabled_when_gate_absent():
    from legis.service.errors import NotEnabledError
    from legis.service.governance import sign_off

    with pytest.raises(NotEnabledError):
        sign_off(None, request_seq=1, operator_id="op-1")


# --- Q-M1: protected != source verified; the honesty property is the signed status ---

def test_genuine_non_source_entity_records_honest_unverified_binding(tmp_path):
    # A non-path protected entity (here a service target) has no local bytes to
    # verify, so it records an HONEST `unverified` source binding rather than
    # being rejected — the qualname/SEI/service protected tier is a first-class
    # feature. "protected" != "source verified".
    store = AuditStore(f"sqlite:///{tmp_path}/protected.db")
    gate = ProtectedGate(store, SystemClock(), judge=_AcceptingJudge(), key=b"k")
    result = submit_protected_override(
        gate,
        identity=None,
        policy="no-eval",
        entity="service:thing",
        rationale="x",
        agent_id="agent-1",
        file_fingerprint="sha256:whatever",
        ast_path="ap",
        source_root=tmp_path,
    )
    assert result.seq == 1
    assert store.read_all()[0].payload["extensions"]["source_binding"]["status"] == "unverified"


def test_source_binding_status_is_bound_into_the_signature(tmp_path):
    # The anti-conflation guarantee (Q-M1): source_binding_status is folded into
    # the SIGNED HMAC fields, so a consumer can always distinguish a verified
    # protected record from an unverified one, and the status cannot be flipped
    # after the fact without breaking the signature.
    from legis.enforcement.protected import signing_fields
    from legis.enforcement.signing import verify

    key = b"protected-key"
    store = AuditStore(f"sqlite:///{tmp_path}/protected.db")
    gate = ProtectedGate(store, SystemClock(), judge=_AcceptingJudge(), key=key)
    result = submit_protected_override(
        gate,
        identity=None,
        policy="no-eval",
        entity="service:thing",
        rationale="x",
        agent_id="agent-1",
        file_fingerprint="sha256:whatever",
        ast_path="ap",
        source_root=tmp_path,
    )

    rec = store.read_all()[0]
    payload = rec.payload
    fields = signing_fields(payload, seq=rec.seq)
    assert fields["source_binding_status"] == "unverified"
    assert verify(fields, result.signature, key) is True

    # Flipping the recorded status to "verified" must break verification.
    payload["extensions"]["source_binding"]["status"] = "verified"
    tampered = signing_fields(payload, seq=rec.seq)
    assert verify(tampered, result.signature, key) is False


# Task 8: read_sei_attestations forge-proof classifier
# ---------------------------------------------------------------------------


def test_read_sei_attestations_empty_trail_is_checked_not_unavailable():
    # The function now ALWAYS returns status='checked' — it only ever sees a
    # signature-verified trail (the handler owns the unavailable pre-gate). An
    # empty verified trail was genuinely checked and honestly has no attestation.
    from legis.service.governance import read_sei_attestations

    out = read_sei_attestations([], "mod.fn#1")
    assert out["status"] == "checked"
    assert out["sei"] == "mod.fn#1"
    assert out["attestations"] == []
    assert "unavailable" not in out


_ATTEST_SEI = "loomweave:eid:cleared"


class _StableJudge:
    def evaluate(self, record):
        return JudgeOpinion(verdict=Verdict.ACCEPTED, model="judge@1", rationale="ok")


def _signed_signoff_gate(tmp_path):
    from legis.clock import FixedClock
    from legis.enforcement.signoff import SignoffGate

    store = AuditStore(f"sqlite:///{tmp_path}/gov.db")
    gate = SignoffGate(
        store, FixedClock("2026-06-02T12:00:00+00:00"), signer=True, key=b"signoff-key"
    )
    return store, gate


def _stable_entity_key(sei=_ATTEST_SEI):
    return EntityKey(value=sei, identity_stable=True)


def _request_and_clear(gate, *, sei=_ATTEST_SEI, content_hash_value="ch:request-1"):
    req = gate.request(
        policy="protected.x",
        entity_key=_stable_entity_key(sei),
        rationale="please review",
        agent_id="agent-1",
        extensions={"loomweave": {"content_hash": content_hash_value}},
    )
    cleared = gate.sign_off(
        request_seq=req.seq, operator_id="operator-1", rationale="approved"
    )
    return req, cleared


def test_read_sei_attestations_admits_genuine_signed_signoff(tmp_path):
    # POSITIVE / FORGE-B SOUNDNESS PROOF: a real signed SignoffGate request+sign_off.
    # If content_hash(stored PENDING) does NOT equal the signed request_payload_hash
    # this admission would not happen — the test passing IS the soundness proof.
    from legis.service.governance import read_sei_attestations

    store, gate = _signed_signoff_gate(tmp_path)
    req, cleared = _request_and_clear(gate, content_hash_value="ch:signoff-content")

    out = read_sei_attestations(store.read_all(), _ATTEST_SEI)
    assert out["status"] == "checked"
    assert out["attestations"] == [
        {
            "kind": "signoff_cleared",
            "content_hash": "ch:signoff-content",
            "recorded_at": "2026-06-02T12:00:00+00:00",
            "seq": cleared.seq,
            "signoff_seq": req.seq,
        }
    ]


def test_read_sei_attestations_admits_genuine_operator_override(tmp_path):
    # POSITIVE: a real signed protected operator override surfaces as
    # operator_override with the inline (signed) content_hash.
    from legis.clock import FixedClock
    from legis.service.governance import read_sei_attestations

    store = AuditStore(f"sqlite:///{tmp_path}/gov.db")
    gate = ProtectedGate(
        store, FixedClock("2026-06-02T12:00:00+00:00"), judge=_StableJudge(), key=b"k"
    )
    result = gate.operator_override(
        policy="protected.x",
        entity_key=_stable_entity_key(),
        rationale="operator clears",
        operator_id="operator-1",
        file_fingerprint="sha256:ff",
        ast_path="ap",
        extensions={"loomweave": {"content_hash": "ch:override-content"}},
    )

    out = read_sei_attestations(store.read_all(), _ATTEST_SEI)
    assert out["status"] == "checked"
    assert out["attestations"] == [
        {
            "kind": "operator_override",
            "content_hash": "ch:override-content",
            "recorded_at": "2026-06-02T12:00:00+00:00",
            "seq": result.seq,
        }
    ]


def test_read_sei_attestations_forge_b_mutated_pending_content_hash_omitted(tmp_path):
    # FORGE-B: real signed SIGNED_OFF; mutate the joined PENDING's content_hash in
    # the materialized list. The signed request_payload_hash no longer matches the
    # recomputed content_hash(pending) -> the sign-off MUST be omitted (the
    # mutated hash is NEVER surfaced). The SIGNED_OFF record is unchanged and still
    # "verifies"; only the classifier's recompute-and-compare catches the forge.
    from legis.service.governance import read_sei_attestations

    store, gate = _signed_signoff_gate(tmp_path)
    req, _cleared = _request_and_clear(gate, content_hash_value="ch:original")

    records = store.read_all()
    for rec in records:
        if rec.seq == req.seq:
            rec.payload["extensions"]["loomweave"]["content_hash"] = "ch:FORGED"

    out = read_sei_attestations(records, _ATTEST_SEI)
    assert out["status"] == "checked"
    assert out["attestations"] == []


def test_read_sei_attestations_forge_a_mutated_verdict_breaks_signature(tmp_path):
    # FORGE-A coverage proof: a real signed BLOCKED protected record whose
    # judge_verdict is mutated to OVERRIDDEN_BY_OPERATOR. Because judge_verdict is
    # SIGNED (signing_fields["verdict"]), the mutation breaks the v3 signature, so
    # TrailVerifier.verify RAISES before the classifier ever runs — the forged
    # override never reaches read_sei_attestations.
    from legis.clock import FixedClock
    from legis.enforcement.protected import TrailVerifier
    from legis.enforcement.verdict import JudgeOpinion

    class _BlockingJudge:
        def evaluate(self, record):
            return JudgeOpinion(verdict=Verdict.BLOCKED, model="judge@1", rationale="no")

    store = AuditStore(f"sqlite:///{tmp_path}/gov.db")
    key = b"k"
    gate = ProtectedGate(
        store, FixedClock("2026-06-02T12:00:00+00:00"), judge=_BlockingJudge(), key=key
    )
    gate.submit(
        policy="protected.x",
        entity_key=_stable_entity_key(),
        rationale="x",
        agent_id="agent-1",
        file_fingerprint="sha256:ff",
        ast_path="ap",
        extensions={"loomweave": {"content_hash": "ch:blocked"}},
    )

    records = store.read_all()
    assert records[0].payload["extensions"]["judge_verdict"] == "BLOCKED"
    records[0].payload["extensions"]["judge_verdict"] = "OVERRIDDEN_BY_OPERATOR"

    verifier = TrailVerifier(key, frozenset({"protected.x"}))
    with pytest.raises(TamperError):
        verifier.verify(records)


def test_read_sei_attestations_chill_self_clear_stuffing_override_omitted(tmp_path):
    # A chill/coached self-clear that STUFFS operator-override extensions. With NO
    # signature marker it must be omitted (keying on bare judge_verdict would admit
    # an unsigned forgery). Even WITH a non-verifying judge_metadata_signature it is
    # omitted unless protected_cell + content_hash are present and signed — but the
    # marker-present branch is what the verified pre-gate would have rejected; here
    # we assert the no-marker stuffing is omitted.
    from legis.service.governance import read_sei_attestations

    class _Rec:
        def __init__(self, seq, payload):
            self.seq = seq
            self.payload = payload

    stuffed = _Rec(
        1,
        {
            "policy": "ordinary",
            "entity_key": {"value": _ATTEST_SEI, "identity_stable": True},
            "recorded_at": "2026-06-02T12:00:00+00:00",
            "extensions": {
                # operator-override value but NO judge_metadata_signature marker
                "judge_verdict": "OVERRIDDEN_BY_OPERATOR",
                "protected_cell": True,
                "loomweave": {"content_hash": "ch:stuffed"},
            },
        },
    )

    out = read_sei_attestations([stuffed], _ATTEST_SEI)
    assert out["attestations"] == []


def test_read_sei_attestations_unsigned_procedural_signoff_omitted(tmp_path):
    # A structured (procedural) sign-off built with no signer -> SIGNED_OFF carries
    # no signoff_signature marker -> omitted.
    from legis.clock import FixedClock
    from legis.enforcement.signoff import SignoffGate
    from legis.service.governance import read_sei_attestations

    store = AuditStore(f"sqlite:///{tmp_path}/gov.db")
    gate = SignoffGate(store, FixedClock("2026-06-02T12:00:00+00:00"))  # no signer
    _request_and_clear(gate)

    out = read_sei_attestations(store.read_all(), _ATTEST_SEI)
    assert out["status"] == "checked"
    assert out["attestations"] == []


def test_read_sei_attestations_cross_sei_not_surfaced(tmp_path):
    # A genuine signed sign-off for a DIFFERENT SEI must not surface under the query.
    from legis.service.governance import read_sei_attestations

    store, gate = _signed_signoff_gate(tmp_path)
    _request_and_clear(gate, sei="loomweave:eid:other")

    out = read_sei_attestations(store.read_all(), _ATTEST_SEI)
    assert out["attestations"] == []


def test_read_sei_attestations_identity_unstable_omitted(tmp_path):
    # identity_stable False in the SIGNED entity dict -> omitted.
    from legis.service.governance import read_sei_attestations

    class _Rec:
        def __init__(self, seq, payload):
            self.seq = seq
            self.payload = payload

    unstable = _Rec(
        1,
        {
            "policy": "protected.x",
            "entity_key": {"value": _ATTEST_SEI, "identity_stable": False},
            "recorded_at": "2026-06-02T12:00:00+00:00",
            "extensions": {
                "judge_metadata_signature": "hmac-sha256:v3:deadbeef",
                "judge_verdict": "OVERRIDDEN_BY_OPERATOR",
                "protected_cell": True,
                "loomweave": {"content_hash": "ch:x"},
            },
        },
    )

    out = read_sei_attestations([unstable], _ATTEST_SEI)
    assert out["attestations"] == []


def test_read_sei_attestations_empty_content_hash_omitted(tmp_path):
    # Empty inline content_hash (operator_override) and empty joined content_hash
    # (signoff) both omit — never surface content_hash == "".
    from legis.service.governance import read_sei_attestations

    # operator_override inline-empty
    class _Rec:
        def __init__(self, seq, payload):
            self.seq = seq
            self.payload = payload

    override_empty = _Rec(
        1,
        {
            "policy": "protected.x",
            "entity_key": {"value": _ATTEST_SEI, "identity_stable": True},
            "recorded_at": "2026-06-02T12:00:00+00:00",
            "extensions": {
                "judge_metadata_signature": "hmac-sha256:v3:deadbeef",
                "judge_verdict": "OVERRIDDEN_BY_OPERATOR",
                "protected_cell": True,
                "loomweave": {"content_hash": ""},
            },
        },
    )
    out = read_sei_attestations([override_empty], _ATTEST_SEI)
    assert out["attestations"] == []

    # signoff join-empty: real signed sign-off whose PENDING has empty content_hash
    store, gate = _signed_signoff_gate(tmp_path)
    _request_and_clear(gate, content_hash_value="")
    out2 = read_sei_attestations(store.read_all(), _ATTEST_SEI)
    assert out2["attestations"] == []


def test_read_sei_attestations_blocked_verdict_omitted(tmp_path):
    # A genuine signed BLOCKED protected verdict is not a clearance -> omitted.
    from legis.clock import FixedClock
    from legis.enforcement.verdict import JudgeOpinion
    from legis.service.governance import read_sei_attestations

    class _BlockingJudge:
        def evaluate(self, record):
            return JudgeOpinion(verdict=Verdict.BLOCKED, model="judge@1", rationale="no")

    store = AuditStore(f"sqlite:///{tmp_path}/gov.db")
    gate = ProtectedGate(
        store, FixedClock("2026-06-02T12:00:00+00:00"), judge=_BlockingJudge(), key=b"k"
    )
    gate.submit(
        policy="protected.x",
        entity_key=_stable_entity_key(),
        rationale="x",
        agent_id="agent-1",
        file_fingerprint="sha256:ff",
        ast_path="ap",
        extensions={"loomweave": {"content_hash": "ch:blocked"}},
    )

    out = read_sei_attestations(store.read_all(), _ATTEST_SEI)
    assert out["status"] == "checked"
    assert out["attestations"] == []
