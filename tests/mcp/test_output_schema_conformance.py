"""Output-schema conformance vector (legis-49b4ca4166).

Every legis MCP tool returns structuredContent with a stable payload shape, so
every tool declares an ``outputSchema`` and this vector drives each tool once
per distinct outcome variant and validates the emitted payload against the
declared schema — the same pin-the-wire-contract discipline as the Wardline
findings conformance vector. A payload key added without updating the schema
(or vice versa) fails here, not in a client.

The error envelope is uniform across all tools and lives in one shared
definition (``ERROR_ENVELOPE_SCHEMA``); error results (``isError: true``) are
validated against it, never against a tool's success schema.
"""

import jsonschema
from jsonschema import Draft202012Validator

from legis.checks.models import CheckOutcome, CheckRun
from legis.checks.surface import CheckSurface
from legis.clock import FixedClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.protected import ProtectedGate
from legis.enforcement.signoff import SignoffGate
from legis.enforcement.verdict import JudgeOpinion, Verdict
from legis.git.surface import GitSurface
from legis.identity.entity_key import EntityKey
from legis.policy.cells import PolicyCellRegistry, PolicyCellRule
from legis.pulls.models import PullRequest, PullRequestState
from legis.pulls.surface import PullSurface
from legis.store.audit_store import AuditStore

KEY = b"protected-key-1"


def _chill_posture_ledger(tmp_path):
    import hashlib
    import uuid

    from legis.posture.ledger import PostureLedger

    ledger = PostureLedger(
        f"sqlite:///{tmp_path / f'posture-{uuid.uuid4().hex}.db'}",
        initialize=True,
    )
    key = b"k" * 32
    ledger.genesis(
        key_fingerprint=hashlib.sha256(key).hexdigest(),
        agent_id="installer",
        recorded_at="t0",
    )
    return ledger


class _ScriptedJudge:
    def __init__(self, *opinions):
        self._opinions = list(opinions)

    def evaluate(self, record):
        if self._opinions:
            return self._opinions.pop(0)
        return JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")


class _FakeFiligree:
    def attach(self, issue_id, entity_id, content_hash, *, actor,
               signoff_seq=None, signature=None):
        return {"issue_id": issue_id, "loomweave_entity_id": entity_id,
                "content_hash_at_attach": content_hash, "attached_at": "t",
                "attached_by": actor}

    def associations_for_entity(self, entity_id):
        return []


def _tool(name):
    from legis.mcp import tool_definitions

    return next(t for t in tool_definitions() if t["name"] == name)


def _runtime(tmp_path, *, judge=None, registry=None, posture_ledger=None):
    from legis.mcp import McpRuntime

    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    engine = EnforcementEngine(
        store, FixedClock("2026-06-02T12:00:00+00:00"), judge=judge
    )
    return McpRuntime(
        agent_id="agent-launch",
        initialized=True,
        engine=engine,
        cell_registry=registry,
        posture_ledger=posture_ledger,
    ), store


def _conformant(runtime, name, args):
    """Call the tool and validate its success payload against its outputSchema."""
    from legis.mcp import call_tool

    result = call_tool(runtime, name, args)
    assert not result.get("isError"), result
    payload = result["structuredContent"]
    jsonschema.validate(payload, _tool(name)["outputSchema"], cls=Draft202012Validator)
    return payload


# --- the schema declarations themselves ---


def test_every_tool_declares_a_valid_output_schema():
    from legis.mcp import tool_definitions

    for tool in tool_definitions():
        assert "outputSchema" in tool, f"{tool['name']} declares no outputSchema"
        Draft202012Validator.check_schema(tool["outputSchema"])


def test_every_output_schema_declares_top_level_object_type():
    """MCP clients validate tools/list strictly: outputSchema must carry a
    top-level ``"type": "object"``. A bare ``oneOf`` is valid JSON Schema but
    fails client-side validation — and one offending tool vanishes the ENTIRE
    catalog from the session (dogfood-4 A6: override_submit + scan_route took
    all 21 tools down)."""
    from legis.mcp import tool_definitions

    for tool in tool_definitions():
        schema = tool["outputSchema"]
        assert schema.get("type") == "object", (
            f"{tool['name']}'s outputSchema must declare top-level type 'object' "
            f"(got {schema.get('type')!r}); MCP clients reject the whole tools/list otherwise"
        )


def test_one_of_helper_always_injects_top_level_object_type():
    """G9: the _one_of helper makes the dogfood-4 A6 bug unrepresentable — a
    discriminated-outcome schema cannot omit the top-level ``"type": "object"``
    because the helper injects it. Every tool whose outputSchema carries a
    ``oneOf`` must be built through _one_of (not a bare dict literal), so a future
    discriminated-outcome tool inherits the fix automatically."""
    from legis.mcp import _one_of, tool_definitions

    # The helper unconditionally injects the type, whatever variants it is given.
    assert _one_of([{"type": "object"}])["type"] == "object"
    assert _one_of([])["type"] == "object"

    # And every oneOf outputSchema in the live catalog carries it (i.e. none was
    # hand-rolled as a bare {"oneOf": [...]} that could regress).
    for tool in tool_definitions():
        schema = tool["outputSchema"]
        if "oneOf" in schema:
            assert schema.get("type") == "object", (
                f"{tool['name']} has a oneOf outputSchema without top-level "
                f"type 'object' — route it through _one_of()"
            )


def test_error_envelope_is_a_shared_schema_and_errors_conform():
    from legis.mcp import ERROR_ENVELOPE_SCHEMA, _tool_error

    Draft202012Validator.check_schema(ERROR_ENVELOPE_SCHEMA)
    for code in ("NOT_FOUND", "AUDIT_INTEGRITY_FAILURE", "CELL_NOT_ENABLED"):
        envelope = _tool_error(code, "msg")["structuredContent"]
        jsonschema.validate(envelope, ERROR_ENVELOPE_SCHEMA, cls=Draft202012Validator)

    # The SEI-on-entry doctrine attaches a structured weft_reason to a
    # non-resolving inline identity; the shared envelope (additionalProperties:
    # False) must admit it, or every client validating an UNRESOLVED_INPUT error
    # against this schema rejects the documented recovery path.
    with_weft_reason = _tool_error(
        "UNRESOLVED_INPUT",
        "msg",
        weft_reason={"kind": "unresolved_input", "cause": "c", "fix": "f"},
    )["structuredContent"]
    jsonschema.validate(
        with_weft_reason, ERROR_ENVELOPE_SCHEMA, cls=Draft202012Validator
    )


# --- per-tool conformance: drive each tool, validate the emitted payload ---


def test_policy_explain_conforms_known_and_unknown(tmp_path):
    runtime, _ = _runtime(
        tmp_path,
        registry=PolicyCellRegistry(
            default_cell="chill",
            rules=[PolicyCellRule(pattern="secure.*", cell="protected")],
        ),
    )
    known = _conformant(
        runtime, "policy_explain", {"policy": "secure.x", "entity": "src/a.py:f"}
    )
    assert known["policy_known"] is True
    unknown = _conformant(
        runtime, "policy_explain", {"policy": "made.up", "entity": "src/a.py:f"}
    )
    assert unknown["matched_rule"] is None


def test_policy_list_conforms(tmp_path):
    runtime, _ = _runtime(
        tmp_path,
        registry=PolicyCellRegistry(
            default_cell="chill",
            rules=[PolicyCellRule(pattern="secure.*", cell="protected")],
        ),
    )
    payload = _conformant(runtime, "policy_list", {})
    assert {c["cell"] for c in payload["cells"]} >= {"chill", "protected"}


def test_posture_get_conforms_missing_and_floored(tmp_path):
    import hashlib

    from legis.enforcement import signing as enf_signing
    from legis.posture.ledger import PostureLedger

    # No ledger -> fail-closed structured floor (cross-cutting checklist #1).
    runtime, _ = _runtime(
        tmp_path, registry=PolicyCellRegistry(default_cell="chill")
    )
    missing = _conformant(runtime, "posture_get", {})
    assert missing["floor"] == "structured"
    assert missing["epoch_reset_unacknowledged"] is False

    # A seeded ledger raised to structured -> per-policy floored effective cell.
    url = f"sqlite:///{tmp_path / 'posture.db'}"
    ledger = PostureLedger(url, initialize=True)
    key = b"k" * 32
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")

    class _MemSigner:
        def __init__(self, held_key=key):
            self._key = held_key

        def fingerprint(self):
            return fp

        def sign(self, fields):
            return enf_signing.sign(fields, self._key, version="v3")

    ledger.transition(
        "structured",
        signer=_MemSigner(),
        session_id="s",
        key_fingerprint=fp,
        agent_id="op",
        rationale="raise",
        recorded_at="t1",
    )
    runtime.posture_ledger = ledger
    floored = _conformant(runtime, "posture_get", {"policy": "anything"})
    assert floored["floor"] == "structured"
    assert floored["effective_cell"] == "structured"


def test_override_submit_conforms_accepted_self(tmp_path):
    runtime, _ = _runtime(
        tmp_path,
        registry=PolicyCellRegistry(default_cell="chill"),
        posture_ledger=_chill_posture_ledger(tmp_path),
    )
    payload = _conformant(
        runtime,
        "override_submit",
        {"policy": "p.a", "entity": "src/a.py:f", "rationale": "r"},
    )
    assert payload["outcome"] == "ACCEPTED_SELF"


def test_override_submit_conforms_judged_accept_and_block(tmp_path):
    runtime, _ = _runtime(
        tmp_path,
        judge=_ScriptedJudge(
            JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok"),
            JudgeOpinion(Verdict.BLOCKED, "judge@1", "insufficient rationale"),
        ),
        registry=PolicyCellRegistry(default_cell="coached"),
        posture_ledger=_chill_posture_ledger(tmp_path),
    )
    accepted = _conformant(
        runtime,
        "override_submit",
        {"policy": "p.a", "entity": "src/a.py:f", "rationale": "r"},
    )
    assert accepted["outcome"] == "ACCEPTED_BY_JUDGE"
    blocked = _conformant(
        runtime,
        "override_submit",
        {"policy": "p.a", "entity": "src/a.py:f", "rationale": "r"},
    )
    assert blocked["outcome"] == "BLOCKED"


def test_override_submit_conforms_escalated_pending(tmp_path):
    runtime, store = _runtime(
        tmp_path, registry=PolicyCellRegistry(default_cell="structured")
    )
    runtime.signoff_gate = SignoffGate(
        store, FixedClock("2026-06-02T12:00:00+00:00")
    )
    payload = _conformant(
        runtime,
        "override_submit",
        {"policy": "p.a", "entity": "src/a.py:f", "rationale": "r"},
    )
    assert payload["outcome"] == "ESCALATED_PENDING"


def test_override_submit_conforms_need_inputs(tmp_path):
    runtime, store = _runtime(
        tmp_path, registry=PolicyCellRegistry(default_cell="protected")
    )
    runtime.protected_gate = ProtectedGate(
        store, FixedClock("2026-06-02T12:00:00+00:00"), _ScriptedJudge(), KEY
    )
    payload = _conformant(
        runtime,
        "override_submit",
        {"policy": "p.a", "entity": "src/a.py:f", "rationale": "r"},
    )
    assert payload["outcome"] == "NEED_INPUTS"


def test_signoff_status_get_conforms_pending_and_cleared(tmp_path):
    from legis.governance.binding_ledger import BindingLedger

    runtime, store = _runtime(tmp_path)
    clock = FixedClock("2026-06-02T12:00:00+00:00")
    gate = SignoffGate(store, clock)
    runtime.signoff_gate = gate
    runtime.binding_ledger = BindingLedger(
        AuditStore(f"sqlite:///{tmp_path / 'bind.db'}"), clock, key=b"ledger-key"
    )
    req = gate.request(
        policy="prod-deploy",
        entity_key=EntityKey.from_sei("loomweave:eid:abc"),
        rationale="needs a human",
        agent_id="agent-launch",
    )

    pending = _conformant(runtime, "signoff_status_get", {"seq": req.seq})
    assert pending["cleared"] is False

    gate.sign_off(request_seq=req.seq, operator_id="op-1")
    cleared = _conformant(runtime, "signoff_status_get", {"seq": req.seq})
    assert cleared["cleared"] is True
    assert cleared["binding"] is None  # ledger wired, nothing bound yet


def test_signoff_bind_issue_conforms(tmp_path):
    from legis.governance.binding_ledger import BindingLedger

    runtime, store = _runtime(tmp_path)
    clock = FixedClock("2026-06-02T12:00:00+00:00")
    gate = SignoffGate(store, clock)
    runtime.signoff_gate = gate
    runtime.filigree = _FakeFiligree()
    runtime.binding_key = b"bind-key"
    runtime.binding_ledger = BindingLedger(
        AuditStore(f"sqlite:///{tmp_path / 'bind.db'}"), clock, key=b"ledger-key"
    )
    req = gate.request(
        policy="prod-deploy",
        entity_key=EntityKey.from_sei("loomweave:eid:abc"),
        rationale="needs a human",
        agent_id="agent-launch",
        extensions={"loomweave": {"content_hash": "blake3", "alive": True,
                                  "lineage_snapshot": None}},
    )
    gate.sign_off(request_seq=req.seq, operator_id="op-1")

    payload = _conformant(
        runtime, "signoff_bind_issue", {"seq": req.seq, "issue_id": "ISSUE-7"}
    )
    assert payload["signoff_seq"] == req.seq
    assert payload["binding_seq"] >= 1


def test_policy_evaluate_conforms(tmp_path):
    runtime, _ = _runtime(tmp_path)
    payload = _conformant(
        runtime, "policy_evaluate", {"policy": "unknown.policy", "target": {}}
    )
    assert payload["outcome"] == "UNKNOWN"


def test_scan_route_conforms_routed(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    monkeypatch.delenv("LEGIS_WARDLINE_CELL_BY_SEVERITY", raising=False)
    runtime, _ = _runtime(tmp_path)
    payload = _conformant(
        runtime,
        "scan_route",
        {
            "scan": {
                "findings": [
                    {
                        "rule_id": "PY-WL-101",
                        "message": "untrusted reaches trusted",
                        "severity": "ERROR",
                        "kind": "defect",
                        "fingerprint": "fp1",
                        "qualname": "m.f",
                        "properties": {},
                        "suppression_state": "active",
                    }
                ]
            }
        },
    )
    assert payload["outcome"] == "ROUTED"
    assert payload["routed"][0]["surfaced"] is True


def test_scan_route_conforms_skipped_dirty_tree(tmp_path, monkeypatch):
    from legis.mcp import ERROR_ENVELOPE_SCHEMA, call_tool

    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    monkeypatch.setenv("LEGIS_WARDLINE_ARTIFACT_KEY", "wardline-key")
    monkeypatch.delenv("LEGIS_WARDLINE_ALLOW_DIRTY", raising=False)
    runtime, _ = _runtime(tmp_path)
    result = call_tool(
        runtime,
        "scan_route",
        {
            "scan": {
                "scanner_identity": "wardline@1.0.0rc1",
                "rule_set_version": "rules@abc123",
                "commit_sha": "a" * 40,
                "tree_sha": "b" * 40,
                "dirty": True,
                "findings": [],
            }
        },
    )
    assert result["isError"] is True
    payload = result["structuredContent"]
    jsonschema.validate(payload, ERROR_ENVELOPE_SCHEMA, cls=Draft202012Validator)
    assert payload["error_code"] == "WARDLINE_DIRTY_TREE"
    assert "SKIPPED_DIRTY_TREE" in payload["message"]


def test_git_tools_conform(tmp_path, git_repo):
    runtime, _ = _runtime(tmp_path)
    runtime.git_surface = GitSurface(git_repo)
    runtime.source_root = str(git_repo)

    branches = _conformant(runtime, "git_branch_list", {})
    head = GitSurface(git_repo).commits(limit=1)[0].sha
    assert {b["name"] for b in branches["branches"]} >= {"main", "feature"}
    _conformant(runtime, "git_commit_get", {"sha": head})
    renames = _conformant(
        runtime, "git_rename_list", {"rev_range": "HEAD~1..HEAD"}
    )
    assert renames["renames"][0]["new_path"] == "renamed.txt"
    feed = _conformant(
        runtime,
        "git_rename_feed_get",
        {"base": "HEAD~1", "head": "HEAD", "include_worktree": True},
    )
    assert feed["worktree_checked"] is True


def test_filigree_closure_gate_get_conforms_both_decisions(tmp_path):
    runtime, _ = _runtime(tmp_path)

    class _Ledger:
        def __init__(self, record):
            self._record = record

        def get_by_issue_id(self, issue_id):
            return self._record

    runtime.binding_ledger = _Ledger(None)
    denied = _conformant(
        runtime, "filigree_closure_gate_get", {"issue_id": "ISSUE-7"}
    )
    assert denied["allowed"] is False and denied["evidence"] is None

    runtime.binding_ledger = _Ledger(
        {"signoff_seq": 3, "content_hash": "blake3", "recorded_at": "t"}
    )
    allowed = _conformant(
        runtime, "filigree_closure_gate_get", {"issue_id": "ISSUE-7"}
    )
    assert allowed["allowed"] is True


def test_lineage_honesty_reads_conform_unavailable(tmp_path):
    # Unwired Loomweave: the honest "could not check" shape for both reads.
    runtime, _ = _runtime(tmp_path)
    gaps = _conformant(runtime, "identity_gap_list", {})
    assert gaps["status"] == "unavailable"
    lineage = _conformant(runtime, "lineage_integrity_get", {})
    assert lineage["status"] == "unavailable"


def test_pull_request_get_and_check_list_conform(tmp_path):
    checks = CheckSurface(f"sqlite:///{tmp_path / 'checks.db'}")
    checks.record(
        CheckRun(
            check_name="unit",
            run_id="run-1",
            commit_sha="abc123",
            outcome=CheckOutcome.PASS,
            branch="main",
            pr=7,
            ran_against="abc123",
        )
    )
    pulls = PullSurface(f"sqlite:///{tmp_path / 'pulls.db'}")
    pulls.record(
        PullRequest(
            number=7,
            title="Feature",
            base="main",
            head="feature",
            state=PullRequestState.OPEN,
            url="https://example.test/pr/7",
        )
    )
    runtime, _ = _runtime(tmp_path)
    runtime.check_surface = checks
    runtime.pull_surface = pulls

    pr = _conformant(runtime, "pull_request_get", {"number": 7})
    assert pr["checks"][0]["check_name"] == "unit"
    for target_type, target in (("commit", "abc123"), ("branch", "main"), ("pr", "7")):
        _conformant(
            runtime, "check_list", {"target_type": target_type, "target": target}
        )


def test_check_report_conforms(tmp_path):
    runtime, _ = _runtime(tmp_path)
    runtime.check_surface = CheckSurface(f"sqlite:///{tmp_path / 'checks.db'}")
    payload = _conformant(
        runtime,
        "check_report",
        {
            "check_name": "ruff",
            "run_id": "run-9",
            "commit_sha": "d" * 40,
            "outcome": "pass",
            "pr": 7,
        },
    )
    assert payload["recorded_by"] == "agent-launch"
    assert payload["provenance"] == "unauthenticated"


def test_override_rate_get_and_override_list_conform(tmp_path):
    runtime, _ = _runtime(tmp_path)
    runtime.engine.submit_override(
        policy="p.a",
        entity_key=EntityKey.from_locator("src/a.py:f"),
        rationale="r",
        agent_id="agent-launch",
    )
    rate = _conformant(runtime, "override_rate_get", {})
    assert rate["status"] in ("PASS", "FAIL", "PASS_WITH_NOTICE")
    overrides = _conformant(runtime, "override_list", {})
    assert overrides["overrides"][0]["seq"] == 1


def test_doctor_get_conforms(tmp_path):
    from legis.mcp import McpRuntime

    runtime = McpRuntime(
        agent_id="agent-1", initialized=True, source_root=str(tmp_path)
    )
    payload = _conformant(runtime, "doctor_get", {})
    assert payload["ok"] is False  # bare dir: install checks error


def test_policy_boundary_check_conforms_pass_and_findings(tmp_path):
    from legis.mcp import McpRuntime

    src = tmp_path / "src"
    src.mkdir()
    (src / "clean.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    runtime = McpRuntime(
        agent_id="agent-1", initialized=True, source_root=str(tmp_path)
    )
    clean = _conformant(runtime, "policy_boundary_check", {})
    assert clean["outcome"] == "PASS"

    (src / "guarded.py").write_text(
        '@policy_boundary(suppresses=("no-eval",))\ndef f():\n    pass\n',
        encoding="utf-8",
    )
    found = _conformant(runtime, "policy_boundary_check", {})
    assert found["outcome"] == "FINDINGS"


def test_policy_boundary_check_no_root_instead_of_vacuous_pass(tmp_path):
    """A project whose source is not <repo_root>/src (e.g. specimen/) must not
    read as a clean PASS when scanned with no explicit root. A non-existent
    default root yields zero findings, which would otherwise be a vacuous green —
    the silent-clean-on-zero-scope footgun (cf. weft-ef2e898642). The tool returns
    NO_ROOT and echoes the root it tried, so the miss is visible."""
    from legis.mcp import McpRuntime

    # Source lives in specimen/, not src/ — so the default <repo_root>/src is absent.
    (tmp_path / "specimen").mkdir()
    (tmp_path / "specimen" / "app.py").write_text(
        "def f():\n    return 1\n", encoding="utf-8"
    )
    runtime = McpRuntime(
        agent_id="agent-1", initialized=True, source_root=str(tmp_path)
    )

    missed = _conformant(runtime, "policy_boundary_check", {})
    assert missed["outcome"] == "NO_ROOT"
    assert missed["findings"] == []
    assert missed["scanned_root"].endswith("src")

    # Pointed at the real source explicitly, it scans (a clean PASS here is honest).
    scanned = _conformant(runtime, "policy_boundary_check", {"root": "specimen"})
    assert scanned["outcome"] == "PASS"
    assert scanned["scanned_root"].endswith("specimen")


def test_warpline_preflight_get_unavailable_conforms(tmp_path):
    runtime, _store = _runtime(tmp_path)  # warpline None
    payload = _conformant(runtime, "warpline_preflight_get", {"base": "aaa"})
    assert payload["status"] == "unavailable"


def test_warpline_preflight_get_checked_conforms(tmp_path):
    class _FakeWarpline:
        """Returns real-shaped envelopes with a GV-LG-3-valid meta.

        A meta-violating envelope would be refused → unavailable, which would
        make the ``status == 'checked'`` assertion below fail silently.
        """

        def impact_radius(self, base, head):
            return {
                "schema": "warpline.impact_radius.v1",
                "ok": True,
                "data": {"completeness": "FULL", "affected": []},
                "meta": {"local_only": True, "peer_side_effects": []},
            }

        def reverify_worklist(self, base, head):
            return {
                "schema": "warpline.reverify_worklist.v1",
                "ok": True,
                "data": {"completeness": "FULL", "items": []},
                "meta": {"local_only": True, "peer_side_effects": []},
            }

    runtime, _store = _runtime(tmp_path)
    runtime.warpline = _FakeWarpline()
    payload = _conformant(runtime, "warpline_preflight_get", {"base": "aaa", "head": "bbb"})
    assert payload["status"] == "checked"


def test_plainweave_preflight_get_unavailable_conforms(tmp_path):
    runtime, _store = _runtime(tmp_path)  # plainweave None
    payload = _conformant(runtime, "plainweave_preflight_get", {"base": "aaa"})
    assert payload["status"] == "unavailable"


def test_plainweave_preflight_get_checked_conforms(tmp_path):
    class _FakePlainweave:
        """Returns a real-shaped envelope with a GV-LG-3-valid authority_boundary.

        A boundary-violating envelope would be refused → unavailable, which would
        make the ``status == 'checked'`` assertion below fail silently.
        """

        def preflight_facts(self, base, head):
            return {
                "schema": "weft.plainweave.preflight_facts.v1",
                "ok": True,
                "data": {
                    "freshness": "partial",
                    "facts": [],
                    "authority_boundary": {
                        "local_only": True,
                        "live_peer_calls": False,
                        "governance_verdicts": False,
                    },
                },
                "warnings": [],
                "meta": {},
            }

    runtime, _store = _runtime(tmp_path)
    runtime.plainweave = _FakePlainweave()
    payload = _conformant(runtime, "plainweave_preflight_get", {"base": "aaa", "head": "bbb"})
    assert payload["status"] == "checked"


def test_attestation_get_unavailable_conforms(tmp_path):
    runtime, _store = _runtime(tmp_path)  # no protected gate
    payload = _conformant(runtime, "attestation_get", {"sei": "mod.fn#1"})
    assert payload["status"] == "unavailable"


def test_attestation_get_tamper_error_conforms_to_envelope(tmp_path):
    from legis.mcp import ERROR_ENVELOPE_SCHEMA, call_tool
    from jsonschema import Draft202012Validator

    runtime, _store = _runtime(tmp_path)

    class _TamperVerifier:
        def verify(self, records):
            from legis.enforcement.protected import TamperError

            raise TamperError("mismatch")

    class _FakeProtectedGate:
        def records(self):
            return ["bad"]

    runtime.protected_gate = _FakeProtectedGate()
    runtime.trail_verifier = _TamperVerifier()
    result = call_tool(runtime, "attestation_get", {"sei": "mod.fn#1"})
    assert result.get("isError")
    Draft202012Validator(ERROR_ENVELOPE_SCHEMA).validate(result["structuredContent"])


# --- governance_read output schema conformance ---


def test_governance_read_checked_variant_conforms(tmp_path):
    """The 'checked' variant of governance_read with actual clearance records
    must validate against the declared _one_of outputSchema."""
    from legis.clock import FixedClock
    from legis.enforcement.protected import ProtectedGate, TrailVerifier
    from legis.enforcement.signoff import SignoffGate
    from legis.identity.entity_key import EntityKey

    _KEY = b"schema-conf-key"
    _POLICY = "protected.schema_test"
    _SEI = "loomweave:eid:schema-conformance"

    store = AuditStore(f"sqlite:///{tmp_path / 'gov-conf.db'}")
    clock = FixedClock("2026-06-02T12:00:00+00:00")

    # Write a genuine signoff_cleared record
    gate = SignoffGate(store, clock, signer=True, key=_KEY)
    req = gate.request(
        policy=_POLICY,
        entity_key=EntityKey(value=_SEI, identity_stable=True),
        rationale="review",
        agent_id="agent-1",
        extensions={"loomweave": {"content_hash": "blake3:schema-conf"}},
    )
    gate.sign_off(request_seq=req.seq, operator_id="op-1", rationale="ok")

    runtime, _ = _runtime(tmp_path)
    runtime.protected_gate = ProtectedGate(
        store, clock, judge=_ScriptedJudge(), key=_KEY,
        protected_policies=frozenset({_POLICY}),
    )
    runtime.trail_verifier = TrailVerifier(_KEY, frozenset({_POLICY}))
    runtime.engine._store = store  # point engine at the store with clearances

    payload = _conformant(runtime, "governance_read", {"sei": _SEI})
    assert payload["status"] == "checked"
    assert len(payload["records"]) >= 1
    rec = payload["records"][0]
    assert rec["disposition"] == "cleared"
    assert rec["posture"] == "operator_signoff"
    assert rec["authority"] == "operator"


def test_governance_read_unavailable_variant_conforms(tmp_path):
    """The 'unavailable' variant (no protected gate wired) must validate against
    the declared _one_of outputSchema."""
    runtime, _store = _runtime(tmp_path)  # no protected gate
    payload = _conformant(runtime, "governance_read", {"sei": "loomweave:eid:any"})
    assert payload["status"] == "unavailable"
    assert payload["records"] == []
    assert payload["unavailable"] and "reason" in payload["unavailable"][0]
