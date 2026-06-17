import json

from legis.cli import build_parser, main


def test_serve_defaults():
    args = build_parser().parse_args(["serve"])
    assert args.command == "serve"
    assert args.host == "127.0.0.1"
    assert args.port == 8000


def test_serve_custom_host_and_port():
    args = build_parser().parse_args(["serve", "--host", "0.0.0.0", "--port", "9001"])
    assert args.host == "0.0.0.0"
    assert args.port == 9001


def test_main_serve_invokes_runner_with_factory():
    calls = []

    def fake_run(app, **kw):
        calls.append((app, kw))

    rc = main(["serve", "--host", "0.0.0.0", "--port", "9001"], run=fake_run)
    assert rc == 0
    assert calls == [("legis.api.app:create_app",
                      {"host": "0.0.0.0", "port": 9001, "factory": True})]


def test_serve_rejects_hmac_key_argument():
    import pytest

    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(["serve", "--hmac-key", "secret"])
    assert excinfo.value.code == 2


def test_main_no_command_returns_2():
    rc = main([], run=lambda *a, **k: None)
    assert rc == 2


def test_version_flag_prints_version_and_exits_zero(capsys):
    import pytest

    from legis import __version__

    with pytest.raises(SystemExit) as excinfo:
        build_parser().parse_args(["--version"])
    # argparse's version action exits 0 after printing.
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert __version__ in out
    assert "legis" in out


def test_check_override_rate_exits_1_on_fail(tmp_path, capsys):
    from legis.clock import FixedClock
    from legis.enforcement.engine import EnforcementEngine
    from legis.enforcement.verdict import Verdict
    from legis.identity.entity_key import EntityKey
    from legis.store.audit_store import AuditStore

    db = f"sqlite:///{tmp_path / 'gov.db'}"
    eng = EnforcementEngine(AuditStore(db), FixedClock("2026-06-02T12:00:00+00:00"))
    for i in range(25):  # 25 operator-overrides → rate 1.0 > 0.2, n>=20 → FAIL
        eng.record_event({"policy": "p", "entity_key": EntityKey.from_locator(f"x{i}").to_dict(),
                          "extensions": {"judge_verdict": Verdict.OVERRIDDEN_BY_OPERATOR.value}})
    rc = main(["check-override-rate", "--db", db])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().out


def test_governance_gate_alias_exits_1_on_fail(tmp_path, capsys):
    from legis.clock import FixedClock
    from legis.enforcement.engine import EnforcementEngine
    from legis.enforcement.verdict import Verdict
    from legis.identity.entity_key import EntityKey
    from legis.store.audit_store import AuditStore

    db = f"sqlite:///{tmp_path / 'gov.db'}"
    eng = EnforcementEngine(AuditStore(db), FixedClock("2026-06-02T12:00:00+00:00"))
    for i in range(25):
        eng.record_event({"policy": "p", "entity_key": EntityKey.from_locator(f"x{i}").to_dict(),
                          "extensions": {"judge_verdict": Verdict.OVERRIDDEN_BY_OPERATOR.value}})
    rc = main(["governance-gate", "--db", db])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().out


def test_check_override_rate_exits_0_when_clean(tmp_path, capsys):
    from legis.clock import FixedClock
    from legis.enforcement.engine import EnforcementEngine
    from legis.enforcement.verdict import Verdict
    from legis.identity.entity_key import EntityKey
    from legis.store.audit_store import AuditStore

    db = f"sqlite:///{tmp_path / 'gov.db'}"
    eng = EnforcementEngine(AuditStore(db), FixedClock("2026-06-02T12:00:00+00:00"))
    for i in range(25):  # all ACCEPTED → rate 0.0 → PASS
        eng.record_event({"policy": "p", "entity_key": EntityKey.from_locator(f"x{i}").to_dict(),
                          "extensions": {"judge_verdict": Verdict.ACCEPTED.value}})
    assert main(["check-override-rate", "--db", db]) == 0
    assert "PASS" in capsys.readouterr().out


def test_governance_gate_missing_sqlite_db_is_pass_with_notice_without_creating_it(tmp_path, capsys, monkeypatch):
    # Exercises the dev/non-CI path; isolate from an ambient CI=true (e.g. GitHub
    # Actions), where a missing governance DB fails closed (rc=1) instead.
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("LEGIS_ALLOW_MISSING_GOVERNANCE_DB", raising=False)
    db_path = tmp_path / "missing.db"
    rc = main(["governance-gate", "--db", f"sqlite:///{db_path}"])
    assert rc == 0
    assert not db_path.exists()
    assert "PASS_WITH_NOTICE" in capsys.readouterr().out


def test_governance_gate_missing_sqlite_db_fails_closed_in_ci(tmp_path, capsys, monkeypatch):
    db_path = tmp_path / "missing.db"
    monkeypatch.setenv("CI", "true")

    rc = main(["governance-gate", "--db", f"sqlite:///{db_path}"])

    assert rc == 1
    assert not db_path.exists()
    captured = capsys.readouterr()
    assert "missing" in captured.err


def test_mcp_command_accepts_store_and_policy_cell_flags():
    from legis.cli import build_parser

    args = build_parser().parse_args(
        [
            "mcp",
            "--agent-id",
            "agent-1",
            "--governance-db",
            "sqlite:///gov.db",
            "--check-db",
            "sqlite:///checks.db",
            "--policy-cells",
            "policy/cells.toml",
        ]
    )

    assert args.command == "mcp"
    assert args.agent_id == "agent-1"
    assert args.governance_db == "sqlite:///gov.db"
    assert args.check_db == "sqlite:///checks.db"
    assert args.policy_cells == "policy/cells.toml"


def test_main_mcp_sets_store_and_policy_cell_env(monkeypatch):
    import os

    import legis.mcp as mcp_module

    calls = []

    def fake_mcp_main(agent_id):
        calls.append(
            {
                "agent_id": agent_id,
                "governance_db": os.environ.get("LEGIS_GOVERNANCE_DB"),
                "check_db": os.environ.get("LEGIS_CHECK_DB"),
                "policy_cells": os.environ.get("LEGIS_POLICY_CELLS"),
            }
        )
        return 0

    for var in ("LEGIS_GOVERNANCE_DB", "LEGIS_CHECK_DB", "LEGIS_POLICY_CELLS"):
        # delenv(raising=False) on an absent var records nothing to restore,
        # so the env writes main()'s mcp path makes below would leak into later
        # tests; seed first so the monkeypatch teardown undoes them.
        monkeypatch.setenv(var, "leak-guard")
        monkeypatch.delenv(var)
    monkeypatch.setattr(mcp_module, "main", fake_mcp_main)

    rc = main(
        [
            "mcp",
            "--agent-id",
            "agent-1",
            "--governance-db",
            "sqlite:///gov.db",
            "--check-db",
            "sqlite:///checks.db",
            "--policy-cells",
            "policy/cells.toml",
        ]
    )

    assert rc == 0
    assert calls == [
        {
            "agent_id": "agent-1",
            "governance_db": "sqlite:///gov.db",
            "check_db": "sqlite:///checks.db",
            "policy_cells": "policy/cells.toml",
        }
    ]


def test_serve_accepts_judge_configuration_flags():
    args = build_parser().parse_args(
        [
            "serve",
            "--judge-provider",
            "openrouter",
            "--judge-model",
            "anthropic/claude-opus-4.7",
            "--judge-max-tokens",
            "2048",
        ]
    )

    assert args.judge_provider == "openrouter"
    assert args.judge_model == "anthropic/claude-opus-4.7"
    assert args.judge_max_tokens == 2048


def test_main_serve_sets_judge_env(monkeypatch):
    import os

    calls = []

    def fake_run(app, **kw):
        calls.append(
            {
                "provider": os.environ.get("LEGIS_JUDGE_PROVIDER"),
                "model": os.environ.get("LEGIS_JUDGE_MODEL"),
                "max_tokens": os.environ.get("LEGIS_JUDGE_MAX_TOKENS"),
            }
        )

    monkeypatch.delenv("LEGIS_JUDGE_PROVIDER", raising=False)
    monkeypatch.delenv("LEGIS_JUDGE_MODEL", raising=False)
    monkeypatch.delenv("LEGIS_JUDGE_MAX_TOKENS", raising=False)

    rc = main(
        [
            "serve",
            "--judge-provider",
            "openrouter",
            "--judge-model",
            "anthropic/claude-opus-4.7",
            "--judge-max-tokens",
            "2048",
        ],
        run=fake_run,
    )

    assert rc == 0
    assert calls == [
        {
            "provider": "openrouter",
            "model": "anthropic/claude-opus-4.7",
            "max_tokens": "2048",
        }
    ]


def test_main_mcp_sets_judge_env(monkeypatch):
    import os

    import legis.mcp as mcp_module

    calls = []

    def fake_mcp_main(agent_id):
        calls.append(
            {
                "provider": os.environ.get("LEGIS_JUDGE_PROVIDER"),
                "model": os.environ.get("LEGIS_JUDGE_MODEL"),
                "max_tokens": os.environ.get("LEGIS_JUDGE_MAX_TOKENS"),
            }
        )
        return 0

    monkeypatch.delenv("LEGIS_JUDGE_PROVIDER", raising=False)
    monkeypatch.delenv("LEGIS_JUDGE_MODEL", raising=False)
    monkeypatch.delenv("LEGIS_JUDGE_MAX_TOKENS", raising=False)
    monkeypatch.setattr(mcp_module, "main", fake_mcp_main)
    rc = main(
        [
            "mcp",
            "--agent-id",
            "agent-1",
            "--judge-provider",
            "openrouter",
            "--judge-model",
            "anthropic/claude-opus-4.7",
            "--judge-max-tokens",
            "2048",
        ]
    )

    assert rc == 0
    assert calls == [
        {
            "provider": "openrouter",
            "model": "anthropic/claude-opus-4.7",
            "max_tokens": "2048",
        }
    ]


def test_sei_backfill_command_defaults_to_dry_run():
    args = build_parser().parse_args(
        ["sei-backfill", "--db", "sqlite:///gov.db", "--loomweave-url", "http://localhost"]
    )

    assert args.command == "sei-backfill"
    assert args.db == "sqlite:///gov.db"
    assert args.loomweave_url == "http://localhost"
    assert args.execute is False
    assert args.actor == "legis-sei-backfill"


def test_main_sei_backfill_dispatches_service(monkeypatch, capsys):
    import legis.cli as cli_module

    calls = []

    class FakeStore:
        def __init__(self, db):
            self.db = db

    class FakeClient:
        def __init__(self, url, *, hmac_key=None):
            self.url = url
            self.hmac_key = hmac_key

    class FakeClock:
        pass

    class FakeReport:
        def to_dict(self):
            return {"dry_run": False, "appended": 2}

    def fake_run_pre_sei_backfill(store, client, clock, *, dry_run, actor):
        calls.append(
            {
                "db": store.db,
                "url": client.url,
                "hmac_key": client.hmac_key,
                "clock_type": type(clock).__name__,
                "dry_run": dry_run,
                "actor": actor,
            }
        )
        return FakeReport()

    monkeypatch.setattr(cli_module, "AuditStore", FakeStore, raising=False)
    monkeypatch.setattr(cli_module, "HttpLoomweaveIdentity", FakeClient, raising=False)
    monkeypatch.setattr(cli_module, "SystemClock", FakeClock, raising=False)
    monkeypatch.setenv("LEGIS_LOOMWEAVE_HMAC_KEY", "loomweave-secret")
    monkeypatch.setattr(
        cli_module,
        "run_pre_sei_backfill",
        fake_run_pre_sei_backfill,
        raising=False,
    )

    rc = main(
        [
            "sei-backfill",
            "--db",
            "sqlite:///gov.db",
            "--loomweave-url",
            "http://localhost",
            "--execute",
            "--actor",
            "operator-1",
        ]
    )

    assert rc == 0
    assert calls == [
        {
            "db": "sqlite:///gov.db",
            "url": "http://localhost",
            "hmac_key": b"loomweave-secret",
            "clock_type": "FakeClock",
            "dry_run": False,
            "actor": "operator-1",
        }
    ]
    assert '"appended": 2' in capsys.readouterr().out


def test_policy_boundary_check_outputs_json_and_fails(monkeypatch, capsys, tmp_path):
    import legis.cli as cli_module
    from legis.cli import main

    class FakeFinding:
        rule_id = "POLICY_BOUNDARY_TEST_WEAK"
        file_path = "src/x.py"
        line = 7
        qualname = "x.guarded"
        reason = "weak"

        def to_dict(self):
            return {"rule_id": self.rule_id, "file_path": self.file_path}

    # Root must hold >=1 analyzable .py file or the no-vacuous-pass guard fires
    # before the (mocked) scanner is consulted.
    (tmp_path / "real.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        cli_module, "scan_policy_boundaries", lambda root, repo_root=None: [FakeFinding()]
    )

    rc = main(["policy-boundary-check", "--root", str(tmp_path), "--repo-root", str(tmp_path), "--format", "json"])

    assert rc == 1
    assert "POLICY_BOUNDARY_TEST_WEAK" in capsys.readouterr().out


def test_policy_boundary_check_passes_when_no_findings(monkeypatch, capsys, tmp_path):
    import legis.cli as cli_module
    from legis.cli import main

    # A genuine clean PASS: the root has analyzable source but the (mocked)
    # scanner finds nothing. This must stay PASS, NOT collapse to NO_ROOT.
    (tmp_path / "real.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(cli_module, "scan_policy_boundaries", lambda root, repo_root=None: [])

    rc = main(["policy-boundary-check", "--root", str(tmp_path), "--repo-root", str(tmp_path)])

    assert rc == 0
    assert "policy-boundary-check: PASS" in capsys.readouterr().out


def test_policy_boundary_check_no_root_when_root_nonexistent(capsys, tmp_path):
    # Friction D: a governance gate must NEVER pass on a nonexistent root.
    from legis.cli import main

    rc = main(["policy-boundary-check", "--root", str(tmp_path / "nope"), "--repo-root", str(tmp_path)])

    assert rc != 0
    out = capsys.readouterr().out
    assert "NO_ROOT" in out
    assert "policy-boundary-check: PASS" not in out


def test_policy_boundary_check_no_root_when_root_has_zero_source_files(capsys, tmp_path):
    # Root exists but holds zero analyzable .py files -> NO_ROOT, never PASS.
    from legis.cli import main

    src = tmp_path / "src"
    src.mkdir()
    (src / "README.md").write_text("# docs only\n", encoding="utf-8")

    rc = main(["policy-boundary-check", "--root", str(src), "--repo-root", str(tmp_path)])

    assert rc != 0
    out = capsys.readouterr().out
    assert "NO_ROOT" in out
    assert "policy-boundary-check: PASS" not in out


def test_policy_boundary_check_no_root_json_format(capsys, tmp_path):
    # The machine-readable surface carries the discriminated outcome too.
    from legis.cli import main

    rc = main([
        "policy-boundary-check",
        "--root", str(tmp_path / "nope"),
        "--repo-root", str(tmp_path),
        "--format", "json",
    ])

    assert rc != 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["outcome"] == "NO_ROOT"
    assert payload["findings"] == []


def test_policy_boundary_check_end_to_end_flags_weak_boundary(tmp_path):
    # Non-mocked: prove the CLI's argument wiring actually reaches the scanner.
    # A monkeypatched-only test would pass even if --root/--repo-root were
    # mis-wired, because src/ has no real decorators.
    from legis.cli import main

    src = tmp_path / "src" / "pkg"
    src.mkdir(parents=True)
    (src / "subject.py").write_text(
        'from legis.policy.decorator import policy_boundary\n\n'
        '@policy_boundary(source="docs/spec.md:1", suppresses=("PY-WL-101",),\n'
        '    invariant="x", test_ref="tests/test_subject.py::test_x", test_fingerprint="stale")\n'
        'def guarded(payload):\n    return "ok"\n',
        encoding="utf-8",
    )
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_subject.py").write_text(
        'def test_x():\n    assert guarded(1) == "ok", "PY-WL-101"\n', encoding="utf-8"
    )

    rc = main(["policy-boundary-check", "--root", str(src), "--repo-root", str(tmp_path)])

    assert rc == 1  # stale fingerprint → a real finding through the real scanner


def test_policy_boundary_check_text_format_with_findings(monkeypatch, capsys, tmp_path):
    import legis.cli as cli_module
    from legis.cli import main

    class FakeFinding:
        rule_id = "POLICY_BOUNDARY_TEST_WEAK"
        file_path = "src/x.py"
        line = 7
        qualname = "x.guarded"
        reason = "weak"

        def to_dict(self):
            return {}

    (tmp_path / "real.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        cli_module, "scan_policy_boundaries", lambda root, repo_root=None: [FakeFinding()]
    )
    rc = main(["policy-boundary-check", "--root", str(tmp_path), "--repo-root", str(tmp_path)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "src/x.py:7: POLICY_BOUNDARY_TEST_WEAK: x.guarded: weak" in out


def test_check_override_rate_fails_closed_for_protected_records_without_hmac_key(tmp_path, monkeypatch, capsys):
    from legis.clock import FixedClock
    from legis.enforcement.protected import ProtectedGate
    from legis.enforcement.verdict import JudgeOpinion, Verdict
    from legis.identity.entity_key import EntityKey
    from legis.store.audit_store import AuditStore

    class ScriptedJudge:
        def evaluate(self, record):
            return JudgeOpinion(Verdict.ACCEPTED, "judge@1", "ok")

    db = f"sqlite:///{tmp_path / 'gov.db'}"
    gate = ProtectedGate(
        AuditStore(db),
        FixedClock("2026-06-02T12:00:00+00:00"),
        judge=ScriptedJudge(),
        key=b"protected-key",
    )
    gate.submit(
        policy="no-eval",
        entity_key=EntityKey.from_locator("src/x.py:f"),
        rationale="approved",
        agent_id="agent-1",
        file_fingerprint="sha256:abc",
        ast_path="Module/Call[eval]",
    )

    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)
    monkeypatch.delenv("LEGIS_PROTECTED_POLICIES", raising=False)

    rc = main(["check-override-rate", "--db", db])

    assert rc == 1
    assert "LEGIS_HMAC_KEY" in capsys.readouterr().err


def test_check_override_rate_rejects_rechained_protected_tampering(tmp_path, monkeypatch, capsys):
    import json
    import sqlite3

    from legis.canonical import canonical_json, content_hash
    from legis.clock import FixedClock
    from legis.enforcement.protected import ProtectedGate
    from legis.enforcement.verdict import JudgeOpinion, Verdict
    from legis.identity.entity_key import EntityKey
    from legis.store.audit_store import GENESIS, AuditStore, _chain

    class ScriptedJudge:
        def evaluate(self, record):
            return JudgeOpinion(Verdict.BLOCKED, "judge@1", "no")

    db_path = tmp_path / "gov.db"
    db = f"sqlite:///{db_path}"
    gate = ProtectedGate(
        AuditStore(db),
        FixedClock("2026-06-02T12:00:00+00:00"),
        judge=ScriptedJudge(),
        key=b"protected-key",
    )
    for i in range(25):
        gate.operator_override(
            policy="no-eval",
            entity_key=EntityKey.from_locator(f"src/x{i}.py:f"),
            rationale="security lead approved release exception",
            operator_id="op-sec-lead",
            file_fingerprint=f"sha256:{i}",
            ast_path="Module/Call[eval]",
        )

    con = sqlite3.connect(db_path)
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    con.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
    rows = con.execute("SELECT seq, payload FROM audit_log ORDER BY seq ASC").fetchall()
    for seq, payload in rows:
        parsed = json.loads(payload)
        parsed["extensions"]["judge_verdict"] = Verdict.ACCEPTED.value
        con.execute("UPDATE audit_log SET payload=? WHERE seq=?", (canonical_json(parsed), seq))
    previous = GENESIS
    for seq, payload in con.execute("SELECT seq, payload FROM audit_log ORDER BY seq ASC").fetchall():
        current_content_hash = content_hash(json.loads(payload))
        current_chain_hash = _chain(previous, current_content_hash)
        con.execute(
            "UPDATE audit_log SET content_hash=?, prev_hash=?, chain_hash=? WHERE seq=?",
            (current_content_hash, previous, current_chain_hash, seq),
        )
        previous = current_chain_hash
    con.commit()
    con.close()

    monkeypatch.setenv("LEGIS_HMAC_KEY", "protected-key")
    monkeypatch.setenv("LEGIS_PROTECTED_POLICIES", "no-eval")

    rc = main(["check-override-rate", "--db", db])

    assert rc == 1
    assert "verification failed" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# session-context (N-1: never exit silently)
# ---------------------------------------------------------------------------


def test_session_context_always_prints_banner(tmp_path, monkeypatch, capsys):
    # N-1: exit 0 with NO output is indistinguishable from a broken command —
    # even a non-project cwd must get a one-line posture banner.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LEGIS_POLICY_CELLS", raising=False)
    rc = main(["session-context"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.startswith("legis: ")
    assert out.count("\n") == 1  # one banner line, nothing else


def test_session_context_prints_banner_then_drift_messages(tmp_path, monkeypatch, capsys):
    from legis import install

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LEGIS_POLICY_CELLS", raising=False)
    install.inject_instructions(tmp_path / "CLAUDE.md")
    monkeypatch.setattr(install, "_instructions_text", lambda: "DRIFTED\n")
    rc = main(["session-context"])
    assert rc == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("legis: ")
    assert any("CLAUDE.md" in line for line in lines[1:])


def test_session_context_prints_failure_line_when_refresh_raises(tmp_path, monkeypatch, capsys):
    import legis.hooks as hooks_module

    monkeypatch.chdir(tmp_path)

    def boom(_root):
        raise OSError("disk gone")

    monkeypatch.setattr(hooks_module, "refresh_instructions", boom)
    rc = main(["session-context"])
    assert rc == 0  # the hook must never fail the session start...
    out = capsys.readouterr().out
    # ...but the failure must be visible, not silent.
    assert "instruction freshness check failed" in out
