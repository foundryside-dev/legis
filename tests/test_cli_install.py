"""Tests for the install / session-context CLI surfaces and MCP-boot refresh."""

from __future__ import annotations

import json

from legis import install
from legis.cli import build_parser, main
from legis.install import INSTRUCTIONS_MARKER, SKILL_NAME


def test_install_all_creates_every_artifact(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    rc = main(["install"])
    assert rc == 0

    assert INSTRUCTIONS_MARKER in (tmp_path / "CLAUDE.md").read_text()
    assert INSTRUCTIONS_MARKER in (tmp_path / "AGENTS.md").read_text()
    assert (tmp_path / ".claude" / "skills" / SKILL_NAME / "SKILL.md").is_file()
    assert (tmp_path / ".agents" / "skills" / SKILL_NAME / "SKILL.md").is_file()
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert "SessionStart" in settings["hooks"]
    gitignore = (tmp_path / ".gitignore").read_text()
    assert ".weft/legis/" in gitignore


def test_install_selective_gitignore_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = main(["install", "--gitignore"])
    assert rc == 0
    assert (tmp_path / ".gitignore").exists()
    assert not (tmp_path / "CLAUDE.md").exists()
    assert not (tmp_path / ".claude").exists()


def test_install_gitignore_ships_nested_dir_ignore(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = main(["install", "--gitignore"])
    assert rc == 0
    # root rule...
    assert ".weft/legis/" in (tmp_path / ".gitignore").read_text()
    # ...and the nested suite-standard ignore (filigree-4ed8152630)
    nested = tmp_path / ".weft" / "legis" / ".gitignore"
    assert nested.is_file()
    assert install.LEGIS_DIR_GITIGNORE_MARKER in nested.read_text()


def test_install_claude_md_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = main(["install", "--claude-md"])
    assert rc == 0
    assert (tmp_path / "CLAUDE.md").exists()
    assert not (tmp_path / "AGENTS.md").exists()


def test_install_reports_failure_rc1_on_symlink(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    real = tmp_path / "real.md"
    real.write_text("x")
    (tmp_path / "CLAUDE.md").symlink_to(real)
    rc = main(["install", "--claude-md"])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().out


def test_install_renders_fail_and_continues_when_a_step_raises(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    def boom(_root):
        raise RuntimeError("step blew up")

    monkeypatch.setattr(install, "install_skills", boom)
    rc = main(["install"])
    out = capsys.readouterr().out
    # A raising step is rendered as a [FAIL] line, not a traceback that aborts
    # the run and leaves the install half-applied...
    assert "[FAIL] Claude Code skill: step blew up" in out
    # ...and the steps after it still run.
    assert (tmp_path / ".gitignore").exists()
    assert rc == 1


def test_session_context_banner_only_when_fresh(tmp_path, monkeypatch, capsys):
    # N-1: a fresh project still gets the one-line posture banner — silence is
    # indistinguishable from a broken command — but no drift messages.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LEGIS_POLICY_CELLS", raising=False)
    install.inject_instructions(tmp_path / "CLAUDE.md")
    rc = main(["session-context"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.startswith("legis: instructions current")
    assert out.count("\n") == 1  # banner line only, no refresh messages


def test_session_context_prints_on_drift(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    install.inject_instructions(tmp_path / "CLAUDE.md")
    monkeypatch.setattr(install, "_instructions_text", lambda: "DRIFTED\n")
    rc = main(["session-context"])
    assert rc == 0
    assert "CLAUDE.md" in capsys.readouterr().out


def test_install_subcommand_parses_flags():
    args = build_parser().parse_args(["install", "--claude-md", "--hooks"])
    assert args.command == "install"
    assert args.claude_md is True
    assert args.hooks is True
    assert args.agents_md is False


# ---------------------------------------------------------------------------
# Posture-ledger install wiring (posture-ratchet, Phase 6)
# ---------------------------------------------------------------------------


def test_install_posture_only_writes_genesis(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LEGIS_OPERATOR_KEY_AGE_PASSPHRASE", "pw")
    rc = main(["install", "--posture"])
    assert rc == 0
    # GENESIS written, age blob persisted, but no unrelated install artifacts.
    from legis.posture import PostureLedger

    led = PostureLedger(install.posture_db_url_for_install(), initialize=False)
    recs = led.store.read_all()
    assert len(recs) == 1
    assert recs[0].payload["kind"] == "GENESIS"
    assert recs[0].payload["floor"] == "chill"
    assert (tmp_path / ".weft" / "legis" / "operator.age").exists()
    assert not (tmp_path / "CLAUDE.md").exists()


def test_install_all_defers_posture_without_custody(tmp_path, monkeypatch, capsys):
    # A bare `legis install` with no custody configured must NOT hard-fail; the
    # posture step defers (no GENESIS written) and rc stays 0.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LEGIS_OPERATOR_KEY_AGE_PASSPHRASE", raising=False)
    monkeypatch.delenv("LEGIS_OPERATOR_KEY", raising=False)
    rc = main(["install"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "deferred" in out
    # No genesis was written.
    db = tmp_path / ".weft" / "legis" / "legis-posture.db"
    if db.exists():
        from legis.posture import PostureLedger

        led = PostureLedger(install.posture_db_url_for_install(), initialize=False)
        assert led.store.read_all() == []


def test_install_posture_only_fails_without_custody(tmp_path, monkeypatch, capsys):
    # An explicit posture install is an automation readiness check: if key
    # custody is not configured, rc must be nonzero and no GENESIS may be written.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LEGIS_OPERATOR_KEY_AGE_PASSPHRASE", raising=False)
    monkeypatch.delenv("LEGIS_OPERATOR_KEY", raising=False)

    rc = main(["install", "--posture"])

    assert rc == 1
    out = capsys.readouterr().out
    assert "[FAIL] posture ledger:" in out
    assert "custody" in out
    db = tmp_path / ".weft" / "legis" / "legis-posture.db"
    if db.exists():
        from legis.posture import PostureLedger

        led = PostureLedger(install.posture_db_url_for_install(), initialize=False)
        assert led.store.read_all() == []


def test_install_posture_env_backend_opt_in(tmp_path, monkeypatch, capsys):
    # --insecure-key-in-env selects the env backend; the env sink is a no-op so
    # the GENESIS lands with no age blob and no custody refusal.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", "ab" * 32)
    rc = main(["install", "--posture", "--insecure-key-in-env"])
    assert rc == 0
    from legis.posture import PostureLedger

    led = PostureLedger(install.posture_db_url_for_install(), initialize=False)
    recs = led.store.read_all()
    assert len(recs) == 1
    assert recs[0].payload["kind"] == "GENESIS"
    assert not (tmp_path / ".weft" / "legis" / "operator.age").exists()


def test_install_posture_recovers_metadata_only_ledger(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from legis.posture import PostureLedger

    ledger = PostureLedger(install.posture_db_url_for_install(), initialize=True)
    ledger.session_opened(
        operator_id="alice",
        enabled_at="t0",
        ttl=300,
        keychain_auth_ref=None,
        session_id="sess-orphan",
    )
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", "ab" * 32)

    rc = main(["install", "--posture", "--insecure-key-in-env"])

    assert rc == 0
    records = PostureLedger(install.posture_db_url_for_install(), initialize=False).store.read_all()
    assert [record.payload["kind"] for record in records] == [
        "OPERATOR_SESSION_OPENED",
        "GENESIS",
    ]


# ---------------------------------------------------------------------------
# MCP-boot refresh wiring
# ---------------------------------------------------------------------------


def test_mcp_boot_refreshes_drifted_instructions(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    install.inject_instructions(tmp_path / "CLAUDE.md")
    monkeypatch.setattr(install, "_instructions_text", lambda: "DRIFTED ON BOOT\n")

    import legis.mcp as mcp_module

    monkeypatch.setattr(mcp_module, "main", lambda agent_id: 0)

    rc = main(["mcp", "--agent-id", "agent-1"])
    assert rc == 0
    assert "DRIFTED ON BOOT" in (tmp_path / "CLAUDE.md").read_text()


def test_mcp_boot_refresh_failure_does_not_break_startup(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    import legis.hooks as hooks_module
    import legis.mcp as mcp_module

    calls = []

    def boom(_root):
        raise RuntimeError("refresh exploded")

    monkeypatch.setattr(hooks_module, "refresh_instructions", boom)
    monkeypatch.setattr(mcp_module, "main", lambda agent_id: calls.append(agent_id) or 0)

    rc = main(["mcp", "--agent-id", "agent-1"])
    assert rc == 0
    assert calls == ["agent-1"]


def test_mcp_boot_refresh_failure_is_logged_with_exc_info(tmp_path, monkeypatch, caplog):
    # The boot refresh is the ONLY refresh trigger in a Codex-only repo with no
    # SessionStart hook. A persistently failing refresh must be visible at the
    # default level (WARNING), not swallowed at DEBUG — otherwise agents run on
    # drifted instructions with no signal. Mirrors hooks.generate_session_context.
    monkeypatch.chdir(tmp_path)

    import logging

    import legis.hooks as hooks_module
    import legis.mcp as mcp_module

    def boom(_root):
        raise RuntimeError("refresh exploded")

    monkeypatch.setattr(hooks_module, "refresh_instructions", boom)
    monkeypatch.setattr(mcp_module, "main", lambda agent_id: 0)

    with caplog.at_level(logging.WARNING, logger="legis.cli"):
        rc = main(["mcp", "--agent-id", "agent-1"])

    assert rc == 0
    assert caplog.records, "expected a warning when boot refresh raises"
    rec = caplog.records[-1]
    assert rec.levelno >= logging.WARNING
    assert rec.exc_info is not None
