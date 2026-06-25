from __future__ import annotations

import json
import sys

from legis.cli import main as cli_main
from legis.doctor import (
    DoctorCheck,
    check_audit_chain,
    check_db_overrides,
    check_filigree_binding_scope,
    check_gitignore,
    check_hmac_key,
    check_hook,
    check_instruction_block,
    check_legacy_stray_db,
    check_mcp_json,
    check_policy_cells,
    check_sibling_url,
    check_skill_pack,
    check_store_dir,
    check_wardline_artifact_key,
    check_wardline_routing,
    check_weft_toml,
    collect_checks,
    render_json,
    render_text,
    run_doctor,
    _store_url,
)
from legis.install import mcp_entry_is_current, register_mcp_json as _register_mcp_json
from legis import install as legis_install


def _write_mcp_entry(tmp_path, entry):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"legis": entry}}))


def test_doctorcheck_to_dict_omits_empty_message():
    assert DoctorCheck("a.b", "ok").to_dict() == {
        "id": "a.b",
        "status": "ok",
        "fixed": False,
        "repairable": False,
    }
    assert DoctorCheck("a.b", "error", message="boom").to_dict() == {
        "id": "a.b",
        "status": "error",
        "fixed": False,
        "repairable": False,
        "message": "boom",
    }


def test_doctorcheck_to_dict_carries_repairable_true():
    assert DoctorCheck("a.b", "error", message="x", repairable=True).to_dict() == {
        "id": "a.b",
        "status": "error",
        "fixed": False,
        "repairable": True,
        "message": "x",
    }


def test_render_json_shape():
    checks = [DoctorCheck("a", "ok"), DoctorCheck("b", "error", message="bad")]
    payload = json.loads(render_json(checks))
    assert payload["ok"] is False
    assert payload["checks"][0] == {"id": "a", "status": "ok", "fixed": False, "repairable": False}
    assert payload["next_actions"] == ["b: bad"]


def test_render_text_lists_only_problems_when_healthy_says_ok():
    # all-ok: banner present, no problem lines
    assert render_text([DoctorCheck("a", "ok")]) == "legis doctor: ok"

    # error present: no "ok" in headline, error listed
    out = render_text([DoctorCheck("a", "ok"), DoctorCheck("b", "error", message="bad")])
    assert "b: error" in out
    assert "legis doctor: ok" not in out

    # warn-only: banner present with warning count AND warn check is listed
    out_warn = render_text([DoctorCheck("a", "ok"), DoctorCheck("b", "warn", message="heads up")])
    assert "legis doctor: ok" in out_warn
    assert "b: warn" in out_warn


def test_render_text_tags_auto_fixable_and_footer():
    out = render_text(
        [DoctorCheck("install.x", "error", message="m", repairable=True)]
    )
    assert "install.x: error — m [auto-fixable]" in out
    assert "Run `legis doctor --fix` to repair auto-fixable items." in out
    # no operator items => no operator footer
    assert "[operator] items are not auto-fixable" not in out


def test_render_text_tags_operator_and_footer():
    out = render_text(
        [DoctorCheck("runtime.policy_cells", "warn", message="m", repairable=False)]
    )
    assert "runtime.policy_cells: warn — m [operator]" in out
    assert "[operator] items are not auto-fixable by `legis doctor --fix`" in out
    # no auto-fixable items => no fix footer
    assert "Run `legis doctor --fix` to repair auto-fixable items." not in out


def test_render_text_tags_fixed():
    # A repaired check carries fixed=True; render it directly since the
    # problems-only filter excludes ok checks from a real --fix run.
    out = render_text([DoctorCheck("install.x", "warn", message="m", fixed=True, repairable=True)])
    assert "install.x: warn — m [fixed]" in out
    # [fixed] is not auto-fixable-pending, so no fix footer from it alone
    assert "Run `legis doctor --fix` to repair auto-fixable items." not in out


def test_render_text_surfaces_realistic_fixed_check():
    # A real `--fix` run constructs each repaired check with status "ok" (e.g.
    # DoctorCheck(cid, "ok", fixed=True, repairable=True)), NOT "warn". The
    # problems-only filter (status != "ok") therefore dropped every fixed check,
    # the [fixed] branch was dead, and an all-repaired run rendered the bare
    # "legis doctor: ok" with no record of what was fixed. render_text must surface
    # fixed checks even when their post-repair status is "ok".
    out = render_text(
        [
            DoctorCheck("a", "ok"),
            DoctorCheck("install.x", "ok", message="re-registered", fixed=True, repairable=True),
        ]
    )
    assert "install.x:" in out and "[fixed]" in out  # the repaired item is listed
    assert "fixed 1 item(s)" in out  # and the banner records that a repair happened
    assert out != "legis doctor: ok"  # not the silent all-ok banner


def test_render_text_both_footers_when_mixed():
    out = render_text(
        [
            DoctorCheck("install.x", "error", message="a", repairable=True),
            DoctorCheck("runtime.policy_cells", "warn", message="b", repairable=False),
        ]
    )
    assert "[auto-fixable]" in out
    assert "[operator]" in out
    assert "Run `legis doctor --fix` to repair auto-fixable items." in out
    assert "[operator] items are not auto-fixable by `legis doctor --fix`" in out


def test_run_doctor_healthy_after_repair(tmp_path, capsys):
    # A project repaired via run_doctor renders healthy on re-check, exit 0.
    run_doctor(tmp_path, repair=True, fmt="text")
    capsys.readouterr()  # discard repair output
    rc = run_doctor(tmp_path, repair=False, fmt="text")
    assert rc == 0
    assert "legis doctor: ok" in capsys.readouterr().out


def test_run_doctor_json_format(tmp_path, capsys, monkeypatch):
    # Clear the governance-enablement env so the report-only N3 checks
    # deterministically warn (an unwired fresh project). They are NOT repairable
    # (operator must set env / author cells.toml out-of-band) and are the honest
    # C-10(c) signal — so a repaired-but-ungoverned project is ok-with-warns,
    # not error, and its only next_actions are those enablement hints. STRIKE D
    # (PDR-0023) adds runtime.wardline_artifact_key to that set: keyless dev is a
    # legitimate warn (verification DISABLED), the recruiting advisory.
    for var in (
        "LEGIS_POLICY_CELLS", "LEGIS_DEV_DEFAULT_CELLS", "LEGIS_SOURCE_ROOT",
        "LEGIS_WARDLINE_CELL", "LEGIS_WARDLINE_CELL_BY_SEVERITY",
        "LEGIS_WARDLINE_ARTIFACT_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    run_doctor(tmp_path, repair=True, fmt="json")
    capsys.readouterr()  # discard repair output
    rc = run_doctor(tmp_path, repair=False, fmt="json")
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert {a.split(":", 1)[0] for a in payload["next_actions"]} == {
        "runtime.policy_cells",
        "runtime.wardline_routing",
        "runtime.wardline_artifact_key",
    }


def test_cli_doctor_runs_and_exits_zero(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = cli_main(["doctor", "--repair"])
    assert rc == 0
    assert "legis doctor: ok" in capsys.readouterr().out


def test_cli_doctor_json(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = cli_main(["doctor", "--repair", "--format", "json"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_cli_doctor_fix_repairs_project(tmp_path, capsys, monkeypatch):
    # --fix is the canonical flag and must drive the same repair path as --repair.
    monkeypatch.chdir(tmp_path)
    rc = cli_main(["doctor", "--fix"])
    assert rc == 0
    assert "legis doctor: ok" in capsys.readouterr().out


def test_cli_doctor_repair_alias_still_accepted(tmp_path, capsys, monkeypatch):
    # Back-compat: --repair remains a working alias of --fix (no break for scripts).
    monkeypatch.chdir(tmp_path)
    rc = cli_main(["doctor", "--repair"])
    assert rc == 0
    assert "legis doctor: ok" in capsys.readouterr().out


def test_cli_doctor_fix_dest_is_fix():
    # argparse dest must be "fix" (both spellings land on the same dest).
    from legis.cli import build_parser

    parser = build_parser()
    assert parser.parse_args(["doctor", "--fix"]).fix is True
    assert parser.parse_args(["doctor", "--repair"]).fix is True
    assert parser.parse_args(["doctor"]).fix is False


def test_doctor_json_carries_repairable_per_check_and_true_for_seven(tmp_path, capsys):
    # repairable is always present per check, and True exactly for the seven
    # repair-honoring check functions (which emit nine check ids, since the
    # instruction-block and skill-pack checks each run for two targets).
    run_doctor(tmp_path, repair=False, fmt="json")
    payload = json.loads(capsys.readouterr().out)
    by_id = {c["id"]: c for c in payload["checks"]}
    for c in payload["checks"]:
        assert "repairable" in c  # always present (stable json shape)
    repairable_ids = {cid for cid, c in by_id.items() if c["repairable"]}
    assert repairable_ids == {
        "install.claude_md",
        "install.agents_md",
        "install.claude_skill",
        "install.agents_skill",
        "install.hook",
        "install.gitignore",
        "install.dir_gitignore",
        "install.mcp_json",
        "store.dir",
    }


# ---------------------------------------------------------------------------
# check_mcp_json
# ---------------------------------------------------------------------------


def test_mcp_json_absent_is_error(tmp_path):
    c = check_mcp_json(tmp_path, repair=False)
    assert c.id == "install.mcp_json"
    assert c.status == "error"
    assert c.fixed is False


def test_mcp_json_repair_fixes_it(tmp_path):
    c = check_mcp_json(tmp_path, repair=True)
    assert c.status == "ok"
    assert c.fixed is True
    assert (tmp_path / ".mcp.json").exists()


def test_mcp_json_present_is_ok(tmp_path):
    from legis.install import register_mcp_json

    register_mcp_json(tmp_path)
    c = check_mcp_json(tmp_path, repair=False)
    assert c.status == "ok"
    assert c.fixed is False


def test_mcp_json_stale_command_is_error_then_repaired(tmp_path):
    """An entry with a dead command path is stale and must trigger repair."""
    stale_entry = {
        "mcpServers": {
            "legis": {
                "type": "stdio",
                "command": "/nonexistent/legis-xyz",
                "args": ["mcp", "--agent-id", "claude-code"],
                "env": {},
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(stale_entry))
    c = check_mcp_json(tmp_path, repair=False)
    assert c.id == "install.mcp_json"
    assert c.status == "error"

    fixed = check_mcp_json(tmp_path, repair=True)
    assert fixed.status == "ok"
    assert fixed.fixed is True


# ---------------------------------------------------------------------------
# Direct unit tests for mcp_entry_is_current predicate
# ---------------------------------------------------------------------------


def test_mcp_entry_is_current_absent_file(tmp_path):
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_malformed_json(tmp_path):
    (tmp_path / ".mcp.json").write_text("{not valid json")
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_non_dict_top_level(tmp_path):
    (tmp_path / ".mcp.json").write_text('["just", "an", "array"]')
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_missing_mcp_servers(tmp_path):
    (tmp_path / ".mcp.json").write_text('{"other": {}}')
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_mcp_servers_not_dict(tmp_path):
    (tmp_path / ".mcp.json").write_text('{"mcpServers": "not a dict"}')
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_no_legis_entry(tmp_path):
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"other": {}}}')
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_legis_entry_not_dict(tmp_path):
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"legis": "string"}}')
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_args_without_mcp(tmp_path):
    entry = {"mcpServers": {"legis": {"command": "legis", "args": ["serve"]}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(entry))
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_rejects_non_stdio_type(tmp_path):
    _write_mcp_entry(
        tmp_path,
        {"type": "sse", "command": sys.executable, "args": ["-P", "-m", "legis", "mcp", "--agent-id", "a"]},
    )
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_requires_mcp_subcommand_and_agent_id(tmp_path):
    _write_mcp_entry(
        tmp_path,
        {"type": "stdio", "command": sys.executable, "args": ["mcp"]},
    )
    assert mcp_entry_is_current(tmp_path) is False

    _write_mcp_entry(
        tmp_path,
        {"type": "stdio", "command": sys.executable, "args": ["serve", "mcp", "--agent-id", "a"]},
    )
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_rejects_repo_local_command(tmp_path):
    local = tmp_path / "legis"
    local.write_text("#!/bin/sh\n")
    local.chmod(0o755)
    _write_mcp_entry(
        tmp_path,
        {"type": "stdio", "command": str(local), "args": ["mcp", "--agent-id", "a"]},
    )
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_rejects_non_legis_executable(tmp_path):
    fake = tmp_path.parent / f"{tmp_path.name}-external" / "fake-runner"
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    _write_mcp_entry(
        tmp_path,
        {"type": "stdio", "command": str(fake), "args": ["mcp", "--agent-id", "a"]},
    )
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_rejects_python_module_without_safe_path(tmp_path):
    _write_mcp_entry(
        tmp_path,
        {
            "type": "stdio",
            "command": sys.executable,
            "args": ["-m", "legis", "mcp", "--agent-id", "a"],
        },
    )
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_rejects_fake_python_prefixed_executable(tmp_path):
    fake = tmp_path.parent / f"{tmp_path.name}-external" / "python3-fake"
    fake.parent.mkdir(parents=True, exist_ok=True)
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    _write_mcp_entry(
        tmp_path,
        {
            "type": "stdio",
            "command": str(fake),
            "args": ["-P", "-m", "legis", "mcp", "--agent-id", "a"],
        },
    )
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_rejects_unsafe_or_secret_env(tmp_path):
    for env in (
        {"LEGIS_UNSAFE_DEV_AUTH": "1"},
        {"LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING": "1"},
        {"LEGIS_HMAC_KEY": "secret"},
        {"OPENROUTER_API_KEY": "secret"},
    ):
        _write_mcp_entry(
            tmp_path,
            {"type": "stdio", "command": sys.executable, "args": ["mcp", "--agent-id", "a"], "env": env},
        )
        assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_empty_command(tmp_path):
    entry = {"mcpServers": {"legis": {"command": "", "args": ["mcp"]}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(entry))
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_dead_command_path(tmp_path):
    entry = {
        "mcpServers": {
            "legis": {
                "command": "/nonexistent/legis-xyz",
                "args": ["mcp", "--agent-id", "claude-code"],
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(entry))
    assert mcp_entry_is_current(tmp_path) is False


def test_mcp_entry_is_current_fresh_registered_entry(tmp_path):
    """A freshly registered entry must read as current."""
    _register_mcp_json(tmp_path)
    assert mcp_entry_is_current(tmp_path) is True


# ---------------------------------------------------------------------------
# Task 6: install-wiring checks (blocks, skills, hook, gitignore)
# ---------------------------------------------------------------------------


def test_instruction_block_absent_is_error(tmp_path):
    c = check_instruction_block(tmp_path, "CLAUDE.md", repair=False)
    assert c.id == "install.claude_md"
    assert c.status == "error"


def test_instruction_block_repair_creates_it(tmp_path):
    c = check_instruction_block(tmp_path, "CLAUDE.md", repair=True)
    assert c.status == "ok"
    assert c.fixed is True
    assert legis_install.INSTRUCTIONS_MARKER in (tmp_path / "CLAUDE.md").read_text()


def test_gitignore_absent_is_error_then_repaired(tmp_path):
    assert check_gitignore(tmp_path, repair=False).status == "error"
    fixed = check_gitignore(tmp_path, repair=True)
    assert fixed.status == "ok" and fixed.fixed is True
    assert ".weft/legis/" in (tmp_path / ".gitignore").read_text()


def test_gitignore_missing_root_reports_error_instead_of_raising(tmp_path):
    missing = tmp_path / "missing"
    c = check_gitignore(missing, repair=False)
    assert c.status == "error"
    assert ".weft/legis/" in (c.message or "")
    repaired = check_gitignore(missing, repair=True)
    assert repaired.status == "error"
    assert str(missing) in (repaired.message or "")


def test_dir_gitignore_absent_dir_is_ok(tmp_path):
    # No .weft/legis/ yet — created lazily; nothing to protect, so OK
    # (mirrors check_store_dir's "absent is ok").
    from legis.doctor import check_dir_gitignore

    assert check_dir_gitignore(tmp_path, repair=False).status == "ok"


def test_dir_gitignore_present_dir_missing_nested_is_error_then_repaired(tmp_path):
    from legis.doctor import check_dir_gitignore

    (tmp_path / ".weft" / "legis").mkdir(parents=True)
    c = check_dir_gitignore(tmp_path, repair=False)
    assert c.status == "error" and c.repairable is True
    fixed = check_dir_gitignore(tmp_path, repair=True)
    assert fixed.status == "ok" and fixed.fixed is True
    nested = tmp_path / ".weft" / "legis" / ".gitignore"
    assert legis_install.LEGIS_DIR_GITIGNORE_MARKER in nested.read_text()


def test_dir_gitignore_present_nested_is_ok(tmp_path):
    from legis.doctor import check_dir_gitignore

    legis_install.ensure_legis_dir_gitignore(tmp_path)
    assert check_dir_gitignore(tmp_path, repair=False).status == "ok"


def test_collect_checks_includes_dir_gitignore(tmp_path):
    ids = {c.id for c in collect_checks(tmp_path, repair=False)}
    assert "install.dir_gitignore" in ids


def test_skill_pack_absent_is_error(tmp_path):
    assert check_skill_pack(tmp_path, ".claude", repair=False).status == "error"


def test_skill_pack_repair_installs(tmp_path):
    c = check_skill_pack(tmp_path, ".claude", repair=True)
    assert c.status == "ok" and c.fixed is True


# ---------------------------------------------------------------------------
# Task 6 (drift): stale block / stale skill pack are the headline behavior
# ---------------------------------------------------------------------------


def test_instruction_block_stale_token_is_error_then_repaired(tmp_path):
    # A real block with a mutated marker token: marker present, token mismatch.
    legis_install.inject_instructions(tmp_path / "CLAUDE.md")
    path = tmp_path / "CLAUDE.md"
    content = path.read_text()
    fresh_token = legis_install._marker_token()
    stale = content.replace(f":{fresh_token} -->", ":v0:deadbeef -->", 1)
    assert stale != content  # the token really was rewritten
    path.write_text(stale)
    assert legis_install._extract_marker_token(stale) != fresh_token

    c = check_instruction_block(tmp_path, "CLAUDE.md", repair=False)
    assert c.status == "error"

    fixed = check_instruction_block(tmp_path, "CLAUDE.md", repair=True)
    assert fixed.status == "ok"
    assert fixed.fixed is True
    assert legis_install._extract_marker_token((tmp_path / "CLAUDE.md").read_text()) == fresh_token


def test_split_brain_block_is_not_reported_fresh(tmp_path):
    # INSTALL-1: a fresh first legis block can coexist with a STALE second legis
    # block — a split brain the injector deliberately tolerates when it cannot
    # canonicalise across a sibling's block (install.py warns + leaves the stale
    # copy). The freshness probe must NOT read "healthy" off the first marker
    # alone; a stale second block is conflicting guidance that must surface.
    fresh = legis_install._marker_token()
    foreign = (
        "<!-- wardline:instructions:v1:abcd1234 -->\n"
        "wardline body\n"
        "<!-- /wardline:instructions -->\n"
    )
    (tmp_path / "CLAUDE.md").write_text(
        "HEAD\n"
        f"{legis_install.INSTRUCTIONS_MARKER}:{fresh} -->\n"
        "first (fresh) legis body\n"
        "<!-- /legis:instructions -->\n"
        + foreign
        + f"{legis_install.INSTRUCTIONS_MARKER}:v0:deadbeef -->\n"
        "stale second legis body\n"
        "<!-- /legis:instructions -->\n"
    )
    c = check_instruction_block(tmp_path, "CLAUDE.md", repair=False)
    assert c.status == "error"
    assert "split" in c.message.lower()
    # repair=True must NOT claim to have fixed a split brain it cannot collapse
    # across the sibling block — it stays an honest error (the stale copy remains).
    repaired = check_instruction_block(tmp_path, "CLAUDE.md", repair=True)
    assert repaired.status == "error"
    assert repaired.fixed is False
    assert "stale second legis body" in (tmp_path / "CLAUDE.md").read_text()
    # INSTALL-1: the split-brain branch documents itself "resolve it by hand" and
    # --fix is a no-op for it (it returns before the repair branch). So it must be
    # repairable=False -> rendered [operator], NOT [auto-fixable]. Tagging it
    # auto-fixable would re-create the --fix loop and is a false signal.
    assert c.repairable is False
    out = render_text([c])
    assert "[operator]" in out
    assert "[auto-fixable]" not in out
    assert "Run `legis doctor --fix` to repair auto-fixable items." not in out


def test_skill_pack_stale_fingerprint_is_error_then_repaired(tmp_path):
    legis_install.install_skills(tmp_path)
    pack = tmp_path / ".claude" / "skills" / legis_install.SKILL_NAME
    # Mutate a file under the installed pack so its fingerprint diverges from source.
    skill_md = pack / "SKILL.md"
    skill_md.write_text(skill_md.read_text() + "\n<!-- drift -->\n")

    c = check_skill_pack(tmp_path, ".claude", repair=False)
    assert c.status == "error"

    fixed = check_skill_pack(tmp_path, ".claude", repair=True)
    assert fixed.status == "ok"
    assert fixed.fixed is True


# ---------------------------------------------------------------------------
# Task 6: hook check
# ---------------------------------------------------------------------------


def test_hook_absent_is_error_then_repaired(tmp_path):
    c = check_hook(tmp_path, repair=False)
    assert c.id == "install.hook"
    assert c.status == "error"

    fixed = check_hook(tmp_path, repair=True)
    assert fixed.status == "ok"
    assert fixed.fixed is True


# ---------------------------------------------------------------------------
# Task 7: config & store checks (weft.toml report-only, store dir, db overrides, legacy)
# ---------------------------------------------------------------------------


def test_weft_toml_absent_is_ok(tmp_path):
    assert check_weft_toml(tmp_path).status == "ok"


def test_weft_toml_valid_legis_table_is_ok(tmp_path):
    (tmp_path / "weft.toml").write_text('[legis]\nstore_dir = ".weft/legis"\n')
    assert check_weft_toml(tmp_path).status == "ok"


def test_weft_toml_malformed_is_error_and_unchanged(tmp_path):
    wt = tmp_path / "weft.toml"
    wt.write_text("[legis]\nstore_dir = \n")  # malformed TOML
    before = wt.read_text()
    c = check_weft_toml(tmp_path)
    assert c.status == "error"
    assert wt.read_text() == before  # C-9(b): never written


def test_weft_toml_legis_not_a_table_is_error(tmp_path):
    (tmp_path / "weft.toml").write_text('legis = "oops"\n')
    assert check_weft_toml(tmp_path).status == "error"


def test_store_dir_writable_parent_is_ok(tmp_path):
    assert check_store_dir(tmp_path).status == "ok"


def test_db_override_bad_url_is_error(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", "::not a url::")
    assert check_db_overrides(tmp_path).status == "error"


def test_legacy_stray_db_is_warn(tmp_path):
    (tmp_path / "legis-governance.db").write_text("x")
    assert check_legacy_stray_db(tmp_path).status == "warn"


# ---------------------------------------------------------------------------
# Task 8: governance integrity + runtime/sibling checks
# ---------------------------------------------------------------------------


def test_audit_chain_absent_db_is_ok(tmp_path):
    c = check_audit_chain("store.governance_chain", "sqlite:///" + str(tmp_path / "nope.db"))
    assert c.status == "ok"
    # No-leak invariant: must NOT create the file
    assert not (tmp_path / "nope.db").exists()


def test_audit_chain_intact_db_is_ok(tmp_path):
    from legis.store.audit_store import AuditStore

    url = "sqlite:///" + str(tmp_path / "gov.db")
    AuditStore(url)  # creates schema
    assert check_audit_chain("store.governance_chain", url).status == "ok"


def test_audit_chain_zero_byte_db_is_error_without_mutation(tmp_path):
    db = tmp_path / "gov.db"
    db.write_bytes(b"")
    c = check_audit_chain("store.governance_chain", "sqlite:///" + str(db))
    assert c.status == "error"
    assert "audit_log" in (c.message or "")
    assert db.read_bytes() == b""


def test_audit_chain_missing_table_is_error_without_creating_schema(tmp_path):
    import sqlite3

    db = tmp_path / "gov.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE unrelated(id INTEGER PRIMARY KEY)")
    con.commit()
    con.close()

    c = check_audit_chain("store.governance_chain", "sqlite:///" + str(db))

    assert c.status == "error"
    assert "audit_log" in (c.message or "")
    con = sqlite3.connect(db)
    try:
        tables = {
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    finally:
        con.close()
    assert tables == {"unrelated"}


def test_hmac_key_warn_when_protected_set_without_key(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_PROTECTED_POLICIES", "secrets.read")
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)
    c = check_hmac_key(tmp_path)
    assert c.status == "warn"


def test_hmac_key_never_prints_value(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_PROTECTED_POLICIES", "secrets.read")
    monkeypatch.setenv("LEGIS_HMAC_KEY", "super-secret-value")
    c = check_hmac_key(tmp_path)
    assert c.status == "ok"
    assert "super-secret-value" not in (c.message or "")


def test_sibling_url_invalid_is_error(tmp_path, monkeypatch):
    monkeypatch.setenv("LOOMWEAVE_API_URL", "localhost:9620")  # no scheme
    c = check_sibling_url("runtime.loomweave_url", "LOOMWEAVE_API_URL")
    assert c.status == "error"


# --- N3 (weft-df8d2ef454): report-only enablement checks (C-10(c)) ----------


def test_policy_cells_warn_when_unconfigured_names_the_path(tmp_path, monkeypatch):
    # Fresh launch, no cells.toml, dev opt-in off -> warn, fail-closed in effect,
    # message names the concrete enablement keys.
    monkeypatch.delenv("LEGIS_POLICY_CELLS", raising=False)
    monkeypatch.delenv("LEGIS_DEV_DEFAULT_CELLS", raising=False)
    monkeypatch.delenv("LEGIS_SOURCE_ROOT", raising=False)
    c = check_policy_cells(tmp_path)
    assert c.status == "warn"
    msg = c.message or ""
    assert "LEGIS_POLICY_CELLS" in msg or "policy/cells.toml" in msg
    assert "LEGIS_DEV_DEFAULT_CELLS" in msg


def test_policy_cells_ok_when_cells_toml_resolves(tmp_path, monkeypatch):
    monkeypatch.delenv("LEGIS_POLICY_CELLS", raising=False)
    monkeypatch.delenv("LEGIS_DEV_DEFAULT_CELLS", raising=False)
    (tmp_path / "policy").mkdir()
    (tmp_path / "policy" / "cells.toml").write_text('default_cell = "structured"\n')
    c = check_policy_cells(tmp_path)
    assert c.status == "ok"


def test_policy_cells_ok_via_env_path(tmp_path, monkeypatch):
    cells = tmp_path / "elsewhere.toml"
    cells.write_text('default_cell = "structured"\n')
    monkeypatch.setenv("LEGIS_POLICY_CELLS", str(cells))
    c = check_policy_cells(tmp_path)
    assert c.status == "ok"


def test_wardline_routing_warn_when_unconfigured_names_the_key(tmp_path, monkeypatch):
    monkeypatch.delenv("LEGIS_WARDLINE_CELL", raising=False)
    monkeypatch.delenv("LEGIS_WARDLINE_CELL_BY_SEVERITY", raising=False)
    c = check_wardline_routing(tmp_path)
    assert c.status == "warn"
    assert "LEGIS_WARDLINE_CELL" in (c.message or "")


def test_wardline_routing_ok_when_cell_set(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_WARDLINE_CELL", "surface_only")
    monkeypatch.delenv("LEGIS_WARDLINE_CELL_BY_SEVERITY", raising=False)
    c = check_wardline_routing(tmp_path)
    assert c.status == "ok"


# --- STRIKE D (PDR-0023): artifact-key-absent posture must be interrogable ----


def test_wardline_artifact_key_warn_when_absent_names_the_key(tmp_path, monkeypatch):
    # Key-absent is the confident-degraded posture: every scan governs as
    # 'unverified' with no operator signal. Doctor must AMBER and NAME the key +
    # the action, so "unverified because no key" is distinguishable from a real
    # verification failure — recruit, do not just confess.
    monkeypatch.delenv("LEGIS_WARDLINE_ARTIFACT_KEY", raising=False)
    c = check_wardline_artifact_key(tmp_path)
    assert c.status == "warn"
    msg = c.message or ""
    assert "LEGIS_WARDLINE_ARTIFACT_KEY" in msg
    assert "unverified" in msg  # names the posture it explains
    # repairable=False: operator-held key, out-of-band — never auto-fixed/MCP.
    assert c.repairable is False


def test_wardline_artifact_key_ok_when_set(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGIS_WARDLINE_ARTIFACT_KEY", "operator-held-secret")
    c = check_wardline_artifact_key(tmp_path)
    assert c.status == "ok"


def test_wardline_artifact_key_never_prints_value(tmp_path, monkeypatch):
    # C-8: presence-only; the key value must never leak into the message.
    monkeypatch.setenv("LEGIS_WARDLINE_ARTIFACT_KEY", "operator-held-secret")
    c = check_wardline_artifact_key(tmp_path)
    assert "operator-held-secret" not in (c.message or "")


def test_collect_checks_includes_artifact_key_amber(tmp_path, monkeypatch):
    # The amber must surface through the aggregate doctor report (next_actions),
    # not just the isolated check — that is the surface an operator/agent reads.
    monkeypatch.delenv("LEGIS_WARDLINE_ARTIFACT_KEY", raising=False)
    checks = collect_checks(tmp_path, repair=False)
    artifact = [c for c in checks if c.id == "runtime.wardline_artifact_key"]
    assert len(artifact) == 1
    assert artifact[0].status == "warn"


def test_n3_checks_never_write_files_or_render_keys(tmp_path, monkeypatch):
    # C-8 / C-9(b): report-only. They must not create any file (no scaffolding)
    # and must never echo a secret value.
    monkeypatch.delenv("LEGIS_POLICY_CELLS", raising=False)
    monkeypatch.delenv("LEGIS_DEV_DEFAULT_CELLS", raising=False)
    monkeypatch.setenv("LEGIS_HMAC_KEY", "super-secret-value")
    before = set(tmp_path.rglob("*"))
    msgs = [
        check_policy_cells(tmp_path).message or "",
        check_wardline_routing(tmp_path).message or "",
    ]
    assert set(tmp_path.rglob("*")) == before  # wrote nothing
    # never render a secret value (the "render_keys" half of the contract)
    assert all("super-secret-value" not in m for m in msgs)
    # neither check signature takes a `repair` parameter (cannot be coerced to write)
    import inspect
    assert "repair" not in inspect.signature(check_policy_cells).parameters
    assert "repair" not in inspect.signature(check_wardline_routing).parameters


# ---------------------------------------------------------------------------
# Review follow-ups: store placement + empty-override precedence
# ---------------------------------------------------------------------------


def test_store_dir_ignores_repo_weft_toml_store_dir(tmp_path, monkeypatch):
    # --root != cwd, with a repo weft.toml that attempts to relocate the store.
    # Doctor must keep governance checks on the built-in store unless an
    # explicit LEGIS_*_DB override is set by the operator environment.
    monkeypatch.chdir(tmp_path)  # cwd has no weft.toml
    # Clear the conftest store override so default resolution is exercised.
    monkeypatch.delenv("LEGIS_GOVERNANCE_DB", raising=False)
    root = tmp_path / "proj"
    (root / "custom_store").mkdir(parents=True)
    (root / "weft.toml").write_text('[legis]\nstore_dir = "custom_store"\n')

    c = check_store_dir(root)
    assert c.status == "ok"

    # The audit-chain URL must point under root/.weft, not repo weft.toml.
    url = _store_url(root, "legis-governance.db", "LEGIS_GOVERNANCE_DB")
    assert url == "sqlite:///" + (root / ".weft" / "legis" / "legis-governance.db").as_posix()
    assert "custom_store" not in url


def test_db_override_empty_string_is_error(tmp_path, monkeypatch):
    # Present-but-empty override is a verbatim broken override, not "unset"
    # (matches config precedence; review #3).
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", "")
    assert check_db_overrides(tmp_path).status == "error"


# ---------------------------------------------------------------------------
# Task 9: end-to-end --repair pipeline + invariant tests
# ---------------------------------------------------------------------------


def test_repair_makes_fresh_project_healthy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Hermetic: an inherited sibling URL env var (valid or not) would otherwise
    # leak into the repair → exit 0 assertion. Unset both so the check is "not
    # configured" (ok), never a non-repairable error.
    monkeypatch.delenv("LOOMWEAVE_API_URL", raising=False)
    monkeypatch.delenv("FILIGREE_API_URL", raising=False)
    # First run: unhealthy (no install artifacts, no .mcp.json).
    assert run_doctor(tmp_path, repair=False, fmt="text") == 1
    # Repair run: install-wiring + .mcp.json get fixed; re-check is healthy.
    assert run_doctor(tmp_path, repair=True, fmt="text") == 0
    # Third run, no repair: stays healthy.
    assert run_doctor(tmp_path, repair=False, fmt="text") == 0


def test_repair_never_writes_weft_toml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "weft.toml").write_text("[legis]\nstore_dir = \n")  # malformed
    before = (tmp_path / "weft.toml").read_text()
    run_doctor(tmp_path, repair=True, fmt="json")
    assert (tmp_path / "weft.toml").read_text() == before


def test_json_output_has_no_secret(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LEGIS_PROTECTED_POLICIES", "secrets.read")
    monkeypatch.setenv("LEGIS_HMAC_KEY", "TOP-SECRET")
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        run_doctor(tmp_path, repair=False, fmt="json")
    out = buf.getvalue()
    assert "TOP-SECRET" not in out
    # Prove the secret-bearing path actually ran: with both the protected policy
    # and the key set, check_hmac_key reads the key and reports ok. Asserting the
    # check is present (and ok) keeps this guard from passing vacuously if the
    # key-reading check were ever removed.
    payload = json.loads(out)
    hmac_checks = [c for c in payload["checks"] if c["id"] == "runtime.hmac_key"]
    assert hmac_checks and hmac_checks[0]["status"] == "ok"


# ---------------------------------------------------------------------------
# check_filigree_binding_scope — the federation scan-results binding in
# .mcp.json must be project-scoped, else filigree server-mode N1 fail-closes
# the unscoped write (HTTP 400) and scans silently non-emit.
# ---------------------------------------------------------------------------


def _mark_filigree_installed(root, *, legacy: bool = False) -> None:
    """Lay down filigree's install markers (file-existence only) so the
    install-gate in check_filigree_binding_scope evaluates the binding instead of
    short-circuiting to "filigree not installed"."""
    (root / ".filigree.conf").write_text("", encoding="utf-8")
    if legacy:
        cfg = root / ".filigree" / "config.json"
    else:
        cfg = root / ".weft" / "filigree" / "config.json"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text("{}", encoding="utf-8")


def _write_mcp_with_filigree_url(root, url: str | None) -> None:
    args = ["mcp", "--root", "."]
    if url is not None:
        args += ["--filigree-url", url]
    (root / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"wardline": {"command": "wardline", "args": args}}}),
        encoding="utf-8",
    )


def test_filigree_scope_warns_on_unscoped_federation_write(tmp_path):
    _mark_filigree_installed(tmp_path)
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:8749/api/weft/scan-results")
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "warn"
    assert c.repairable is False  # operator-owned; legis never writes the binding
    # honors "outputs": names the offending URL so the operator sees the binding
    assert "8749/api/weft/scan-results" in c.message
    assert "/api/p/<project>" in c.message  # operator action + literal placeholder
    assert "operator-pinned" in c.message  # names ownership
    assert "Operator action" in c.message


def test_filigree_scope_warns_on_unscoped_remote_binding_without_local_install(tmp_path):
    # The federation-consumer case: a pure scan-results emitter with NO local
    # filigree marker, pinning an unscoped --filigree-url at a REMOTE server-mode
    # daemon. That remote daemon fail-closes the unscoped federation write (N1,
    # HTTP 400) so scans silently non-emit — the harm is driven by the binding URL
    # targeting a server-mode daemon, NOT by whether filigree is installed locally.
    # The old local-install gate reported all-clear here (the false-green the
    # governance forbids); the binding URL itself is the operative signal, so this
    # MUST warn even with no local install marker present.
    _write_mcp_with_filigree_url(tmp_path, "https://central-host/api/weft/scan-results")
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "warn"
    assert "central-host/api/weft/scan-results" in c.message
    assert "/api/p/<project>" in c.message  # operator action named


def test_filigree_scope_conf_only_is_installed_and_warns(tmp_path):
    # .filigree.conf ALONE is a genuine install: filigree's find_filigree_anchor
    # resolves on the conf alone (core.py:1050-1054), no config.json required.
    # So a conf-only project with an unscoped binding MUST warn — suppressing it
    # would be the exact false-green the governance forbids (a server-mode daemon
    # fail-closes the unscoped write while doctor stays green).
    (tmp_path / ".filigree.conf").write_text("", encoding="utf-8")
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:8749/api/weft/scan-results")
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "warn"
    assert "8749/api/weft/scan-results" in c.message


def test_filigree_scope_confless_weft_store_is_installed_and_warns(tmp_path):
    # Confless federation install: .weft/filigree/ dir present, NO .filigree.conf.
    # filigree resolves this as installed (core.py:1055-1059); legis must too, or
    # it suppresses a real unscoped-binding warning.
    (tmp_path / ".weft" / "filigree").mkdir(parents=True)
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:8749/api/weft/scan-results")
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "warn"
    assert "8749/api/weft/scan-results" in c.message


def test_filigree_scope_confless_legacy_dir_is_installed_and_warns(tmp_path):
    # Confless legacy install: legacy .filigree/ dir present, NO .filigree.conf.
    # filigree resolves this as installed (core.py:1060-1064); legis must too.
    # This is the live federation-legacy-path case (legacy .filigree/ dirs exist
    # in this environment).
    (tmp_path / ".filigree").mkdir(parents=True)
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:8749/api/weft/scan-results")
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "warn"
    assert "8749/api/weft/scan-results" in c.message


def test_filigree_scope_warns_with_legacy_config_marker(tmp_path):
    _mark_filigree_installed(tmp_path, legacy=True)
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:8749/api/weft/scan-results")
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "warn"


def test_filigree_scope_ok_on_path_scoped_binding(tmp_path):
    _mark_filigree_installed(tmp_path)
    url = "http://127.0.0.1:8749/api/p/legis/weft/scan-results"
    _write_mcp_with_filigree_url(tmp_path, url)
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "ok"
    # honors "outputs": surfaces the project-scoped binding rather than a bare ok
    assert url in c.message


def test_filigree_scope_ok_on_query_scoped_binding(tmp_path):
    _mark_filigree_installed(tmp_path)
    _write_mcp_with_filigree_url(
        tmp_path, "http://127.0.0.1:8749/api/weft/scan-results?project=legis"
    )
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "ok"


def test_filigree_scope_ok_when_no_binding_present(tmp_path):
    _mark_filigree_installed(tmp_path)
    _write_mcp_with_filigree_url(tmp_path, None)
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "ok"


def test_filigree_scope_ok_when_no_mcp_json(tmp_path):
    _mark_filigree_installed(tmp_path)
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "ok"


def test_filigree_scope_ignores_non_federation_path(tmp_path):
    # A non-federation-write filigree path is not N1-gated, so it must not warn
    # (avoid false positives on, e.g., a base or an issue endpoint).
    _mark_filigree_installed(tmp_path)
    _write_mcp_with_filigree_url(tmp_path, "http://127.0.0.1:8749/api/issue/x/comments")
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "ok"


def test_filigree_scope_survives_malformed_mcp_json(tmp_path):
    _mark_filigree_installed(tmp_path)
    (tmp_path / ".mcp.json").write_text("{not json", encoding="utf-8")
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "ok"


def test_collect_checks_includes_filigree_scope(tmp_path):
    ids = {c.id for c in collect_checks(tmp_path, repair=False)}
    assert "install.filigree_scope" in ids
