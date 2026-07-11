from __future__ import annotations

import json
import os
import sys
import tomllib
from pathlib import Path

import pytest

from legis import install, plainweave_binding
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
    check_plainweave_codex_binding,
    check_plainweave_project_binding,
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
from legis.plainweave_binding import PLAINWEAVE_ENV


def _write_mcp_entry(tmp_path, entry):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"legis": entry}}))


def _make_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _plainweave_project(
    tmp_path: Path,
    monkeypatch,
    *,
    initialized: bool = True,
    project_env: object | None = None,
    global_legis: bool = True,
) -> tuple[Path, Path, Path]:
    root = tmp_path / "project"
    root.mkdir()
    executable = _make_executable(tmp_path / "tools" / "legis")
    if initialized:
        state = root / ".plainweave"
        state.mkdir()
        (state / "plainweave.db").touch()
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "plainweave": {
                        "type": "stdio",
                        "command": str(executable),
                        "args": ["--root", str(root)],
                    },
                    "legis": {
                        "type": "stdio",
                        "command": str(executable),
                        "args": ["mcp", "--agent-id", "operator"],
                        "env": {} if project_env is None else project_env,
                    },
                }
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    config = codex_home / "config.toml"
    if global_legis:
        config.write_text(
            "[mcp_servers.legis]\n"
            f"command = {json.dumps(str(executable))}\n"
            'args = ["mcp", "--agent-id", "operator"]\n'
            "[mcp_servers.legis.env]\n",
            encoding="utf-8",
        )
    return root, executable, config


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
    assert payload["checks"][0] == {
        "id": "a",
        "status": "ok",
        "fixed": False,
        "repairable": False,
    }
    assert payload["next_actions"] == ["b: bad"]


def test_render_text_lists_only_problems_when_healthy_says_ok():
    # all-ok: banner present, no problem lines
    assert render_text([DoctorCheck("a", "ok")]) == "legis doctor: ok"

    # error present: no "ok" in headline, error listed
    out = render_text(
        [DoctorCheck("a", "ok"), DoctorCheck("b", "error", message="bad")]
    )
    assert "b: error" in out
    assert "legis doctor: ok" not in out

    # warn-only: banner present with warning count AND warn check is listed
    out_warn = render_text(
        [DoctorCheck("a", "ok"), DoctorCheck("b", "warn", message="heads up")]
    )
    assert "legis doctor: ok" in out_warn
    assert "b: warn" in out_warn


def test_render_text_tags_auto_fixable_and_footer():
    out = render_text([DoctorCheck("install.x", "error", message="m", repairable=True)])
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
    out = render_text(
        [DoctorCheck("install.x", "warn", message="m", fixed=True, repairable=True)]
    )
    assert "install.x: warn — m [fixed]" in out
    # [fixed] is not auto-fixable-pending, so no fix footer from it alone
    assert "Run `legis doctor --fix` to repair auto-fixable items." not in out


def test_render_text_tags_partial_cleanup_as_fixed_and_operator_owned():
    out = render_text(
        [
            DoctorCheck(
                "install.plainweave_codex_binding",
                "error",
                message="legacy cleanup completed; remove fixed cwd",
                fixed=True,
                repairable=False,
            )
        ]
    )

    assert (
        "install.plainweave_codex_binding: error — legacy cleanup completed; "
        "remove fixed cwd [fixed] [operator]"
    ) in out
    assert "[operator] items are not auto-fixable by `legis doctor --fix`" in out


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
            DoctorCheck(
                "install.x", "ok", message="re-registered", fixed=True, repairable=True
            ),
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
        "LEGIS_POLICY_CELLS",
        "LEGIS_DEV_DEFAULT_CELLS",
        "LEGIS_SOURCE_ROOT",
        "LEGIS_WARDLINE_CELL",
        "LEGIS_WARDLINE_CELL_BY_SEVERITY",
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


@pytest.mark.parametrize("repair", [False, True], ids=["report", "fix"])
def test_mcp_json_deep_nesting_is_reported_without_crashing(
    tmp_path: Path,
    repair: bool,
) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text("[" * 10_000 + "0" + "]" * 10_000, encoding="utf-8")
    before = config.read_bytes()

    check = check_mcp_json(tmp_path, repair=repair)

    assert check.status == "error"
    assert check.fixed is False
    assert check.repairable is False
    assert check.message is not None and "malformed" in check.message.lower()
    assert config.read_bytes() == before


@pytest.mark.parametrize("repair", [False, True], ids=["report", "fix"])
def test_mcp_json_without_writer_lock_is_operator_only(
    tmp_path: Path,
    monkeypatch,
    repair: bool,
) -> None:
    monkeypatch.setattr(install, "fcntl", None)

    check = check_mcp_json(tmp_path, repair=repair)

    assert check.status == "error"
    assert check.repairable is False
    assert check.fixed is False
    assert check.message is not None and "platform" in check.message.lower()
    assert not (tmp_path / ".mcp.json").exists()


def test_mcp_json_missing_nonblock_is_reported_as_platform_capability(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / ".mcp.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(install.os, "O_NONBLOCK", None)

    check = check_mcp_json(tmp_path, repair=False)

    assert check.status == "error"
    assert check.repairable is False
    assert check.message is not None
    assert "platform" in check.message.lower()
    assert "project mcp" in check.message.lower()
    assert "read" in check.message.lower()


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
# Plainweave launch bindings
# ---------------------------------------------------------------------------


def test_plainweave_independent_legacy_bindings_are_auto_fixable(
    tmp_path, monkeypatch
):
    root, _executable, _config = _plainweave_project(tmp_path, monkeypatch)
    project_path = root / ".mcp.json"
    project_data = json.loads(project_path.read_text(encoding="utf-8"))
    project_data["mcpServers"]["legis"]["env"][PLAINWEAVE_ENV] = "legacy-project"
    project_path.write_text(json.dumps(project_data), encoding="utf-8")
    _config.write_text(
        _config.read_text(encoding="utf-8")
        + f'{PLAINWEAVE_ENV} = "legacy-global"\n',
        encoding="utf-8",
    )
    project = check_plainweave_project_binding(root, repair=False)
    codex = check_plainweave_codex_binding(root, repair=False)
    assert project.id == "install.plainweave_project_binding"
    assert codex.id == "install.plainweave_codex_binding"
    assert project.status == codex.status == "error"
    assert project.repairable is codex.repairable is True
    assert project.fixed is codex.fixed is False
    assert "legacy" in (project.message or "").lower()
    assert "project-agnostic" in (project.message or "").lower()
    assert "legacy" in (codex.message or "").lower()


def test_plainweave_doctor_converges_across_two_projects(
    tmp_path: Path,
    monkeypatch,
) -> None:
    legis_executable = _make_executable(tmp_path / "tools" / "legis")
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    roots: dict[str, Path] = {}
    commands: dict[str, str] = {}
    for name in ("alpha", "beta"):
        root = tmp_path / name
        (root / ".plainweave").mkdir(parents=True)
        (root / ".plainweave" / "plainweave.db").touch()
        executable = _make_executable(tmp_path / f"{name}-bin" / "plainweave-mcp")
        command = f"{executable.resolve()} --root {root.resolve()}"
        (root / ".mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "plainweave": {
                            "type": "stdio",
                            "command": str(executable),
                            "args": ["--root", str(root)],
                        },
                        "legis": {
                            "type": "stdio",
                            "command": str(legis_executable),
                            "args": ["mcp", "--agent-id", "operator"],
                            "env": {PLAINWEAVE_ENV: command},
                        },
                    }
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        roots[name] = root
        commands[name] = command

    config = codex_home / "config.toml"
    config.write_text(
        "[mcp_servers.legis]\n"
        f"command = {json.dumps(str(legis_executable))}\n"
        'args = ["mcp", "--agent-id", "operator"]\n'
        "[mcp_servers.legis.env]\n"
        f"{PLAINWEAVE_ENV} = {json.dumps(commands['alpha'])}\n",
        encoding="utf-8",
    )

    alpha_repaired = {
        check.id: check for check in collect_checks(roots["alpha"], repair=True)
    }
    beta_repaired = {
        check.id: check for check in collect_checks(roots["beta"], repair=True)
    }
    alpha_current = {
        check.id: check for check in collect_checks(roots["alpha"], repair=False)
    }

    binding_ids = (
        "install.plainweave_project_binding",
        "install.plainweave_codex_binding",
    )
    for checks in (alpha_repaired, beta_repaired, alpha_current):
        assert all(checks[check_id].status == "ok" for check_id in binding_ids)

    global_text = config.read_text(encoding="utf-8")
    assert PLAINWEAVE_ENV not in global_text
    assert all(str(root) not in global_text for root in roots.values())
    for root in roots.values():
        project_env = json.loads((root / ".mcp.json").read_text(encoding="utf-8"))[
            "mcpServers"
        ]["legis"]["env"]
        assert PLAINWEAVE_ENV not in project_env


def test_plainweave_global_check_is_independent_of_active_project_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    alpha = tmp_path / "alpha"
    beta = tmp_path / "beta"
    alpha.mkdir()
    beta.mkdir()
    executable = _make_executable(alpha / "bin" / "legis")
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    (codex_home / "config.toml").write_text(
        "[mcp_servers.legis]\n"
        f"command = {json.dumps(str(executable))}\n"
        'args = ["mcp", "--agent-id", "operator"]\n'
        "[mcp_servers.legis.env]\n",
        encoding="utf-8",
    )

    from_alpha = check_plainweave_codex_binding(alpha, repair=False)
    from_beta = check_plainweave_codex_binding(beta, repair=False)

    assert from_alpha == from_beta
    assert from_alpha.status == "ok"


def test_plainweave_global_fixed_cwd_is_operator_owned_and_unchanged(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    executable = _make_executable(tmp_path / "tools" / "legis")
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    config = codex_home / "config.toml"
    config.write_text(
        "[mcp_servers.legis]\n"
        f"command = {json.dumps(str(executable))}\n"
        'args = ["mcp", "--agent-id", "operator"]\n'
        f"cwd = {json.dumps(str(root))}\n",
        encoding="utf-8",
    )
    before = config.read_bytes()

    check = check_plainweave_codex_binding(root, repair=True)

    assert check.id == "install.plainweave_codex_binding"
    assert check.status == "error"
    assert check.repairable is False
    assert check.fixed is False
    assert "fixed cwd" in (check.message or "").lower()
    assert "runtime autodiscovery" in (check.message or "").lower()
    assert config.read_bytes() == before


def test_plainweave_global_repair_removes_legacy_key_but_preserves_fixed_cwd(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    executable = _make_executable(tmp_path / "tools" / "legis")
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    config = codex_home / "config.toml"
    config.write_text(
        "[mcp_servers.legis]\n"
        f"command = {json.dumps(str(executable))}\n"
        'args = ["mcp", "--agent-id", "operator"]\n'
        f"cwd = {json.dumps(str(root))}\n"
        "[mcp_servers.legis.env]\n"
        f'{PLAINWEAVE_ENV} = "legacy --root elsewhere"\n'
        'KEEP_ME = "operator"\n',
        encoding="utf-8",
    )

    check = check_plainweave_codex_binding(root, repair=True)

    parsed = tomllib.loads(config.read_text(encoding="utf-8"))
    entry = parsed["mcp_servers"]["legis"]
    assert check.status == "error"
    assert check.repairable is False
    assert check.fixed is True
    assert "legacy" in (check.message or "").lower()
    assert "fixed cwd" in (check.message or "").lower()
    assert "remove" in (check.message or "").lower()
    assert entry["cwd"] == str(root)
    assert entry["env"] == {"KEEP_ME": "operator"}


def test_plainweave_project_repair_rechecks_discovery_before_success(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root, _executable, _config = _plainweave_project(tmp_path, monkeypatch)
    project_path = root / ".mcp.json"
    project_data = json.loads(project_path.read_text(encoding="utf-8"))
    plainweave_executable = _make_executable(
        tmp_path / "plainweave-bin" / "plainweave-mcp"
    )
    project_data["mcpServers"]["plainweave"]["command"] = str(
        plainweave_executable
    )
    project_data["mcpServers"]["legis"]["env"][PLAINWEAVE_ENV] = "legacy"
    project_path.write_text(json.dumps(project_data), encoding="utf-8")
    monkeypatch.setenv("PATH", "")
    original_repair = plainweave_binding.repair_project_binding

    def repair_then_break_discovery(
        project_root: Path,
        desired: str | None,
    ) -> str | None:
        error = original_repair(project_root, desired)
        data = json.loads(project_path.read_text(encoding="utf-8"))
        del data["mcpServers"]["plainweave"]
        project_path.write_text(json.dumps(data), encoding="utf-8")
        return error

    monkeypatch.setattr(
        plainweave_binding,
        "repair_project_binding",
        repair_then_break_discovery,
    )

    check = check_plainweave_project_binding(root, repair=True)

    assert check.status == "error"
    assert check.fixed is False
    assert "no executable" in (check.message or "").lower()


def test_plainweave_missing_project_registration_is_auto_fixable(tmp_path, monkeypatch):
    root, _executable, _config = _plainweave_project(tmp_path, monkeypatch)
    data = json.loads((root / ".mcp.json").read_text(encoding="utf-8"))
    del data["mcpServers"]["legis"]
    (root / ".mcp.json").write_text(json.dumps(data), encoding="utf-8")
    check = check_plainweave_project_binding(root, repair=False)
    assert check.status == "error" and check.repairable is True
    assert "install.mcp_json" in (check.message or "")


@pytest.mark.parametrize(
    "case",
    [
        "operator_secret",
        "unsafe_flag",
        "env_list",
        "malformed_json",
        "symlink",
        "non_object",
        "mcp_servers_list",
        "legis_list",
    ],
)
def test_doctor_refuses_operator_owned_mcp_json_unchanged(tmp_path, monkeypatch, case):
    root, _executable, _config = _plainweave_project(tmp_path, monkeypatch)
    path = root / ".mcp.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    secret = "do-not-render-this-secret"
    if case == "operator_secret":
        data["mcpServers"]["legis"]["env"] = {"LEGIS_OPERATOR_KEY": secret}
        path.write_text(json.dumps(data), encoding="utf-8")
    elif case == "unsafe_flag":
        data["mcpServers"]["legis"]["env"] = {"LEGIS_UNSAFE_DEV_AUTH": "1"}
        path.write_text(json.dumps(data), encoding="utf-8")
    elif case == "env_list":
        data["mcpServers"]["legis"]["env"] = ["not", "a", "mapping"]
        path.write_text(json.dumps(data), encoding="utf-8")
    elif case == "malformed_json":
        path.write_text("{not valid json", encoding="utf-8")
    elif case == "symlink":
        target = tmp_path / "operator-mcp.json"
        target.write_text(json.dumps(data), encoding="utf-8")
        path.unlink()
        path.symlink_to(target)
    elif case == "non_object":
        path.write_text("[]", encoding="utf-8")
    elif case == "mcp_servers_list":
        path.write_text(json.dumps({"mcpServers": []}), encoding="utf-8")
    else:
        data["mcpServers"]["legis"] = []
        path.write_text(json.dumps(data), encoding="utf-8")

    fallback = _make_executable(tmp_path / "path" / "plainweave-mcp")
    monkeypatch.setenv("PATH", str(fallback.parent))
    link_before = path.readlink() if path.is_symlink() else None
    before = path.read_bytes()

    direct = check_mcp_json(root, repair=True)
    checks = {check.id: check for check in collect_checks(root, repair=True)}

    assert direct.status == "error" and direct.repairable is False
    assert direct.fixed is False
    assert secret not in (direct.message or "")
    for cid in ("install.mcp_json", "install.plainweave_project_binding"):
        assert checks[cid].status == "error"
        assert checks[cid].repairable is False
        assert checks[cid].fixed is False
        assert secret not in (checks[cid].message or "")
    assert path.read_bytes() == before
    if link_before is not None:
        assert path.is_symlink() and path.readlink() == link_before


def test_doctor_refuses_duplicate_mcp_json_unchanged(tmp_path: Path) -> None:
    executable = _make_executable(tmp_path / "tools" / "legis")
    path = tmp_path / ".mcp.json"
    path.write_text(
        '{"mcpServers":{"legis":{'
        '"type":"stdio",'
        f'"command":{json.dumps(str(executable))},'
        '"args":["mcp","--agent-id","operator"],'
        '"env":{"KEEP_FIRST":"operator"},'
        '"env":{}'
        "}}}",
        encoding="utf-8",
    )
    before = path.read_bytes()

    check = check_mcp_json(tmp_path, repair=True)

    assert check.status == "error"
    assert check.repairable is False
    assert check.fixed is False
    assert check.message is not None and "malformed" in check.message.lower()
    assert path.read_bytes() == before


def test_doctor_mcp_repair_preserves_secret_added_after_preflight(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / ".mcp.json"
    _write_mcp_entry(
        tmp_path,
        {
            "type": "stdio",
            "command": "/definitely/dead",
            "args": ["mcp", "--agent-id", "operator"],
            "env": {"KEEP_ME": "operator"},
        },
    )
    original_current = legis_install.mcp_entry_is_current
    calls = 0

    def add_secret_after_preflight(root: Path) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            data = json.loads(path.read_text(encoding="utf-8"))
            data["mcpServers"]["legis"]["env"]["LEGIS_HMAC_KEY"] = "operator-secret"
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            return False
        return original_current(root)

    monkeypatch.setattr(
        legis_install,
        "mcp_entry_is_current",
        add_secret_after_preflight,
    )

    check = check_mcp_json(tmp_path, repair=True)
    env = json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["legis"]["env"]

    assert check.status == "error"
    assert check.fixed is False
    assert check.repairable is False
    assert check.message is not None and "secret" in check.message.lower()
    assert env == {
        "KEEP_ME": "operator",
        "LEGIS_HMAC_KEY": "operator-secret",
    }


def test_doctor_mcp_repair_does_not_overwrite_changed_safe_snapshot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / ".mcp.json"
    _write_mcp_entry(
        tmp_path,
        {
            "type": "stdio",
            "command": "/definitely/dead",
            "args": ["mcp", "--agent-id", "operator"],
            "env": {"KEEP_ME": "operator"},
        },
    )
    original_entry = legis_install._legis_mcp_entry
    changed: bytes | None = None

    def change_after_register_read(*args, **kwargs):
        nonlocal changed
        data = json.loads(path.read_text(encoding="utf-8"))
        data["mcpServers"]["legis"]["env"]["OPERATOR_ADDED"] = "newer"
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        changed = path.read_bytes()
        return original_entry(*args, **kwargs)

    monkeypatch.setattr(
        legis_install,
        "_legis_mcp_entry",
        change_after_register_read,
    )

    check = check_mcp_json(tmp_path, repair=True)

    assert check.status == "error"
    assert check.fixed is False
    assert check.repairable is True
    assert check.message is not None and "changed" in check.message.lower()
    assert changed is not None and path.read_bytes() == changed


def test_doctor_mcp_repair_contains_snapshot_recheck_read_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / ".mcp.json"
    _write_mcp_entry(
        tmp_path,
        {
            "type": "stdio",
            "command": "/definitely/dead",
            "args": ["mcp", "--agent-id", "operator"],
            "env": {"KEEP_ME": "operator"},
        },
    )
    before = path.read_bytes()
    original_read = install._read_anchored_mcp_json
    reads = 0

    def fail_recheck(directory_fd: int):
        nonlocal reads
        reads += 1
        if reads == 2:
            raise PermissionError("simulated recheck denial")
        return original_read(directory_fd)

    monkeypatch.setattr(install, "_read_anchored_mcp_json", fail_recheck)

    check = check_mcp_json(tmp_path, repair=True)

    assert check.status == "error"
    assert check.fixed is False
    assert check.repairable is True
    assert check.message is not None and "changed" in check.message.lower()
    assert path.read_bytes() == before


def test_doctor_repairs_safe_stale_command_and_preserves_operator_env(
    tmp_path, monkeypatch
):
    root, _executable, _config = _plainweave_project(
        tmp_path,
        monkeypatch,
        project_env={"LEGIS_WARDLINE_CELL": "surface_override"},
    )
    path = root / ".mcp.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["mcpServers"]["legis"]["command"] = "/missing/legis"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    checks = {check.id: check for check in collect_checks(root, repair=True)}

    assert checks["install.mcp_json"].status == "ok"
    assert checks["install.mcp_json"].fixed is True
    assert checks["install.plainweave_project_binding"].status == "ok"
    assert checks["install.plainweave_project_binding"].fixed is False
    env = json.loads(path.read_text())["mcpServers"]["legis"]["env"]
    assert env["LEGIS_WARDLINE_CELL"] == "surface_override"
    assert PLAINWEAVE_ENV not in env


def test_plainweave_binding_repair_is_ordered_post_verified_and_idempotent(
    tmp_path, monkeypatch
):
    root, _executable, config = _plainweave_project(tmp_path, monkeypatch)
    data = json.loads((root / ".mcp.json").read_text(encoding="utf-8"))
    del data["mcpServers"]["legis"]
    (root / ".mcp.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    repaired = collect_checks(root, repair=True)
    ids = [check.id for check in repaired]
    assert ids.index("install.mcp_json") + 1 == ids.index(
        "install.plainweave_project_binding"
    )
    assert ids.index("install.plainweave_project_binding") + 1 == ids.index(
        "install.plainweave_codex_binding"
    )
    by_id = {check.id: check for check in repaired}
    assert by_id["install.mcp_json"].fixed is True
    for cid in (
        "install.plainweave_project_binding",
        "install.plainweave_codex_binding",
    ):
        assert by_id[cid].status == "ok"
        assert by_id[cid].fixed is False
        assert by_id[cid].repairable is True

    project_bytes = (root / ".mcp.json").read_bytes()
    codex_bytes = config.read_bytes()
    current = {check.id: check for check in collect_checks(root, repair=False)}
    second = {check.id: check for check in collect_checks(root, repair=True)}
    for cid in (
        "install.plainweave_project_binding",
        "install.plainweave_codex_binding",
    ):
        assert current[cid].status == second[cid].status == "ok"
        assert current[cid].fixed is second[cid].fixed is False
    assert (root / ".mcp.json").read_bytes() == project_bytes
    assert config.read_bytes() == codex_bytes
    assert PLAINWEAVE_ENV not in json.loads(project_bytes)["mcpServers"]["legis"]["env"]


def test_plainweave_no_global_legis_registration_is_ok_and_never_created(
    tmp_path, monkeypatch
):
    root, _executable, config = _plainweave_project(
        tmp_path, monkeypatch, global_legis=False
    )
    check = check_plainweave_codex_binding(root, repair=True)
    assert check.status == "ok" and check.repairable is False and check.fixed is False
    assert "not configured" in (check.message or "")
    assert not config.exists()


@pytest.mark.parametrize("global_state", ["malformed", "legacy"])
def test_uninitialized_plainweave_still_inspects_global_config(
    tmp_path,
    monkeypatch,
    global_state,
):
    root, _executable, config = _plainweave_project(
        tmp_path, monkeypatch, initialized=False
    )
    data = json.loads((root / ".mcp.json").read_text(encoding="utf-8"))
    del data["mcpServers"]["plainweave"]
    (root / ".mcp.json").write_text(json.dumps(data), encoding="utf-8")
    plainweave = _make_executable(tmp_path / "path" / "plainweave-mcp")
    monkeypatch.setenv("PATH", str(plainweave.parent))
    if global_state == "malformed":
        config.write_text("invalid = [", encoding="utf-8")
    else:
        config.write_text(
            config.read_text(encoding="utf-8")
            + f'{PLAINWEAVE_ENV} = "legacy --root elsewhere"\n',
            encoding="utf-8",
        )
    before = config.read_bytes()
    project = check_plainweave_project_binding(root, repair=True)
    codex = check_plainweave_codex_binding(root, repair=False)
    assert project.status == "ok"
    assert project.repairable is False
    assert "installed" in (project.message or "") and "not initialized" in (
        project.message or ""
    )
    assert codex.status == "error"
    assert codex.fixed is False
    assert codex.repairable is (global_state == "legacy")
    expected = "malformed" if global_state == "malformed" else "legacy"
    assert expected in (codex.message or "").lower()
    assert config.read_bytes() == before


def test_uninitialized_unconfigured_plainweave_message_is_distinct(
    tmp_path, monkeypatch
):
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.setenv("PATH", "")
    check = check_plainweave_project_binding(root, repair=False)
    assert check.status == "ok" and check.repairable is False
    assert "not configured" in (check.message or "")
    assert "not initialized" not in (check.message or "")


def test_initialized_plainweave_without_executable_is_operator_error(
    tmp_path, monkeypatch
):
    root = tmp_path / "project"
    (root / ".plainweave").mkdir(parents=True)
    (root / ".plainweave" / "plainweave.db").touch()
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    config = codex_home / "config.toml"
    config.write_text("invalid = [", encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.setenv("PATH", "")
    before = config.read_bytes()
    project = check_plainweave_project_binding(root, repair=True)
    codex = check_plainweave_codex_binding(root, repair=True)
    assert project.status == codex.status == "error"
    assert project.repairable is codex.repairable is False
    assert "no executable" in (project.message or "")
    assert "malformed" in (codex.message or "")
    assert "[operator]" in render_text([project, codex])
    assert config.read_bytes() == before


def test_unsafe_project_and_malformed_global_are_operator_owned(tmp_path, monkeypatch):
    root, _executable, config = _plainweave_project(
        tmp_path, monkeypatch, project_env={"LEGIS_OPERATOR_KEY": "secret"}
    )
    project_file = root / ".mcp.json"
    project_before = project_file.read_bytes()
    config.write_text("[mcp_servers.legis\n", encoding="utf-8")
    global_before = config.read_bytes()
    project = check_plainweave_project_binding(root, repair=True)
    codex = check_plainweave_codex_binding(root, repair=True)
    assert project.status == codex.status == "error"
    assert project.repairable is codex.repairable is False
    assert project_file.read_bytes() == project_before
    assert config.read_bytes() == global_before


def test_malformed_project_and_unsafe_global_are_operator_owned(tmp_path, monkeypatch):
    root, executable, config = _plainweave_project(tmp_path, monkeypatch)
    project_file = root / ".mcp.json"
    project_file.write_text("{not valid json", encoding="utf-8")
    plainweave = _make_executable(tmp_path / "path" / "plainweave-mcp")
    monkeypatch.setenv("PATH", str(plainweave.parent))
    config.write_text(
        "[mcp_servers.legis]\n"
        f"command = {json.dumps(str(executable))}\n"
        'args = ["mcp", "--agent-id", "operator"]\n'
        'url = "https://example.invalid/mcp"\n',
        encoding="utf-8",
    )
    project_before = project_file.read_bytes()
    global_before = config.read_bytes()
    project = check_plainweave_project_binding(root, repair=True)
    codex = check_plainweave_codex_binding(root, repair=True)
    assert project.status == codex.status == "error"
    assert project.repairable is codex.repairable is False
    assert project_file.read_bytes() == project_before
    assert config.read_bytes() == global_before


@pytest.mark.parametrize("shape", ["inline", "dotted"])
def test_unsupported_codex_env_shape_is_operator_owned_not_auto_fixable(
    tmp_path: Path,
    monkeypatch,
    capsys,
    shape: str,
) -> None:
    root, executable, config = _plainweave_project(tmp_path, monkeypatch)
    env_line = (
        f'env = {{ KEEP_ME = "operator", {PLAINWEAVE_ENV} = "legacy" }}'
        if shape == "inline"
        else (
            'env.KEEP_ME = "operator"\n'
            f'env.{PLAINWEAVE_ENV} = "legacy"'
        )
    )
    config.write_text(
        "[mcp_servers.legis]\n"
        f"command = {json.dumps(str(executable))}\n"
        'args = ["mcp", "--agent-id", "operator"]\n'
        f"{env_line}\n",
        encoding="utf-8",
    )
    before = config.read_bytes()

    check = check_plainweave_codex_binding(root, repair=False)
    exit_code = run_doctor(root, repair=False, fmt="json")
    payload = json.loads(capsys.readouterr().out)
    rendered = next(
        item
        for item in payload["checks"]
        if item["id"] == "install.plainweave_codex_binding"
    )

    assert check.status == "error"
    assert check.repairable is False
    assert check.fixed is False
    assert check.message is not None and "unsupported" in check.message.lower()
    assert "[operator]" in render_text([check])
    assert exit_code == 1
    assert rendered["status"] == "error"
    assert rendered["repairable"] is False
    assert rendered["fixed"] is False
    assert config.read_bytes() == before


def test_initialized_plainweave_aggregate_and_rendering(tmp_path, monkeypatch):
    root, _executable, config = _plainweave_project(tmp_path, monkeypatch)
    project_path = root / ".mcp.json"
    project_data = json.loads(project_path.read_text(encoding="utf-8"))
    project_data["mcpServers"]["legis"]["env"][PLAINWEAVE_ENV] = "legacy-project"
    project_path.write_text(json.dumps(project_data), encoding="utf-8")
    config.write_text(
        config.read_text(encoding="utf-8")
        + f'{PLAINWEAVE_ENV} = "legacy-global"\n',
        encoding="utf-8",
    )
    checks = collect_checks(root, repair=False)
    repairable = {check.id for check in checks if check.repairable}
    assert {
        "install.plainweave_project_binding",
        "install.plainweave_codex_binding",
    } <= repairable
    text = render_text(checks)
    assert "install.plainweave_project_binding:" in text
    assert "install.plainweave_codex_binding:" in text
    assert "[auto-fixable]" in text
    payload = json.loads(render_json(checks))
    assert all(
        "repairable" in check and "fixed" in check for check in payload["checks"]
    )


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
        {
            "type": "sse",
            "command": sys.executable,
            "args": ["-P", "-m", "legis", "mcp", "--agent-id", "a"],
        },
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
        {
            "type": "stdio",
            "command": sys.executable,
            "args": ["serve", "mcp", "--agent-id", "a"],
        },
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
            {
                "type": "stdio",
                "command": sys.executable,
                "args": ["mcp", "--agent-id", "a"],
                "env": env,
            },
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
    assert (
        legis_install._extract_marker_token((tmp_path / "CLAUDE.md").read_text())
        == fresh_token
    )


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
    c = check_audit_chain(
        "store.governance_chain", "sqlite:///" + str(tmp_path / "nope.db")
    )
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
    assert (
        url
        == "sqlite:///" + (root / ".weft" / "legis" / "legis-governance.db").as_posix()
    )
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
    codex_home = tmp_path / "isolated-codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
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
    assert list(codex_home.iterdir()) == []


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
    _write_mcp_with_filigree_url(
        tmp_path, "http://127.0.0.1:8749/api/weft/scan-results"
    )
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "warn"
    assert c.repairable is False  # operator-owned; legis never writes the binding
    # honors "outputs": names the offending URL so the operator sees the binding
    assert "8749/api/weft/scan-results" in c.message
    assert "/api/p/<project>" in c.message  # operator action + literal placeholder
    assert "operator-pinned" in c.message  # names ownership
    assert "Operator action" in c.message


def test_filigree_scope_warns_on_unscoped_remote_binding_without_local_install(
    tmp_path,
):
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
    _write_mcp_with_filigree_url(
        tmp_path, "http://127.0.0.1:8749/api/weft/scan-results"
    )
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "warn"
    assert "8749/api/weft/scan-results" in c.message


def test_filigree_scope_confless_weft_store_is_installed_and_warns(tmp_path):
    # Confless federation install: .weft/filigree/ dir present, NO .filigree.conf.
    # filigree resolves this as installed (core.py:1055-1059); legis must too, or
    # it suppresses a real unscoped-binding warning.
    (tmp_path / ".weft" / "filigree").mkdir(parents=True)
    _write_mcp_with_filigree_url(
        tmp_path, "http://127.0.0.1:8749/api/weft/scan-results"
    )
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "warn"
    assert "8749/api/weft/scan-results" in c.message


def test_filigree_scope_confless_legacy_dir_is_installed_and_warns(tmp_path):
    # Confless legacy install: legacy .filigree/ dir present, NO .filigree.conf.
    # filigree resolves this as installed (core.py:1060-1064); legis must too.
    # This is the live federation-legacy-path case (legacy .filigree/ dirs exist
    # in this environment).
    (tmp_path / ".filigree").mkdir(parents=True)
    _write_mcp_with_filigree_url(
        tmp_path, "http://127.0.0.1:8749/api/weft/scan-results"
    )
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "warn"
    assert "8749/api/weft/scan-results" in c.message


def test_filigree_scope_warns_with_legacy_config_marker(tmp_path):
    _mark_filigree_installed(tmp_path, legacy=True)
    _write_mcp_with_filigree_url(
        tmp_path, "http://127.0.0.1:8749/api/weft/scan-results"
    )
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


@pytest.mark.parametrize(
    ("url", "expected_status"),
    [
        ("https://central.example/api/weft/scan-results", "warn"),
        ("https://central.example/api/p/project/weft/scan-results", "ok"),
    ],
)
def test_filigree_scope_parses_equals_form_url(
    tmp_path,
    url,
    expected_status,
):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wardline": {
                        "command": "wardline",
                        "args": ["mcp", f"--filigree-url={url}"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    c = check_filigree_binding_scope(tmp_path)

    assert c.status == expected_status
    assert url in (c.message or "")


@pytest.mark.parametrize(
    ("path", "expected_status"),
    [
        ("/%61pi/weft/scan-results", "warn"),
        ("/api%2Fweft%2Fscan-results", "warn"),
        ("/%61pi/p/project/weft/scan-results", "ok"),
        ("/api%2Fp%2Fproject%2Fweft%2Fscan-results", "ok"),
        ("/api/p/fake/../../weft/scan-results", "warn"),
        ("/api/p/fake/%2e%2e/%2e%2e/weft/scan-results", "warn"),
        ("/api/other/../p/project/weft/scan-results", "ok"),
    ],
)
def test_filigree_scope_classifies_decoded_normalized_paths(
    tmp_path,
    path,
    expected_status,
):
    url = f"https://central.example{path}"
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wardline": {
                        "args": ["mcp", f"--filigree-url={url}"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    c = check_filigree_binding_scope(tmp_path)

    assert c.status == expected_status
    assert path in (c.message or "")


@pytest.mark.parametrize(
    ("url", "expected_status"),
    [
        ("https://central.example/api/p//weft/scan-results", "error"),
        ("https://central.example/api%2Fp%2F%2Fweft%2Fscan-results", "error"),
        ("https://central.example/api/weft/scan-results?project=", "warn"),
        ("https://central.example/api/weft/scan-results?project=%20", "warn"),
        ("https://central.example/api/weft/scan-results?project=%00", "error"),
        ("https://central.example/api/weft/scan-results?project=legis", "ok"),
        (
            "https://central.example/api/weft/scan-results?project=legis&project=",
            "warn",
        ),
        (
            "https://central.example/api/weft/scan-results?project=legis&project=%20",
            "warn",
        ),
        (
            "https://central.example/api/weft/scan-results?project=&project=legis",
            "ok",
        ),
    ],
)
def test_filigree_scope_requires_nonempty_safe_project_identity(
    tmp_path,
    url,
    expected_status,
):
    _write_mcp_with_filigree_url(tmp_path, url)

    c = check_filigree_binding_scope(tmp_path)

    assert c.status == expected_status


@pytest.mark.parametrize(
    ("field_count", "expected_status"),
    [(100, "ok"), (101, "error")],
)
def test_filigree_scope_bounds_project_query_fields(
    tmp_path,
    field_count,
    expected_status,
):
    filler = [f"f{index}=x" for index in range(field_count - 1)]
    query = "&".join([*filler, "project=legis"])
    _write_mcp_with_filigree_url(
        tmp_path,
        f"https://central.example/api/weft/scan-results?{query}",
    )

    c = check_filigree_binding_scope(tmp_path)

    assert c.status == expected_status


@pytest.mark.parametrize(
    "args",
    [
        ["mcp", "--filigree-url"],
        ["mcp", "--filigree-url", ""],
        ["mcp", "--filigree-url", "   "],
        ["mcp", "--filigree-url", "--other"],
        ["mcp", "--filigree-url="],
        ["mcp", "--filigree-url=   "],
        ["mcp", "--filigree-url=--other"],
        ["mcp", "--filigree-url", "not-a-url"],
        ["mcp", "--filigree-url=not-a-url"],
        ["mcp", "--filigree-url=ftp://host/api/weft/scan-results"],
        ["mcp", "--filigree-url=https:///api/weft/scan-results"],
        ["mcp", "--filigree-url=https://host:bad/api/weft/scan-results"],
        ["mcp", "--filigree-url=https://host/api/weft/scan results"],
        ["mcp", "--filigree-url=https://host/api/weft/%ZZ"],
        ["mcp", "--filigree-url=https://host/api/weft/%FF"],
        ["mcp", "--filigree-url=https://ho%ZZst.example/api/weft/scan-results"],
        ["mcp", "--filigree-url=https://%FF.example/api/weft/scan-results"],
        ["mcp", "--filigree-url=https://host%0Aevil.example/api/weft/scan-results"],
        ["mcp", "--filigree-url=https://host\\evil.example/api/weft/scan-results"],
    ],
)
def test_filigree_scope_rejects_missing_or_invalid_url_value(tmp_path, args):
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"wardline": {"command": "wardline", "args": args}}}),
        encoding="utf-8",
    )

    c = check_filigree_binding_scope(tmp_path)

    assert c.status == "error"
    assert c.repairable is False
    assert c.message is not None and "could not inspect" in c.message.lower()


@pytest.mark.parametrize(
    ("args", "expected_status"),
    [
        (
            [
                "mcp",
                "--filigree-url=https://alice:s3cr3t@central.example/api/weft/scan-results",
            ],
            "error",
        ),
        (
            [
                "mcp",
                "--filigree-url",
                "https://central.example/api/weft/scan-results?token=s3cr3t",
            ],
            "warn",
        ),
        (
            [
                "mcp",
                "--filigree-url=https://central.example/api/weft/scan-results"
                "?project=legis&token=s3cr3t#fragment-secret",
            ],
            "ok",
        ),
    ],
)
def test_filigree_scope_never_exposes_url_credentials(
    tmp_path,
    args,
    expected_status,
):
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"wardline": {"args": args}}}),
        encoding="utf-8",
    )

    c = check_filigree_binding_scope(tmp_path)

    assert c.status == expected_status
    message = c.message or ""
    assert "s3cr3t" not in message
    assert "fragment-secret" not in message
    assert "alice" not in message
    if expected_status != "error":
        assert "central.example/api/weft/scan-results" in message


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_rendered_doctor_output_redacts_filigree_url_credentials(
    tmp_path,
    capsys,
    fmt,
):
    secret = "rendered-secret-value"
    url = (
        "https://central.example/api/weft/scan-results"
        f"?token={secret}#fragment-{secret}"
    )
    _write_mcp_with_filigree_url(tmp_path, url)

    run_doctor(tmp_path, repair=False, fmt=fmt)
    rendered = capsys.readouterr().out

    assert secret not in rendered
    assert f"fragment-{secret}" not in rendered
    assert "central.example/api/weft/scan-results" in rendered


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize("control", ["\x00", "\x1b", "\x7f", "\u202e"])
def test_rendered_doctor_output_rejects_url_control_characters(
    tmp_path,
    capsys,
    fmt,
    control,
):
    marker = "control-injection-marker"
    url = f"https://central.example/api/weft/scan-results{control}{marker}"
    _write_mcp_with_filigree_url(tmp_path, url)

    check = check_filigree_binding_scope(tmp_path)
    assert check.status == "error"
    assert marker not in (check.message or "")
    assert control not in (check.message or "")

    run_doctor(tmp_path, repair=False, fmt=fmt)
    rendered = capsys.readouterr().out

    assert marker not in rendered
    assert control not in rendered


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


def test_filigree_scope_reports_malformed_mcp_json_as_unavailable(tmp_path):
    _mark_filigree_installed(tmp_path)
    (tmp_path / ".mcp.json").write_text("{not json", encoding="utf-8")
    c = check_filigree_binding_scope(tmp_path)
    assert c.status == "error"
    assert c.repairable is False
    assert c.message is not None and "could not inspect" in c.message.lower()


@pytest.mark.parametrize(
    "document",
    [
        {"mcpServers": None},
        {"mcpServers": []},
        {"mcpServers": {"wardline": None}},
        {"mcpServers": {"wardline": {"args": "not-a-list"}}},
        {"mcpServers": {"wardline": {"args": ["--filigree-url", 42]}}},
    ],
)
def test_filigree_scope_reports_malformed_server_shapes_as_unavailable(
    tmp_path,
    document,
):
    (tmp_path / ".mcp.json").write_text(json.dumps(document), encoding="utf-8")

    c = check_filigree_binding_scope(tmp_path)

    assert c.status == "error"
    assert c.repairable is False
    assert c.message is not None and "could not inspect" in c.message.lower()


def test_filigree_scope_reports_fifo_mcp_json_as_unavailable(tmp_path):
    os.mkfifo(tmp_path / ".mcp.json")

    c = check_filigree_binding_scope(tmp_path)

    assert c.status == "error"
    assert c.repairable is False
    assert c.message is not None and "could not inspect" in c.message.lower()


def test_collect_checks_includes_filigree_scope(tmp_path):
    ids = {c.id for c in collect_checks(tmp_path, repair=False)}
    assert "install.filigree_scope" in ids
