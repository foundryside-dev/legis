from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest

from legis import plainweave_binding
from legis.plainweave_binding import PLAINWEAVE_ENV, discover_plainweave


def _make_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _initialize(root: Path) -> None:
    state = root / ".plainweave"
    state.mkdir(parents=True)
    (state / "plainweave.db").touch()


def _write_entry(root: Path, command: object, args: object) -> None:
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "plainweave": {
                        "type": "stdio",
                        "command": command,
                        "args": args,
                    }
                }
            }
        ),
        encoding="utf-8",
    )


def _write_legis_entry(root: Path, *, env: object | None = None) -> Path:
    config = root / ".mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "legis": {
                        "type": "stdio",
                        "command": sys.executable,
                        "args": [
                            "-P",
                            "-m",
                            "legis",
                            "mcp",
                            "--agent-id",
                            "operator-agent",
                        ],
                        "env": {} if env is None else env,
                        "timeout": 17_000,
                    },
                    "sibling": {"command": "sibling-mcp", "args": ["serve"]},
                }
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return config


def test_missing_project_binding_is_registered_but_noncurrent(tmp_path: Path) -> None:
    _write_legis_entry(tmp_path, env={"KEEP_ME": "operator-value"})

    state = plainweave_binding.inspect_project_binding(tmp_path, "plainweave --root .")

    assert state == plainweave_binding.BindingState(
        registered=True,
        current=False,
        error=None,
    )


def test_repair_changes_only_nested_binding_and_preserves_operator_config(
    tmp_path: Path,
) -> None:
    config = _write_legis_entry(tmp_path, env={"KEEP_ME": "operator-value"})
    before = json.loads(config.read_text(encoding="utf-8"))
    expected = json.loads(json.dumps(before))
    desired = "/opt/plainweave-mcp --root /operator/project"
    expected["mcpServers"]["legis"]["env"][PLAINWEAVE_ENV] = desired

    error = plainweave_binding.repair_project_binding(tmp_path, desired)

    assert error is None
    assert json.loads(config.read_text(encoding="utf-8")) == expected


def test_repair_replaces_stale_project_binding(tmp_path: Path) -> None:
    config = _write_legis_entry(
        tmp_path,
        env={PLAINWEAVE_ENV: "old-command --root /old", "KEEP_ME": "yes"},
    )

    error = plainweave_binding.repair_project_binding(
        tmp_path,
        "new-command --root /new",
    )

    assert error is None
    entry = json.loads(config.read_text(encoding="utf-8"))["mcpServers"]["legis"]
    assert entry["env"] == {
        PLAINWEAVE_ENV: "new-command --root /new",
        "KEEP_ME": "yes",
    }


def test_current_project_binding_does_not_write(tmp_path: Path, monkeypatch) -> None:
    desired = "plainweave-mcp --root /already-current"
    _write_legis_entry(tmp_path, env={PLAINWEAVE_ENV: desired})

    def unexpected_write(_path: Path, _content: str) -> None:
        pytest.fail("current binding must not be rewritten")

    monkeypatch.setattr(
        plainweave_binding.install,
        "_atomic_write_text",
        unexpected_write,
    )

    assert plainweave_binding.repair_project_binding(tmp_path, desired) is None


def test_second_repair_is_byte_identical(tmp_path: Path) -> None:
    config = _write_legis_entry(tmp_path, env={"KEEP_ME": "yes"})
    desired = "plainweave-mcp --root /stable"

    assert plainweave_binding.repair_project_binding(tmp_path, desired) is None
    after_first = config.read_bytes()
    assert plainweave_binding.repair_project_binding(tmp_path, desired) is None

    assert config.read_bytes() == after_first


def test_repair_preserves_file_mode(tmp_path: Path) -> None:
    config = _write_legis_entry(tmp_path)
    config.chmod(0o640)

    assert (
        plainweave_binding.repair_project_binding(
            tmp_path,
            "plainweave-mcp --root /mode-test",
        )
        is None
    )

    assert config.stat().st_mode & 0o777 == 0o640


def test_malformed_json_is_reported_and_unchanged(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text("{definitely not json", encoding="utf-8")
    before = config.read_bytes()

    state = plainweave_binding.inspect_project_binding(tmp_path, "desired")
    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert state.registered is False
    assert state.current is False
    assert state.error
    assert error
    assert config.read_bytes() == before


def test_symlinked_project_config_is_reported_and_unchanged(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    external = tmp_path / "external.json"
    external.write_text('{"mcpServers": {}}\n', encoding="utf-8")
    (project / ".mcp.json").symlink_to(external)
    before = external.read_bytes()

    state = plainweave_binding.inspect_project_binding(project, "desired")
    error = plainweave_binding.repair_project_binding(project, "desired")

    assert state.registered is False
    assert state.current is False
    assert state.error and "symlink" in state.error.lower()
    assert error and "symlink" in error.lower()
    assert external.read_bytes() == before


@pytest.mark.parametrize(
    ("document", "expected_registered"),
    [
        (["not", "an", "object"], False),
        ({"mcpServers": "not-an-object"}, False),
        ({"mcpServers": {"legis": "not-an-object"}}, False),
        (
            {
                "mcpServers": {
                    "legis": {
                        "type": "stdio",
                        "command": sys.executable,
                        "args": [
                            "-P",
                            "-m",
                            "legis",
                            "mcp",
                            "--agent-id",
                            "operator-agent",
                        ],
                        "env": ["not", "an", "object"],
                    }
                }
            },
            True,
        ),
    ],
    ids=["top-level", "mcpServers", "legis", "env"],
)
def test_non_object_config_sections_are_reported_and_unchanged(
    tmp_path: Path,
    document: object,
    expected_registered: bool,
) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps(document), encoding="utf-8")
    before = config.read_bytes()

    state = plainweave_binding.inspect_project_binding(tmp_path, "desired")
    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert state.registered is expected_registered
    assert state.current is False
    assert state.error
    assert error
    assert config.read_bytes() == before


def test_secret_environment_is_rejected_and_unchanged(tmp_path: Path) -> None:
    config = _write_legis_entry(
        tmp_path,
        env={"KEEP_ME": "yes", "LEGIS_HMAC_KEY": "must-not-be-touched"},
    )
    before = config.read_bytes()

    state = plainweave_binding.inspect_project_binding(tmp_path, "desired")
    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert state.registered is True
    assert state.current is False
    assert state.error and "environment" in state.error.lower()
    assert error and "environment" in error.lower()
    assert config.read_bytes() == before


@pytest.mark.parametrize("stale", [False, True], ids=["missing", "stale"])
def test_missing_or_stale_legis_entry_is_unregistered_and_unchanged(
    tmp_path: Path,
    stale: bool,
) -> None:
    config = _write_legis_entry(tmp_path)
    data = json.loads(config.read_text(encoding="utf-8"))
    if stale:
        data["mcpServers"]["legis"]["command"] = "/missing/legis"
    else:
        del data["mcpServers"]["legis"]
    config.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    before = config.read_bytes()

    state = plainweave_binding.inspect_project_binding(tmp_path, "desired")
    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert state.registered is False
    assert state.current is False
    assert state.error
    assert error
    assert config.read_bytes() == before


def test_atomic_writer_error_is_returned_without_partial_write(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _write_legis_entry(tmp_path, env={"KEEP_ME": "yes"})
    before = config.read_bytes()

    def fail_write(_path: Path, _content: str) -> None:
        raise OSError("simulated atomic replacement failure")

    monkeypatch.setattr(
        plainweave_binding.install,
        "_atomic_write_text",
        fail_write,
    )

    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert error and "simulated atomic replacement failure" in error
    assert config.read_bytes() == before


def test_plainweave_environment_variable_name_is_stable() -> None:
    assert PLAINWEAVE_ENV == "PLAINWEAVE_MCP_CMD"


def test_root_pinned_project_entry_wins_over_path_fallback(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    project_command = _make_executable(tmp_path / "project-bin" / "plainweave")
    fallback = _make_executable(tmp_path / "fallback-bin" / "plainweave-mcp")
    args = ["serve", "--root", str(root), "--quiet"]
    _write_entry(root, str(project_command), args)
    monkeypatch.setenv("PATH", str(fallback.parent))

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is True
    assert shlex.split(result.command or "") == [str(project_command), *args]
    assert result.error is None


def test_path_fallback_adds_explicit_resolved_root(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    fallback = _make_executable(tmp_path / "bin" / "plainweave-mcp")
    monkeypatch.setenv("PATH", str(fallback.parent))

    result = discover_plainweave(root / ".")

    assert result.applicable is True
    assert result.installed is True
    assert shlex.split(result.command or "") == [
        str(fallback),
        "--root",
        str(root.resolve()),
    ]
    assert result.error is None


def test_installed_executable_does_not_recruit_uninitialized_project(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    fallback = _make_executable(tmp_path / "bin" / "plainweave-mcp")
    monkeypatch.setenv("PATH", str(fallback.parent))

    result = discover_plainweave(root)

    assert result.applicable is False
    assert result.installed is True
    assert result.command is None
    assert result.error is None


def test_initialized_project_without_executable_fails_closed(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None
    assert "no executable" in result.error.lower()


def test_symlinked_database_is_not_project_state(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "project"
    state = root / ".plainweave"
    state.mkdir(parents=True)
    database = tmp_path / "external.db"
    database.touch()
    (state / "plainweave.db").symlink_to(database)
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is False
    assert result.installed is False
    assert result.command is None
    assert result.error is None


def test_malformed_mcp_json_is_invalid_for_initialized_project(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    (root / ".mcp.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None
    assert "malformed" in result.error.lower()
    assert "no executable" in result.error.lower()


def test_non_string_project_args_are_invalid(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    command = _make_executable(tmp_path / "bin" / "plainweave")
    _write_entry(root, str(command), ["--root", str(root), 7])
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None
    assert "invalid" in result.error.lower()
    assert "no executable" in result.error.lower()


def test_project_entry_without_root_is_invalid(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    command = _make_executable(tmp_path / "bin" / "plainweave")
    _write_entry(root, str(command), ["serve"])
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None
    assert "invalid" in result.error.lower()
    assert "no executable" in result.error.lower()


def test_project_entry_with_mismatched_root_is_invalid(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    other_root = tmp_path / "other"
    other_root.mkdir()
    command = _make_executable(tmp_path / "bin" / "plainweave")
    _write_entry(root, str(command), ["--root", str(other_root)])
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None
    assert "invalid" in result.error.lower()
    assert "no executable" in result.error.lower()


def test_project_entry_rejects_later_equals_root_override(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    other_root = tmp_path / "other"
    other_root.mkdir()
    command = _make_executable(tmp_path / "bin" / "plainweave")
    _write_entry(
        root,
        str(command),
        ["serve", "--root", str(root), "--quiet", f"--root={other_root}"],
    )
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None
    assert "invalid" in result.error.lower()


def test_project_entry_rejects_later_abbreviated_root_override(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    other_root = tmp_path / "other"
    other_root.mkdir()
    command = _make_executable(tmp_path / "bin" / "plainweave")
    _write_entry(
        root,
        str(command),
        ["--root", str(root), f"--roo={other_root}", "--quiet"],
    )
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None
    assert "invalid" in result.error.lower()


def test_project_entry_with_dead_command_is_invalid(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    _write_entry(root, str(tmp_path / "missing-plainweave"), ["--root", str(root)])
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None
    assert "invalid" in result.error.lower()
    assert "no executable" in result.error.lower()


def test_command_path_with_spaces_round_trips_exactly(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "project with spaces"
    root.mkdir()
    command = _make_executable(tmp_path / "bin with spaces" / "plainweave mcp")
    args = ["--root", str(root), "--label", "project label"]
    _write_entry(root, str(command), args)
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is True
    assert result.command is not None
    assert shlex.split(result.command) == [str(command), *args]
    assert result.error is None


def test_symlinked_project_config_cannot_establish_applicability(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    command = _make_executable(tmp_path / "bin" / "plainweave")
    external_config = outside / ".mcp.json"
    external_config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "plainweave": {
                        "type": "stdio",
                        "command": str(command),
                        "args": ["--root", str(root)],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (root / ".mcp.json").symlink_to(external_config)
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is False
    assert result.installed is False
    assert result.command is None
    assert result.error is None


def test_symlinked_state_directory_cannot_recruit_fallback(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    external_state = tmp_path / "external-state"
    external_state.mkdir()
    (external_state / "plainweave.db").touch()
    (root / ".plainweave").symlink_to(external_state, target_is_directory=True)
    fallback = _make_executable(tmp_path / "fallback-bin" / "plainweave-mcp")
    monkeypatch.setenv("PATH", str(fallback.parent))

    result = discover_plainweave(root)

    assert result.applicable is False
    assert result.installed is True
    assert result.command is None
    assert result.error is None
