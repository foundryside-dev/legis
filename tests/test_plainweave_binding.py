from __future__ import annotations

import json
import shlex
from pathlib import Path

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
