"""Discover a project-scoped Plainweave MCP invocation."""

from __future__ import annotations

import json
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from legis import install


PLAINWEAVE_ENV = "PLAINWEAVE_MCP_CMD"

_MALFORMED_CONFIG = "project .mcp.json is malformed or unreadable"
_INVALID_ENTRY = "project .mcp.json Plainweave entry is invalid"


@dataclass(frozen=True, slots=True)
class PlainweaveDiscovery:
    applicable: bool
    installed: bool
    command: str | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class BindingState:
    registered: bool
    current: bool
    error: str | None = None


@dataclass(slots=True)
class _BindingInspection:
    state: BindingState
    path: Path | None = None
    data: dict[str, Any] | None = None
    entry: dict[str, Any] | None = None
    env: dict[str, str] | None = None


def _binding_error(error: str, *, registered: bool = False) -> _BindingInspection:
    return _BindingInspection(
        BindingState(registered=registered, current=False, error=error)
    )


def _inspect_project_binding(root: Path, desired: str) -> _BindingInspection:
    try:
        resolved_root = root.resolve()
    except (OSError, RuntimeError) as exc:
        return _binding_error(f"could not resolve project root: {exc}")

    config = resolved_root / ".mcp.json"
    if config.is_symlink():
        return _binding_error("project .mcp.json is a symlink; refusing to inspect it")
    if not config.is_file():
        return _binding_error("project .mcp.json is missing or is not a regular file")

    try:
        data: Any = json.loads(config.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeError) as exc:
        return _binding_error(f"project .mcp.json is malformed or unreadable: {exc}")
    if not isinstance(data, dict):
        return _binding_error("project .mcp.json top level is not an object")

    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return _binding_error("project .mcp.json mcpServers is not an object")
    entry = servers.get("legis")
    if not isinstance(entry, dict):
        return _binding_error("project Legis MCP registration is missing or malformed")

    raw_env = entry.get("env", {})
    safe_env = install._safe_mcp_env(raw_env)
    if safe_env is None or safe_env != raw_env:
        return _binding_error(
            "project Legis MCP environment is malformed, unsafe, or contains secrets",
            registered=True,
        )

    try:
        registered = install.mcp_entry_is_current(resolved_root)
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        return _binding_error(f"could not inspect project Legis MCP registration: {exc}")
    if not registered:
        return _binding_error(
            "project Legis MCP registration is missing, stale, or malformed"
        )

    return _BindingInspection(
        state=BindingState(
            registered=True,
            current=safe_env.get(PLAINWEAVE_ENV) == desired,
        ),
        path=config,
        data=data,
        entry=entry,
        env=safe_env,
    )


def inspect_project_binding(root: Path, desired: str) -> BindingState:
    """Inspect the Plainweave command bound to a usable project Legis entry."""
    return _inspect_project_binding(root, desired).state


def repair_project_binding(root: Path, desired: str) -> str | None:
    """Bind Plainweave in an existing usable project Legis MCP entry."""
    inspection = _inspect_project_binding(root, desired)
    if inspection.state.current:
        return None
    if inspection.state.error is not None:
        return inspection.state.error

    path = inspection.path
    data = inspection.data
    entry = inspection.entry
    env = inspection.env
    if path is None or data is None or entry is None or env is None:
        return "project Legis MCP binding could not be repaired"

    updated_env = dict(env)
    updated_env[PLAINWEAVE_ENV] = desired
    entry["env"] = updated_env
    content = json.dumps(data, indent=2) + "\n"
    try:
        install._atomic_write_text(path, content)
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        return f"could not repair project Plainweave binding: {exc}"
    return None


def _resolve_executable(command: object) -> str | None:
    if not isinstance(command, str) or not command:
        return None
    try:
        return shutil.which(command)
    except (OSError, UnicodeError):
        return None


def _project_plainweave_argv(root: Path) -> tuple[list[str] | None, str | None]:
    config = root / ".mcp.json"
    if not config.exists():
        return None, None
    if config.is_symlink() or not config.is_file():
        return None, _MALFORMED_CONFIG

    try:
        data: Any = json.loads(config.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeError):
        return None, _MALFORMED_CONFIG

    if not isinstance(data, dict):
        return None, _MALFORMED_CONFIG
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return None, _MALFORMED_CONFIG
    if "plainweave" not in servers:
        return None, None

    entry = servers["plainweave"]
    if not isinstance(entry, dict):
        return None, _INVALID_ENTRY
    if entry.get("type", "stdio") != "stdio":
        return None, _INVALID_ENTRY

    executable = _resolve_executable(entry.get("command"))
    args = entry.get("args")
    if executable is None or not isinstance(args, list):
        return None, _INVALID_ENTRY
    if not all(isinstance(arg, str) for arg in args):
        return None, _INVALID_ENTRY

    root_values: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        option = arg.partition("=")[0]
        if arg == "--root":
            if index + 1 >= len(args):
                return None, _INVALID_ENTRY
            root_values.append(args[index + 1])
            index += 2
            continue
        if arg.startswith("--root="):
            value = arg.partition("=")[2]
            if not value:
                return None, _INVALID_ENTRY
            root_values.append(value)
        elif len(option) > 2 and "--root".startswith(option):
            return None, _INVALID_ENTRY
        index += 1

    if len(root_values) != 1:
        return None, _INVALID_ENTRY

    root_value = Path(root_values[0])
    if not root_value.is_absolute():
        root_value = root / root_value
    try:
        if root_value.resolve() != root:
            return None, _INVALID_ENTRY
    except (OSError, RuntimeError):
        return None, _INVALID_ENTRY

    return [executable, *args], None


def discover_plainweave(root: Path) -> PlainweaveDiscovery:
    """Return a usable Plainweave command only for an initialized project."""
    resolved_root = root.resolve()
    state_directory = resolved_root / ".plainweave"
    database = state_directory / "plainweave.db"
    initialized = (
        state_directory.is_dir()
        and not state_directory.is_symlink()
        and database.is_file()
        and not database.is_symlink()
    )

    project_argv, project_issue = _project_plainweave_argv(resolved_root)
    fallback = _resolve_executable("plainweave-mcp")

    if project_argv is not None:
        return PlainweaveDiscovery(
            applicable=True,
            installed=True,
            command=shlex.join(project_argv),
        )

    if not initialized:
        return PlainweaveDiscovery(applicable=False, installed=fallback is not None)

    if fallback is not None:
        return PlainweaveDiscovery(
            applicable=True,
            installed=True,
            command=shlex.join([fallback, "--root", str(resolved_root)]),
        )

    error = "Plainweave project has no executable available"
    if project_issue is not None:
        error += f"; {project_issue}"
    return PlainweaveDiscovery(applicable=True, installed=False, error=error)
