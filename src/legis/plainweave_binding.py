"""Discover a project-scoped Plainweave MCP invocation."""

from __future__ import annotations

import json
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PLAINWEAVE_ENV = "PLAINWEAVE_MCP_CMD"


@dataclass(frozen=True, slots=True)
class PlainweaveDiscovery:
    applicable: bool
    installed: bool
    command: str | None = None
    error: str | None = None


def _resolve_executable(command: object) -> str | None:
    if not isinstance(command, str) or not command:
        return None
    try:
        return shutil.which(command)
    except (OSError, UnicodeError):
        return None


def _project_plainweave_argv(root: Path) -> tuple[list[str] | None, bool]:
    config = root / ".mcp.json"
    if not config.exists():
        return None, False

    try:
        data: Any = json.loads(config.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeError):
        return None, True

    if not isinstance(data, dict):
        return None, True
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return None, True
    if "plainweave" not in servers:
        return None, False

    entry = servers["plainweave"]
    if not isinstance(entry, dict):
        return None, True
    if entry.get("type", "stdio") != "stdio":
        return None, True

    executable = _resolve_executable(entry.get("command"))
    args = entry.get("args")
    if executable is None or not isinstance(args, list):
        return None, True
    if not all(isinstance(arg, str) for arg in args):
        return None, True

    root_indexes = [index for index, arg in enumerate(args) if arg == "--root"]
    if len(root_indexes) != 1 or root_indexes[0] + 1 >= len(args):
        return None, True

    root_value = Path(args[root_indexes[0] + 1])
    if not root_value.is_absolute():
        root_value = root / root_value
    try:
        if root_value.resolve() != root:
            return None, True
    except (OSError, RuntimeError):
        return None, True

    return [executable, *args], False


def discover_plainweave(root: Path) -> PlainweaveDiscovery:
    """Return a usable Plainweave command only for an initialized project."""
    resolved_root = root.resolve()
    database = resolved_root / ".plainweave" / "plainweave.db"
    initialized = database.is_file() and not database.is_symlink()

    project_argv, invalid_project_entry = _project_plainweave_argv(resolved_root)
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
    if invalid_project_entry:
        error += "; the project .mcp.json Plainweave entry is invalid"
    return PlainweaveDiscovery(applicable=True, installed=False, error=error)
