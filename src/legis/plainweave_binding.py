"""Discover a project-scoped Plainweave MCP invocation."""

from __future__ import annotations

import errno
import json
import os
import secrets
import shlex
import shutil
import stat
from collections.abc import Collection
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
    root_fd: int | None = None
    snapshot: bytes | None = None
    identity: tuple[int, int] | None = None
    mode: int | None = None
    data: dict[str, Any] | None = None
    entry: dict[str, Any] | None = None
    env: dict[str, str] | None = None


def _binding_error(error: str, *, registered: bool = False) -> _BindingInspection:
    return _BindingInspection(
        BindingState(registered=registered, current=False, error=error)
    )


def _close_root_fd(inspection: _BindingInspection) -> None:
    if inspection.root_fd is not None:
        try:
            os.close(inspection.root_fd)
        except (OSError, NotImplementedError):
            pass
        inspection.root_fd = None


def _read_fd(fd: int) -> bytes:
    chunks: list[bytes] = []
    while chunk := os.read(fd, 64 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


def _anchored_io_support_error() -> str | None:
    directory_flag = getattr(os, "O_DIRECTORY", None)
    nofollow_flag = getattr(os, "O_NOFOLLOW", None)
    supported: Collection[object] = getattr(os, "supports_dir_fd", frozenset())
    replace_supported = os.replace in supported or os.rename in supported
    if (
        directory_flag is None
        or nofollow_flag is None
        or not hasattr(os, "fchmod")
        or os.open not in supported
        or os.unlink not in supported
        or not replace_supported
    ):
        return "platform does not support race-safe anchored project I/O"
    return None


def _inspect_project_binding(root: Path, desired: str) -> _BindingInspection:
    try:
        resolved_root = root.resolve()
    except (OSError, RuntimeError) as exc:
        return _binding_error(f"could not resolve project root: {exc}")

    support_error = _anchored_io_support_error()
    if support_error is not None:
        return _binding_error(support_error)

    directory_flag = os.O_DIRECTORY
    nofollow_flag = os.O_NOFOLLOW

    root_flags = os.O_RDONLY | directory_flag | nofollow_flag
    root_flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(resolved_root, root_flags)
    except (OSError, NotImplementedError, TypeError) as exc:
        return _binding_error(f"could not open resolved project root safely: {exc}")

    def fail(error: str, *, registered: bool = False) -> _BindingInspection:
        try:
            os.close(root_fd)
        except (OSError, NotImplementedError):
            pass
        return _binding_error(error, registered=registered)

    target_flags = os.O_RDONLY | nofollow_flag | getattr(os, "O_CLOEXEC", 0)
    try:
        target_fd = os.open(".mcp.json", target_flags, dir_fd=root_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return fail("project .mcp.json is a symlink; refusing to inspect it")
        return fail(f"project .mcp.json is missing, unreadable, or unsafe: {exc}")
    except (NotImplementedError, TypeError) as exc:
        return fail(f"platform does not support anchored project file access: {exc}")

    try:
        target_stat = os.fstat(target_fd)
        if not stat.S_ISREG(target_stat.st_mode):
            return fail("project .mcp.json is not a regular file")
        snapshot = _read_fd(target_fd)
    except (OSError, NotImplementedError) as exc:
        return fail(f"project .mcp.json is unreadable: {exc}")
    finally:
        try:
            os.close(target_fd)
        except (OSError, NotImplementedError):
            pass

    try:
        data: Any = json.loads(snapshot.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        return fail(f"project .mcp.json is malformed or unreadable: {exc}")
    if not isinstance(data, dict):
        return fail("project .mcp.json top level is not an object")

    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return fail("project .mcp.json mcpServers is not an object")
    entry = servers.get("legis")
    if not isinstance(entry, dict):
        return fail("project Legis MCP registration is missing or malformed")

    try:
        registered = install._parsed_mcp_entry_is_current(
            resolved_root,
            data,
            check_env=False,
        )
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        return fail(f"could not inspect project Legis MCP registration: {exc}")
    if not registered:
        return fail("project Legis MCP registration is missing, stale, or malformed")

    raw_env = entry.get("env", {})
    safe_env = install._safe_mcp_env(raw_env)
    if safe_env is None or safe_env != raw_env:
        return fail(
            "project Legis MCP environment is malformed, unsafe, or contains secrets",
            registered=True,
        )

    return _BindingInspection(
        state=BindingState(
            registered=True,
            current=safe_env.get(PLAINWEAVE_ENV) == desired,
        ),
        root_fd=root_fd,
        snapshot=snapshot,
        identity=(target_stat.st_dev, target_stat.st_ino),
        mode=stat.S_IMODE(target_stat.st_mode),
        data=data,
        entry=entry,
        env=safe_env,
    )


def inspect_project_binding(root: Path, desired: str) -> BindingState:
    """Inspect the Plainweave command bound to a usable project Legis entry."""
    inspection = _inspect_project_binding(root, desired)
    try:
        return inspection.state
    finally:
        _close_root_fd(inspection)


def _write_all(fd: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise OSError("short write while preparing project binding replacement")
        remaining = remaining[written:]


def _anchored_replace(inspection: _BindingInspection, content: bytes) -> str | None:
    root_fd = inspection.root_fd
    snapshot = inspection.snapshot
    identity = inspection.identity
    mode = inspection.mode
    if root_fd is None or snapshot is None or identity is None or mode is None:
        return "project Legis MCP binding snapshot is incomplete"

    nofollow_flag = getattr(os, "O_NOFOLLOW", None)
    if nofollow_flag is None:
        return "platform does not support race-safe project binding replacement"

    temp_name: str | None = None
    temp_fd: int | None = None
    try:
        temp_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow_flag
        temp_flags |= getattr(os, "O_CLOEXEC", 0)
        for _attempt in range(10):
            candidate = f".mcp.json.{secrets.token_hex(8)}.tmp"
            try:
                temp_fd = os.open(candidate, temp_flags, 0o600, dir_fd=root_fd)
            except FileExistsError:
                continue
            temp_name = candidate
            break
        if temp_fd is None or temp_name is None:
            return "could not allocate a temporary project binding file"

        _write_all(temp_fd, content)
        os.fchmod(temp_fd, mode)
        os.close(temp_fd)
        temp_fd = None

        current_flags = os.O_RDONLY | nofollow_flag | getattr(os, "O_CLOEXEC", 0)
        try:
            current_fd = os.open(".mcp.json", current_flags, dir_fd=root_fd)
        except (OSError, TypeError) as exc:
            return f"project .mcp.json changed after inspection: {exc}"
        try:
            current_stat = os.fstat(current_fd)
            current = _read_fd(current_fd)
        finally:
            os.close(current_fd)

        current_identity = (current_stat.st_dev, current_stat.st_ino)
        if (
            not stat.S_ISREG(current_stat.st_mode)
            or current_identity != identity
            or current != snapshot
        ):
            return "project .mcp.json changed after inspection; refusing to overwrite it"

        # This rechecks snapshot bytes and identity immediately before an atomic,
        # directory-anchored replace. Portable POSIX APIs do not offer a content
        # compare-and-swap: an arbitrary non-cooperating writer can still mutate
        # the target inside the final syscall window. Linearizability against such
        # writers is outside this CLI repair contract.
        try:
            os.replace(
                temp_name,
                ".mcp.json",
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
            )
        except TypeError as exc:
            return f"platform does not support anchored project replacement: {exc}"
        temp_name = None
        return None
    except (OSError, RuntimeError, TypeError, UnicodeError, ValueError) as exc:
        return f"could not repair project Plainweave binding: {exc}"
    finally:
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except (OSError, NotImplementedError):
                pass
        if temp_name is not None:
            try:
                os.unlink(temp_name, dir_fd=root_fd)
            except (OSError, NotImplementedError, TypeError):
                pass


def repair_project_binding(root: Path, desired: str) -> str | None:
    """Bind Plainweave in an existing usable project Legis MCP entry."""
    inspection = _inspect_project_binding(root, desired)
    try:
        if inspection.state.current:
            return None
        if inspection.state.error is not None:
            return inspection.state.error

        data = inspection.data
        entry = inspection.entry
        env = inspection.env
        if data is None or entry is None or env is None:
            return "project Legis MCP binding could not be repaired"

        updated_env = dict(env)
        updated_env[PLAINWEAVE_ENV] = desired
        entry["env"] = updated_env
        content = (json.dumps(data, indent=2) + "\n").encode("utf-8")
        return _anchored_replace(inspection, content)
    finally:
        _close_root_fd(inspection)


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
