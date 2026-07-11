"""Discover a project-scoped Plainweave MCP invocation."""

from __future__ import annotations

import errno
import copy
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import tomllib
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
    target_name: str = ".mcp.json"
    subject: str = "project .mcp.json"
    repair_subject: str = "project Plainweave binding"
    text: str | None = None
    container_path: Path | None = None
    container_identity: tuple[int, int] | None = None


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
        data: Any = install._strict_json_loads(snapshot.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
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


def _anchored_container_changed(inspection: _BindingInspection) -> str | None:
    path = inspection.container_path
    identity = inspection.container_identity
    if path is None or identity is None:
        return None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        current_path = path.resolve()
        current_fd = os.open(current_path, flags)
        try:
            current_stat = os.fstat(current_fd)
        finally:
            os.close(current_fd)
    except (OSError, RuntimeError, NotImplementedError, TypeError) as exc:
        return f"{inspection.subject} directory changed after inspection: {exc}"
    if (current_stat.st_dev, current_stat.st_ino) != identity:
        return f"{inspection.subject} directory changed after inspection"
    return None


def _anchored_replace(inspection: _BindingInspection, content: bytes) -> str | None:
    root_fd = inspection.root_fd
    snapshot = inspection.snapshot
    identity = inspection.identity
    mode = inspection.mode
    target_name = inspection.target_name
    subject = inspection.subject
    repair_subject = inspection.repair_subject
    if root_fd is None or snapshot is None or identity is None or mode is None:
        return f"{repair_subject} snapshot is incomplete"

    nofollow_flag = getattr(os, "O_NOFOLLOW", None)
    if nofollow_flag is None:
        return "platform does not support race-safe project binding replacement"

    temp_name: str | None = None
    temp_fd: int | None = None
    try:
        temp_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow_flag
        temp_flags |= getattr(os, "O_CLOEXEC", 0)
        for _attempt in range(10):
            candidate = f"{target_name}.{secrets.token_hex(8)}.tmp"
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
            current_fd = os.open(target_name, current_flags, dir_fd=root_fd)
        except (OSError, NotImplementedError, TypeError) as exc:
            return f"{subject} changed after inspection: {exc}"
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
            return f"{subject} changed after inspection; refusing to overwrite it"

        container_error = _anchored_container_changed(inspection)
        if container_error is not None:
            return container_error

        # This rechecks snapshot bytes, file identity, and (when supplied) the
        # configured container identity immediately before an atomic,
        # directory-anchored replace. Portable POSIX APIs do not offer a content
        # compare-and-swap: an arbitrary non-cooperating writer can still mutate
        # the target or swap the configured path inside the final syscall window.
        # Linearizability against such writers is outside this CLI repair contract.
        try:
            os.replace(
                temp_name,
                target_name,
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
            )
        except TypeError as exc:
            return f"platform does not support anchored {repair_subject} replacement: {exc}"
        temp_name = None
        return None
    except (OSError, RuntimeError, TypeError, UnicodeError, ValueError) as exc:
        return f"could not repair {repair_subject}: {exc}"
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
        snapshot = inspection.snapshot
        if data is None or entry is None or env is None or snapshot is None:
            return "project Legis MCP binding could not be repaired"

        updated_env = dict(env)
        updated_env[PLAINWEAVE_ENV] = desired
        entry["env"] = updated_env
        original = snapshot.decode("utf-8")
        newline = _newline_for(original)
        rendered = json.dumps(data, indent=2).replace("\n", newline)
        if original.endswith(("\r\n", "\n", "\r")):
            rendered += newline
        content = rendered.encode("utf-8")
        return _anchored_replace(inspection, content)
    finally:
        _close_root_fd(inspection)


_CODEX_NOT_CONFIGURED = "global Codex Legis MCP registration is not configured"
_CODEX_HTTP_TRANSPORT_FIELDS = frozenset(
    {
        "auth",
        "auth_mode",
        "bearer_token_env_var",
        "env_http_headers",
        "http_headers",
        "oauth",
        "oauth_client_id",
        "oauth_resource",
        "scopes",
        "url",
    }
)
_TOML_TARGET_RE = re.compile(
    rf"(?m)^[ \t]*{PLAINWEAVE_ENV}[ \t]*=[ \t]*"
    r"(?P<value>\"(?:\\.|[^\"\\\r\n])*\"|'[^'\r\n]*')"
    r"[ \t]*(?:#[^\r\n]*)?(?:\r\n|\n|\r|\Z)"
)


def _codex_config_path() -> Path:
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home) / "config.toml"
    return Path.home() / ".codex" / "config.toml"


def _parse_toml_header_path(inner: str) -> tuple[str, ...] | None:
    try:
        parsed: Any = tomllib.loads(f"[{inner}]\n")
    except tomllib.TOMLDecodeError:
        return None
    path: list[str] = []
    current = parsed
    while True:
        if not isinstance(current, dict):
            return None
        if not current:
            return tuple(path) if path else None
        if len(current) != 1:
            return None
        key, current = next(iter(current.items()))
        path.append(key)


def _toml_header_inner(line: str) -> str | None:
    logical_line = line.rstrip("\r\n")
    index = len(logical_line) - len(logical_line.lstrip(" \t"))
    if index >= len(logical_line) or logical_line[index] != "[":
        return None

    inner_start = index + 1
    in_basic = False
    in_literal = False
    escaped = False
    for index in range(inner_start, len(logical_line)):
        character = logical_line[index]
        if in_basic:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_basic = False
            continue
        if in_literal:
            if character == "'":
                in_literal = False
            continue
        if character == '"':
            in_basic = True
        elif character == "'":
            in_literal = True
        elif character == "]":
            suffix = logical_line[index + 1 :].lstrip(" \t")
            if not suffix or suffix.startswith("#"):
                return logical_line[inner_start:index]
            return None
    return None


def _toml_table_spans(content: str) -> list[tuple[tuple[str, ...], int, int]]:
    headers: list[tuple[int, tuple[str, ...]]] = []
    offset = 0
    for line in content.splitlines(keepends=True):
        inner = _toml_header_inner(line)
        path = _parse_toml_header_path(inner) if inner is not None else None
        if path is None:
            offset += len(line)
            continue
        try:
            tomllib.loads(content[:offset])
        except tomllib.TOMLDecodeError:
            offset += len(line)
            continue
        headers.append((offset, path))
        offset += len(line)
    return [
        (
            path,
            start,
            headers[index + 1][0] if index + 1 < len(headers) else len(content),
        )
        for index, (start, path) in enumerate(headers)
    ]


def _toml_table_span(content: str, path: tuple[str, ...]) -> tuple[int, int] | None:
    matches = [
        (start, end)
        for found_path, start, end in _toml_table_spans(content)
        if found_path == path
    ]
    return matches[0] if len(matches) == 1 else None


def _inspect_codex_binding(root: Path, desired: str) -> _BindingInspection:
    try:
        resolved_root = root.resolve()
    except (OSError, RuntimeError) as exc:
        return _binding_error(f"could not resolve project root: {exc}")

    support_error = _anchored_io_support_error()
    if support_error is not None:
        return _binding_error(support_error.replace("project", "Codex config"))

    config_path = _codex_config_path()
    try:
        config_dir = config_path.parent.resolve()
    except (OSError, RuntimeError) as exc:
        if not config_path.parent.exists():
            return _BindingInspection(BindingState(False, False))
        return _binding_error(f"could not resolve Codex config directory: {exc}")

    root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(config_dir, root_flags)
    except FileNotFoundError:
        return _BindingInspection(BindingState(False, False))
    except (OSError, NotImplementedError, TypeError) as exc:
        return _binding_error(f"could not open Codex config directory safely: {exc}")
    try:
        root_stat = os.fstat(root_fd)
    except (OSError, NotImplementedError) as exc:
        try:
            os.close(root_fd)
        except (OSError, NotImplementedError):
            pass
        return _binding_error(f"could not inspect Codex config directory safely: {exc}")

    def fail(error: str, *, registered: bool = False) -> _BindingInspection:
        try:
            os.close(root_fd)
        except (OSError, NotImplementedError):
            pass
        return _binding_error(error, registered=registered)

    target_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        target_fd = os.open(config_path.name, target_flags, dir_fd=root_fd)
    except FileNotFoundError:
        try:
            os.close(root_fd)
        except (OSError, NotImplementedError):
            pass
        return _BindingInspection(BindingState(False, False))
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return fail("Codex config.toml is a symlink; refusing to inspect it")
        return fail(f"Codex config.toml is unreadable or unsafe: {exc}")
    except (NotImplementedError, TypeError) as exc:
        return fail(f"platform does not support anchored Codex config access: {exc}")

    try:
        target_stat = os.fstat(target_fd)
        if not stat.S_ISREG(target_stat.st_mode):
            return fail("Codex config.toml is not a regular file")
        snapshot = _read_fd(target_fd)
    except (OSError, NotImplementedError) as exc:
        return fail(f"Codex config.toml is unreadable: {exc}")
    finally:
        try:
            os.close(target_fd)
        except (OSError, NotImplementedError):
            pass

    try:
        text = snapshot.decode("utf-8")
        data: Any = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, UnicodeError) as exc:
        return fail(f"Codex config.toml is malformed or unreadable: {exc}")
    if not isinstance(data, dict):
        return fail("Codex config.toml top level is not a table")

    servers = data.get("mcp_servers")
    if servers is None:
        _close_root_fd(_BindingInspection(BindingState(False, False), root_fd=root_fd))
        return _BindingInspection(BindingState(False, False))
    if not isinstance(servers, dict):
        return fail("Codex config.toml mcp_servers is not a table")
    if "legis" not in servers:
        _close_root_fd(_BindingInspection(BindingState(False, False), root_fd=root_fd))
        return _BindingInspection(BindingState(False, False))

    entry = servers["legis"]
    if not isinstance(entry, dict):
        return fail("global Codex Legis MCP registration is malformed", registered=True)
    if _toml_table_span(text, ("mcp_servers", "legis")) is None:
        return fail(
            "global Codex Legis MCP registration uses an unsupported inline or dotted shape",
            registered=True,
        )
    conflicting_transport_fields = sorted(
        _CODEX_HTTP_TRANSPORT_FIELDS.intersection(entry)
    )
    if "command" in entry and conflicting_transport_fields:
        return fail(
            "global Codex Legis MCP registration mixes stdio command and HTTP "
            f"transport fields: {', '.join(conflicting_transport_fields)}",
            registered=True,
        )
    try:
        usable = install._mcp_args_are_current(
            entry.get("args")
        ) and install._mcp_command_resolves_safely(
            entry.get("command"), resolved_root, entry.get("args")
        )
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        return fail(
            f"could not inspect global Codex Legis MCP invocation: {exc}",
            registered=True,
        )
    if not usable:
        return fail(
            "global Codex Legis MCP invocation is missing, stale, or malformed",
            registered=True,
        )

    raw_env = entry.get("env", {})
    if not isinstance(raw_env, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in raw_env.items()
    ):
        return fail(
            "global Codex Legis MCP environment must be a table of strings",
            registered=True,
        )
    env = dict(raw_env)
    inspection = _BindingInspection(
        state=BindingState(True, env.get(PLAINWEAVE_ENV) == desired),
        root_fd=root_fd,
        snapshot=snapshot,
        identity=(target_stat.st_dev, target_stat.st_ino),
        mode=stat.S_IMODE(target_stat.st_mode),
        data=data,
        entry=entry,
        env=env,
        target_name=config_path.name,
        subject="Codex config.toml",
        repair_subject="global Codex Plainweave binding",
        text=text,
        container_path=config_path.parent,
        container_identity=(root_stat.st_dev, root_stat.st_ino),
    )
    if not inspection.state.current:
        _updated_text, edit_error = _updated_codex_text(inspection, desired)
        if edit_error is not None:
            return fail(edit_error, registered=True)
    return inspection


def inspect_codex_binding(root: Path, desired: str) -> BindingState:
    """Inspect the Plainweave command bound to the global Codex Legis entry."""
    inspection = _inspect_codex_binding(root, desired)
    try:
        return inspection.state
    finally:
        _close_root_fd(inspection)


def _newline_for(content: str) -> str:
    match = re.search(r"\r\n|\n|\r", content)
    return match.group(0) if match is not None else "\n"


def _append_before_table_end(
    content: str, table_end: int, addition: str, newline: str
) -> str:
    prefix = content[:table_end]
    if prefix and not prefix.endswith(("\r\n", "\n", "\r")):
        addition = newline + addition
    return prefix + addition + content[table_end:]


def _supported_target_assignment(
    content: str, span: tuple[int, int]
) -> re.Match[str] | None:
    start, end = span
    matches: list[re.Match[str]] = []
    for match in _TOML_TARGET_RE.finditer(content, start, end):
        try:
            tomllib.loads(content[: match.start()])
            parsed = tomllib.loads(match.group(0))
        except tomllib.TOMLDecodeError:
            continue
        if parsed == {PLAINWEAVE_ENV: parsed.get(PLAINWEAVE_ENV)} and isinstance(
            parsed.get(PLAINWEAVE_ENV), str
        ):
            matches.append(match)
    return matches[0] if len(matches) == 1 else None


def _codex_documents_match_except_target(
    before: dict[str, Any], after: dict[str, Any]
) -> bool:
    def normalized(document: dict[str, Any]) -> dict[str, Any]:
        result = copy.deepcopy(document)
        servers = result.get("mcp_servers")
        if not isinstance(servers, dict):
            return result
        entry = servers.get("legis")
        if not isinstance(entry, dict):
            return result
        env = entry.setdefault("env", {})
        if isinstance(env, dict):
            env.pop(PLAINWEAVE_ENV, None)
        return result

    return normalized(before) == normalized(after)


def _updated_codex_text(
    inspection: _BindingInspection, desired: str
) -> tuple[str | None, str | None]:
    text = inspection.text
    entry = inspection.entry
    env = inspection.env
    if text is None or entry is None or env is None:
        return None, "global Codex Plainweave binding snapshot is incomplete"

    parent_span = _toml_table_span(text, ("mcp_servers", "legis"))
    if parent_span is None:
        return None, "global Codex Legis MCP table has an unsupported shape"
    env_span = _toml_table_span(text, ("mcp_servers", "legis", "env"))
    if "env" in entry and env_span is None:
        return (
            None,
            "global Codex Legis MCP env uses an unsupported inline or dotted shape",
        )

    newline = _newline_for(text)
    rendered = json.dumps(desired)
    if env_span is None:
        block = (
            f"{newline}[mcp_servers.legis.env]{newline}"
            f"{PLAINWEAVE_ENV} = {rendered}{newline}"
        )
        return _append_before_table_end(text, parent_span[1], block, newline), None

    if PLAINWEAVE_ENV not in env:
        new_assignment = f"{PLAINWEAVE_ENV} = {rendered}{newline}"
        return _append_before_table_end(
            text, env_span[1], new_assignment, newline
        ), None

    existing_assignment = _supported_target_assignment(text, env_span)
    if existing_assignment is None:
        return (
            None,
            "global Codex Plainweave target assignment has an unsupported shape",
        )
    start, end = existing_assignment.span("value")
    return text[:start] + rendered + text[end:], None


def repair_codex_binding(root: Path, desired: str) -> str | None:
    """Bind Plainweave in an existing usable global Codex Legis MCP entry."""
    inspection = _inspect_codex_binding(root, desired)
    try:
        if inspection.state.current:
            return None
        if inspection.state.error is not None:
            return inspection.state.error
        if not inspection.state.registered:
            return _CODEX_NOT_CONFIGURED

        updated_text, error = _updated_codex_text(inspection, desired)
        if error is not None or updated_text is None:
            return error or "global Codex Plainweave binding could not be repaired"
        try:
            updated_data: Any = tomllib.loads(updated_text)
        except tomllib.TOMLDecodeError as exc:
            return f"updated Codex config.toml would be malformed: {exc}"
        if not isinstance(updated_data, dict):
            return "updated Codex config.toml would not be a table"
        updated_servers = updated_data.get("mcp_servers")
        updated_entry = (
            updated_servers.get("legis") if isinstance(updated_servers, dict) else None
        )
        updated_env = (
            updated_entry.get("env") if isinstance(updated_entry, dict) else None
        )
        if (
            not isinstance(updated_env, dict)
            or updated_env.get(PLAINWEAVE_ENV) != desired
        ):
            return "updated Codex config.toml did not contain the desired binding"
        data = inspection.data
        if data is None or not _codex_documents_match_except_target(data, updated_data):
            return "Codex binding semantic comparison refused an unrelated mutation"
        try:
            content = updated_text.encode("utf-8")
        except UnicodeError as exc:
            return f"could not encode updated Codex config.toml: {exc}"
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


def _resolve_plainweave_executable(command: object, root: Path) -> str | None:
    if not isinstance(command, str) or not command:
        return None
    if install._path_head_is_project_local(command, root):
        return None
    candidates: list[str] = []
    first = _resolve_executable(command)
    if first is not None:
        candidates.append(first)
    if "/" not in command and "\\" not in command:
        for entry in os.environ.get("PATH", "").split(os.pathsep):
            try:
                candidate = shutil.which(command, path=entry)
            except (OSError, UnicodeError):
                continue
            if candidate is not None and candidate not in candidates:
                candidates.append(candidate)

    for resolved in candidates:
        if install._path_head_is_project_local(resolved, root):
            continue
        try:
            resolved_path = Path(resolved).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if install._path_head_is_project_local(str(resolved_path), root):
            continue
        if resolved_path.name.lower() not in {
            "plainweave-mcp",
            "plainweave-mcp.exe",
        }:
            continue
        return str(resolved_path)
    return None


def _project_plainweave_argv(root: Path) -> tuple[list[str] | None, str | None]:
    config = root / ".mcp.json"
    if not config.exists():
        return None, None
    if config.is_symlink() or not config.is_file():
        return None, _MALFORMED_CONFIG

    try:
        data: Any = install._strict_json_loads(config.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeError, ValueError):
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

    executable = _resolve_plainweave_executable(entry.get("command"), root)
    args = entry.get("args")
    if executable is None or not isinstance(args, list):
        return None, _INVALID_ENTRY
    if not all(isinstance(arg, str) for arg in args):
        return None, _INVALID_ENTRY

    root_options: list[tuple[int, str, bool]] = []
    index = 0
    while index < len(args):
        arg = args[index]
        option = arg.partition("=")[0]
        if arg == "--root":
            if index + 1 >= len(args):
                return None, _INVALID_ENTRY
            root_options.append((index + 1, args[index + 1], False))
            index += 2
            continue
        if arg.startswith("--root="):
            value = arg.partition("=")[2]
            if not value:
                return None, _INVALID_ENTRY
            root_options.append((index, value, True))
        elif len(option) > 2 and "--root".startswith(option):
            return None, _INVALID_ENTRY
        index += 1

    if len(root_options) != 1:
        return None, _INVALID_ENTRY

    root_index, supplied_root, inline_root = root_options[0]
    root_value = Path(supplied_root)
    if not root_value.is_absolute():
        root_value = root / root_value
    try:
        if root_value.resolve() != root:
            return None, _INVALID_ENTRY
    except (OSError, RuntimeError):
        return None, _INVALID_ENTRY

    canonical_args = list(args)
    canonical_root = str(root)
    canonical_args[root_index] = (
        f"--root={canonical_root}" if inline_root else canonical_root
    )
    return [executable, *canonical_args], None


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
    fallback = _resolve_plainweave_executable("plainweave-mcp", resolved_root)

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
