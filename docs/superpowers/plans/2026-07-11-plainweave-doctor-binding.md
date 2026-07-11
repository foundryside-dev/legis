# Plainweave Doctor Binding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `legis doctor` detect and safely repair missing `PLAINWEAVE_MCP_CMD` wiring in project and existing Codex Legis MCP registrations for initialized Plainweave projects.

**Architecture:** Add a focused `legis.plainweave_binding` module that owns applicability, command discovery, project JSON mutation, and fail-closed Codex TOML mutation. Keep `legis.doctor` responsible for translating those results into two independent `DoctorCheck` records after the existing project registration check. Every repair is a nested-key update, never a registration replacement.

**Tech Stack:** Python 3.12+, stdlib (`dataclasses`, `json`, `os`, `pathlib`, `re`, `shlex`, `shutil`, `tomllib`), existing atomic writer and MCP safety predicates, pytest, ruff, mypy.

---

## File map

- Create `src/legis/plainweave_binding.py`: discovery plus project and Codex binding inspection/repair.
- Create `tests/test_plainweave_binding.py`: isolated unit and mutation tests using temporary roots and `CODEX_HOME`.
- Modify `src/legis/doctor.py`: two doctor adapters and check ordering.
- Modify `tests/test_doctor.py` and `tests/mcp/test_server.py`: doctor behavior and report-only invariants.
- Modify `README.md`, `docs/guide/configuration.md`, `docs/guide/cli-reference.md`, `docs/guide/reading-legis-output.md`, and `CHANGELOG.md`: operator behavior.

### Task 1: Discover an applicable, root-pinned Plainweave invocation

**Files:**
- Create: `src/legis/plainweave_binding.py`
- Create: `tests/test_plainweave_binding.py`

- [ ] **Step 1: Write failing discovery tests**

Create `tests/test_plainweave_binding.py` with executable helpers and four initial cases:

```python
from __future__ import annotations

import json
import shlex
from pathlib import Path

from legis.plainweave_binding import discover_plainweave


def _make_executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _initialize_plainweave(root: Path) -> None:
    store = root / ".plainweave" / "plainweave.db"
    store.parent.mkdir(parents=True)
    store.write_bytes(b"sqlite marker")


def _write_project_plainweave_entry(root: Path, executable: Path) -> None:
    (root / ".mcp.json").write_text(json.dumps({
        "mcpServers": {"plainweave": {
            "type": "stdio", "command": str(executable),
            "args": ["--root", str(root.resolve())], "env": {},
        }}
    }), encoding="utf-8")


def test_discovery_prefers_root_pinned_project_entry(tmp_path, monkeypatch):
    executable = _make_executable(tmp_path.parent / "tools" / "plainweave-mcp")
    _initialize_plainweave(tmp_path)
    _write_project_plainweave_entry(tmp_path, executable)
    monkeypatch.setattr(
        "legis.plainweave_binding.shutil.which",
        lambda name: str(executable) if name == str(executable) else None,
    )
    found = discover_plainweave(tmp_path)
    assert found.applicable is True
    assert found.installed is True
    assert found.error is None
    assert shlex.split(found.command or "") == [str(executable), "--root", str(tmp_path.resolve())]


def test_discovery_path_fallback_is_explicitly_root_pinned(tmp_path, monkeypatch):
    executable = _make_executable(tmp_path.parent / "tools" / "plainweave-mcp")
    _initialize_plainweave(tmp_path)
    monkeypatch.setattr("legis.plainweave_binding.shutil.which", lambda name: str(executable) if name == "plainweave-mcp" else None)
    found = discover_plainweave(tmp_path)
    assert shlex.split(found.command or "") == [str(executable), "--root", str(tmp_path.resolve())]


def test_discovery_does_not_recruit_installed_tool_for_uninitialized_project(tmp_path, monkeypatch):
    executable = _make_executable(tmp_path.parent / "tools" / "plainweave-mcp")
    monkeypatch.setattr("legis.plainweave_binding.shutil.which", lambda _name: str(executable))
    found = discover_plainweave(tmp_path)
    assert (found.applicable, found.installed, found.command, found.error) == (False, True, None, None)


def test_discovery_fails_closed_for_initialized_project_without_executable(tmp_path, monkeypatch):
    _initialize_plainweave(tmp_path)
    monkeypatch.setattr("legis.plainweave_binding.shutil.which", lambda _name: None)
    found = discover_plainweave(tmp_path)
    assert found.applicable is True
    assert found.installed is False
    assert found.command is None
    assert "no executable" in (found.error or "").lower()
```

- [ ] **Step 2: Run discovery tests and verify RED**

Run `uv run pytest -q tests/test_plainweave_binding.py`.

Expected: collection fails with `ModuleNotFoundError: No module named 'legis.plainweave_binding'`.

- [ ] **Step 3: Implement the minimal discovery model**

Create `src/legis/plainweave_binding.py`:

```python
from __future__ import annotations

import json
import os
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
    resolved = shutil.which(command)
    if resolved is None:
        candidate = Path(command)
        if not candidate.is_absolute() or not candidate.is_file():
            return None
        resolved = str(candidate)
    return resolved if os.access(resolved, os.X_OK) else None


def _project_plainweave_argv(root: Path) -> tuple[list[str] | None, bool]:
    path = root / ".mcp.json"
    if not path.is_file() or path.is_symlink():
        return None, False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None, False
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    entry = servers.get("plainweave") if isinstance(servers, dict) else None
    if not isinstance(entry, dict):
        return None, False
    command = _resolve_executable(entry.get("command"))
    args = entry.get("args", [])
    if command is None or not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        return None, True
    try:
        index = args.index("--root")
    except ValueError:
        return None, True
    if index + 1 >= len(args) or Path(args[index + 1]).resolve() != root:
        return None, True
    return [command, *args], True


def discover_plainweave(root: Path) -> PlainweaveDiscovery:
    root = root.resolve()
    database = root / ".plainweave" / "plainweave.db"
    database_present = database.is_file() and not database.is_symlink()
    project_argv, entry_present = _project_plainweave_argv(root)
    fallback = _resolve_executable(shutil.which("plainweave-mcp"))
    installed = project_argv is not None or fallback is not None
    applicable = database_present or project_argv is not None
    if not applicable:
        return PlainweaveDiscovery(False, installed)
    if project_argv is not None:
        return PlainweaveDiscovery(True, True, command=shlex.join(project_argv))
    if fallback is not None:
        return PlainweaveDiscovery(True, True, command=shlex.join([fallback, "--root", str(root)]))
    detail = "invalid project MCP entry and no executable found" if entry_present else "no executable found"
    return PlainweaveDiscovery(True, False, error=f"Plainweave project initialized but {detail}")
```

- [ ] **Step 4: Verify GREEN, add edge cases, and commit**

Add cases for a symlinked database, malformed `.mcp.json`, non-string args, missing/mismatched `--root`, a dead executable, and a path containing spaces. Then run:

```bash
uv run pytest -q tests/test_plainweave_binding.py
git add src/legis/plainweave_binding.py tests/test_plainweave_binding.py
git commit -m "feat(doctor): discover initialized Plainweave projects"
```

Expected: all tests pass; the first implementation commit contains only discovery and its tests.

### Task 2: Repair only the project Legis environment binding

**Files:**
- Modify: `src/legis/plainweave_binding.py`
- Modify: `tests/test_plainweave_binding.py`

- [ ] **Step 1: Write failing project-binding tests**

Add tests for missing/stale/current values, idempotence, and preservation:

```python
from legis.plainweave_binding import inspect_project_binding, repair_project_binding


def test_project_binding_repair_changes_only_plainweave_env(tmp_path):
    legis_entry = {
        "type": "stdio", "command": "/usr/bin/legis",
        "args": ["mcp", "--agent-id", "operator-choice"],
        "env": {"KEEP_ME": "yes"}, "timeout": 30,
    }
    original = {"mcpServers": {"legis": legis_entry, "filigree": {"command": "filigree-mcp"}}}
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps(original, indent=4) + "\n", encoding="utf-8")
    desired = "plainweave-mcp --root /repo"
    assert inspect_project_binding(tmp_path, desired).current is False
    assert repair_project_binding(tmp_path, desired) is None
    updated = json.loads(path.read_text(encoding="utf-8"))
    assert updated["mcpServers"]["legis"] == {
        **legis_entry,
        "env": {"KEEP_ME": "yes", "PLAINWEAVE_MCP_CMD": desired},
    }
    assert updated["mcpServers"]["filigree"] == original["mcpServers"]["filigree"]
    first = path.read_bytes()
    assert repair_project_binding(tmp_path, desired) is None
    assert path.read_bytes() == first
```

Add unchanged-byte failure cases for malformed JSON, symlinked `.mcp.json`, non-dict `mcpServers`, missing/non-dict Legis entries, non-dict env, and env values rejected by `_safe_mcp_env`.

- [ ] **Step 2: Run selected tests and verify RED**

Run `uv run pytest -q tests/test_plainweave_binding.py -k project_binding`.

Expected: import failure for the two new functions.

- [ ] **Step 3: Implement project inspection and repair**

Add the following API, using `legis.install.reject_symlink`, `_safe_mcp_env`, and `_atomic_write_text`:

```python
@dataclass(frozen=True, slots=True)
class BindingState:
    registered: bool
    current: bool
    error: str | None = None


def _read_project_config(root: Path) -> tuple[Path, dict[str, Any] | None, str | None]:
    from legis.install import reject_symlink
    path = root / ".mcp.json"
    try:
        reject_symlink(path)
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return path, None, f"cannot safely read {path}: {exc}"
    if not isinstance(parsed, dict):
        return path, None, f"{path} must contain a JSON object"
    return path, parsed, None


def inspect_project_binding(root: Path, desired: str) -> BindingState:
    from legis.install import _safe_mcp_env, mcp_entry_is_current
    if not mcp_entry_is_current(root):
        return BindingState(False, False, "project Legis MCP registration is missing or malformed")
    _path, data, error = _read_project_config(root.resolve())
    if data is None:
        return BindingState(False, False, error)
    servers = data.get("mcpServers")
    entry = servers.get("legis") if isinstance(servers, dict) else None
    if not isinstance(entry, dict):
        return BindingState(False, False, "project Legis MCP registration is missing or malformed")
    env = _safe_mcp_env(entry.get("env"))
    if env is None or env != entry.get("env", {}):
        return BindingState(True, False, "project Legis MCP environment is unsafe or malformed")
    return BindingState(True, env.get(PLAINWEAVE_ENV) == desired)


def repair_project_binding(root: Path, desired: str) -> str | None:
    from legis.install import _atomic_write_text, _safe_mcp_env
    path, data, error = _read_project_config(root.resolve())
    if data is None:
        return error
    servers = data.get("mcpServers")
    entry = servers.get("legis") if isinstance(servers, dict) else None
    if not isinstance(entry, dict):
        return "project Legis MCP registration is missing or malformed"
    env = _safe_mcp_env(entry.get("env"))
    if env is None or env != entry.get("env", {}):
        return "project Legis MCP environment is unsafe or malformed"
    if env.get(PLAINWEAVE_ENV) == desired:
        return None
    entry["env"] = {**env, PLAINWEAVE_ENV: desired}
    try:
        _atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError) as exc:
        return f"cannot update {path}: {exc}"
    return None
```

- [ ] **Step 4: Verify GREEN and commit**

```bash
uv run pytest -q tests/test_plainweave_binding.py
git add src/legis/plainweave_binding.py tests/test_plainweave_binding.py
git commit -m "feat(doctor): repair project Plainweave binding"
```

Expected: all binding tests pass; no unrelated project fields change.

### Task 3: Surgically repair the active Codex Legis environment table

**Files:**
- Modify: `src/legis/plainweave_binding.py`
- Modify: `tests/test_plainweave_binding.py`

- [ ] **Step 1: Write failing Codex binding tests**

Use `monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))`. Cover an existing env child table, no env child table, stale/current values, quoted headers, CRLF, idempotence, and preservation:

```python
from legis.plainweave_binding import inspect_codex_binding, repair_codex_binding


def test_codex_binding_repair_preserves_parent_siblings_comments_and_mode(tmp_path, monkeypatch):
    codex_home = tmp_path / "codex"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    path = codex_home / "config.toml"
    path.write_text(
        '# keep top\n[mcp_servers.legis]\ncommand = "/opt/legis"\n'
        'args = ["mcp", "--agent-id", "codex"]\ntimeout_sec = 30\n\n'
        '[mcp_servers.legis.env]\nKEEP_ME = "yes" # keep inline\n\n'
        '[mcp_servers.filigree]\ncommand = "filigree-mcp"\n',
        encoding="utf-8",
    )
    path.chmod(0o640)
    desired = "plainweave-mcp --root /repo"
    assert repair_codex_binding(tmp_path, desired) is None
    content = path.read_text(encoding="utf-8")
    assert '# keep top' in content
    assert 'timeout_sec = 30' in content
    assert 'KEEP_ME = "yes" # keep inline' in content
    assert '[mcp_servers.filigree]' in content
    assert 'PLAINWEAVE_MCP_CMD = "plainweave-mcp --root /repo"' in content
    assert path.stat().st_mode & 0o777 == 0o640
    assert inspect_codex_binding(tmp_path, desired).current is True


def test_codex_binding_absent_legis_registration_is_not_created(tmp_path, monkeypatch):
    codex_home = tmp_path / "codex"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    path = codex_home / "config.toml"
    path.write_text('[mcp_servers.filigree]\ncommand = "filigree-mcp"\n', encoding="utf-8")
    before = path.read_bytes()
    state = inspect_codex_binding(tmp_path, "plainweave-mcp --root /repo")
    error = repair_codex_binding(tmp_path, "plainweave-mcp --root /repo")
    assert state.registered is False
    assert error == "global Codex Legis MCP registration is not configured"
    assert path.read_bytes() == before
```

Add unchanged-byte cases for malformed TOML, symlinked config, inline `legis = {...}`, inline `env = {...}`, dotted env assignments, duplicate assignments, and multiline target strings.

- [ ] **Step 2: Run selected tests and verify RED**

Run `uv run pytest -q tests/test_plainweave_binding.py -k codex_binding`.

Expected: import failure for the new Codex functions.

- [ ] **Step 3: Add a fail-closed TOML table scanner**

Add stdlib-only helpers:

```python
import re
import tomllib

_TOML_HEADER_RE = re.compile(
    r"(?m)^[ \t]*\[([^\r\n\]]+)\][ \t]*(?:#[^\r\n]*)?(?:\r\n|\n|\r|\Z)"
)


def _codex_config_path() -> Path:
    home = os.environ.get("CODEX_HOME")
    return Path(home).expanduser() / "config.toml" if home else Path.home() / ".codex" / "config.toml"


def _parse_header_path(inner: str) -> tuple[str, ...] | None:
    try:
        parsed: Any = tomllib.loads(f"[{inner}]\n")
    except tomllib.TOMLDecodeError:
        return None
    result: list[str] = []
    while isinstance(parsed, dict) and len(parsed) == 1:
        key, parsed = next(iter(parsed.items()))
        result.append(key)
    return tuple(result) if isinstance(parsed, dict) and not parsed else None


def _table_span(content: str, target: tuple[str, ...]) -> tuple[int, int] | None:
    headers: list[tuple[int, tuple[str, ...]]] = []
    for match in _TOML_HEADER_RE.finditer(content):
        path = _parse_header_path(match.group(1))
        if path is not None:
            headers.append((match.start(), path))
    for index, (start, path) in enumerate(headers):
        if path == target:
            end = headers[index + 1][0] if index + 1 < len(headers) else len(content)
            return start, end
    return None


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
```

Parse the complete TOML document before trusting header spans. Require an explicit `("mcp_servers", "legis")` parent span; a parsed Legis table without that span is an unsupported inline/dotted shape.

- [ ] **Step 4: Implement inspection**

```python
def inspect_codex_binding(root: Path, desired: str) -> BindingState:
    path = _codex_config_path()
    if not path.is_file():
        return BindingState(False, False)
    if path.is_symlink():
        return BindingState(False, False, f"{path} is a symlink; refusing Codex config repair")
    try:
        content = path.read_text(encoding="utf-8")
        parsed = tomllib.loads(content)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return BindingState(False, False, f"cannot safely read {path}: {exc}")
    servers = parsed.get("mcp_servers")
    entry = servers.get("legis") if isinstance(servers, dict) else None
    if entry is None:
        return BindingState(False, False)
    if not isinstance(entry, dict) or _table_span(content, ("mcp_servers", "legis")) is None:
        return BindingState(True, False, "global Codex Legis MCP registration has an unsupported shape")
    from legis.install import _mcp_args_are_current, _mcp_command_resolves_safely
    if not _mcp_args_are_current(entry.get("args")) or not _mcp_command_resolves_safely(
        entry.get("command"), root.resolve(), entry.get("args")
    ):
        return BindingState(True, False, "global Codex Legis MCP registration is not usable")
    env = entry.get("env", {})
    if not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items()):
        return BindingState(True, False, "global Codex Legis MCP environment is malformed")
    return BindingState(True, env.get(PLAINWEAVE_ENV) == desired)
```

- [ ] **Step 5: Implement assignment-level repair**

Add `import copy` and this single-line assignment pattern. It accepts only TOML strings and preserves indentation, trailing comments, and newline style:

```python
_TARGET_ASSIGNMENT_RE = re.compile(
    rf"(?m)^(?P<indent>[ \t]*){PLAINWEAVE_ENV}[ \t]*=[ \t]*"
    r"(?P<value>\"(?:[^\"\\]|\\.)*\"|'[^']*')"
    r"(?P<suffix>[ \t]*(?:#[^\r\n]*)?)(?P<newline>\r\n|\n|\r|\Z)"
)


def _without_plainweave_env(data: dict[str, Any]) -> dict[str, Any]:
    cloned = copy.deepcopy(data)
    servers = cloned.get("mcp_servers")
    legis = servers.get("legis") if isinstance(servers, dict) else None
    env = legis.get("env") if isinstance(legis, dict) else None
    if isinstance(env, dict):
        env.pop(PLAINWEAVE_ENV, None)
    return cloned
```

Implement the repair with an explicit pre-write semantic comparison:

```python
def repair_codex_binding(root: Path, desired: str) -> str | None:
    from legis.install import _atomic_write_text

    state = inspect_codex_binding(root, desired)
    if state.current:
        return None
    if not state.registered:
        return state.error or "global Codex Legis MCP registration is not configured"
    if state.error:
        return state.error

    path = _codex_config_path()
    try:
        content = path.read_text(encoding="utf-8")
        before = tomllib.loads(content)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return f"cannot safely read {path}: {exc}"

    parent_span = _table_span(content, ("mcp_servers", "legis"))
    if parent_span is None:
        return "global Codex Legis MCP registration has an unsupported shape"
    servers = before.get("mcp_servers")
    legis = servers.get("legis") if isinstance(servers, dict) else None
    env = legis.get("env") if isinstance(legis, dict) else None
    env_span = _table_span(content, ("mcp_servers", "legis", "env"))
    if env is not None and env_span is None:
        return "global Codex Legis MCP environment has an unsupported inline or dotted shape"

    newline_match = re.search(r"\r\n|\n|\r", content)
    newline = newline_match.group(0) if newline_match else "\n"
    rendered = _toml_string(desired)
    if env_span is None:
        parent_end = parent_span[1]
        block = (
            f"{newline}[mcp_servers.legis.env]{newline}"
            f"{PLAINWEAVE_ENV} = {rendered}{newline}"
        )
        updated = content[:parent_end] + block + content[parent_end:]
    else:
        env_start, env_end = env_span
        env_text = content[env_start:env_end]
        matches = list(_TARGET_ASSIGNMENT_RE.finditer(env_text))
        if len(matches) > 1:
            return f"global Codex Legis MCP environment defines {PLAINWEAVE_ENV} more than once"
        if not matches:
            if isinstance(env, dict) and PLAINWEAVE_ENV in env:
                return f"global Codex {PLAINWEAVE_ENV} assignment has an unsupported shape"
            separator = "" if env_text.endswith(("\r\n", "\n", "\r")) else newline
            insertion = f"{separator}{PLAINWEAVE_ENV} = {rendered}{newline}"
            updated = content[:env_end] + insertion + content[env_end:]
        else:
            match = matches[0]
            replacement = (
                f"{match.group('indent')}{PLAINWEAVE_ENV} = {rendered}"
                f"{match.group('suffix')}{match.group('newline')}"
            )
            absolute_start = env_start + match.start()
            absolute_end = env_start + match.end()
            updated = content[:absolute_start] + replacement + content[absolute_end:]

    try:
        after = tomllib.loads(updated)
    except tomllib.TOMLDecodeError as exc:
        return f"refusing invalid Codex config update: {exc}"
    after_servers = after.get("mcp_servers")
    after_legis = after_servers.get("legis") if isinstance(after_servers, dict) else None
    after_env = after_legis.get("env") if isinstance(after_legis, dict) else None
    if not isinstance(after_env, dict) or after_env.get(PLAINWEAVE_ENV) != desired:
        return "refusing Codex config update that did not persist the Plainweave binding"
    if _without_plainweave_env(before) != _without_plainweave_env(after):
        return "refusing Codex config update that changes unrelated configuration"
    try:
        _atomic_write_text(path, updated)
    except (OSError, ValueError) as exc:
        return f"cannot update {path}: {exc}"
    return None
```

- [ ] **Step 6: Verify GREEN and commit**

```bash
uv run pytest -q tests/test_plainweave_binding.py
uv run ruff check src/legis/plainweave_binding.py tests/test_plainweave_binding.py
uv run mypy src/legis/plainweave_binding.py
git add src/legis/plainweave_binding.py tests/test_plainweave_binding.py
git commit -m "feat(doctor): repair Codex Plainweave binding"
```

Expected: tests, lint, and types pass; unsupported TOML remains byte-identical.

### Task 4: Expose two honest doctor checks and keep MCP report-only

**Files:**
- Modify: `src/legis/doctor.py:117-137,966-995`
- Modify: `tests/test_doctor.py:224-244,247-296,891-903`
- Modify: `tests/mcp/test_server.py:3151-3183`

- [ ] **Step 1: Write failing doctor tests**

Arrange `.plainweave/plainweave.db`, a root-pinned Plainweave project entry, project Legis entry, and temporary `CODEX_HOME` with an existing global Legis entry. Assert:

```python
def test_plainweave_bindings_are_independently_auto_fixable(tmp_path, monkeypatch):
    project = check_plainweave_project_binding(tmp_path, repair=False)
    codex = check_plainweave_codex_binding(tmp_path, repair=False)
    assert (project.id, project.status, project.repairable) == (
        "install.plainweave_project_binding", "error", True
    )
    assert (codex.id, codex.status, codex.repairable) == (
        "install.plainweave_codex_binding", "error", True
    )


def test_plainweave_binding_fix_repairs_both_and_requests_reconnect(tmp_path, monkeypatch):
    project = check_plainweave_project_binding(tmp_path, repair=True)
    codex = check_plainweave_codex_binding(tmp_path, repair=True)
    assert project.status == codex.status == "ok"
    assert project.fixed is codex.fixed is True
    assert "reconnect" in (project.message or "").lower()
    assert "reconnect" in (codex.message or "").lower()
```

Add cases for uninitialized-but-installed, initialized-without-executable, absent global registration, malformed config, and idempotent second repair.

- [ ] **Step 2: Run selected tests and verify RED**

Run `uv run pytest -q tests/test_doctor.py -k plainweave_binding`.

Expected: import failure for the new doctor checks.

- [ ] **Step 3: Implement the project DoctorCheck adapter**

Add after `check_mcp_json`:

```python
def _plainweave_not_applicable_message(installed: bool) -> str:
    return "Plainweave installed, project not initialized" if installed else "Plainweave not configured for this project"


def check_plainweave_project_binding(root: Path, *, repair: bool) -> DoctorCheck:
    from legis.plainweave_binding import discover_plainweave, inspect_project_binding, repair_project_binding
    cid = "install.plainweave_project_binding"
    found = discover_plainweave(root)
    if not found.applicable:
        return DoctorCheck(cid, "ok", message=_plainweave_not_applicable_message(found.installed))
    if found.command is None:
        return DoctorCheck(cid, "error", message=found.error or "Plainweave executable unavailable")
    state = inspect_project_binding(root, found.command)
    if state.current:
        return DoctorCheck(cid, "ok", repairable=True)
    if state.error and state.registered:
        return DoctorCheck(cid, "error", message=state.error)
    if repair:
        error = repair_project_binding(root, found.command)
        if error is None and inspect_project_binding(root, found.command).current:
            return DoctorCheck(cid, "ok", fixed=True, message="Plainweave project binding repaired; reconnect MCP clients", repairable=True)
        return DoctorCheck(cid, "error", message=error or "project binding repair did not persist", repairable=True)
    return DoctorCheck(cid, "error", message=state.error or "Legis project MCP entry does not pass PLAINWEAVE_MCP_CMD", repairable=True)
```

- [ ] **Step 4: Implement the Codex DoctorCheck adapter and ordering**

```python
def check_plainweave_codex_binding(root: Path, *, repair: bool) -> DoctorCheck:
    from legis.plainweave_binding import discover_plainweave, inspect_codex_binding, repair_codex_binding
    cid = "install.plainweave_codex_binding"
    found = discover_plainweave(root)
    if not found.applicable:
        return DoctorCheck(cid, "ok", message=_plainweave_not_applicable_message(found.installed))
    if found.command is None:
        return DoctorCheck(cid, "error", message=found.error or "Plainweave executable unavailable")
    state = inspect_codex_binding(root, found.command)
    if not state.registered and state.error is None:
        return DoctorCheck(cid, "ok", message="global Codex Legis MCP registration not configured")
    if state.current:
        return DoctorCheck(cid, "ok", repairable=True)
    if state.error:
        return DoctorCheck(cid, "error", message=state.error)
    if repair:
        error = repair_codex_binding(root, found.command)
        if error is None and inspect_codex_binding(root, found.command).current:
            return DoctorCheck(cid, "ok", fixed=True, message="Plainweave Codex binding repaired; reconnect MCP clients", repairable=True)
        return DoctorCheck(cid, "error", message=error or "Codex binding repair did not persist", repairable=True)
    return DoctorCheck(cid, "error", message="Codex Legis MCP entry does not pass PLAINWEAVE_MCP_CMD", repairable=True)
```

Append both immediately after `check_mcp_json` in `collect_checks` so a repair pass creates/repairs the project Legis entry before binding it.

- [ ] **Step 5: Update aggregate and MCP report-only tests**

Keep the exact repairable-ID set unchanged for a bare uninitialized project. Add an initialized-project assertion where both new IDs are repairable. In `test_doctor_get_is_report_only_and_never_repairs`, snapshot project JSON and temporary Codex TOML bytes, call `doctor_get`, assert both IDs are present with `fixed=False`, and assert both files remain byte-identical.

- [ ] **Step 6: Verify GREEN and commit**

```bash
uv run pytest -q tests/test_doctor.py tests/mcp/test_server.py -k 'doctor or plainweave_binding'
git add src/legis/doctor.py tests/test_doctor.py tests/mcp/test_server.py
git commit -m "feat(doctor): check Plainweave launch bindings"
```

Expected: focused doctor/MCP tests pass and MCP performs no repair writes.

### Task 5: Document detection, repair scope, and reconnection

**Files:**
- Modify: `README.md:11-15`
- Modify: `docs/guide/configuration.md:187-210`
- Modify: `docs/guide/cli-reference.md:215-240`
- Modify: `docs/guide/reading-legis-output.md:168-180`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Update operator documentation**

Add this contract consistently across the five files:

```markdown
When the current project has `.plainweave/plainweave.db` (or a valid root-pinned
Plainweave project MCP entry), `legis doctor` checks that both the project Legis
entry and any existing global Codex Legis entry pass `PLAINWEAVE_MCP_CMD`.
`legis doctor --fix` repairs only that nested environment value. It does not
initialize Plainweave or create a missing global Legis registration, and MCP
clients must reconnect before the repaired binding takes effect.
```

Name `install.plainweave_project_binding` and `install.plainweave_codex_binding` in the configuration and output guides. Explain `[auto-fixable]`, `[operator]`, and `[fixed]`. Add one bullet under the current changelog's unreleased section.

- [ ] **Step 2: Validate documentation references**

```bash
rg -n "plainweave_(project|codex)_binding|PLAINWEAVE_MCP_CMD|reconnect" \
  README.md CHANGELOG.md docs/guide/configuration.md \
  docs/guide/cli-reference.md docs/guide/reading-legis-output.md
git diff --check
```

Expected: both check IDs and the reconnection requirement are present; whitespace check exits 0.

- [ ] **Step 3: Commit documentation**

```bash
git add README.md CHANGELOG.md docs/guide/configuration.md docs/guide/cli-reference.md docs/guide/reading-legis-output.md
git commit -m "docs: explain Plainweave doctor binding repair"
```

### Task 6: Run complete verification and isolated symptom proof

**Files:**
- Verify all files changed in Tasks 1-5

- [ ] **Step 1: Run formatting and lint**

```bash
uv run python scripts/check_changed_format.py --base 9c372d6
uv run ruff check src
```

Expected: every Python file changed by this plan exits the format check cleanly,
and source lint exits 0. The repository-wide Ruff format baseline is not clean
and predates this feature; CI does not currently enforce whole-tree formatting.
Do not turn that unrelated baseline into either a false completion failure or a
bulk formatting rewrite inside this plan. The helper compares the plan commit
directly with the current working tree, adds untracked Python files, and filters
out deleted paths before invoking Ruff, so staged/unstaged review remediation is
included without pinning a stale count or false-failing on a later deletion.

- [ ] **Step 2: Run type checking**

Run `uv run mypy src/legis`.

Expected: exit 0 with no type errors.

- [ ] **Step 3: Run full tests and coverage gates**

```bash
uv run pytest --cov=legis --cov-report=term-missing --cov-report=json --cov-fail-under=88
uv run python scripts/check_coverage_floors.py
```

Expected: all tests pass, total coverage is at least 88%, and every per-package floor holds. If measured coverage justifies a dedicated floor for `plainweave_binding.py`, add the module to `scripts/check_coverage_floors.py` at a passing percentage and rerun both commands.

- [ ] **Step 4: Run repository conformance gates**

```bash
uv run pytest tests/conformance/test_sei_oracle.py
uv run legis policy-boundary-check --root src --repo-root .
```

Expected: SEI oracle passes; policy-boundary check prints `PASS` and exits 0.

- [ ] **Step 5: Prove the original symptom only in temporary configurations**

Do not run `--fix` against the real home config. Create a temporary initialized project with root-pinned Plainweave and Legis entries plus a temporary `CODEX_HOME/config.toml` containing an existing Legis entry. Run:

```bash
CODEX_HOME="$tmp_codex_home" uv run legis doctor --root "$tmp_project" --format json
CODEX_HOME="$tmp_codex_home" uv run legis doctor --root "$tmp_project" --fix --format json
CODEX_HOME="$tmp_codex_home" uv run legis doctor --root "$tmp_project" --format json
```

Expected: first run reports both binding IDs as auto-fixable errors; fix run reports both fixed and requests reconnection; final run reports both `ok` without rewriting either file.

- [ ] **Step 6: Review diff and repository state**

```bash
git diff --check aa06f5d..HEAD
git status --short
git log -6 --oneline --decorate
```

Expected: no whitespace errors, no unintended files, and the design, plan, and five implementation/documentation commits are visible.

- [ ] **Step 7: Request review before integration**

Invoke `superpowers:requesting-code-review`. Address validated findings with `superpowers:receiving-code-review`, then rerun Steps 1-5 before claiming completion.
