from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
import threading
import tomllib
from contextlib import contextmanager
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


def _codex_home(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path / "codex home"
    home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(home))
    return home


def _codex_config(
    tmp_path: Path,
    monkeypatch,
    *,
    env: str = '[mcp_servers.legis.env]\nKEEP_ME = "operator" # KEEP_ME\n',
    cwd: str | None = None,
    quoted: bool = False,
    newline: str = "\n",
) -> Path:
    home = _codex_home(tmp_path, monkeypatch)
    parent = '[mcp_servers."legis"]' if quoted else "[mcp_servers.legis]"
    if quoted:
        env = env.replace("[mcp_servers.legis.env]", '[mcp_servers."legis"."env"]')
    cwd_assignment = f"cwd = {json.dumps(cwd)}\n" if cwd is not None else ""
    content = (
        "# operator top comment\n"
        f"{parent}\n"
        f"command = {json.dumps(sys.executable)}\n"
        'args = ["-P", "-m", "legis", "mcp", "--agent-id", "operator"]\n'
        f"{cwd_assignment}"
        "startup_timeout_sec = 17\n"
        f"{env}"
        "\n[mcp_servers.sibling]\n"
        'command = "sibling-mcp"\n'
        'args = ["serve"]\n'
    ).replace("\n", newline)
    config = home / "config.toml"
    config.write_bytes(content.encode())
    return config


def test_codex_missing_stale_and_current_binding(tmp_path: Path, monkeypatch) -> None:
    config = _codex_config(tmp_path, monkeypatch)
    root = tmp_path / "project"
    root.mkdir()

    missing = plainweave_binding.inspect_codex_binding(root, "desired")
    assert missing == plainweave_binding.BindingState(True, False, None)

    assert plainweave_binding.repair_codex_binding(root, "desired") is None
    stale = plainweave_binding.inspect_codex_binding(root, "other")
    current = plainweave_binding.inspect_codex_binding(root, "desired")
    assert stale == plainweave_binding.BindingState(True, False, None)
    assert current == plainweave_binding.BindingState(True, True, None)
    assert (
        tomllib.loads(config.read_text())["mcp_servers"]["legis"]["env"][PLAINWEAVE_ENV]
        == "desired"
    )


def test_deeply_nested_codex_config_fails_closed_without_crashing(
    tmp_path: Path, monkeypatch
) -> None:
    home = _codex_home(tmp_path, monkeypatch)
    # A sub-1-MiB but pathologically nested value makes tomllib recurse past the
    # interpreter limit; doctor must fail closed, not crash with RecursionError.
    (home / "config.toml").write_bytes(
        ("probe = " + "[" * 5000 + "]" * 5000 + "\n").encode()
    )
    root = tmp_path / "project"
    root.mkdir()

    state = plainweave_binding.inspect_codex_binding(root, "desired")

    assert state.registered is False
    assert state.current is False
    assert state.error is not None
    assert "nesting" in state.error


def test_codex_repair_is_surgical_mode_preserving_and_idempotent(
    tmp_path: Path, monkeypatch
) -> None:
    config = _codex_config(
        tmp_path,
        monkeypatch,
        env=(
            '[mcp_servers.legis.env]\nKEEP_ME = "operator" # KEEP_ME\n'
            f'{PLAINWEAVE_ENV} = "stale" # target comment\n'
        ),
        cwd="/operator/workspace",
    )
    config.chmod(0o640)
    root = tmp_path / "project"
    root.mkdir()
    desired = 'plainweave --root "a path" \\server\\share'

    assert plainweave_binding.repair_codex_binding(root, desired) is None
    first = config.read_bytes()
    assert plainweave_binding.repair_codex_binding(root, desired) is None

    text = first.decode()
    assert config.read_bytes() == first
    assert config.stat().st_mode & 0o777 == 0o640
    assert text.startswith("# operator top comment\n")
    assert 'KEEP_ME = "operator" # KEEP_ME' in text
    assert "# target comment" in text
    parsed = tomllib.loads(text)
    assert parsed["mcp_servers"]["legis"] == {
        "command": sys.executable,
        "args": ["-P", "-m", "legis", "mcp", "--agent-id", "operator"],
        "cwd": "/operator/workspace",
        "startup_timeout_sec": 17,
        "env": {"KEEP_ME": "operator", PLAINWEAVE_ENV: desired},
    }
    assert parsed["mcp_servers"]["sibling"] == {
        "command": "sibling-mcp",
        "args": ["serve"],
    }


def test_codex_autodiscovery_repair_removes_legacy_binding_surgically(
    tmp_path: Path, monkeypatch
) -> None:
    target_line = f'{PLAINWEAVE_ENV} = "stale" # remove this whole line\n'
    config = _codex_config(
        tmp_path,
        monkeypatch,
        env=(f'[mcp_servers.legis.env]\nKEEP_ME = "operator" # KEEP_ME\n{target_line}'),
    )
    config.chmod(0o640)
    before = config.read_bytes()
    root = tmp_path / "project"
    root.mkdir()

    assert plainweave_binding.inspect_codex_binding(root, None) == (
        plainweave_binding.BindingState(True, False, None)
    )
    assert plainweave_binding.repair_codex_binding(root, None) is None

    first = config.read_bytes()
    assert first == before.replace(target_line.encode(), b"")
    assert config.stat().st_mode & 0o777 == 0o640
    assert plainweave_binding.inspect_codex_binding(root, None) == (
        plainweave_binding.BindingState(True, True, None)
    )

    assert plainweave_binding.repair_codex_binding(root, None) is None
    assert config.read_bytes() == first


def test_codex_autodiscovery_updated_text_is_unchanged_when_key_is_absent(
    tmp_path: Path, monkeypatch
) -> None:
    config = _codex_config(tmp_path, monkeypatch)
    root = tmp_path / "project"
    root.mkdir()
    inspection = plainweave_binding._inspect_codex_binding(root, None)

    try:
        updated_text, error = plainweave_binding._updated_codex_text(inspection, None)

        assert error is None
        assert updated_text == inspection.text == config.read_text()
    finally:
        plainweave_binding._close_root_fd(inspection)


def test_codex_autodiscovery_reports_fixed_cwd_as_project_bound(
    tmp_path: Path, monkeypatch
) -> None:
    _codex_config(tmp_path, monkeypatch, cwd="/operator/workspace")
    root = tmp_path / "project"
    root.mkdir()

    assert plainweave_binding.inspect_codex_binding(root, None) == (
        plainweave_binding.BindingState(
            registered=True,
            current=True,
            error=None,
            project_bound=True,
        )
    )


def test_codex_autodiscovery_remove_only_preserves_fixed_cwd_exactly(
    tmp_path: Path, monkeypatch
) -> None:
    target_line = f'{PLAINWEAVE_ENV} = "stale" # remove only this line\n'
    config = _codex_config(
        tmp_path,
        monkeypatch,
        env=(f'[mcp_servers.legis.env]\nKEEP_ME = "operator" # KEEP_ME\n{target_line}'),
        cwd="/operator/workspace with spaces",
    )
    before = config.read_bytes()
    root = tmp_path / "project"
    root.mkdir()

    assert plainweave_binding.inspect_codex_binding(root, None).project_bound is True
    assert plainweave_binding.repair_codex_binding(root, None) is None

    after = config.read_bytes()
    assert after == before.replace(target_line.encode(), b"")
    assert tomllib.loads(after.decode())["mcp_servers"]["legis"]["cwd"] == (
        "/operator/workspace with spaces"
    )


def test_current_codex_binding_does_not_write(tmp_path: Path, monkeypatch) -> None:
    desired = "plainweave --root /current"
    _codex_config(
        tmp_path,
        monkeypatch,
        env=f"[mcp_servers.legis.env]\n{PLAINWEAVE_ENV} = {json.dumps(desired)}\n",
    )
    root = tmp_path / "project"
    root.mkdir()

    def unexpected_replace(*_args, **_kwargs) -> None:
        pytest.fail("current Codex binding must not be rewritten")

    monkeypatch.setattr(plainweave_binding, "_anchored_replace", unexpected_replace)
    assert plainweave_binding.repair_codex_binding(root, desired) is None


@pytest.mark.parametrize("quoted", [False, True], ids=["bare", "quoted"])
def test_codex_repair_creates_missing_env_child_and_supports_quoted_headers(
    tmp_path: Path, monkeypatch, quoted: bool
) -> None:
    config = _codex_config(tmp_path, monkeypatch, env="", quoted=quoted)
    root = tmp_path / "project"
    root.mkdir()

    assert plainweave_binding.repair_codex_binding(root, "desired") is None

    parsed = tomllib.loads(config.read_text())
    assert parsed["mcp_servers"]["legis"]["env"] == {PLAINWEAVE_ENV: "desired"}
    assert parsed["mcp_servers"]["sibling"]["command"] == "sibling-mcp"


def test_codex_repair_preserves_crlf(tmp_path: Path, monkeypatch) -> None:
    config = _codex_config(tmp_path, monkeypatch, newline="\r\n")
    root = tmp_path / "project"
    root.mkdir()

    assert plainweave_binding.repair_codex_binding(root, "desired") is None

    content = config.read_bytes()
    assert b"\r\n" in content
    assert content.replace(b"\r\n", b"").find(b"\n") == -1


@pytest.mark.parametrize("with_config", [False, True], ids=["config", "legis-table"])
def test_absent_codex_config_or_legis_table_is_never_created(
    tmp_path: Path, monkeypatch, with_config: bool
) -> None:
    home = _codex_home(tmp_path, monkeypatch)
    config = home / "config.toml"
    if with_config:
        config.write_text('[mcp_servers.sibling]\ncommand = "sibling"\n')
    before = config.read_bytes() if config.exists() else None
    root = tmp_path / "project"
    root.mkdir()

    state = plainweave_binding.inspect_codex_binding(root, "desired")
    error = plainweave_binding.repair_codex_binding(root, "desired")

    assert state == plainweave_binding.BindingState(False, False, None)
    assert error == "global Codex Legis MCP registration is not configured"
    assert (config.read_bytes() if config.exists() else None) == before


def test_empty_codex_home_uses_home_config_not_cwd_config(
    tmp_path: Path, monkeypatch
) -> None:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    cwd_config = cwd / "config.toml"
    cwd_config.write_text('[mcp_servers.unrelated]\ncommand = "leave-me-alone"\n')
    cwd_before = cwd_config.read_bytes()

    home = tmp_path / "home"
    codex_home = home / ".codex"
    codex_home.mkdir(parents=True)
    home_config = codex_home / "config.toml"
    home_config.write_text(
        f"[mcp_servers.legis]\ncommand = {json.dumps(sys.executable)}\n"
        'args = ["-P", "-m", "legis", "mcp", "--agent-id", "operator"]\n'
        '[mcp_servers.legis.env]\nKEEP_ME = "operator"\n'
    )
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CODEX_HOME", "")
    root = tmp_path / "project"
    root.mkdir()

    assert plainweave_binding.inspect_codex_binding(root, "desired") == (
        plainweave_binding.BindingState(True, False, None)
    )
    assert plainweave_binding.repair_codex_binding(root, "desired") is None

    assert cwd_config.read_bytes() == cwd_before
    parsed = tomllib.loads(home_config.read_text())
    assert parsed["mcp_servers"]["legis"]["env"] == {
        "KEEP_ME": "operator",
        PLAINWEAVE_ENV: "desired",
    }


@pytest.mark.parametrize(
    "conflict",
    [
        'url = "https://example.invalid/mcp"',
        'auth = "oauth"',
        'auth_mode = "oauth"',
        'bearer_token_env_var = "TOKEN"',
        'http_headers = { Authorization = "Bearer token" }',
        'env_http_headers = { Authorization = "TOKEN" }',
        'oauth = { client_id = "client" }',
        'oauth_client_id = "client"',
        'oauth_resource = "https://example.invalid/"',
        'scopes = ["tools.read"]',
    ],
    ids=[
        "url",
        "auth",
        "auth-mode",
        "bearer-token",
        "headers",
        "env-headers",
        "oauth-inline",
        "oauth-client",
        "oauth-resource",
        "scopes",
    ],
)
def test_codex_stdio_legis_rejects_http_transport_fields(
    tmp_path: Path, monkeypatch, conflict: str
) -> None:
    config = _codex_config(tmp_path, monkeypatch)
    config.write_text(
        config.read_text().replace(
            "[mcp_servers.legis.env]",
            f"{conflict}\n[mcp_servers.legis.env]",
        )
    )
    before = config.read_bytes()
    root = tmp_path / "project"
    root.mkdir()

    state = plainweave_binding.inspect_codex_binding(root, "desired")
    error = plainweave_binding.repair_codex_binding(root, "desired")

    assert state.registered is True
    assert state.current is False
    assert state.error and "transport" in state.error.lower()
    assert error and "transport" in error.lower()
    assert config.read_bytes() == before


def test_codex_stdio_legis_rejects_explicit_oauth_transport_child(
    tmp_path: Path, monkeypatch
) -> None:
    config = _codex_config(tmp_path, monkeypatch)
    config.write_text(
        config.read_text().replace(
            "[mcp_servers.legis.env]",
            (
                '[mcp_servers.legis.oauth]\nclient_id = "client"\n'
                "[mcp_servers.legis.env]"
            ),
        )
    )
    before = config.read_bytes()
    root = tmp_path / "project"
    root.mkdir()

    state = plainweave_binding.inspect_codex_binding(root, "desired")
    error = plainweave_binding.repair_codex_binding(root, "desired")

    assert state.registered is True
    assert state.current is False
    assert state.error and "transport" in state.error.lower()
    assert error and "transport" in error.lower()
    assert config.read_bytes() == before


def test_codex_stdio_legis_allows_stdio_specific_and_shared_fields(
    tmp_path: Path, monkeypatch
) -> None:
    config = _codex_config(tmp_path, monkeypatch)
    config.write_text(
        config.read_text().replace(
            "startup_timeout_sec = 17",
            (
                "startup_timeout_sec = 17\n"
                "tool_timeout_sec = 60\n"
                "enabled = true\n"
                "required = true\n"
                'env_vars = ["PATH"]\n'
                'enabled_tools = ["policy_check"]\n'
                'disabled_tools = ["unsafe_tool"]'
            ),
        )
    )
    root = tmp_path / "project"
    root.mkdir()

    assert plainweave_binding.inspect_codex_binding(root, "desired") == (
        plainweave_binding.BindingState(True, False, None)
    )
    assert plainweave_binding.repair_codex_binding(root, "desired") is None

    parsed = tomllib.loads(config.read_text())
    entry = parsed["mcp_servers"]["legis"]
    assert entry["env_vars"] == ["PATH"]
    assert entry["enabled_tools"] == ["policy_check"]
    assert entry["disabled_tools"] == ["unsafe_tool"]


@pytest.mark.parametrize(
    "content",
    [
        "not = [valid TOML",
        'mcp_servers = "not a table"\n',
        'mcp_servers = { legis = { command = "x", args = [] } }\n',
        (
            '[mcp_servers.legis]\ncommand = "x"\n'
            'args = ["mcp", "--agent-id", "a"]\n'
            'env = { PLAINWEAVE_MCP_CMD = "stale" }\n'
        ),
        (
            '[mcp_servers.legis]\ncommand = "x"\n'
            'args = ["mcp", "--agent-id", "a"]\n'
            'env.PLAINWEAVE_MCP_CMD = "stale"\n'
        ),
        (
            f"[mcp_servers.legis]\ncommand = {json.dumps(sys.executable)}\n"
            'args = ["-P", "-m", "legis", "mcp", "--agent-id", "a"]\n'
            '[mcp_servers.legis.env]\n"PLAINWEAVE_MCP_CMD" = "stale"\n'
        ),
        (
            f"[mcp_servers.legis]\ncommand = {json.dumps(sys.executable)}\n"
            'args = ["-P", "-m", "legis", "mcp", "--agent-id", "a"]\n'
            '[mcp_servers.legis.env]\nPLAINWEAVE_MCP_CMD = """stale"""\n'
        ),
        (
            f"[mcp_servers.legis]\ncommand = {json.dumps(sys.executable)}\n"
            'args = ["-P", "-m", "legis", "mcp", "--agent-id", "a"]\n'
            "[mcp_servers.legis.env]\nPLAINWEAVE_MCP_CMD = 7\n"
        ),
        (
            f"[mcp_servers.legis]\ncommand = {json.dumps(sys.executable)}\n"
            'args = ["-P", "-m", "legis", "mcp", "--agent-id", "a"]\n'
            '[mcp_servers.legis.env]\nPLAINWEAVE_MCP_CMD = "a"\n'
            'PLAINWEAVE_MCP_CMD = "b"\n'
        ),
    ],
    ids=[
        "malformed",
        "non-table-servers",
        "inline-legis",
        "inline-env",
        "dotted-env",
        "quoted-target",
        "multiline-target",
        "non-string-target",
        "duplicate-target",
    ],
)
def test_unsupported_codex_shapes_are_unchanged(
    tmp_path: Path, monkeypatch, content: str
) -> None:
    home = _codex_home(tmp_path, monkeypatch)
    config = home / "config.toml"
    config.write_text(content)
    before = config.read_bytes()
    root = tmp_path / "project"
    root.mkdir()

    state = plainweave_binding.inspect_codex_binding(root, "desired")
    error = plainweave_binding.repair_codex_binding(root, "desired")

    assert state.current is False
    assert error
    assert config.read_bytes() == before


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("/missing/legis", ["mcp", "--agent-id", "a"]),
        (sys.executable, ["mcp", "--agent-id", "a"]),
        (sys.executable, ["-P", "-m", "legis", "mcp"]),
    ],
)
def test_unusable_codex_legis_invocation_is_unchanged(
    tmp_path: Path, monkeypatch, command: str, args: list[str]
) -> None:
    home = _codex_home(tmp_path, monkeypatch)
    config = home / "config.toml"
    config.write_text(
        f"[mcp_servers.legis]\ncommand = {json.dumps(command)}\n"
        f"args = {json.dumps(args)}\n[mcp_servers.legis.env]\n"
    )
    before = config.read_bytes()
    root = tmp_path / "project"
    root.mkdir()

    state = plainweave_binding.inspect_codex_binding(root, "desired")
    error = plainweave_binding.repair_codex_binding(root, "desired")

    assert state.registered is True
    assert state.error and "invocation" in state.error.lower()
    assert error and "invocation" in error.lower()
    assert config.read_bytes() == before


def test_codex_header_scanner_ignores_multiline_string_brackets(
    tmp_path: Path, monkeypatch
) -> None:
    config = _codex_config(
        tmp_path,
        monkeypatch,
        env=(
            "[mcp_servers.legis.env]\n"
            'KEEP_ME = """line one\n[mcp_servers.fake]\nline three"""\n'
        ),
    )
    root = tmp_path / "project"
    root.mkdir()

    assert plainweave_binding.repair_codex_binding(root, "desired") is None

    parsed = tomllib.loads(config.read_text())
    assert parsed["mcp_servers"]["legis"]["env"][PLAINWEAVE_ENV] == "desired"
    assert "fake" not in parsed["mcp_servers"]


@pytest.mark.parametrize(
    ("rendered_sibling", "parsed_sibling"),
    [
        ('"sib]ling"', "sib]ling"),
        ('"sib#ling"', "sib#ling"),
        ('"sib\\"ling"', 'sib"ling'),
    ],
    ids=["closing-bracket", "hash", "escaped-quote"],
)
def test_codex_env_insertion_stops_at_legal_quoted_sibling_header(
    tmp_path: Path,
    monkeypatch,
    rendered_sibling: str,
    parsed_sibling: str,
) -> None:
    home = _codex_home(tmp_path, monkeypatch)
    config = home / "config.toml"
    sibling = (
        f"[mcp_servers.{rendered_sibling}] # sibling header\n"
        'command = "sibling-mcp" # sibling command\n'
        f'{PLAINWEAVE_ENV} = "sibling-owned" # sibling target\n'
    )
    config.write_text(
        "# operator top comment\n"
        '[mcp_servers."legis"]\n'
        f"command = {json.dumps(sys.executable)}\n"
        'args = ["-P", "-m", "legis", "mcp", "--agent-id", "operator"]\n'
        '[mcp_servers."legis"."env"]\n'
        'KEEP_ME = "operator" # env comment\n'
        f"{sibling}"
    )
    sibling_bytes = sibling.encode()
    root = tmp_path / "project"
    root.mkdir()

    assert plainweave_binding.repair_codex_binding(root, "desired") is None

    after = config.read_bytes()
    parsed = tomllib.loads(after.decode())
    assert after.endswith(sibling_bytes)
    assert parsed["mcp_servers"]["legis"]["env"] == {
        "KEEP_ME": "operator",
        PLAINWEAVE_ENV: "desired",
    }
    assert parsed["mcp_servers"][parsed_sibling][PLAINWEAVE_ENV] == "sibling-owned"


@pytest.mark.parametrize(
    ("rendered_sibling", "parsed_sibling"),
    [
        ('"sib]ling"', "sib]ling"),
        ('"sib#ling"', "sib#ling"),
        ('"sib\\"ling"', 'sib"ling'),
    ],
    ids=["closing-bracket", "hash", "escaped-quote"],
)
def test_codex_env_replacement_stops_at_legal_quoted_sibling_header(
    tmp_path: Path,
    monkeypatch,
    rendered_sibling: str,
    parsed_sibling: str,
) -> None:
    home = _codex_home(tmp_path, monkeypatch)
    config = home / "config.toml"
    sibling = (
        f"[mcp_servers.{rendered_sibling}] # sibling header\n"
        'command = "sibling-mcp" # sibling command\n'
        f'{PLAINWEAVE_ENV} = "sibling-owned" # sibling target\n'
    )
    config.write_text(
        '[mcp_servers."legis"]\n'
        f"command = {json.dumps(sys.executable)}\n"
        'args = ["-P", "-m", "legis", "mcp", "--agent-id", "operator"]\n'
        '[mcp_servers."legis"."env"]\n'
        f'{PLAINWEAVE_ENV} = "stale" # env target\n'
        f"{sibling}"
    )
    sibling_bytes = sibling.encode()
    root = tmp_path / "project"
    root.mkdir()

    assert plainweave_binding.repair_codex_binding(root, "desired") is None

    after = config.read_bytes()
    parsed = tomllib.loads(after.decode())
    assert after.endswith(sibling_bytes)
    assert parsed["mcp_servers"]["legis"]["env"][PLAINWEAVE_ENV] == "desired"
    assert parsed["mcp_servers"][parsed_sibling][PLAINWEAVE_ENV] == "sibling-owned"


@pytest.mark.parametrize("shape", ["inline", "dotted"])
def test_codex_inline_or_dotted_env_is_readable_but_not_repaired(
    tmp_path: Path, monkeypatch, shape: str
) -> None:
    home = _codex_home(tmp_path, monkeypatch)
    config = home / "config.toml"
    desired = 'plainweave --root "quoted path"'
    env_line = (
        f"env = {{ {PLAINWEAVE_ENV} = {json.dumps(desired)} }}"
        if shape == "inline"
        else f"env.{PLAINWEAVE_ENV} = {json.dumps(desired)}"
    )
    config.write_text(
        f"[mcp_servers.legis]\ncommand = {json.dumps(sys.executable)}\n"
        'args = ["-P", "-m", "legis", "mcp", "--agent-id", "a"]\n'
        f"{env_line}\n"
    )
    before = config.read_bytes()
    root = tmp_path / "project"
    root.mkdir()

    assert plainweave_binding.inspect_codex_binding(root, desired) == (
        plainweave_binding.BindingState(True, True, None)
    )
    assert plainweave_binding.repair_codex_binding(root, desired) is None
    error = plainweave_binding.repair_codex_binding(root, "replacement")

    assert error and "inline or dotted" in error
    assert config.read_bytes() == before


def test_symlinked_codex_config_is_rejected_without_touching_target(
    tmp_path: Path, monkeypatch
) -> None:
    home = _codex_home(tmp_path, monkeypatch)
    external = tmp_path / "external.toml"
    external.write_text('[mcp_servers.legis]\ncommand = "external"\n')
    (home / "config.toml").symlink_to(external)
    before = external.read_bytes()
    root = tmp_path / "project"
    root.mkdir()

    state = plainweave_binding.inspect_codex_binding(root, "desired")
    error = plainweave_binding.repair_codex_binding(root, "desired")

    assert state.error and "symlink" in state.error.lower()
    assert error and "symlink" in error.lower()
    assert external.read_bytes() == before


def test_codex_snapshot_change_is_not_overwritten(tmp_path: Path, monkeypatch) -> None:
    config = _codex_config(tmp_path, monkeypatch)
    root = tmp_path / "project"
    root.mkdir()
    original_predicate = plainweave_binding.install._mcp_command_resolves_safely
    changed: bytes | None = None

    def change_after_validation(*args, **kwargs) -> bool:
        nonlocal changed
        result = original_predicate(*args, **kwargs)
        config.write_bytes(config.read_bytes() + b"# external writer\n")
        changed = config.read_bytes()
        return result

    monkeypatch.setattr(
        plainweave_binding.install,
        "_mcp_command_resolves_safely",
        change_after_validation,
    )

    error = plainweave_binding.repair_codex_binding(root, "desired")

    assert error and "changed" in error.lower()
    assert changed is not None and config.read_bytes() == changed


def test_codex_repair_stays_anchored_when_config_directory_is_swapped(
    tmp_path: Path, monkeypatch
) -> None:
    config = _codex_config(tmp_path, monkeypatch)
    codex_home = config.parent
    original = config.read_bytes()
    moved = tmp_path / "moved-codex-home"
    external_home = tmp_path / "external-codex-home"
    external_home.mkdir()
    external_config = external_home / "config.toml"
    external_config.write_bytes(original.replace(b"operator top", b"external top"))
    external_before = external_config.read_bytes()
    root = tmp_path / "project"
    root.mkdir()
    original_predicate = plainweave_binding.install._mcp_command_resolves_safely

    def swap_after_validation(*args, **kwargs) -> bool:
        result = original_predicate(*args, **kwargs)
        codex_home.rename(moved)
        codex_home.symlink_to(external_home, target_is_directory=True)
        return result

    monkeypatch.setattr(
        plainweave_binding.install,
        "_mcp_command_resolves_safely",
        swap_after_validation,
    )

    error = plainweave_binding.repair_codex_binding(root, "desired")

    assert error and "directory changed" in error.lower()
    assert external_config.read_bytes() == external_before
    assert not (external_home / "config.toml.legis.lock").exists()
    assert (moved / "config.toml").read_bytes() == original


def test_codex_replace_failure_is_safe_and_cleans_temp(
    tmp_path: Path, monkeypatch
) -> None:
    config = _codex_config(tmp_path, monkeypatch)
    before = config.read_bytes()
    root = tmp_path / "project"
    root.mkdir()

    def fail_replace(*_args, **_kwargs) -> None:
        raise OSError("simulated Codex replace failure")

    monkeypatch.setattr(plainweave_binding.os, "replace", fail_replace)
    error = plainweave_binding.repair_codex_binding(root, "desired")

    assert error and "simulated Codex replace failure" in error
    assert config.read_bytes() == before
    assert list(config.parent.glob("config.toml.*.tmp")) == []


def test_codex_platform_not_implemented_is_fail_closed(
    tmp_path: Path, monkeypatch
) -> None:
    config = _codex_config(tmp_path, monkeypatch)
    before = config.read_bytes()
    root = tmp_path / "project"
    root.mkdir()
    real_open = plainweave_binding.os.open

    def unsupported_open(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None:
            raise NotImplementedError("Codex anchored open unavailable")
        return real_open(path, flags, mode)

    supported = set(plainweave_binding.os.supports_dir_fd)
    supported.add(unsupported_open)
    monkeypatch.setattr(plainweave_binding.os, "open", unsupported_open)
    monkeypatch.setattr(plainweave_binding.os, "supports_dir_fd", supported)

    state = plainweave_binding.inspect_codex_binding(root, "desired")
    error = plainweave_binding.repair_codex_binding(root, "desired")

    assert state.error and "Codex anchored open unavailable" in state.error
    assert error and "Codex anchored open unavailable" in error
    assert config.read_bytes() == before


def test_codex_semantic_guard_refuses_unrelated_mutation(
    tmp_path: Path, monkeypatch
) -> None:
    config = _codex_config(tmp_path, monkeypatch)
    before = config.read_bytes()
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.setattr(
        plainweave_binding,
        "_codex_documents_match_except_target",
        lambda *_args: False,
    )

    error = plainweave_binding.repair_codex_binding(root, "desired")

    assert error and "semantic" in error.lower()
    assert config.read_bytes() == before


@pytest.mark.parametrize(
    ("before_env", "after_env"),
    [
        ({"KEEP": "same"}, {"KEEP": "same", PLAINWEAVE_ENV: "added"}),
        (
            {"KEEP": "same", PLAINWEAVE_ENV: "stale"},
            {"KEEP": "same", PLAINWEAVE_ENV: "replacement"},
        ),
    ],
    ids=["add", "replace"],
)
def test_codex_semantic_guard_accepts_only_target_change(
    before_env: dict[str, object], after_env: dict[str, object]
) -> None:
    before = {
        "mcp_servers": {
            "legis": {"command": "legis", "args": ["mcp"], "env": before_env},
            "sibling": {"command": "sibling"},
        }
    }
    after = {
        "mcp_servers": {
            "legis": {"command": "legis", "args": ["mcp"], "env": after_env},
            "sibling": {"command": "sibling"},
        }
    }

    assert plainweave_binding._codex_documents_match_except_target(before, after)


@pytest.mark.parametrize(
    "after",
    [
        {
            "mcp_servers": {
                "legis": {
                    "command": "legis",
                    "args": ["mcp"],
                    "env": {"KEEP": "same", "NESTED": {"owner": "same"}},
                },
                "sibling": {"command": "changed"},
            }
        },
        {
            "mcp_servers": {
                "legis": {
                    "command": "other",
                    "args": ["mcp"],
                    "env": {"KEEP": "same", "NESTED": {"owner": "same"}},
                },
                "sibling": {"command": "sibling"},
            }
        },
        {
            "mcp_servers": {
                "legis": {
                    "command": "legis",
                    "args": ["other"],
                    "env": {"KEEP": "same", "NESTED": {"owner": "same"}},
                },
                "sibling": {"command": "sibling"},
            }
        },
        {
            "mcp_servers": {
                "legis": {
                    "command": "legis",
                    "args": ["mcp"],
                    "env": {"KEEP": "changed", "NESTED": {"owner": "same"}},
                },
                "sibling": {"command": "sibling"},
            }
        },
        {
            "mcp_servers": {
                "legis": {
                    "command": "legis",
                    "args": ["mcp"],
                    "env": {"KEEP": "same", "NESTED": {"owner": "changed"}},
                },
                "sibling": {"command": "sibling"},
            }
        },
    ],
    ids=["sibling", "command", "args", "other-env", "nested-env"],
)
def test_codex_semantic_guard_rejects_unrelated_change(
    after: dict[str, object],
) -> None:
    before = {
        "mcp_servers": {
            "legis": {
                "command": "legis",
                "args": ["mcp"],
                "env": {"KEEP": "same", "NESTED": {"owner": "same"}},
            },
            "sibling": {"command": "sibling"},
        }
    }

    assert not plainweave_binding._codex_documents_match_except_target(before, after)


def test_missing_project_binding_is_registered_but_noncurrent(tmp_path: Path) -> None:
    _write_legis_entry(tmp_path, env={"KEEP_ME": "operator-value"})

    state = plainweave_binding.inspect_project_binding(tmp_path, "plainweave --root .")

    assert state == plainweave_binding.BindingState(
        registered=True,
        current=False,
        error=None,
    )


def test_project_autodiscovery_inspection_rejects_legacy_binding(
    tmp_path: Path,
) -> None:
    _write_legis_entry(
        tmp_path,
        env={"KEEP_ME": "operator-value", PLAINWEAVE_ENV: "legacy-command"},
    )

    state = plainweave_binding.inspect_project_binding(tmp_path, None)

    assert state == plainweave_binding.BindingState(True, False, None)


def test_project_autodiscovery_repair_removes_only_legacy_binding(
    tmp_path: Path,
) -> None:
    config = _write_legis_entry(
        tmp_path,
        env={"KEEP_ME": "operator-value", PLAINWEAVE_ENV: "legacy-command"},
    )
    before = json.loads(config.read_text(encoding="utf-8"))
    expected = json.loads(json.dumps(before))
    expected["mcpServers"]["legis"]["env"].pop(PLAINWEAVE_ENV)

    error = plainweave_binding.repair_project_binding(tmp_path, None)

    assert error is None
    assert json.loads(config.read_text(encoding="utf-8")) == expected
    assert plainweave_binding.inspect_project_binding(
        tmp_path, None
    ) == plainweave_binding.BindingState(True, True, None)


def test_project_autodiscovery_second_repair_is_byte_identical(
    tmp_path: Path,
) -> None:
    config = _write_legis_entry(
        tmp_path,
        env={"KEEP_ME": "operator-value", PLAINWEAVE_ENV: "legacy-command"},
    )

    assert plainweave_binding.repair_project_binding(tmp_path, None) is None
    after_first = config.read_bytes()
    assert plainweave_binding.repair_project_binding(tmp_path, None) is None

    assert config.read_bytes() == after_first


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


@pytest.mark.parametrize(
    ("newline", "final_newline"),
    [
        ("\r\n", True),
        ("\r\n", False),
        ("\n", True),
        ("\n", False),
        ("\r", True),
        ("\r", False),
    ],
)
def test_project_repair_preserves_newline_style_and_final_newline_state(
    tmp_path: Path,
    newline: str,
    final_newline: bool,
) -> None:
    document = {
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
                "env": {"KEEP_ME": "operator-value"},
                "timeout": 17_000,
            },
            "sibling": {"command": "sibling-mcp", "args": ["serve"]},
        }
    }
    rendered = json.dumps(document, indent=4).replace("\n", newline)
    if final_newline:
        rendered += newline
    config = tmp_path / ".mcp.json"
    config.write_bytes(rendered.encode())
    desired = "plainweave-mcp --root /newline-style"

    assert plainweave_binding.repair_project_binding(tmp_path, desired) is None

    repaired = config.read_bytes().decode()
    without_expected_newlines = repaired.replace(newline, "")
    assert "\n" not in without_expected_newlines
    assert "\r" not in without_expected_newlines
    assert repaired.endswith(newline) is final_newline
    parsed = json.loads(repaired)
    assert parsed["mcpServers"]["legis"]["env"] == {
        "KEEP_ME": "operator-value",
        PLAINWEAVE_ENV: desired,
    }
    assert parsed["mcpServers"]["sibling"] == document["mcpServers"]["sibling"]


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

    def unexpected_replace(*_args, **_kwargs) -> None:
        pytest.fail("current binding must not be rewritten")

    monkeypatch.setattr(
        plainweave_binding,
        "_anchored_replace",
        unexpected_replace,
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


@pytest.mark.parametrize("extra_byte", [False, True], ids=["exact-limit", "over-limit"])
def test_project_binding_read_size_limit(
    tmp_path: Path,
    extra_byte: bool,
) -> None:
    config = _write_legis_entry(tmp_path)
    content = config.read_bytes()
    config.write_bytes(
        content
        + b" "
        * (
            plainweave_binding._MAX_BINDING_CONFIG_BYTES
            - len(content)
            + int(extra_byte)
        )
    )

    state = plainweave_binding.inspect_project_binding(tmp_path, "desired")

    if extra_byte:
        assert state.error is not None and "size limit" in state.error.lower()
    else:
        assert state.registered is True
        assert state.error is None


@pytest.mark.parametrize("extra_byte", [False, True], ids=["exact-limit", "over-limit"])
def test_codex_binding_read_size_limit(
    tmp_path: Path,
    monkeypatch,
    extra_byte: bool,
) -> None:
    config = _codex_config(tmp_path, monkeypatch)
    content = config.read_bytes()
    config.write_bytes(
        content
        + b" "
        * (
            plainweave_binding._MAX_BINDING_CONFIG_BYTES
            - len(content)
            + int(extra_byte)
        )
    )

    state = plainweave_binding.inspect_codex_binding(tmp_path, "desired")

    if extra_byte:
        assert state.error is not None and "size limit" in state.error.lower()
    else:
        assert state.registered is True
        assert state.error is None


def test_project_binding_recheck_refuses_oversized_replacement(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _write_legis_entry(tmp_path)
    original_gate = plainweave_binding.install._parsed_mcp_entry_is_current
    oversized: bytes | None = None

    def replace_with_oversized_config(*args, **kwargs) -> bool:
        nonlocal oversized
        current = original_gate(*args, **kwargs)
        content = config.read_bytes()
        oversized = content + b" " * (
            plainweave_binding._MAX_BINDING_CONFIG_BYTES - len(content) + 1
        )
        config.write_bytes(oversized)
        return current

    monkeypatch.setattr(
        plainweave_binding.install,
        "_parsed_mcp_entry_is_current",
        replace_with_oversized_config,
    )

    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert error is not None and "size limit" in error.lower()
    assert oversized is not None and config.read_bytes() == oversized


def test_duplicate_project_json_is_reported_and_unchanged(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    command = json.dumps(sys.executable)
    config.write_text(
        '{"mcpServers":{"legis":{'
        '"type":"stdio",'
        f'"command":{command},'
        '"args":["-P","-m","legis","mcp","--agent-id","operator"],'
        '"env":{"KEEP_FIRST":"operator"},'
        '"env":{}'
        "}}}",
        encoding="utf-8",
    )
    before = config.read_bytes()

    state = plainweave_binding.inspect_project_binding(tmp_path, "desired")
    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert state.error is not None and "malformed" in state.error.lower()
    assert error is not None and "malformed" in error.lower()
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


def test_project_binding_inspection_rejects_fifo_without_blocking(
    tmp_path: Path,
) -> None:
    os.mkfifo(tmp_path / ".mcp.json")
    script = (
        "from pathlib import Path; "
        "from legis.plainweave_binding import inspect_project_binding; "
        "state = inspect_project_binding(Path(__import__('sys').argv[1]), 'desired'); "
        "print(state.error or 'no error')"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "not a regular file" in completed.stdout.lower()


def test_codex_binding_inspection_rejects_fifo_without_blocking(
    tmp_path: Path,
) -> None:
    codex_home = tmp_path / "codex"
    codex_home.mkdir()
    os.mkfifo(codex_home / "config.toml")
    script = (
        "from pathlib import Path; "
        "from legis.plainweave_binding import inspect_codex_binding; "
        "state = inspect_codex_binding(Path(__import__('sys').argv[1]), 'desired'); "
        "print(state.error or 'no error')"
    )
    env = os.environ.copy()
    env["CODEX_HOME"] = str(codex_home)

    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
        env=env,
    )

    assert completed.returncode == 0, completed.stderr
    assert "not a regular file" in completed.stdout.lower()


def test_project_binding_recheck_rejects_fifo_without_blocking(
    tmp_path: Path,
) -> None:
    script = """
import json
import os
import sys
from pathlib import Path
from legis import plainweave_binding

root = Path(sys.argv[1])
config = root / ".mcp.json"
config.write_text(json.dumps({"mcpServers": {"legis": {
    "type": "stdio",
    "command": sys.executable,
    "args": ["-P", "-m", "legis", "mcp", "--agent-id", "operator"],
    "env": {},
}}}), encoding="utf-8")
original_gate = plainweave_binding.install._parsed_mcp_entry_is_current
def replace_with_fifo(*args, **kwargs):
    current = original_gate(*args, **kwargs)
    config.unlink()
    os.mkfifo(config)
    return current
plainweave_binding.install._parsed_mcp_entry_is_current = replace_with_fifo
print(plainweave_binding.repair_project_binding(root, "desired") or "no error")
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "changed after inspection" in completed.stdout.lower()


def test_project_binding_recheck_rejects_fifo_before_reading(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _write_legis_entry(tmp_path)
    original_gate = plainweave_binding.install._parsed_mcp_entry_is_current
    original_read = plainweave_binding._read_fd
    reads = 0

    def replace_with_fifo(*args, **kwargs) -> bool:
        current = original_gate(*args, **kwargs)
        config.unlink()
        os.mkfifo(config)
        return current

    def reject_second_read(fd: int) -> bytes:
        nonlocal reads
        reads += 1
        if reads > 1:
            raise AssertionError("non-regular final target was read")
        return original_read(fd)

    monkeypatch.setattr(
        plainweave_binding.install,
        "_parsed_mcp_entry_is_current",
        replace_with_fifo,
    )
    monkeypatch.setattr(plainweave_binding, "_read_fd", reject_second_read)

    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert reads == 1
    assert error is not None and "changed after inspection" in error.lower()


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


def test_anchored_replace_error_is_returned_without_partial_write(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _write_legis_entry(tmp_path, env={"KEEP_ME": "yes"})
    before = config.read_bytes()

    def fail_replace(*_args, **_kwargs) -> None:
        raise OSError("simulated atomic replacement failure")

    monkeypatch.setattr(
        plainweave_binding.install.os,
        "replace",
        fail_replace,
    )

    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert error and "simulated atomic replacement failure" in error
    assert config.read_bytes() == before


def test_plainweave_binding_replace_is_file_and_directory_durable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _write_legis_entry(tmp_path)
    events: list[str] = []
    real_fsync = plainweave_binding.os.fsync
    real_replace = plainweave_binding.os.replace

    def observed_fsync(fd: int) -> None:
        mode = plainweave_binding.os.fstat(fd).st_mode
        events.append("fsync-directory" if stat.S_ISDIR(mode) else "fsync-file")
        real_fsync(fd)

    def observed_replace(*args, **kwargs) -> None:
        events.append("replace")
        real_replace(*args, **kwargs)

    monkeypatch.setattr(plainweave_binding.os, "fsync", observed_fsync)
    monkeypatch.setattr(plainweave_binding.os, "replace", observed_replace)

    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert error is None
    assert events == ["fsync-file", "replace", "fsync-directory"]
    assert (
        PLAINWEAVE_ENV in json.loads(config.read_text())["mcpServers"]["legis"]["env"]
    )


def test_repair_refuses_to_overwrite_changed_validated_snapshot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _write_legis_entry(tmp_path, env={"KEEP_ME": "original"})
    original_gate = plainweave_binding.install._parsed_mcp_entry_is_current
    newer: bytes | None = None

    def change_after_validation(root: Path, *args, **kwargs) -> bool:
        nonlocal newer
        current = original_gate(root, *args, **kwargs)
        data = json.loads(config.read_text(encoding="utf-8"))
        data["mcpServers"]["legis"]["timeout"] = 99_000
        data["mcpServers"]["legis"]["env"]["OPERATOR_ADDED"] = "newer"
        config.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        newer = config.read_bytes()
        return current

    monkeypatch.setattr(
        plainweave_binding.install,
        "_parsed_mcp_entry_is_current",
        change_after_validation,
    )

    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert error and "changed" in error.lower()
    assert newer is not None
    assert config.read_bytes() == newer


def test_repair_waits_for_legis_writer_and_rechecks_snapshot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _write_legis_entry(tmp_path, env={"KEEP_ME": "original"})
    assert hasattr(plainweave_binding.install, "_config_writer_lock")
    real_lock = plainweave_binding.install._config_writer_lock
    attempting_lock = threading.Event()
    repair_acquired_lock = threading.Event()
    writer_in_critical_section = threading.Event()
    allow_writer = threading.Event()
    repair_result: list[str | None] = []
    register_result: list[tuple[bool, str]] = []
    newer_bytes: list[bytes] = []

    @contextmanager
    def observed_lock(path: Path, *, dir_fd: int | None = None):
        if threading.current_thread().name == "binding-repair":
            attempting_lock.set()
        with real_lock(path, dir_fd=dir_fd):
            if threading.current_thread().name == "binding-repair":
                repair_acquired_lock.set()
            yield

    def staged_register(*_args, **_kwargs) -> tuple[bool, str]:
        writer_in_critical_section.set()
        assert allow_writer.wait(timeout=2)
        newer = json.loads(config.read_text(encoding="utf-8"))
        newer["mcpServers"]["legis"]["timeout"] = 99_000
        newer["mcpServers"]["legis"]["env"]["OPERATOR_ADDED"] = "newer"
        config.write_text(json.dumps(newer, indent=2) + "\n", encoding="utf-8")
        newer_bytes.append(config.read_bytes())
        return True, "cooperating registration updated .mcp.json"

    monkeypatch.setattr(
        plainweave_binding.install,
        "_config_writer_lock",
        observed_lock,
    )
    monkeypatch.setattr(
        plainweave_binding.install,
        "_register_mcp_json_unlocked",
        staged_register,
    )

    writer = threading.Thread(
        name="registration-writer",
        target=lambda: register_result.append(
            plainweave_binding.install.register_mcp_json(tmp_path)
        ),
    )
    writer.start()
    assert writer_in_critical_section.wait(timeout=2)
    repair = threading.Thread(
        name="binding-repair",
        target=lambda: repair_result.append(
            plainweave_binding.repair_project_binding(tmp_path, "desired")
        ),
    )
    repair.start()
    assert attempting_lock.wait(timeout=2)
    assert not repair_acquired_lock.wait(timeout=0.1)
    allow_writer.set()

    writer.join(timeout=2)
    repair.join(timeout=2)
    assert not writer.is_alive()
    assert not repair.is_alive()
    assert repair_acquired_lock.is_set()
    assert register_result and register_result[0][0] is True
    assert (
        repair_result
        and repair_result[0] is not None
        and "changed" in repair_result[0].lower()
    )
    assert newer_bytes and config.read_bytes() == newer_bytes[0]


def test_repair_stays_anchored_when_project_path_is_swapped_for_symlink(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    original_config = _write_legis_entry(project, env={"OWNER": "original"})
    original_bytes = original_config.read_bytes()
    moved = tmp_path / "moved-original"
    external = tmp_path / "external"
    external.mkdir()
    external_config = _write_legis_entry(external, env={"OWNER": "external"})
    external_bytes = external_config.read_bytes()
    original_gate = plainweave_binding.install._parsed_mcp_entry_is_current

    def swap_root_after_validation(root: Path, *args, **kwargs) -> bool:
        current = original_gate(root, *args, **kwargs)
        project.rename(moved)
        project.symlink_to(external, target_is_directory=True)
        return current

    monkeypatch.setattr(
        plainweave_binding.install,
        "_parsed_mcp_entry_is_current",
        swap_root_after_validation,
    )

    error = plainweave_binding.repair_project_binding(project, "desired")

    assert error is not None and "directory changed" in error.lower()
    assert external_config.read_bytes() == external_bytes
    assert not (external / ".mcp.json.legis.lock").exists()
    assert (moved / ".mcp.json").read_bytes() == original_bytes


def test_repair_rejects_project_symlink_back_to_same_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    original_config = _write_legis_entry(project, env={"OWNER": "original"})
    original_bytes = original_config.read_bytes()
    moved = tmp_path / "moved-original"
    original_gate = plainweave_binding.install._parsed_mcp_entry_is_current

    def swap_root_after_validation(root: Path, *args, **kwargs) -> bool:
        current = original_gate(root, *args, **kwargs)
        project.rename(moved)
        project.symlink_to(moved, target_is_directory=True)
        return current

    monkeypatch.setattr(
        plainweave_binding.install,
        "_parsed_mcp_entry_is_current",
        swap_root_after_validation,
    )

    error = plainweave_binding.repair_project_binding(project, "desired")

    assert error is not None and "directory changed" in error.lower()
    assert project.is_symlink() and project.resolve() == moved
    assert (moved / ".mcp.json").read_bytes() == original_bytes


def test_repair_rejects_symlinked_project_ancestor_back_to_same_tree(
    tmp_path: Path,
    monkeypatch,
) -> None:
    parent = tmp_path / "project-parent"
    project = parent / "project"
    project.mkdir(parents=True)
    original_config = _write_legis_entry(project, env={"OWNER": "original"})
    original_bytes = original_config.read_bytes()
    moved_parent = tmp_path / "moved-project-parent"
    original_gate = plainweave_binding.install._parsed_mcp_entry_is_current

    def swap_parent_after_validation(root: Path, *args, **kwargs) -> bool:
        current = original_gate(root, *args, **kwargs)
        parent.rename(moved_parent)
        parent.symlink_to(moved_parent, target_is_directory=True)
        return current

    monkeypatch.setattr(
        plainweave_binding.install,
        "_parsed_mcp_entry_is_current",
        swap_parent_after_validation,
    )

    error = plainweave_binding.repair_project_binding(project, "desired")

    assert error is not None and "directory changed" in error.lower()
    assert parent.is_symlink() and parent.resolve() == moved_parent
    assert (moved_parent / "project" / ".mcp.json").read_bytes() == original_bytes


def test_failure_after_temp_creation_cleans_temp_and_preserves_destination(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _write_legis_entry(tmp_path, env={"KEEP_ME": "yes"})
    before = config.read_bytes()

    def fail_replace(*_args, **_kwargs) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(plainweave_binding.install.os, "replace", fail_replace)

    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert error and "simulated replace failure" in error
    assert config.read_bytes() == before
    assert list(tmp_path.glob(".mcp.json*.tmp")) == []


def test_stale_registration_takes_precedence_over_unsafe_environment(
    tmp_path: Path,
) -> None:
    config = _write_legis_entry(tmp_path, env={"LEGIS_HMAC_KEY": "secret"})
    data = json.loads(config.read_text(encoding="utf-8"))
    data["mcpServers"]["legis"]["command"] = "/missing/legis"
    config.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    before = config.read_bytes()

    state = plainweave_binding.inspect_project_binding(tmp_path, "desired")
    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert state.registered is False
    assert state.current is False
    assert state.error and "registration" in state.error.lower()
    assert error and "registration" in error.lower()
    assert config.read_bytes() == before


def test_missing_dir_fd_support_fails_closed_before_inspection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write_legis_entry(tmp_path)
    supported = set(plainweave_binding.os.supports_dir_fd)
    supported.discard(plainweave_binding.os.open)
    monkeypatch.setattr(plainweave_binding.os, "supports_dir_fd", supported)

    state = plainweave_binding.inspect_project_binding(tmp_path, "desired")

    assert state.registered is False
    assert state.current is False
    assert state.error and "platform" in state.error.lower()


def test_missing_dir_fd_support_fails_closed_before_discovery(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _initialize(tmp_path)
    supported = set(plainweave_binding.os.supports_dir_fd)
    supported.discard(plainweave_binding.os.open)
    monkeypatch.setattr(plainweave_binding.os, "supports_dir_fd", supported)

    result = discover_plainweave(tmp_path)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None and "platform" in result.error.lower()


def test_unsupported_anchored_target_open_returns_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write_legis_entry(tmp_path)
    real_open = plainweave_binding.os.open

    def unsupported_open(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None:
            raise NotImplementedError("anchored open unavailable")
        return real_open(path, flags, mode)

    supported = set(plainweave_binding.os.supports_dir_fd)
    supported.add(unsupported_open)
    monkeypatch.setattr(plainweave_binding.os, "open", unsupported_open)
    monkeypatch.setattr(plainweave_binding.os, "supports_dir_fd", supported)

    state = plainweave_binding.inspect_project_binding(tmp_path, "desired")

    assert state.registered is False
    assert state.current is False
    assert state.error and "anchored open unavailable" in state.error


def test_cleanup_not_implemented_does_not_mask_replace_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _write_legis_entry(tmp_path)
    before = config.read_bytes()

    def fail_replace(*_args, **_kwargs) -> None:
        raise OSError("original replace failure")

    def unsupported_unlink(*_args, **_kwargs) -> None:
        raise NotImplementedError("anchored cleanup unavailable")

    supported = set(plainweave_binding.os.supports_dir_fd)
    supported.add(unsupported_unlink)
    monkeypatch.setattr(plainweave_binding.os, "replace", fail_replace)
    monkeypatch.setattr(plainweave_binding.os, "unlink", unsupported_unlink)
    monkeypatch.setattr(plainweave_binding.os, "supports_dir_fd", supported)

    error = plainweave_binding.repair_project_binding(tmp_path, "desired")

    assert error and "original replace failure" in error
    assert config.read_bytes() == before


def test_public_mcp_predicate_has_no_environment_safety_bypass(
    tmp_path: Path,
) -> None:
    config = _write_legis_entry(tmp_path, env={"LEGIS_HMAC_KEY": "secret"})
    data = json.loads(config.read_text(encoding="utf-8"))

    assert plainweave_binding.install.mcp_entry_is_current(tmp_path) is False
    with pytest.raises(TypeError):
        plainweave_binding.install.mcp_entry_is_current(
            tmp_path,
            _data=data,
            _check_env=False,
        )


def test_plainweave_environment_variable_name_is_stable() -> None:
    assert PLAINWEAVE_ENV == "PLAINWEAVE_MCP_CMD"


def test_root_pinned_project_entry_wins_over_path_fallback(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    project_command = _make_executable(tmp_path / "project-bin" / "plainweave-mcp")
    fallback = _make_executable(tmp_path / "fallback-bin" / "plainweave-mcp")
    args = ["serve", "--root", str(root), "--quiet"]
    _write_entry(root, str(project_command), args)
    monkeypatch.setenv("PATH", str(fallback.parent))

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is True
    assert shlex.split(result.command or "") == [str(project_command), *args]
    assert result.error is None


def test_project_entry_accepts_plainweave_python_module_launcher(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    args = ["-P", "-m", "plainweave.mcp_server", "--root", str(root)]
    _write_entry(root, sys.executable, args)
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is True
    assert shlex.split(result.command or "") == [
        str(Path(sys.executable).resolve()),
        *args,
    ]
    assert result.error is None


def test_python_module_launcher_rejects_non_python_command(
    tmp_path: Path,
    monkeypatch,
) -> None:
    # The `-P -m plainweave.mcp_server` arg head only trusts a real interpreter:
    # a non-python command carrying those args must be rejected.
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    command = _make_executable(tmp_path / "outside-bin" / "not-plainweave")
    _write_entry(
        root, str(command), ["-P", "-m", "plainweave.mcp_server", "--root", str(root)]
    )
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None


def test_python_module_launcher_rejects_non_plainweave_module(
    tmp_path: Path,
    monkeypatch,
) -> None:
    # The interpreter branch requires the exact `-P -m plainweave.mcp_server`
    # head; a python launcher for any other module must not be trusted (guards
    # against loosening the guard to `args[:2] == ["-P", "-m"]`).
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    _write_entry(
        root, sys.executable, ["-P", "-m", "not_plainweave.evil", "--root", str(root)]
    )
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None


@pytest.mark.parametrize(
    "root_form",
    ["separate-relative", "equals-relative", "separate-alias", "equals-alias"],
)
def test_project_entry_canonicalizes_validated_root_argument(
    tmp_path: Path,
    monkeypatch,
    root_form: str,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    command = _make_executable(tmp_path / "project-bin" / "plainweave-mcp")
    alias = tmp_path / "project-alias"
    alias.symlink_to(root, target_is_directory=True)
    supplied_root = "." if root_form.endswith("relative") else str(alias)
    if root_form.startswith("separate"):
        args = ["serve", "--root", supplied_root, "--quiet"]
        expected_args = ["serve", "--root", str(root.resolve()), "--quiet"]
    else:
        args = ["serve", f"--root={supplied_root}", "--quiet"]
        expected_args = ["serve", f"--root={root.resolve()}", "--quiet"]
    _write_entry(root, str(command), args)
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is True
    assert shlex.split(result.command or "") == [str(command), *expected_args]
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


def test_path_fallback_skips_project_local_shadow(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    local = _make_executable(root / "bin" / "plainweave-mcp")
    external = _make_executable(tmp_path / "external-bin" / "plainweave-mcp")
    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(local.parent), str(external.parent)])
    )

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is True
    assert shlex.split(result.command or "") == [
        str(external.resolve()),
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


def test_hostile_nul_project_root_fails_closed_without_echoing_value(
    monkeypatch,
) -> None:
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(Path("hostile\0project"))

    assert result == plainweave_binding.PlainweaveDiscovery(
        applicable=True,
        installed=False,
        error="Plainweave project root is invalid or unreadable",
    )


@pytest.mark.parametrize("hostile_source", ["command", "path", "root-argument"])
def test_embedded_nul_discovery_inputs_fail_closed(
    tmp_path: Path,
    monkeypatch,
    hostile_source: str,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
    configured_command = str(command)
    configured_root = str(root)
    path = ""
    if hostile_source == "command":
        configured_command = "plainweave-mcp\0hostile"
    elif hostile_source == "path":
        configured_command = "missing-plainweave"
        path = "hostile\0path"
    else:
        configured_root = "hostile\0root"
    _write_entry(
        root,
        configured_command,
        ["--root", configured_root],
    )
    if hostile_source == "path":
        monkeypatch.setattr(plainweave_binding.os, "environ", {"PATH": path})
    else:
        monkeypatch.setenv("PATH", path)

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None and "invalid" in result.error.lower()


def test_embedded_nul_in_non_root_argument_is_invalid(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
    _write_entry(
        root,
        str(command),
        ["--root", str(root), "--label", "hostile\0value"],
    )
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.installed is False
    assert result.command is None
    assert result.error is not None and "invalid" in result.error.lower()


def test_root_after_end_of_options_marker_is_not_effective(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
    _write_entry(root, str(command), ["--", "--root", str(root)])
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.installed is False
    assert result.command is None
    assert result.error is not None and "invalid" in result.error.lower()


@pytest.mark.parametrize("failure", [MemoryError(), RecursionError()])
def test_root_resolution_resource_failure_is_generic(
    monkeypatch,
    failure: BaseException,
) -> None:
    def fail_resolve(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(Path, "resolve", fail_resolve)

    result = discover_plainweave(Path("project"))

    assert result == plainweave_binding.PlainweaveDiscovery(
        applicable=True,
        installed=False,
        error="Plainweave project root is invalid or unreadable",
    )


@pytest.mark.parametrize("failure", [MemoryError(), RecursionError()])
def test_executable_resolution_resource_failure_is_generic(
    tmp_path: Path,
    monkeypatch,
    failure: BaseException,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)

    def fail_which(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(plainweave_binding.shutil, "which", fail_which)

    result = discover_plainweave(root)

    assert result == plainweave_binding.PlainweaveDiscovery(
        applicable=True,
        installed=False,
        error="Plainweave project discovery exhausted safe resources",
    )


def test_project_config_swap_is_opened_anchored_nofollow_nonblocking(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
    config = root / ".mcp.json"
    _write_entry(root, str(command), ["--root", str(root)])
    external = tmp_path / "external.json"
    external.write_bytes(config.read_bytes())
    moved = root / "original.mcp.json"
    real_open = plainweave_binding.os.open
    swapped = False

    def swap_before_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == ".mcp.json" and kwargs.get("dir_fd") is not None and not swapped:
            swapped = True
            assert flags & os.O_NOFOLLOW
            assert flags & os.O_NONBLOCK
            config.rename(moved)
            config.symlink_to(external)
        return real_open(path, flags, *args, **kwargs)

    supported = set(plainweave_binding.os.supports_dir_fd)
    supported.add(swap_before_open)
    monkeypatch.setattr(plainweave_binding.os, "open", swap_before_open)
    monkeypatch.setattr(plainweave_binding.os, "supports_dir_fd", supported)
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert swapped
    assert result.installed is False
    assert result.command is None
    assert result.error is not None and "malformed" in result.error.lower()


def test_state_directory_swap_cannot_recruit_fallback(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    state = root / ".plainweave"
    moved = root / "original-state"
    external = tmp_path / "external-state"
    external.mkdir()
    (external / "plainweave.db").touch()
    fallback = _make_executable(tmp_path / "bin" / "plainweave-mcp")
    real_open = plainweave_binding.os.open
    swapped = False

    def swap_before_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == ".plainweave" and kwargs.get("dir_fd") is not None and not swapped:
            swapped = True
            state.rename(moved)
            state.symlink_to(external, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    supported = set(plainweave_binding.os.supports_dir_fd)
    supported.add(swap_before_open)
    monkeypatch.setattr(plainweave_binding.os, "open", swap_before_open)
    monkeypatch.setattr(plainweave_binding.os, "supports_dir_fd", supported)
    monkeypatch.setenv("PATH", str(fallback.parent))

    result = discover_plainweave(root)

    assert swapped
    assert result.applicable is False
    assert result.installed is True
    assert result.command is None


def test_excessively_nested_project_json_is_reported_as_malformed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    nested = "[" * 2_000 + "0" + "]" * 2_000
    (root / ".mcp.json").write_text(
        '{"mcpServers":{"plainweave":{"metadata":' + nested + "}}}",
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None and "malformed" in result.error.lower()


@pytest.mark.parametrize("parser_error", [RecursionError(), MemoryError()])
def test_project_json_parser_resource_failure_is_reported_as_malformed(
    tmp_path: Path,
    monkeypatch,
    parser_error: BaseException,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    (root / ".mcp.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("PATH", "")

    def fail_parse(_text: str):
        raise parser_error

    monkeypatch.setattr(
        plainweave_binding.install,
        "_strict_json_loads",
        fail_parse,
    )

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None and "malformed" in result.error.lower()


def test_json_nesting_limit_ignores_brackets_inside_strings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
    document = {
        "mcpServers": {
            "plainweave": {
                "type": "stdio",
                "command": str(command),
                "args": ["--root", str(root)],
                "metadata": 'escaped quote: \\"' + "[" * 500,
            }
        }
    }
    (root / ".mcp.json").write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.installed is True
    assert result.command is not None


def test_json_nesting_limit_pins_exact_boundary() -> None:
    assert plainweave_binding._json_nesting_is_bounded("[" * 100 + "]" * 100)
    assert not plainweave_binding._json_nesting_is_bounded("[" * 101 + "]" * 101)


@pytest.mark.parametrize("extra_byte", [False, True], ids=["exact-limit", "over-limit"])
def test_project_json_size_limit_pins_exact_boundary(
    tmp_path: Path,
    extra_byte: bool,
) -> None:
    payload = b"{}" + b" " * (
        plainweave_binding._MAX_PLAINWEAVE_CONFIG_BYTES - 2 + int(extra_byte)
    )
    (tmp_path / ".mcp.json").write_bytes(payload)
    root_fd = plainweave_binding._open_directory_path_nofollow(tmp_path)
    try:
        if extra_byte:
            with pytest.raises(ValueError, match="size limit"):
                plainweave_binding._bounded_plainweave_json(
                    tmp_path / ".mcp.json",
                    root_fd=root_fd,
                )
        else:
            assert (
                plainweave_binding._bounded_plainweave_json(
                    tmp_path / ".mcp.json",
                    root_fd=root_fd,
                )
                == {}
            )
    finally:
        os.close(root_fd)


def test_oversized_project_json_is_reported_as_malformed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "plainweave": {
                        "type": "stdio",
                        "command": str(command),
                        "args": ["--root", str(root)],
                        "padding": "x" * (2 * 1024 * 1024),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None and "malformed" in result.error.lower()


@pytest.mark.parametrize("ambiguous_json", ["duplicate", "nonstandard-constant"])
def test_ambiguous_project_json_cannot_establish_plainweave_discovery(
    tmp_path: Path,
    monkeypatch,
    ambiguous_json: str,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
    root_json = json.dumps(str(root))
    command_json = json.dumps(str(command))
    if ambiguous_json == "duplicate":
        tail = f'"args":["--root",{root_json}],"args":["--root",{root_json}]'
    else:
        tail = f'"args":["--root",{root_json}],"metadata":NaN'
    (root / ".mcp.json").write_text(
        '{"mcpServers":{"plainweave":{'
        f'"type":"stdio","command":{command_json},{tail}'
        "}}}",
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None
    assert "malformed" in result.error.lower()


@pytest.mark.parametrize(
    "number",
    ["1e1000", "1e-1000", "-1e-1000", "1.234567890123456789"],
)
def test_project_repair_rejects_lossy_floating_point_unchanged(
    tmp_path: Path,
    monkeypatch,
    number: str,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
    config = root / ".mcp.json"
    config.write_text(
        '{"mcpServers":{"plainweave":{'
        f'"type":"stdio","command":{json.dumps(str(command))},'
        f'"args":["--root",{json.dumps(str(root))}]'
        '},"legis":{'
        f'"type":"stdio","command":{json.dumps(sys.executable)},'
        '"args":["-P","-m","legis","mcp","--agent-id","operator"],'
        f'"env":{{}},"unrelated":{number}'
        "}}}",
        encoding="utf-8",
    )
    before = config.read_bytes()
    monkeypatch.setenv("PATH", "")

    discovery = discover_plainweave(root)
    error = plainweave_binding.repair_project_binding(root, "desired")

    assert discovery.error is not None and "malformed" in discovery.error.lower()
    assert error is not None and "malformed" in error.lower()
    assert config.read_bytes() == before


def test_non_string_project_args_are_invalid(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
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
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
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
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
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
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
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
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
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


def test_project_entry_with_dead_command_is_invalid(
    tmp_path: Path, monkeypatch
) -> None:
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


@pytest.mark.parametrize("unsafe_command", ["wrong-name", "project-local"])
def test_project_entry_rejects_untrusted_plainweave_executable(
    tmp_path: Path,
    monkeypatch,
    unsafe_command: str,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    _initialize(root)
    if unsafe_command == "wrong-name":
        command = _make_executable(tmp_path / "outside-bin" / "not-plainweave")
    else:
        command = _make_executable(root / "bin" / "plainweave-mcp")
    _write_entry(root, str(command), ["--root", str(root)])
    monkeypatch.setenv("PATH", "")

    result = discover_plainweave(root)

    assert result.applicable is True
    assert result.installed is False
    assert result.command is None
    assert result.error is not None
    assert "invalid" in result.error.lower()
    assert "no executable" in result.error.lower()


def test_command_path_with_spaces_round_trips_exactly(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "project with spaces"
    root.mkdir()
    command = _make_executable(tmp_path / "bin with spaces" / "plainweave-mcp")
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
    command = _make_executable(tmp_path / "bin" / "plainweave-mcp")
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
