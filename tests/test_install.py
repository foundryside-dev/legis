"""Tests for legis.install — instruction injection, skills, hooks, gitignore."""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from legis import install
from legis.install import (
    INSTRUCTIONS_MARKER,
    SKILL_NAME,
    UnsafeInstallPathError,
    _build_instructions_block,
    _extract_marker_token,
    _instructions_hash,
    _instructions_text,
    _instructions_version,
    _marker_token,
    _skill_tree_fingerprint,
    ensure_gitignore,
    inject_instructions,
    install_claude_code_hooks,
    install_codex_skills,
    install_skills,
    reject_symlink,
)


# ---------------------------------------------------------------------------
# Instructions block primitives
# ---------------------------------------------------------------------------


def test_instructions_text_is_nonempty_and_marker_free():
    text = _instructions_text()
    assert text.strip()
    # The body must not contain markers; they are added programmatically.
    assert INSTRUCTIONS_MARKER not in text
    assert "/legis:instructions" not in text


def test_instructions_hash_is_stable_8_hex():
    h = _instructions_hash()
    assert len(h) == 8
    assert all(c in "0123456789abcdef" for c in h)
    assert h == _instructions_hash()


def test_instructions_version_prefers_dist_metadata():
    import importlib.metadata

    # Prefers installed distribution metadata; falls back to legis.__version__.
    # (In a dev venv the editable dist metadata can lag the source __version__;
    # in a real release they agree. Assert the documented preference, not a
    # hardcoded string.)
    try:
        expected = importlib.metadata.version("legis")
    except importlib.metadata.PackageNotFoundError:
        from legis import __version__

        expected = __version__
    assert _instructions_version() == expected
    assert _instructions_version()  # non-empty


def test_instructions_version_falls_back_to_dunder(monkeypatch):
    import importlib.metadata

    def _raise(_name):
        raise importlib.metadata.PackageNotFoundError("legis")

    monkeypatch.setattr(install.importlib.metadata, "version", _raise)
    from legis import __version__

    assert _instructions_version() == __version__


def test_build_block_has_open_and_close_markers():
    block = _build_instructions_block()
    assert block.startswith(f"{INSTRUCTIONS_MARKER}:{_marker_token()} -->")
    assert block.rstrip().endswith("<!-- /legis:instructions -->")
    assert _instructions_text() in block


def test_extract_marker_token_round_trips_the_writer():
    # The freshness check's reader must parse the exact marker the writer emits.
    # Driving it off the real `_build_instructions_block()` output (not a
    # hand-written marker) is what keeps the reader from silently desyncing if
    # the marker format ever changes — both live in install.py now.
    assert _extract_marker_token(_build_instructions_block()) == _marker_token()


def test_extract_marker_token_ignores_the_close_marker_and_absence():
    # The close marker (`<!-- /legis:instructions -->`) carries no token and must
    # not be mistaken for the open marker; absent any marker yields None.
    assert _extract_marker_token("<!-- /legis:instructions -->") is None
    assert _extract_marker_token("no marker here") is None


# ---------------------------------------------------------------------------
# inject_instructions
# ---------------------------------------------------------------------------


def test_inject_creates_missing_file(tmp_path):
    target = tmp_path / "CLAUDE.md"
    ok, msg = inject_instructions(target)
    assert ok
    assert "Created" in msg
    content = target.read_text()
    assert INSTRUCTIONS_MARKER in content
    assert "<!-- /legis:instructions -->" in content


def test_inject_appends_to_existing_file_without_marker(tmp_path):
    target = tmp_path / "AGENTS.md"
    target.write_text("# My project\n\nExisting guidance.\n")
    ok, msg = inject_instructions(target)
    assert ok
    assert "Appended" in msg
    content = target.read_text()
    assert "Existing guidance." in content
    assert content.index("Existing guidance.") < content.index(INSTRUCTIONS_MARKER)


def test_inject_replaces_existing_block_preserving_surrounding_text(
    tmp_path, monkeypatch
):
    target = tmp_path / "CLAUDE.md"
    target.write_text("TOP\n\n")
    inject_instructions(target)
    # Append trailing user content after the block.
    target.write_text(target.read_text() + "\nBOTTOM\n")

    monkeypatch.setattr(install, "_instructions_text", lambda: "NEW BODY CONTENT\n")
    ok, msg = inject_instructions(target)
    assert ok
    assert "Updated" in msg
    content = target.read_text()
    assert "TOP" in content
    assert "BOTTOM" in content
    assert "NEW BODY CONTENT" in content
    # Exactly one block remains.
    assert content.count(INSTRUCTIONS_MARKER) == 1
    assert content.count("<!-- /legis:instructions -->") == 1


def test_inject_idempotent_when_content_unchanged(tmp_path):
    target = tmp_path / "CLAUDE.md"
    inject_instructions(target)
    first = target.read_text()
    inject_instructions(target)
    assert target.read_text() == first


def test_inject_repairs_block_with_missing_end_marker(tmp_path):
    target = tmp_path / "CLAUDE.md"
    # Open marker but no close marker, plus trailing junk.
    target.write_text(
        f"HEAD\n{INSTRUCTIONS_MARKER}:vX:dead -->\norphan body no close\n"
    )
    ok, msg = inject_instructions(target)
    assert ok
    content = target.read_text()
    assert "HEAD" in content
    assert "orphan body no close" not in content
    assert content.count(INSTRUCTIONS_MARKER) == 1
    assert "<!-- /legis:instructions -->" in content


def test_inject_rejects_symlink_target(tmp_path):
    real = tmp_path / "real.md"
    real.write_text("x")
    link = tmp_path / "CLAUDE.md"
    link.symlink_to(real)
    ok, msg = inject_instructions(link)
    assert ok is False
    assert "symlink" in msg.lower()


# ---------------------------------------------------------------------------
# inject_instructions — foreign-block safety (peer of filigree-bcbd4d66fd)
# ---------------------------------------------------------------------------

_WARDLINE_BLOCK = (
    "<!-- wardline:instructions:v1:abcd1234 -->\n"
    "wardline body\n"
    "<!-- /wardline:instructions -->\n"
)


def test_inject_malformed_block_preserves_coresident_foreign_block(tmp_path):
    """An unclosed legis block must NOT truncate a sibling block that follows it."""
    target = tmp_path / "CLAUDE.md"
    target.write_text(
        "HEAD\n"
        f"{INSTRUCTIONS_MARKER}:vX:dead -->\n"
        "legis body, block NOT closed\n" + _WARDLINE_BLOCK
    )
    ok, _ = inject_instructions(target)
    assert ok
    content = target.read_text()
    # The foreign block survives intact.
    assert "wardline body" in content
    assert "<!-- wardline:instructions:v1:abcd1234 -->" in content
    assert "<!-- /wardline:instructions -->" in content
    # Exactly one well-formed legis block remains; the orphan body is gone.
    assert content.count(INSTRUCTIONS_MARKER) == 1
    assert "block NOT closed" not in content
    assert content.count("<!-- /legis:instructions -->") == 1


def test_inject_shape2_sandwich_preserves_foreign_block(tmp_path, caplog):
    """Unclosed-first / closed-later legis must not splice over a sandwiched sibling.

    The stale second legis block surviving beyond the foreign fence must also be
    surfaced as a warning (refinement 4), not silently shipped as a split brain.
    """
    target = tmp_path / "CLAUDE.md"
    target.write_text(
        "HEAD\n"
        f"{INSTRUCTIONS_MARKER}:vX:dead -->\n"
        "first legis body (unclosed)\n"
        + _WARDLINE_BLOCK
        + f"{INSTRUCTIONS_MARKER}:vY:beef -->\n"
        "second legis body\n"
        "<!-- /legis:instructions -->\n"
    )
    with caplog.at_level(logging.WARNING, logger="legis.install"):
        ok, _ = inject_instructions(target)
    assert ok
    content = target.read_text()
    assert "wardline body" in content
    assert "<!-- /wardline:instructions -->" in content
    # Stale duplicate beyond the foreign fence is surfaced, not silent.
    assert "duplicate that could not be canonicalised" in caplog.text


def test_inject_uppercase_namespace_sibling_survives(tmp_path):
    """A sibling block with an upper-cased namespace is still a boundary (refinement 1)."""
    target = tmp_path / "CLAUDE.md"
    target.write_text(
        "HEAD\n"
        f"{INSTRUCTIONS_MARKER}:vX:dead -->\n"
        "legis body no close\n"
        "<!-- Wardline:instructions:v1:abcd1234 -->\n"
        "wardline body\n"
        "<!-- /Wardline:instructions -->\n"
    )
    ok, _ = inject_instructions(target)
    assert ok
    content = target.read_text()
    assert "wardline body" in content
    assert "<!-- /Wardline:instructions -->" in content


def test_instructions_body_has_no_fence_token():
    """Pin: the shipped body must not contain a ``:instructions`` fence (refinement 2).

    The bounded scan runs across legis's own body; a fence token there would
    misroute the common well-formed path into bounded recovery.
    """
    assert ":instructions" not in _instructions_text()


def test_inject_marker_text_inside_foreign_block_not_mistaken_for_own(tmp_path):
    """A legis marker quoted *inside* a sibling block is not legis's own anchor.

    The literal ``<!-- legis:instructions ... -->`` can legitimately appear inside
    another tool's block (a quoted example, documentation). A bare substring anchor
    would splice there and gut the sibling. The anchor must respect foreign block
    spans, so this file has *no* legis block of its own → append, sibling untouched.
    """
    target = tmp_path / "CLAUDE.md"
    foreign_block = (
        "<!-- wardline:instructions:v1:zzz -->\n"
        f"See example: {INSTRUCTIONS_MARKER}:v0:0000 -->\n"
        "WARDLINE BODY MUST SURVIVE\n"
        "<!-- /wardline:instructions -->\n"
    )
    target.write_text("HEAD\n" + foreign_block)
    ok, _ = inject_instructions(target)
    assert ok
    content = target.read_text()
    # The sibling block is preserved verbatim — not gutted, not spliced into.
    assert foreign_block in content
    assert "WARDLINE BODY MUST SURVIVE" in content
    # Exactly one well-formed legis block was appended, after the sibling close.
    assert content.count("<!-- /legis:instructions -->") == 1
    assert content.rindex(INSTRUCTIONS_MARKER) > content.index(
        "<!-- /wardline:instructions -->"
    )


def test_inject_reinject_preserves_foreign_block_placed_before_legis(tmp_path):
    """A sibling block *before* the legis block survives re-injection on drift.

    The shared-file layout where wardline installs before legis is realistic; the
    in-place replace must not reach backwards past ``start`` into a preceding block.
    """
    target = tmp_path / "CLAUDE.md"
    target.write_text(
        "HEAD\n" + _WARDLINE_BLOCK + f"{INSTRUCTIONS_MARKER}:vX:dead -->\n"
        "stale legis body\n"
        "<!-- /legis:instructions -->\n"
    )
    ok, _ = inject_instructions(target)
    assert ok
    content = target.read_text()
    assert "wardline body" in content
    assert "<!-- wardline:instructions:v1:abcd1234 -->" in content
    assert "<!-- /wardline:instructions -->" in content
    # The legis block was replaced in place (stale body gone), exactly one remains.
    assert content.count(INSTRUCTIONS_MARKER) == 1
    assert "stale legis body" not in content
    # The sibling still precedes the legis block.
    assert content.index("<!-- wardline:instructions:v1:abcd1234 -->") < content.index(
        INSTRUCTIONS_MARKER
    )


def test_inject_bounded_recovery_is_idempotent(tmp_path):
    """Repairing a malformed block next to a foreign one is byte-stable on re-run (refinement 3)."""
    target = tmp_path / "CLAUDE.md"
    target.write_text(
        "HEAD\n"
        f"{INSTRUCTIONS_MARKER}:vX:dead -->\n"
        "legis body no close\n" + _WARDLINE_BLOCK
    )
    inject_instructions(target)
    first = target.read_text()
    inject_instructions(target)
    second = target.read_text()
    assert first == second
    assert "wardline body" in second


def test_inject_into_empty_file_produces_clean_single_block(tmp_path):
    """An existing zero-byte file gets a clean block, not leading blank lines."""
    target = tmp_path / "CLAUDE.md"
    target.write_text("")
    ok, _ = inject_instructions(target)
    assert ok
    content = target.read_text()
    assert content.count(INSTRUCTIONS_MARKER) == 1
    # No leading blank-line artifact: the block starts at byte 0.
    assert content.startswith(INSTRUCTIONS_MARKER)


def test_inject_crlf_file_preserves_foreign_block(tmp_path):
    """A CRLF-terminated shared file: the sibling block still survives recovery."""
    target = tmp_path / "CLAUDE.md"
    target.write_bytes(
        (
            "HEAD\r\n"
            f"{INSTRUCTIONS_MARKER}:vX:dead -->\r\n"
            "legis body, block NOT closed\r\n"
            "<!-- wardline:instructions:v1:abcd1234 -->\r\n"
            "wardline body\r\n"
            "<!-- /wardline:instructions -->\r\n"
        ).encode("utf-8")
    )
    ok, _ = inject_instructions(target)
    assert ok
    content = target.read_text()
    assert "wardline body" in content
    assert "<!-- /wardline:instructions -->" in content
    assert content.count(INSTRUCTIONS_MARKER) == 1


def test_inject_two_clean_legis_blocks_canonicalises_first_keeps_second(
    tmp_path, caplog
):
    """Two well-formed legis blocks: the first is canonicalised, the second is kept.

    Bounding at the first own close (not EOF) is deliberate — it preserves any
    trailing content legis does not own, so a second block in the tail is surfaced
    via a warning rather than silently deleted. Collapsing would require a deletion
    window over the bytes between the two blocks, which may be user content.
    """
    target = tmp_path / "CLAUDE.md"
    target.write_text(
        "HEAD\n"
        f"{INSTRUCTIONS_MARKER}:vX:dead -->\n"
        "first legis body\n"
        "<!-- /legis:instructions -->\n"
        f"{INSTRUCTIONS_MARKER}:vY:beef -->\n"
        "second legis body\n"
        "<!-- /legis:instructions -->\n"
    )
    with caplog.at_level(logging.WARNING, logger="legis.install"):
        ok, _ = inject_instructions(target)
    assert ok
    content = target.read_text()
    # First block canonicalised (stale body gone); second block NOT deleted.
    assert "first legis body" not in content
    assert "second legis body" in content
    # The surviving duplicate is surfaced, not silent.
    assert caplog.records


# ---------------------------------------------------------------------------
# _atomic_write_text
# ---------------------------------------------------------------------------


def test_atomic_write_preserves_existing_mode(tmp_path):
    target = tmp_path / "CLAUDE.md"
    target.write_text("seed")
    os.chmod(target, 0o640)
    inject_instructions(target)
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o640


def test_atomic_write_uses_safe_mode_without_touching_process_umask(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "CLAUDE.md"

    def reject_process_umask(_mode: int) -> int:
        raise AssertionError("process-wide umask must not be changed")

    monkeypatch.setattr(install.os, "umask", reject_process_umask)

    install._atomic_write_text(target, "new content\n")

    assert target.read_text(encoding="utf-8") == "new content\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_atomic_write_is_file_and_directory_durable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "CLAUDE.md"
    events: list[str] = []
    real_fsync = install.os.fsync
    real_replace = install.os.replace

    def observed_fsync(fd: int) -> None:
        mode = install.os.fstat(fd).st_mode
        events.append("fsync-directory" if stat.S_ISDIR(mode) else "fsync-file")
        real_fsync(fd)

    def observed_replace(*args, **kwargs) -> None:
        events.append("replace")
        real_replace(*args, **kwargs)

    monkeypatch.setattr(install.os, "fsync", observed_fsync)
    monkeypatch.setattr(install.os, "replace", observed_replace)

    install._atomic_write_text(target, "durable content\n")

    assert events == ["fsync-file", "replace", "fsync-directory"]
    assert target.read_text(encoding="utf-8") == "durable content\n"


def test_anchored_mcp_write_is_file_and_directory_durable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    events: list[str] = []
    real_fsync = install.os.fsync
    real_replace = install.os.replace

    def observed_fsync(fd: int) -> None:
        mode = install.os.fstat(fd).st_mode
        events.append("fsync-directory" if stat.S_ISDIR(mode) else "fsync-file")
        real_fsync(fd)

    def observed_replace(*args, **kwargs) -> None:
        events.append("replace")
        real_replace(*args, **kwargs)

    monkeypatch.setattr(install.os, "fsync", observed_fsync)
    monkeypatch.setattr(install.os, "replace", observed_replace)
    directory_fd = install._open_directory_path_nofollow(tmp_path.resolve())
    try:
        install._atomic_write_anchored_mcp_json(
            directory_fd,
            '{"mcpServers": {}}\n',
            mode=None,
        )
    finally:
        install.os.close(directory_fd)

    assert events == ["fsync-file", "replace", "fsync-directory"]
    assert (tmp_path / ".mcp.json").read_text(encoding="utf-8") == (
        '{"mcpServers": {}}\n'
    )


def test_reject_symlink_raises_on_symlink(tmp_path):
    real = tmp_path / "r"
    real.write_text("x")
    link = tmp_path / "l"
    link.symlink_to(real)
    with pytest.raises(UnsafeInstallPathError):
        reject_symlink(link)


@pytest.mark.parametrize("payload", ["", "   \n\t  \n"])
def test_atomic_write_refuses_empty_content(tmp_path, payload):
    """Refuse-to-empty guard (filigree-04bad2a2bf parity): never truncate a file to nothing."""
    target = tmp_path / "CLAUDE.md"
    target.write_text("populated content\n")
    with pytest.raises(ValueError, match="empty"):
        install._atomic_write_text(target, payload)
    # The populated file is left untouched.
    assert target.read_text() == "populated content\n"


# ---------------------------------------------------------------------------
# Skill pack
# ---------------------------------------------------------------------------


def test_install_skills_copies_pack(tmp_path):
    ok, msg = install_skills(tmp_path)
    assert ok
    skill = tmp_path / ".claude" / "skills" / SKILL_NAME / "SKILL.md"
    assert skill.is_file()
    assert "legis-workflow" in skill.read_text()


def test_install_codex_skills_targets_agents_dir(tmp_path):
    ok, _ = install_codex_skills(tmp_path)
    assert ok
    assert (tmp_path / ".agents" / "skills" / SKILL_NAME / "SKILL.md").is_file()


def test_install_skills_idempotent(tmp_path):
    install_skills(tmp_path)
    skill = tmp_path / ".claude" / "skills" / SKILL_NAME / "SKILL.md"
    first = skill.read_text()
    ok, _ = install_skills(tmp_path)
    assert ok
    assert skill.read_text() == first


def test_skill_tree_fingerprint_changes_with_content(tmp_path):
    root = tmp_path / "pack"
    root.mkdir()
    (root / "a.md").write_text("one")
    fp1 = _skill_tree_fingerprint(root)
    (root / "a.md").write_text("two")
    fp2 = _skill_tree_fingerprint(root)
    assert fp1 != fp2


# ---------------------------------------------------------------------------
# Hook registration
# ---------------------------------------------------------------------------


def _session_commands(settings: dict) -> list[str]:
    cmds: list[str] = []
    for block in settings.get("hooks", {}).get("SessionStart", []):
        for hook in block.get("hooks", []):
            cmds.append(hook.get("command", ""))
    return cmds


def test_install_hooks_fresh(tmp_path):
    ok, msg = install_claude_code_hooks(tmp_path)
    assert ok
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    cmds = _session_commands(settings)
    assert any(c.endswith("session-context") for c in cmds)


def test_install_hooks_idempotent_no_duplicate(tmp_path):
    install_claude_code_hooks(tmp_path)
    install_claude_code_hooks(tmp_path)
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    cmds = [c for c in _session_commands(settings) if c.endswith("session-context")]
    assert len(cmds) == 1


def test_install_hooks_upgrades_bare_command(tmp_path, monkeypatch):
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [
                                {"type": "command", "command": "legis session-context"}
                            ]
                        }
                    ]
                }
            }
        )
    )
    # Force a resolved binary path so the bare command must be upgraded.
    monkeypatch.setattr(
        install, "_find_legis_command", lambda *_a, **_k: ["/opt/bin/legis"]
    )
    ok, msg = install_claude_code_hooks(tmp_path)
    assert ok
    settings = json.loads((claude / "settings.json").read_text())
    cmds = _session_commands(settings)
    assert "/opt/bin/legis session-context" in cmds
    assert cmds.count("/opt/bin/legis session-context") == 1


def test_install_hooks_backs_up_malformed_settings(tmp_path, caplog):
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text("{ this is not json")
    with caplog.at_level(logging.WARNING, logger="legis.install"):
        ok, msg = install_claude_code_hooks(tmp_path)
    assert ok
    assert (claude / "settings.json.bak").is_file()
    settings = json.loads((claude / "settings.json").read_text())
    assert any(c.endswith("session-context") for c in _session_commands(settings))
    # The reset is not silent: the user is told a backup was written.
    assert ".bak" in msg
    assert ".bak" in caplog.text


def test_install_hooks_does_not_reuse_scoped_block(tmp_path):
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "matcher": "resume",
                            "hooks": [
                                {"type": "command", "command": "legis session-context"}
                            ],
                        }
                    ]
                }
            }
        )
    )
    install_claude_code_hooks(tmp_path)
    settings = json.loads((claude / "settings.json").read_text())
    # A new unscoped block must be added — the scoped one does not cover cold start.
    blocks = settings["hooks"]["SessionStart"]
    unscoped = [
        b for b in blocks if "matcher" not in b or b.get("matcher") in (None, "*")
    ]
    assert unscoped
    assert any(
        h["command"].endswith("session-context") for b in unscoped for h in b["hooks"]
    )


# ---------------------------------------------------------------------------
# _hook_cmd_matches
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command,expected",
    [
        ("legis session-context", True),
        ("/usr/local/bin/legis session-context", True),
        ("./legis session-context", False),
        ("bin/legis session-context", False),
        ("/path/python -P -m legis session-context", True),
        ("/path/python -m legis session-context", True),
        ("echo legis session-context", False),
        ("legis serve", False),
    ],
)
def test_hook_cmd_matches(command, expected):
    assert install._hook_cmd_matches(command, "legis session-context") is expected


# ---------------------------------------------------------------------------
# register_mcp_json
# ---------------------------------------------------------------------------


def test_register_mcp_json_creates_file_with_legis_entry(tmp_path, monkeypatch):
    from legis.install import register_mcp_json

    monkeypatch.setattr(
        install,
        "_find_legis_command",
        lambda *_a, **_k: ["/usr/bin/python3", "-P", "-m", "legis"],
    )
    ok, msg = register_mcp_json(tmp_path)
    assert ok, msg
    data = json.loads((tmp_path / ".mcp.json").read_text())
    entry = data["mcpServers"]["legis"]
    assert entry["type"] == "stdio"
    assert entry["command"] == "/usr/bin/python3"
    assert entry["args"] == ["-P", "-m", "legis", "mcp", "--agent-id", "claude-code"]
    assert "--agent-id" in entry["args"]
    lock = tmp_path / ".mcp.json.legis.lock"
    assert lock.is_file()
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600


def test_register_mcp_json_uses_shared_writer_lock(tmp_path, monkeypatch) -> None:
    assert hasattr(install, "_config_writer_lock")
    locked_paths: list[Path] = []

    @contextmanager
    def observed_lock(path: Path):
        locked_paths.append(path)
        yield

    monkeypatch.setattr(install, "_config_writer_lock", observed_lock)

    ok, _ = install.register_mcp_json(tmp_path)

    assert ok
    assert locked_paths == [tmp_path / ".mcp.json"]


@pytest.mark.parametrize(
    "operation",
    ["install", "doctor-register", "doctor-binding-scan"],
)
def test_mcp_json_fifo_is_rejected_without_blocking(
    tmp_path: Path,
    operation: str,
) -> None:
    os.mkfifo(tmp_path / ".mcp.json")
    script = """
import sys
from pathlib import Path

root = Path(sys.argv[1])
operation = sys.argv[2]
if operation == "install":
    from legis.install import register_mcp_json
    result = register_mcp_json(root)
elif operation == "doctor-register":
    from legis.install import register_mcp_json
    result = register_mcp_json(root, doctor_safe=True)
else:
    from legis.doctor import check_filigree_binding_scope
    check = check_filigree_binding_scope(root)
    result = (check.status, check.repairable, check.message)
print(repr(result))
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path), operation],
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    if operation == "doctor-binding-scan":
        assert completed.stdout.startswith("('error', False,")
    else:
        assert completed.stdout.startswith("(False,")
    assert stat.S_ISFIFO((tmp_path / ".mcp.json").stat().st_mode)


@pytest.mark.parametrize("extra_byte", [False, True], ids=["exact-limit", "over-limit"])
def test_project_mcp_reader_size_limit(
    tmp_path: Path,
    extra_byte: bool,
) -> None:
    config = tmp_path / ".mcp.json"
    payload = b"{}" + b" " * (install._MAX_PROJECT_MCP_JSON_BYTES - 2 + int(extra_byte))
    config.write_bytes(payload)

    if extra_byte:
        with pytest.raises(ValueError, match="1 MiB"):
            install._read_mcp_json_path(config)
    else:
        snapshot = install._read_mcp_json_path(config)
        assert snapshot is not None and snapshot[0] == payload


def test_doctor_safe_register_rejects_project_root_swap(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    config = project / ".mcp.json"
    config.write_text('{"mcpServers": {}}\n', encoding="utf-8")
    original = config.read_bytes()
    moved = tmp_path / "moved-project"
    external = tmp_path / "external"
    external.mkdir()
    real_lock = install._config_writer_lock
    swapped = False

    @contextmanager
    def swap_before_lock(path: Path, *, dir_fd: int | None = None):
        nonlocal swapped
        if not swapped:
            swapped = True
            project.rename(moved)
            project.symlink_to(external, target_is_directory=True)
        with real_lock(path, dir_fd=dir_fd):
            yield

    monkeypatch.setattr(install, "_config_writer_lock", swap_before_lock)

    ok, message = install.register_mcp_json(project, doctor_safe=True)

    assert ok is False
    assert "changed" in message.lower()
    assert not (external / ".mcp.json").exists()
    assert (moved / ".mcp.json").read_bytes() == original


def test_doctor_safe_register_rechecks_project_root_immediately_before_write(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    moved = tmp_path / "moved-project"
    external = tmp_path / "external"
    external.mkdir()
    real_read = install._read_anchored_mcp_json
    reads = 0

    def swap_after_final_snapshot_read(directory_fd: int):
        nonlocal reads
        snapshot = real_read(directory_fd)
        reads += 1
        if reads == 2:
            project.rename(moved)
            project.symlink_to(external, target_is_directory=True)
        return snapshot

    monkeypatch.setattr(
        install,
        "_read_anchored_mcp_json",
        swap_after_final_snapshot_read,
    )

    ok, message = install.register_mcp_json(project, doctor_safe=True)

    assert reads == 2
    assert ok is False
    assert "changed" in message.lower()
    assert not (external / ".mcp.json").exists()
    assert not (moved / ".mcp.json").exists()


def test_doctor_safe_register_contains_oversized_final_recheck(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text('{"mcpServers": {}}\n', encoding="utf-8")
    real_read = install._read_anchored_mcp_json
    oversized = b"{}" + b" " * (install._MAX_PROJECT_MCP_JSON_BYTES - 1)
    reads = 0

    def replace_before_second_read(directory_fd: int):
        nonlocal reads
        reads += 1
        if reads == 2:
            config.write_bytes(oversized)
        return real_read(directory_fd)

    monkeypatch.setattr(
        install,
        "_read_anchored_mcp_json",
        replace_before_second_read,
    )

    ok, message = install.register_mcp_json(tmp_path, doctor_safe=True)

    assert reads == 2
    assert ok is False
    assert "changed" in message.lower()
    assert config.read_bytes() == oversized


def test_missing_nonblock_reports_mcp_reader_capability(
    monkeypatch,
) -> None:
    monkeypatch.setattr(install.os, "O_NONBLOCK", None)

    error = install._config_writer_lock_support_error()

    assert error is not None
    assert "project mcp" in error.lower()
    assert "read" in error.lower()


def test_doctor_safe_register_closes_project_fd_when_initial_fstat_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    opened: list[int] = []
    real_open_directory = install._open_directory_path_nofollow
    real_fstat = install.os.fstat

    def capture_open(path: Path) -> int:
        fd = real_open_directory(path)
        opened.append(fd)
        return fd

    def fail_initial_fstat(fd: int):
        if opened and fd == opened[0]:
            raise PermissionError("simulated initial inspection failure")
        return real_fstat(fd)

    monkeypatch.setattr(install, "_open_directory_path_nofollow", capture_open)
    monkeypatch.setattr(install.os, "fstat", fail_initial_fstat)

    ok, message = install.register_mcp_json(tmp_path, doctor_safe=True)

    assert ok is False
    assert "safely" in message.lower()
    assert len(opened) == 1
    with pytest.raises(OSError):
        real_fstat(opened[0])


def test_register_mcp_json_rejects_symlinked_writer_lock(tmp_path: Path) -> None:
    external = tmp_path / "external.lock"
    external.touch()
    (tmp_path / ".mcp.json.legis.lock").symlink_to(external)

    ok, message = install.register_mcp_json(tmp_path)

    assert ok is False
    assert "lock" in message.lower()
    assert not (tmp_path / ".mcp.json").exists()


def test_register_mcp_json_rejects_hardlinked_writer_lock(tmp_path: Path) -> None:
    victim = tmp_path / "operator-owned"
    victim.touch()
    victim.chmod(0o644)
    os.link(victim, tmp_path / ".mcp.json.legis.lock")

    ok, message = install.register_mcp_json(tmp_path)

    assert ok is False
    assert "lock" in message.lower()
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    assert not (tmp_path / ".mcp.json").exists()


def test_writer_lock_revalidates_path_identity_after_acquiring_flock(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / ".mcp.json"
    lock_path = tmp_path / ".mcp.json.legis.lock"
    orphaned_lock = tmp_path / "orphaned.lock"
    real_fchmod = install.os.fchmod
    swapped = False
    nested_acquired = False
    outer_yielded = False

    def swap_lock_during_fchmod(fd: int, mode: int) -> None:
        nonlocal swapped, nested_acquired
        real_fchmod(fd, mode)
        if swapped:
            return
        swapped = True
        lock_path.rename(orphaned_lock)
        lock_path.touch(mode=0o600)
        with install._config_writer_lock(target):
            nested_acquired = True

    monkeypatch.setattr(install.os, "fchmod", swap_lock_during_fchmod)

    with pytest.raises(install._ConfigWriterLockError, match="changed"):
        with install._config_writer_lock(target):
            outer_yielded = True

    assert nested_acquired is True
    assert outer_yielded is False


def test_register_mcp_json_returns_error_for_symlinked_target(tmp_path: Path) -> None:
    external = tmp_path / "external.json"
    external.write_text("{}\n", encoding="utf-8")
    (tmp_path / ".mcp.json").symlink_to(external)

    ok, message = install.register_mcp_json(tmp_path)

    assert ok is False
    assert "symlink" in message.lower()
    assert external.read_text(encoding="utf-8") == "{}\n"


def test_register_mcp_json_preserves_sibling_entries(tmp_path):
    from legis.install import register_mcp_json

    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"filigree": {"command": "x", "type": "stdio"}}})
    )
    ok, _ = register_mcp_json(tmp_path)
    assert ok
    data = json.loads((tmp_path / ".mcp.json").read_text())
    assert "filigree" in data["mcpServers"]
    assert "legis" in data["mcpServers"]


def test_register_mcp_json_idempotent(tmp_path):
    from legis.install import register_mcp_json

    register_mcp_json(tmp_path)
    first = (tmp_path / ".mcp.json").read_text()
    register_mcp_json(tmp_path)
    assert (tmp_path / ".mcp.json").read_text() == first


def test_legis_mcp_entry_module_fallback_splits_command_and_args(monkeypatch):
    monkeypatch.setattr(
        install,
        "_find_legis_command",
        lambda *_a, **_k: ["/usr/bin/python3", "-P", "-m", "legis"],
    )
    entry = install._legis_mcp_entry("claude-code")
    assert entry["command"] == "/usr/bin/python3"
    assert entry["args"] == ["-P", "-m", "legis", "mcp", "--agent-id", "claude-code"]


def test_register_mcp_json_explicit_agent_id_wins_over_existing(tmp_path):
    from legis.install import register_mcp_json

    register_mcp_json(tmp_path, "claude-code")
    register_mcp_json(tmp_path, "new-bot")
    data = json.loads((tmp_path / ".mcp.json").read_text())
    args = data["mcpServers"]["legis"]["args"]
    i = args.index("--agent-id")
    assert args[i + 1] == "new-bot"


def test_register_mcp_json_default_preserves_existing_agent_id(tmp_path):
    from legis.install import register_mcp_json

    register_mcp_json(tmp_path, "operator-pick")
    register_mcp_json(tmp_path)  # default (None) → preserve operator choice
    data = json.loads((tmp_path / ".mcp.json").read_text())
    args = data["mcpServers"]["legis"]["args"]
    i = args.index("--agent-id")
    assert args[i + 1] == "operator-pick"


def test_register_mcp_json_non_dict_top_level_is_rejected_unchanged(tmp_path):
    from legis.install import register_mcp_json

    mcp = tmp_path / ".mcp.json"
    mcp.write_text("[]")
    ok, msg = register_mcp_json(tmp_path)
    assert ok is False
    assert "not a JSON object" in msg
    assert mcp.read_text() == "[]"


def test_register_mcp_json_rejects_duplicate_keys_unchanged(tmp_path: Path) -> None:
    from legis.install import register_mcp_json

    mcp = tmp_path / ".mcp.json"
    mcp.write_text(
        '{"mcpServers":{"sibling":{"command":"keep"}},"mcpServers":{}}',
        encoding="utf-8",
    )
    before = mcp.read_bytes()

    ok, message = register_mcp_json(tmp_path)

    assert ok is False
    assert "unreadable" in message.lower()
    assert mcp.read_bytes() == before


@pytest.mark.parametrize("doctor_safe", [False, True], ids=["install", "doctor"])
def test_register_mcp_json_rejects_deep_nesting_unchanged(
    tmp_path: Path,
    doctor_safe: bool,
) -> None:
    mcp = tmp_path / ".mcp.json"
    mcp.write_text("[" * 101 + "0" + "]" * 101, encoding="utf-8")
    before = mcp.read_bytes()

    ok, message = install.register_mcp_json(tmp_path, doctor_safe=doctor_safe)

    assert ok is False
    assert "unreadable" in message.lower()
    assert install.mcp_entry_is_current(tmp_path) is False
    assert mcp.read_bytes() == before


@pytest.mark.parametrize(
    "number",
    ["1e1000", "1e-1000", "-1e-1000", "1.234567890123456789"],
)
def test_strict_json_rejects_lossy_floating_point_numbers(number: str) -> None:
    with pytest.raises(ValueError, match="non-finite|without loss"):
        install._strict_json_loads(f'{{"unrelated": {number}}}')

    assert install._strict_json_loads('{"finite": 1e100}') == {"finite": 1e100}


def test_strict_json_enforces_nesting_limit() -> None:
    at_limit = "[" * 100 + "0" + "]" * 100
    over_limit = "[" * 101 + "0" + "]" * 101
    brackets_inside_string = json.dumps("[" * 101)

    assert install._strict_json_loads(at_limit) is not None
    assert install._strict_json_loads(brackets_inside_string) == "[" * 101
    with pytest.raises(ValueError, match="nesting"):
        install._strict_json_loads(over_limit)


# ---------------------------------------------------------------------------
# .gitignore
# ---------------------------------------------------------------------------


def test_ensure_gitignore_creates_file(tmp_path):
    ok, msg = ensure_gitignore(tmp_path)
    assert ok
    content = (tmp_path / ".gitignore").read_text()
    assert ".weft/legis/" in content
    assert "/.mcp.json.legis.lock" in content
    assert ".weft/\n" not in content


def test_ensure_gitignore_appends_missing_rules(tmp_path):
    (tmp_path / ".gitignore").write_text("*.db\n")
    ok, msg = ensure_gitignore(tmp_path)
    assert ok
    content = (tmp_path / ".gitignore").read_text()
    assert "*.db" in content
    assert ".weft/legis/" in content
    assert ".weft/\n" not in content


def test_ensure_gitignore_does_not_accept_top_level_weft_rule(tmp_path):
    (tmp_path / ".gitignore").write_text(".weft/\n")
    ok, msg = ensure_gitignore(tmp_path)
    assert ok
    assert "Added" in msg
    content = (tmp_path / ".gitignore").read_text()
    assert ".weft/\n" in content
    assert ".weft/legis/\n" in content


def test_gitignore_rules_present_missing_root_is_false(tmp_path):
    assert install.gitignore_rules_present(tmp_path / "missing") is False


def test_ensure_gitignore_idempotent(tmp_path):
    ensure_gitignore(tmp_path)
    first = (tmp_path / ".gitignore").read_text()
    ok, msg = ensure_gitignore(tmp_path)
    assert ok
    assert "already" in msg
    assert (tmp_path / ".gitignore").read_text() == first


# ---------------------------------------------------------------------------
# Nested .weft/legis/.gitignore (suite standard: filigree-4ed8152630)
# ---------------------------------------------------------------------------


def _git(repo, *args):
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=False
    )


def test_ensure_legis_dir_gitignore_creates_nested_file(tmp_path):
    ok, _msg = install.ensure_legis_dir_gitignore(tmp_path)
    assert ok
    nested = tmp_path / ".weft" / "legis" / ".gitignore"
    assert nested.is_file()
    content = nested.read_text()
    # durable-vs-ephemeral header + named runtime files (reviewer visibility)
    assert install.LEGIS_DIR_GITIGNORE_MARKER in content
    assert "legis-*.db" in content
    assert "operator.age" in content
    assert "operator_session.json" in content
    # atomic-write staging temps (mkstemp orphans) — incl. the secret-shaped one
    assert "*.tmp" in content
    assert ".operator.age.*" in content


def test_ensure_legis_dir_gitignore_idempotent(tmp_path):
    install.ensure_legis_dir_gitignore(tmp_path)
    nested = tmp_path / ".weft" / "legis" / ".gitignore"
    first = nested.read_text()
    ok, msg = install.ensure_legis_dir_gitignore(tmp_path)
    assert ok
    assert "already" in msg
    assert nested.read_text() == first


def test_ensure_legis_dir_gitignore_appends_to_user_file_without_clobber(tmp_path):
    legis_dir = tmp_path / ".weft" / "legis"
    legis_dir.mkdir(parents=True)
    (legis_dir / ".gitignore").write_text("# my own rule\nscratch/\n")
    ok, msg = install.ensure_legis_dir_gitignore(tmp_path)
    assert ok
    assert "Added" in msg
    content = (legis_dir / ".gitignore").read_text()
    assert "scratch/" in content  # user content preserved
    assert install.LEGIS_DIR_GITIGNORE_MARKER in content  # legis block appended


def test_nested_gitignore_hides_runtime_state_without_root_weft_rule(tmp_path):
    """The standard's actual guarantee: the nested file hides legis runtime
    state even when the project-root .gitignore has NO .weft/ rule, so the
    nested file is provably the thing doing the work."""
    if shutil.which("git") is None:
        pytest.skip("git not available")
    repo = tmp_path
    _git(repo, "init")
    # Root .gitignore deliberately has NO .weft/ rule — any ignore of legis
    # runtime files can therefore only come from the nested file.
    (repo / ".gitignore").write_text("node_modules/\n")
    install.ensure_legis_dir_gitignore(repo)
    legis_dir = repo / ".weft" / "legis"
    (legis_dir / "legis-pulls.db").write_bytes(b"")
    (legis_dir / "operator.age").write_bytes(b"")
    (legis_dir / "operator_session.json5678.tmp").write_bytes(b"")  # mkstemp orphan
    # DB + secret + staging temp are ignored by the nested file...
    assert _git(repo, "check-ignore", ".weft/legis/legis-pulls.db").returncode == 0
    assert _git(repo, "check-ignore", ".weft/legis/operator.age").returncode == 0
    assert (
        _git(
            repo, "check-ignore", ".weft/legis/operator_session.json5678.tmp"
        ).returncode
        == 0
    )
    # ...but the nested .gitignore itself stays tracked (not ignored).
    assert _git(repo, "check-ignore", ".weft/legis/.gitignore").returncode == 1


# ---------------------------------------------------------------------------
# Command resolution and safe-path edges
# ---------------------------------------------------------------------------


def test_find_legis_command_prefers_binary_on_path(monkeypatch):
    monkeypatch.setattr(install.shutil, "which", lambda _name: "/opt/bin/legis")
    assert install._find_legis_command() == ["/opt/bin/legis"]


def test_find_legis_command_module_fallback(monkeypatch):
    monkeypatch.setattr(install.shutil, "which", lambda _name: None)
    cmd = install._find_legis_command()
    assert cmd[-3:] == ["-P", "-m", "legis"]


def test_project_path_rejects_symlinked_component(tmp_path):
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    link_dir = tmp_path / ".claude"
    link_dir.symlink_to(real_dir, target_is_directory=True)
    with pytest.raises(UnsafeInstallPathError):
        install.project_path(tmp_path, ".claude", "settings.json")


def test_ensure_project_dir_creates_and_returns_dir(tmp_path):
    created = install.ensure_project_dir(tmp_path, ".claude", "skills")
    assert created.is_dir()
    assert created == tmp_path / ".claude" / "skills"


def test_install_skills_reports_missing_source(tmp_path, monkeypatch):
    empty = tmp_path / "no_skills_here"
    empty.mkdir()
    monkeypatch.setattr(install, "_get_skills_source_dir", lambda: empty)
    ok, msg = install_skills(tmp_path)
    assert ok is False
    assert "not found" in msg


def test_upgrade_hook_commands_tolerates_non_dict_settings():
    assert (
        install._upgrade_hook_commands({"hooks": []}, "legis session-context", "x")
        is False
    )
    assert install._upgrade_hook_commands({}, "legis session-context", "x") is False


def test_has_unscoped_session_start_hook_tolerates_non_dict():
    assert (
        install._has_unscoped_session_start_hook(
            {"hooks": "nope"}, "legis session-context"
        )
        is False
    )
    assert (
        install._has_unscoped_session_start_hook({}, "legis session-context") is False
    )


def test_has_unscoped_session_start_hook_rejects_repo_local_command(tmp_path):
    settings = {
        "hooks": {
            "SessionStart": [
                {"hooks": [{"type": "command", "command": "./legis session-context"}]}
            ]
        }
    }
    assert (
        install._has_unscoped_session_start_hook(
            settings,
            "legis session-context",
            project_root=tmp_path,
        )
        is False
    )


def test_install_hooks_rewrites_repo_local_hook_command(tmp_path, monkeypatch):
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "./legis session-context",
                                }
                            ]
                        }
                    ]
                }
            }
        )
    )
    monkeypatch.setattr(
        install, "_find_legis_command", lambda *_a, **_k: ["/opt/bin/legis"]
    )
    ok, msg = install_claude_code_hooks(tmp_path)
    assert ok, msg
    blocks = json.loads((claude / "settings.json").read_text())["hooks"]["SessionStart"]
    commands = [h["command"] for block in blocks for h in block["hooks"]]
    assert commands == ["/opt/bin/legis session-context"]


def test_install_hooks_leaves_user_scoped_block_command_untouched(
    tmp_path, monkeypatch
):
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "matcher": "resume",
                            "hooks": [
                                {"type": "command", "command": "legis session-context"}
                            ],
                        }
                    ]
                }
            }
        )
    )
    monkeypatch.setattr(
        install, "_find_legis_command", lambda *_a, **_k: ["/opt/bin/legis"]
    )
    install_claude_code_hooks(tmp_path)
    blocks = json.loads((claude / "settings.json").read_text())["hooks"]["SessionStart"]

    scoped = [b for b in blocks if b.get("matcher") == "resume"][0]
    # The user's portable bare command must NOT be pinned to a venv path.
    assert scoped["hooks"][0]["command"] == "legis session-context"
    # legis still adds its own unscoped block with the resolved command.
    unscoped = [
        b for b in blocks if "matcher" not in b or b.get("matcher") in (None, "*")
    ]
    assert any(
        h["command"] == "/opt/bin/legis session-context"
        for b in unscoped
        for h in b["hooks"]
    )


def test_install_hooks_backs_up_nested_corrupt_structure(tmp_path):
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text(
        json.dumps({"hooks": "important user data", "keep": 1})
    )
    ok, msg = install_claude_code_hooks(tmp_path)
    assert ok
    bak = claude / "settings.json.bak"
    assert bak.is_file()
    assert "important user data" in bak.read_text()
    settings = json.loads((claude / "settings.json").read_text())
    assert settings.get("keep") == 1  # sibling key preserved
    assert any(c.endswith("session-context") for c in _session_commands(settings))
    # The recovery of the corrupt nested structure is surfaced, not silent.
    assert ".bak" in msg


def test_install_skills_restores_original_on_genuine_swap_failure(
    tmp_path, monkeypatch
):
    install_skills(tmp_path)
    skill = tmp_path / ".claude" / "skills" / SKILL_NAME / "SKILL.md"
    original = skill.read_text()

    real_rename = os.rename
    calls = {"n": 0}

    def flaky_rename(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:  # the staging -> target swap
            raise OSError("simulated swap failure")
        return real_rename(src, dst)

    monkeypatch.setattr(install.os, "rename", flaky_rename)
    ok, msg = install_skills(tmp_path)

    assert ok is False
    assert "swap failed" in msg
    # The previously installed pack must survive a genuine swap failure.
    assert skill.is_file()
    assert skill.read_text() == original


def test_inject_append_keeps_marker_off_users_last_line(tmp_path):
    target = tmp_path / "CLAUDE.md"
    target.write_text("# Project\nlast line no newline")  # no trailing newline
    inject_instructions(target)
    content = target.read_text()
    assert "last line no newline\n" in content
    idx = content.index(INSTRUCTIONS_MARKER)
    assert content[idx - 1] == "\n"


def test_ensure_gitignore_present_among_other_rules_not_duplicated(tmp_path):
    # All of legis's rules already present alongside unrelated rules → nothing to
    # add. The posture-ratchet operator-secret paths are now part of the rule set
    # (root-anchored), and the stable writer lock is local-only, so a complete
    # .gitignore lists all four.
    (tmp_path / ".gitignore").write_text(
        "*.db\n"
        ".weft/legis/\n"
        "/.weft/legis/operator_session.json\n"
        "/.weft/legis/operator.age\n"
        "/.mcp.json.legis.lock\n"
    )
    ok, msg = ensure_gitignore(tmp_path)
    assert ok
    assert "already" in msg  # detected as present, not re-appended
    content = (tmp_path / ".gitignore").read_text()
    # The bare subtree line appears exactly once (not re-appended).
    subtree_lines = [ln for ln in content.splitlines() if ln.strip() == ".weft/legis/"]
    assert len(subtree_lines) == 1


# ---------------------------------------------------------------------------
# legis-788a85fac1 — faithful binary resolution + operator-state preservation.
# `legis install` (and doctor --fix, which calls the same writers) must never
# repoint a WORKING command at whatever `which legis` happens to find, and must
# never wipe an operator-customized .mcp.json env. Staleness means "cannot
# run" (bare token or dead path) — the same invariant mcp_entry_is_current
# already encodes for the reader side.
# ---------------------------------------------------------------------------


def _touch_exe(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


def _write_legis_mcp_entry(
    tmp_path,
    command,
    env=None,
    agent_id="claude-code",
    args=None,
):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "legis": {
                        "args": args or ["mcp", "--agent-id", agent_id],
                        "command": str(command),
                        "env": dict(env or {}),
                        "type": "stdio",
                    }
                }
            }
        )
    )


def _read_legis_mcp_entry(tmp_path):
    return json.loads((tmp_path / ".mcp.json").read_text())["mcpServers"]["legis"]


def test_find_legis_command_prefers_running_executable(tmp_path, monkeypatch):
    # A dev-venv legis shadows PATH, but the process was launched from the
    # uv-tool binary — the running executable must win, not `which legis`.
    import sys

    running = _touch_exe(tmp_path / "uv-tools" / "legis")
    shadow = _touch_exe(tmp_path / "dev-venv" / "legis")
    monkeypatch.setenv("PATH", str(shadow.parent), prepend=os.pathsep)
    monkeypatch.setattr(sys, "argv", [str(running), "install"])
    assert install._find_legis_command() == [str(running)]


def test_find_legis_command_path_fallback_when_argv0_is_not_legis(
    tmp_path, monkeypatch
):
    # Not running as the legis entrypoint (e.g. pytest) → PATH lookup stands.
    import sys

    shadow = _touch_exe(tmp_path / "bin" / "legis")
    monkeypatch.setenv("PATH", str(shadow.parent))
    monkeypatch.setattr(sys, "argv", ["/usr/bin/pytest"])
    assert install._find_legis_command() == [str(shadow)]


def test_find_legis_command_skips_project_local_running_binary(tmp_path, monkeypatch):
    # `legis install` launched from a repo venv (<repo>/.venv/bin/legis): the
    # running binary is project-local, so the freshness checks would flag any
    # entry written with it as stale-on-arrival. With project_root given, the
    # resolver skips it in favour of the stable global tool on PATH.
    import sys

    project_root = tmp_path / "repo"
    running = _touch_exe(project_root / ".venv" / "bin" / "legis")
    global_legis = _touch_exe(tmp_path / "uv-tools" / "legis")
    monkeypatch.setenv("PATH", str(global_legis.parent))
    monkeypatch.setattr(sys, "argv", [str(running), "install"])

    # Without project_root the running binary still wins (faithful resolution).
    assert install._find_legis_command() == [str(running)]
    # With it, the project-local running binary is skipped for the global tool.
    resolved = install._find_legis_command(project_root)
    assert resolved == [str(global_legis)]
    assert not install._path_head_is_project_local(resolved[0], project_root)


def test_find_legis_command_scans_past_project_local_path_hit(tmp_path, monkeypatch):
    # PATH lists a project-local legis first, then a stable one — the resolver
    # must scan past the local shim instead of returning it.
    import sys

    project_root = tmp_path / "repo"
    local = _touch_exe(project_root / ".venv" / "bin" / "legis")
    stable = _touch_exe(tmp_path / "uv-tools" / "legis")
    monkeypatch.setenv("PATH", os.pathsep.join([str(local.parent), str(stable.parent)]))
    monkeypatch.setattr(sys, "argv", ["/usr/bin/pytest"])
    assert install._find_legis_command(project_root) == [str(stable)]


def test_register_mcp_json_preserves_customized_env(tmp_path, monkeypatch):
    from legis.install import register_mcp_json

    exe = _touch_exe(tmp_path / "tools" / "legis")
    _write_legis_mcp_entry(
        tmp_path, exe, env={"LEGIS_WARDLINE_CELL": "surface_override"}
    )
    monkeypatch.setattr(
        install, "_find_legis_command", lambda *_a, **_k: ["/opt/bin/legis"]
    )
    ok, _ = register_mcp_json(tmp_path)
    assert ok
    assert _read_legis_mcp_entry(tmp_path)["env"] == {
        "LEGIS_WARDLINE_CELL": "surface_override"
    }


def test_register_mcp_json_keeps_usable_command(tmp_path, monkeypatch):
    # A working binary that differs from the current resolution is operator
    # state, not drift — the entry must be left alone.
    from legis.install import register_mcp_json

    exe = _touch_exe(tmp_path.parent / f"{tmp_path.name}-external" / "legis")
    _write_legis_mcp_entry(tmp_path, exe)
    monkeypatch.setattr(
        install, "_find_legis_command", lambda *_a, **_k: ["/opt/elsewhere/legis"]
    )
    ok, msg = register_mcp_json(tmp_path)
    assert ok
    assert "already" in msg
    assert _read_legis_mcp_entry(tmp_path)["command"] == str(exe)


def test_register_mcp_json_rewrites_non_legis_executable(tmp_path, monkeypatch):
    from legis.install import register_mcp_json

    fake = _touch_exe(tmp_path.parent / f"{tmp_path.name}-external" / "fake-runner")
    safe_legis = "/opt/bin/legis"
    _write_legis_mcp_entry(
        tmp_path, fake, env={"LEGIS_WARDLINE_CELL": "surface_override"}
    )
    monkeypatch.setattr(install, "_find_legis_command", lambda *_a, **_k: [safe_legis])

    ok, msg = register_mcp_json(tmp_path)

    assert ok
    assert "Registered" in msg
    entry = _read_legis_mcp_entry(tmp_path)
    assert entry["command"] == safe_legis
    assert entry["env"] == {"LEGIS_WARDLINE_CELL": "surface_override"}


def test_register_mcp_json_rewrites_python_module_without_safe_path(
    tmp_path,
    monkeypatch,
):
    from legis.install import register_mcp_json

    _write_legis_mcp_entry(
        tmp_path,
        sys.executable,
        env={"LEGIS_WARDLINE_CELL": "surface_override"},
        args=["-m", "legis", "mcp", "--agent-id", "claude-code"],
    )
    monkeypatch.setattr(
        install,
        "_find_legis_command",
        lambda *_a, **_k: ["/usr/bin/python3", "-P", "-m", "legis"],
    )

    ok, _ = register_mcp_json(tmp_path)

    assert ok
    entry = _read_legis_mcp_entry(tmp_path)
    assert entry["command"] == "/usr/bin/python3"
    assert entry["args"] == ["-P", "-m", "legis", "mcp", "--agent-id", "claude-code"]
    assert entry["env"] == {"LEGIS_WARDLINE_CELL": "surface_override"}


def test_register_mcp_json_rewrites_fake_python_prefixed_executable(
    tmp_path,
    monkeypatch,
):
    from legis.install import register_mcp_json

    fake = _touch_exe(tmp_path.parent / f"{tmp_path.name}-external" / "python3-fake")
    _write_legis_mcp_entry(
        tmp_path,
        fake,
        env={"LEGIS_WARDLINE_CELL": "surface_override"},
        args=["-P", "-m", "legis", "mcp", "--agent-id", "claude-code"],
    )
    monkeypatch.setattr(
        install,
        "_find_legis_command",
        lambda *_a, **_k: ["/usr/bin/python3", "-P", "-m", "legis"],
    )

    ok, _ = register_mcp_json(tmp_path)

    assert ok
    entry = _read_legis_mcp_entry(tmp_path)
    assert entry["command"] == "/usr/bin/python3"
    assert entry["args"] == ["-P", "-m", "legis", "mcp", "--agent-id", "claude-code"]
    assert entry["env"] == {"LEGIS_WARDLINE_CELL": "surface_override"}


def test_register_mcp_json_refreshes_dead_command_but_keeps_env(tmp_path, monkeypatch):
    from legis.install import register_mcp_json

    dead = tmp_path / "gone-venv" / "legis"  # never created
    _write_legis_mcp_entry(
        tmp_path, dead, env={"LEGIS_WARDLINE_CELL": "surface_override"}
    )
    monkeypatch.setattr(
        install, "_find_legis_command", lambda *_a, **_k: ["/opt/bin/legis"]
    )
    ok, _ = register_mcp_json(tmp_path)
    assert ok
    entry = _read_legis_mcp_entry(tmp_path)
    assert entry["command"] == "/opt/bin/legis"
    assert entry["env"] == {"LEGIS_WARDLINE_CELL": "surface_override"}


def test_register_mcp_json_drops_unsafe_or_secret_env(tmp_path, monkeypatch):
    from legis.install import register_mcp_json

    exe = _touch_exe(tmp_path / "tools" / "legis")
    _write_legis_mcp_entry(
        tmp_path,
        exe,
        env={
            "LEGIS_WARDLINE_CELL": "surface_override",
            "LEGIS_UNSAFE_DEV_AUTH": "1",
            "LEGIS_HMAC_KEY": "secret",
            # Retired by G11 but still secret-shaped: a stale operator-set value
            # must still be scrubbed, never copied verbatim into .mcp.json.
            "LEGIS_FILIGREE_HMAC_KEY": "stale-retired-secret",
            "OPENROUTER_API_KEY": "secret",
        },
    )
    monkeypatch.setattr(
        install, "_find_legis_command", lambda *_a, **_k: ["/opt/bin/legis"]
    )
    ok, _ = register_mcp_json(tmp_path)
    assert ok
    entry = _read_legis_mcp_entry(tmp_path)
    assert entry["command"] == "/opt/bin/legis"
    assert entry["env"] == {"LEGIS_WARDLINE_CELL": "surface_override"}
    assert "LEGIS_FILIGREE_HMAC_KEY" not in entry["env"]


def test_register_mcp_json_explicit_agent_id_updates_usable_entry_in_place(
    tmp_path, monkeypatch
):
    from legis.install import register_mcp_json

    exe = _touch_exe(tmp_path.parent / f"{tmp_path.name}-external" / "legis")
    _write_legis_mcp_entry(tmp_path, exe, env={"K": "V"}, agent_id="claude-code")
    monkeypatch.setattr(
        install, "_find_legis_command", lambda *_a, **_k: ["/opt/elsewhere/legis"]
    )
    ok, _ = register_mcp_json(tmp_path, "new-bot")
    assert ok
    entry = _read_legis_mcp_entry(tmp_path)
    args = entry["args"]
    assert args[args.index("--agent-id") + 1] == "new-bot"
    assert entry["command"] == str(exe)  # in-place retarget, no regeneration
    assert entry["env"] == {"K": "V"}


def test_install_hooks_does_not_rewrite_working_absolute_command_outside_project(
    tmp_path, monkeypatch
):
    exe = _touch_exe(tmp_path.parent / f"{tmp_path.name}-external" / "legis")
    working = f"{exe} session-context"
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {"hooks": [{"type": "command", "command": working}]}
                    ]
                }
            }
        )
    )
    monkeypatch.setattr(
        install, "_find_legis_command", lambda *_a, **_k: ["/opt/bin/legis"]
    )
    ok, msg = install_claude_code_hooks(tmp_path)
    assert ok
    cmds = _session_commands(json.loads((claude / "settings.json").read_text()))
    assert cmds == [working]
    assert "already" in msg


def test_install_hooks_upgrades_project_local_absolute_command(tmp_path, monkeypatch):
    exe = _touch_exe(tmp_path / "tools" / "legis")
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [
                                {"type": "command", "command": f"{exe} session-context"}
                            ]
                        }
                    ]
                }
            }
        )
    )
    monkeypatch.setattr(
        install, "_find_legis_command", lambda *_a, **_k: ["/opt/bin/legis"]
    )
    ok, _ = install_claude_code_hooks(tmp_path)
    assert ok
    cmds = _session_commands(json.loads((claude / "settings.json").read_text()))
    assert cmds == ["/opt/bin/legis session-context"]


def test_install_hooks_upgrades_dead_absolute_command(tmp_path, monkeypatch):
    dead = tmp_path / "gone-venv" / "legis"  # never created
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": f"{dead} session-context",
                                }
                            ]
                        }
                    ]
                }
            }
        )
    )
    monkeypatch.setattr(
        install, "_find_legis_command", lambda *_a, **_k: ["/opt/bin/legis"]
    )
    ok, _ = install_claude_code_hooks(tmp_path)
    assert ok
    cmds = _session_commands(json.loads((claude / "settings.json").read_text()))
    assert cmds == ["/opt/bin/legis session-context"]
