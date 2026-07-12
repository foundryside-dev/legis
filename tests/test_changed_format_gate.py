from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )


def test_changed_format_gate_uses_current_existing_paths(tmp_path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git not available")
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "kept.py").write_text("value=1\n", encoding="utf-8")
    (tmp_path / "later.py").write_text("value=1\n", encoding="utf-8")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")
    base = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()

    (tmp_path / "kept.py").write_text("value = 2\n", encoding="utf-8")
    (tmp_path / "later.py").write_text("value=2\n", encoding="utf-8")
    _git(tmp_path, "commit", "-am", "planned changes")
    _git(tmp_path, "mv", "kept.py", "renamed file.py")
    _git(tmp_path, "rm", "later.py")
    (tmp_path / "untracked file.py").write_text("value = 3\n", encoding="utf-8")
    non_utf8_name = b"non-utf8-\xff.py"
    non_utf8_path = os.path.join(os.fsencode(tmp_path), non_utf8_name)
    fd = os.open(non_utf8_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, b"value = 4\n")
    finally:
        os.close(fd)

    script = Path(__file__).parents[1] / "scripts" / "check_changed_format.py"
    result = subprocess.run(
        [sys.executable, script, "--base", base, "--print-only"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    printed = result.stdout.decode("utf-8", errors="surrogateescape").splitlines()

    assert printed == sorted(
        [os.fsdecode(non_utf8_name), "renamed file.py", "untracked file.py"]
    )

    checked = subprocess.run(
        [sys.executable, script, "--base", base],
        cwd=tmp_path,
        check=False,
        capture_output=True,
    )
    assert checked.returncode == 0, checked.stderr.decode(errors="replace")
