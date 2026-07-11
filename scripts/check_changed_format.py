"""Run Ruff's format check on current Python paths changed since a base commit."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


def _git_paths(root: Path, *args: str) -> set[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return {
        item.decode("utf-8", errors="surrogateescape")
        for item in result.stdout.split(b"\0")
        if item
    }


def changed_python_files(root: Path, base: str) -> list[str]:
    """Return existing tracked/untracked Python paths changed from *base*."""
    paths = _git_paths(
        root,
        "diff",
        "-M",
        "--name-only",
        "--diff-filter=ACMR",
        "-z",
        base,
        "--",
        "*.py",
    )
    paths.update(
        _git_paths(
            root,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "*.py",
        )
    )
    return sorted(path for path in paths if (root / path).is_file())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--print-only", action="store_true")
    args = parser.parse_args()
    root = Path.cwd()
    paths = changed_python_files(root, args.base)
    if args.print_only:
        print("\n".join(paths))
        return 0
    if not paths:
        return 0
    ruff = shutil.which("ruff")
    if ruff is None:
        parser.error("ruff is not available on PATH")
    return subprocess.run(
        [ruff, "format", "--check", "--no-cache", "--", *paths],
        cwd=root,
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
