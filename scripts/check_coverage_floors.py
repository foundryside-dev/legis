#!/usr/bin/env python3
"""Per-package coverage-floor gate (roadmap 11 / Q-L7).

The global ``--cov-fail-under`` floor closes the aggregate silent-regression
headroom, but a regression concentrated in one security-critical package can
hide behind a high total. This gate enforces a minimum line-coverage percentage
per package (or single module) against ``coverage.json``.

Floors are intentionally set a few points below current coverage: tight enough
to catch a real regression, loose enough not to trip on incidental churn. Raise
a floor when a package's coverage rises and you want to lock the gain in.

Usage:
    python scripts/check_coverage_floors.py [coverage.json]

Exit status 0 if every floor holds, 1 otherwise (with a per-package report).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

# A prefix may be staged before its source lands only by explicit exception.
# Once that target exists, zero measured statements fail even if the stale
# exception was not removed yet.
UNMEASURED_PREFIX_ALLOWLIST: frozenset[str] = frozenset()

# path-prefix (relative to repo root, as coverage records it) -> floor percent.
# A prefix ending in ".py" matches a single module; otherwise it matches a
# package subtree. Current coverage (2026-06-06) shown in the trailing comment.
FLOORS: dict[str, float] = {
    "src/legis/crypto/": 93.0,  # security-critical: HMAC signing leaf (was under enforcement's floor)
    "src/legis/enforcement/": 93.0,  # currently ~95.0
    "src/legis/posture/": 93.0,  # security-critical: signed key-gated floor
    "src/legis/service/": 92.0,  # currently ~94.1
    "src/legis/governance/": 90.0,  # currently ~92.7
    "src/legis/api/": 88.0,  # currently ~89.8
    "src/legis/mcp.py": 80.0,  # currently ~82
    "src/legis/doctor.py": 88.0,  # currently ~91
    "src/legis/plainweave_binding.py": 80.0,  # race-aware config repair
    "src/legis/warpline_preflight/": 88.0,  # currently ~92
    "src/legis/plainweave_preflight/": 88.0,  # advisory sibling consumer
}


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh, parse_constant=_reject_json_constant)


def _validated_files(data: object) -> dict[str, dict]:
    if not isinstance(data, dict):
        raise ValueError("top level is not an object")
    files = data.get("files")
    if not isinstance(files, dict):
        raise ValueError("files is not an object")
    for path, info in files.items():
        if not isinstance(path, str) or not isinstance(info, dict):
            raise ValueError("files entries must map path strings to objects")
        summary = info.get("summary")
        if not isinstance(summary, dict):
            raise ValueError(f"{path}: summary is not an object")
        covered = summary.get("covered_lines")
        statements = summary.get("num_statements")
        if type(covered) is not int or type(statements) is not int:
            raise ValueError(f"{path}: coverage counters must be integers")
        if covered < 0 or statements < 0 or covered > statements:
            raise ValueError(f"{path}: coverage counters are inconsistent")
    return files


def _aggregate(files: dict, prefix: str) -> tuple[int, int]:
    """Sum (covered_lines, num_statements) over files matching ``prefix``."""
    covered = statements = 0
    for path, info in files.items():
        norm = path.replace("\\", "/")
        if prefix.endswith(".py"):
            match = norm == prefix
        else:
            match = norm.startswith(prefix)
        if match:
            summary = info["summary"]
            covered += summary["covered_lines"]
            statements += summary["num_statements"]
    return covered, statements


def main(argv: list[str]) -> int:
    report_path = argv[1] if len(argv) > 1 else "coverage.json"
    try:
        data = _load(report_path)
    except FileNotFoundError:
        print(
            f"coverage report not found: {report_path}\n"
            "Run pytest with --cov-report=json first.",
            file=sys.stderr,
        )
        return 1
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        print(f"invalid coverage report: {exc}", file=sys.stderr)
        return 1

    try:
        files = _validated_files(data)
    except ValueError as exc:
        print(f"invalid coverage report: {exc}", file=sys.stderr)
        return 1
    failures: list[str] = []
    print(f"Per-package coverage floors ({report_path}):")
    for prefix, floor in sorted(FLOORS.items()):
        covered, statements = _aggregate(files, prefix)
        if statements == 0:
            target_exists = (REPO_ROOT / prefix).exists()
            if prefix in UNMEASURED_PREFIX_ALLOWLIST and not target_exists:
                print(
                    f"  [skip] {prefix:28} not yet measured "
                    "(explicit future-prefix allowlist)"
                )
                continue
            if target_exists:
                detail = "matched no measured files"
            else:
                detail = "target is absent and not explicitly allowlisted"
            print(f"  [FAIL] {prefix:28} {detail}")
            failures.append(f"  {prefix}: {detail}")
            continue
        pct = 100.0 * covered / statements
        status = "ok" if pct >= floor else "FAIL"
        print(
            f"  [{status}] {prefix:28} {pct:5.1f}%  (floor {floor:.1f}%, {covered}/{statements})"
        )
        if pct < floor:
            failures.append(f"  {prefix}: {pct:.1f}% < floor {floor:.1f}%")

    if failures:
        print("\nCoverage floor breach:", file=sys.stderr)
        for line in failures:
            print(line, file=sys.stderr)
        return 1
    print("All per-package coverage floors hold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
