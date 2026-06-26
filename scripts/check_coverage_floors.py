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

# path-prefix (relative to repo root, as coverage records it) -> floor percent.
# A prefix ending in ".py" matches a single module; otherwise it matches a
# package subtree. Current coverage (2026-06-06) shown in the trailing comment.
FLOORS: dict[str, float] = {
    "src/legis/enforcement/": 93.0,  # currently ~95.0
    "src/legis/posture/": 93.0,      # security-critical: signed key-gated floor

    "src/legis/service/": 92.0,      # currently ~94.1
    "src/legis/governance/": 90.0,   # currently ~92.7
    "src/legis/api/": 88.0,          # currently ~89.8
    "src/legis/mcp.py": 80.0,        # currently ~82
    "src/legis/doctor.py": 88.0,     # currently ~91
    "src/legis/warpline_preflight/": 88.0,  # currently ~92
}


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


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

    files = data.get("files", {})
    failures: list[str] = []
    print(f"Per-package coverage floors ({report_path}):")
    for prefix, floor in sorted(FLOORS.items()):
        covered, statements = _aggregate(files, prefix)
        if statements == 0:
            # A floor may be registered before its package's first module lands
            # (e.g. the posture floor is committed in Phase 0, ahead of the
            # Phase 1 ``records.py``). An unmeasured prefix is reported, not a
            # failure — the floor becomes fail-closed the moment statements
            # exist. This is intentionally gated on having ZERO statements; any
            # measured package below floor still FAILs below.
            print(f"  [skip] {prefix:28} not yet measured (prefix matched no files)")
            continue
        pct = 100.0 * covered / statements
        status = "ok" if pct >= floor else "FAIL"
        print(f"  [{status}] {prefix:28} {pct:5.1f}%  (floor {floor:.1f}%, {covered}/{statements})")
        if pct < floor:
            failures.append(
                f"  {prefix}: {pct:.1f}% < floor {floor:.1f}%"
            )

    if failures:
        print("\nCoverage floor breach:", file=sys.stderr)
        for line in failures:
            print(line, file=sys.stderr)
        return 1
    print("All per-package coverage floors hold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
