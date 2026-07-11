from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


_SCRIPT = Path(__file__).parents[1] / "scripts" / "check_coverage_floors.py"
_SPEC = importlib.util.spec_from_file_location("check_coverage_floors", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
check_coverage_floors = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_coverage_floors)


def _empty_report(tmp_path: Path) -> Path:
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps({"files": {}}), encoding="utf-8")
    return report


def test_unmeasured_existing_floor_fails(tmp_path: Path, monkeypatch, capsys) -> None:
    target = tmp_path / "src" / "legis" / "protected.py"
    target.parent.mkdir(parents=True)
    target.write_text("protected = True\n", encoding="utf-8")
    monkeypatch.setattr(
        check_coverage_floors,
        "FLOORS",
        {"src/legis/protected.py": 80.0},
    )
    monkeypatch.setattr(check_coverage_floors, "REPO_ROOT", tmp_path, raising=False)

    result = check_coverage_floors.main(
        ["check_coverage_floors.py", str(_empty_report(tmp_path))]
    )

    assert result == 1
    assert "matched no measured files" in capsys.readouterr().err


def test_unmeasured_unknown_floor_fails_without_allowlist(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        check_coverage_floors,
        "FLOORS",
        {"src/legis/future.py": 80.0},
    )
    monkeypatch.setattr(check_coverage_floors, "REPO_ROOT", tmp_path, raising=False)

    result = check_coverage_floors.main(
        ["check_coverage_floors.py", str(_empty_report(tmp_path))]
    )

    assert result == 1
    assert "not explicitly allowlisted" in capsys.readouterr().err


def test_allowlisted_nonexistent_future_floor_skips(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    prefix = "src/legis/future.py"
    monkeypatch.setattr(check_coverage_floors, "FLOORS", {prefix: 80.0})
    monkeypatch.setattr(
        check_coverage_floors,
        "UNMEASURED_PREFIX_ALLOWLIST",
        frozenset({prefix}),
        raising=False,
    )
    monkeypatch.setattr(check_coverage_floors, "REPO_ROOT", tmp_path, raising=False)

    result = check_coverage_floors.main(
        ["check_coverage_floors.py", str(_empty_report(tmp_path))]
    )

    assert result == 0
    assert "explicit future-prefix allowlist" in capsys.readouterr().out


def test_allowlisted_floor_starts_failing_when_target_exists(
    tmp_path: Path,
    monkeypatch,
) -> None:
    prefix = "src/legis/future.py"
    target = tmp_path / prefix
    target.parent.mkdir(parents=True)
    target.write_text("landed = True\n", encoding="utf-8")
    monkeypatch.setattr(check_coverage_floors, "FLOORS", {prefix: 80.0})
    monkeypatch.setattr(
        check_coverage_floors,
        "UNMEASURED_PREFIX_ALLOWLIST",
        frozenset({prefix}),
        raising=False,
    )
    monkeypatch.setattr(check_coverage_floors, "REPO_ROOT", tmp_path, raising=False)

    assert (
        check_coverage_floors.main(
            ["check_coverage_floors.py", str(_empty_report(tmp_path))]
        )
        == 1
    )


@pytest.mark.parametrize(
    "summary",
    [
        {"covered_lines": 2, "num_statements": 1},
        {"covered_lines": -1, "num_statements": 1},
        {"covered_lines": 1.0, "num_statements": 1},
        {"covered_lines": float("inf"), "num_statements": 1},
        {"covered_lines": 1},
    ],
)
def test_invalid_coverage_summary_fails_closed(
    tmp_path: Path,
    monkeypatch,
    capsys,
    summary: dict[str, object],
) -> None:
    prefix = "src/legis/protected.py"
    target = tmp_path / prefix
    target.parent.mkdir(parents=True)
    target.write_text("protected = True\n", encoding="utf-8")
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps({"files": {prefix: {"summary": summary}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(check_coverage_floors, "FLOORS", {prefix: 80.0})
    monkeypatch.setattr(check_coverage_floors, "REPO_ROOT", tmp_path)

    result = check_coverage_floors.main(["check_coverage_floors.py", str(report)])

    assert result == 1
    assert "invalid coverage report" in capsys.readouterr().err.lower()


def test_invalid_coverage_files_shape_fails_closed(
    tmp_path: Path,
    capsys,
) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps({"files": []}), encoding="utf-8")

    result = check_coverage_floors.main(["check_coverage_floors.py", str(report)])

    assert result == 1
    assert "invalid coverage report" in capsys.readouterr().err.lower()
