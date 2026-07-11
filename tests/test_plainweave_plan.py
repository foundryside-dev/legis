from __future__ import annotations

from pathlib import Path


def test_plainweave_plan_uses_changed_file_format_gate() -> None:
    plan = Path(
        "docs/superpowers/plans/2026-07-11-plainweave-doctor-binding.md"
    ).read_text(encoding="utf-8")
    ci = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "uv run ruff format --check src tests" not in plan
    assert "uv run python scripts/check_changed_format.py --base 9c372d6" in plan
    assert "repository-wide Ruff format baseline is not clean" in plan
    assert "run: uv run ruff check src" in ci
    assert "ruff format --check src tests" not in ci
