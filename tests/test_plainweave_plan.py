from __future__ import annotations

from pathlib import Path


def test_historical_plainweave_binding_docs_are_superseded() -> None:
    expected_targets = {
        Path(
            "docs/superpowers/specs/2026-07-11-plainweave-doctor-binding-design.md"
        ): "[2026-07-12 Plainweave runtime autodiscovery design]"
        "(2026-07-12-plainweave-runtime-autodiscovery-design.md)",
        Path(
            "docs/superpowers/plans/2026-07-11-plainweave-doctor-binding.md"
        ): "[2026-07-12 Plainweave runtime autodiscovery design]"
        "(../specs/2026-07-12-plainweave-runtime-autodiscovery-design.md)",
    }

    for path, target in expected_targets.items():
        lines = path.read_text(encoding="utf-8").splitlines()

        assert lines[2].startswith("> **Superseded:**"), path
        assert target in lines[2], path
        assert "historical 1.5.0 implementation record" in lines[2], path
        relative_target = target.rpartition("(")[2].removesuffix(")")
        assert (path.parent / relative_target).resolve().is_file(), path


def test_historical_plainweave_design_and_plan_are_not_active_instructions() -> None:
    design = Path(
        "docs/superpowers/specs/2026-07-11-plainweave-doctor-binding-design.md"
    ).read_text(encoding="utf-8")
    plan = Path(
        "docs/superpowers/plans/2026-07-11-plainweave-doctor-binding.md"
    ).read_text(encoding="utf-8")

    assert "Status: superseded" in design
    assert "Historical plan — do not execute" in plan
    assert "REQUIRED SUB-SKILL" not in "\n".join(plan.splitlines()[:12])


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
