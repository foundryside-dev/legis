from pathlib import Path

import yaml


def _ci_steps():
    workflow = yaml.safe_load(Path(".github/workflows/ci.yml").read_text())
    return workflow["jobs"]["test"]["steps"]


def _release_jobs():
    workflow = yaml.safe_load(Path(".github/workflows/release.yml").read_text())
    return workflow["jobs"]


def test_ci_enforces_coverage_threshold():
    commands = "\n".join(str(step.get("run", "")) for step in _ci_steps())

    assert "--cov=legis" in commands
    assert "--cov-fail-under=" in commands


def test_ci_runs_sei_and_live_loomweave_conformance_targets():
    commands = "\n".join(str(step.get("run", "")) for step in _ci_steps())

    assert "tests/conformance/test_sei_oracle.py" in commands
    assert "tests/conformance/test_live_loomweave_oracle.py" in commands


def test_release_publish_requires_live_loomweave_conformance():
    jobs = _release_jobs()
    publish_needs = jobs["publish"]["needs"]

    assert "live-loomweave-conformance" in jobs
    assert "build" in publish_needs
    assert "live-loomweave-conformance" in publish_needs

    live_job = jobs["live-loomweave-conformance"]
    assert "if" not in live_job
    env = live_job["env"]
    assert env["LOOMWEAVE_URL"] == "${{ vars.LOOMWEAVE_URL }}"
    assert env["LOOMWEAVE_LIVE_ORACLE_LOCATOR"] == "${{ vars.LOOMWEAVE_LIVE_ORACLE_LOCATOR }}"
    assert "LEGIS_LOOMWEAVE_HMAC_KEY" not in env

    commands = "\n".join(str(step.get("run", "")) for step in live_job["steps"])
    assert "Missing required release conformance environment" in commands
    assert "configured=false" not in commands
    assert "configured=true" not in commands
    assert "not blocking publish" not in commands
    assert "tests/conformance/test_live_loomweave_oracle.py" in commands
    oracle_steps = [
        step
        for step in live_job["steps"]
        if "test_live_loomweave_oracle.py" in str(step.get("run", ""))
    ]
    assert oracle_steps
    assert all("if" not in step for step in oracle_steps)
    oracle_step = oracle_steps[0]
    assert oracle_step["env"] == {
        "LEGIS_LOOMWEAVE_HMAC_KEY": "${{ secrets.LEGIS_LOOMWEAVE_HMAC_KEY }}"
    }
    assert "LEGIS_LOOMWEAVE_HMAC_KEY" in oracle_step["run"]
    non_oracle_steps = [step for step in live_job["steps"] if step is not oracle_step]
    assert all(
        "LEGIS_LOOMWEAVE_HMAC_KEY" not in step.get("env", {})
        for step in non_oracle_steps
    )


def test_release_workflow_repeats_publication_quality_gates():
    steps = _release_jobs()["build"]["steps"]
    commands = "\n".join(str(step.get("run", "")) for step in steps)

    assert "uv run ruff check src" in commands
    assert "uv run mypy src/legis" in commands
    assert "uv lock --check" in commands
    assert "uv run legis policy-boundary-check --root src --repo-root ." in commands
