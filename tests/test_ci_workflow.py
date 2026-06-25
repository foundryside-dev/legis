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
    # Skip-not-fail contract (owner decision 2026-06-25): Legis does not run
    # live Loomweave conformance in remote CI. Publish stays chained through the
    # conformance job, but the job no-ops with a notice when the oracle config
    # is absent (never blocking publish); when the config IS present the oracle
    # runs for real and a failure still blocks publish. The HMAC secret stays
    # scoped to the steps that use it.
    jobs = _release_jobs()
    publish_needs = jobs["publish"]["needs"]

    assert "live-loomweave-conformance" in jobs
    assert "build" in publish_needs
    assert "live-loomweave-conformance" in publish_needs

    live_job = jobs["live-loomweave-conformance"]
    assert "if" not in live_job  # gated per-step, never the whole job
    env = live_job["env"]
    assert env["LOOMWEAVE_URL"] == "${{ vars.LOOMWEAVE_URL }}"
    assert env["LOOMWEAVE_LIVE_ORACLE_LOCATOR"] == "${{ vars.LOOMWEAVE_LIVE_ORACLE_LOCATOR }}"
    # The secret is never exposed to the whole job — only to the steps below.
    assert "LEGIS_LOOMWEAVE_HMAC_KEY" not in env

    steps = live_job["steps"]
    commands = "\n".join(str(step.get("run", "")) for step in steps)
    # Skip-not-fail, not fail-closed: missing config no-ops, it does not error.
    assert "configured=false" in commands
    assert "configured=true" in commands
    assert "not blocking publish" in commands
    assert "Missing required release conformance environment" not in commands

    # When configured, the live oracle still runs for real, gated on detection.
    assert "tests/conformance/test_live_loomweave_oracle.py" in commands
    gate_if = "steps.oracle_config.outputs.configured == 'true'"
    oracle_steps = [
        step
        for step in steps
        if "test_live_loomweave_oracle.py" in str(step.get("run", ""))
    ]
    assert oracle_steps
    assert all(step.get("if") == gate_if for step in oracle_steps)
    oracle_step = oracle_steps[0]
    assert oracle_step["env"] == {
        "LEGIS_LOOMWEAVE_HMAC_KEY": "${{ secrets.LEGIS_LOOMWEAVE_HMAC_KEY }}"
    }

    # Secret scoping: the HMAC key appears only in the steps that need it (the
    # presence check and the oracle run), never anywhere else in the job.
    key_step_names = {
        step.get("name")
        for step in steps
        if "LEGIS_LOOMWEAVE_HMAC_KEY" in step.get("env", {})
    }
    assert key_step_names == {
        "Detect live oracle configuration",
        "Run live Loomweave oracle",
    }


def test_release_workflow_repeats_publication_quality_gates():
    steps = _release_jobs()["build"]["steps"]
    commands = "\n".join(str(step.get("run", "")) for step in steps)

    assert "uv run ruff check src" in commands
    assert "uv run mypy src/legis" in commands
    assert "uv lock --check" in commands
    assert "uv run legis policy-boundary-check --root src --repo-root ." in commands
