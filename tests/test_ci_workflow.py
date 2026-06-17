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
    assert env["LEGIS_LOOMWEAVE_HMAC_KEY"] == "${{ secrets.LEGIS_LOOMWEAVE_HMAC_KEY }}"

    commands = "\n".join(str(step.get("run", "")) for step in live_job["steps"])
    # Skip-not-fail contract (0dafc83 / f95036b): when the live-oracle release
    # env is unprovisioned the job passes as a fast no-op so it never blocks the
    # PyPI publish; when the env IS present, the oracle runs for real and a
    # conformance failure blocks publish — the gate still bites where it can.
    # (The old hard-fail "Missing required release conformance environment"
    # guard was deliberately removed and must not be reintroduced.)
    assert "Missing required release conformance environment" not in commands
    assert "configured=false" in commands  # the skip branch is present
    assert "configured=true" in commands  # the run branch is present
    assert "not blocking publish" in commands  # skip, not hard-fail
    assert "tests/conformance/test_live_loomweave_oracle.py" in commands
    # The real oracle run is gated on the live config being detected, so an
    # unprovisioned environment skips it rather than erroring.
    gated = [
        step
        for step in live_job["steps"]
        if "test_live_loomweave_oracle.py" in str(step.get("run", ""))
    ]
    assert gated
    assert all(
        step.get("if") == "steps.oracle_config.outputs.configured == 'true'"
        for step in gated
    )
