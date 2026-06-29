"""Q-M7 / audit H6: the in-code policy-cell default must fail closed.

When no policy-cell configuration is found, an unmatched policy must escalate
to a human operator (``structured``) rather than fall through to the chill
self-clear cell — unless a deployment explicitly opts into the dev posture.
"""


def _clear_cell_env(monkeypatch, tmp_path):
    # No explicit registry, and point the source root at an empty dir so the
    # repo's policy/cells.toml is not discovered.
    monkeypatch.delenv("LEGIS_POLICY_CELLS", raising=False)
    monkeypatch.delenv("LEGIS_DEV_DEFAULT_CELLS", raising=False)
    monkeypatch.setenv("LEGIS_SOURCE_ROOT", str(tmp_path))


def test_absent_config_fails_closed_to_structured(monkeypatch, tmp_path):
    from legis.policy.cells import load_policy_cell_registry

    _clear_cell_env(monkeypatch, tmp_path)
    registry = load_policy_cell_registry()
    assert registry.default_cell == "structured"
    assert registry.cell_for("anything-unlisted") == "structured"


def test_dev_opt_in_restores_chill_default(monkeypatch, tmp_path):
    from legis.policy.cells import load_policy_cell_registry

    _clear_cell_env(monkeypatch, tmp_path)
    monkeypatch.setenv("LEGIS_DEV_DEFAULT_CELLS", "1")
    registry = load_policy_cell_registry()
    assert registry.default_cell == "chill"


def test_explicit_config_still_wins(monkeypatch, tmp_path):
    from legis.policy.cells import load_policy_cell_registry

    _clear_cell_env(monkeypatch, tmp_path)
    cells = tmp_path / "explicit.toml"
    cells.write_text('default_cell = "coached"\n', encoding="utf-8")
    monkeypatch.setenv("LEGIS_POLICY_CELLS", str(cells))
    registry = load_policy_cell_registry()
    assert registry.default_cell == "coached"


def test_fail_closed_helper_is_structured():
    from legis.policy.cells import fail_closed_policy_cells

    assert fail_closed_policy_cells().cell_for("anything") == "structured"
