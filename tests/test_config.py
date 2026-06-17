"""Store-location resolver: the federated ``.weft/legis`` subtree.

These pin the contract from the weft config/store consolidation:
  * machine-written DBs default under ``.weft/legis/`` (cwd-anchored, the same
    notion the installer uses for project root);
  * the operator-authored ``weft.toml`` ``[legis]`` table is not load-bearing
    for DB placement — absent, section-less, malformed, or hostile weft.toml
    must still boot on built-in defaults;
  * computing a URL is pure (creates nothing); the directory materialises only
    when a DB is actually opened, via ``ensure_sqlite_parent``.
"""

from __future__ import annotations

import pytest

from legis import config


@pytest.fixture
def _clear_db_env(monkeypatch):
    """Clear the per-DB ``LEGIS_*_DB`` overrides so a test can probe the lower
    weft.toml / built-in-default precedence layers. The autouse suite fixture
    (tests/conftest.py) sets these to isolate stores, and the resolvers now honour
    them (highest precedence), so a default-layer assertion must drop them first.
    A test's own monkeypatch runs after the autouse fixture, so this wins.
    """
    for var in (
        "LEGIS_CHECK_DB",
        "LEGIS_GOVERNANCE_DB",
        "LEGIS_BINDING_DB",
        "LEGIS_PULL_DB",
    ):
        monkeypatch.delenv(var, raising=False)


def test_all_four_db_urls_default_under_weft_legis(_clear_db_env, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert config.check_db_url() == "sqlite:///.weft/legis/legis-checks.db"
    assert config.governance_db_url() == "sqlite:///.weft/legis/legis-governance.db"
    assert config.binding_db_url() == "sqlite:///.weft/legis/legis-binding.db"
    assert config.pull_db_url() == "sqlite:///.weft/legis/legis-pulls.db"


def test_legis_db_env_var_takes_precedence_over_repo_weft_toml_and_default(
    tmp_path, monkeypatch
):
    # A per-DB LEGIS_*_DB override is the only supported relocation mechanism.
    # Repo-authored weft.toml must not redirect any unset governance store.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "weft.toml").write_text(
        '[legis]\nstore_dir = "var/legis-state"\n', encoding="utf-8"
    )
    monkeypatch.setenv("LEGIS_GOVERNANCE_DB", "sqlite:///explicit-gov.db")
    monkeypatch.setenv("LEGIS_CHECK_DB", "sqlite:///explicit-check.db")
    assert config.governance_db_url() == "sqlite:///explicit-gov.db"
    assert config.check_db_url() == "sqlite:///explicit-check.db"
    # An unset var falls through to the built-in default, not repo weft.toml.
    monkeypatch.delenv("LEGIS_BINDING_DB", raising=False)
    assert config.binding_db_url() == "sqlite:///.weft/legis/legis-binding.db"


def test_db_urls_use_builtin_defaults_with_no_weft_toml(_clear_db_env, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert not (tmp_path / "weft.toml").exists()
    assert config.governance_db_url() == "sqlite:///.weft/legis/legis-governance.db"


def test_weft_toml_store_dir_does_not_redirect_default_stores(
    _clear_db_env, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "weft.toml").write_text(
        '[legis]\nstore_dir = "var/legis-state"\n', encoding="utf-8"
    )
    assert config.governance_db_url() == "sqlite:///.weft/legis/legis-governance.db"
    assert config.check_db_url() == "sqlite:///.weft/legis/legis-checks.db"


def test_weft_toml_absolute_store_dir_does_not_redirect_default_stores(
    _clear_db_env, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    abs_dir = tmp_path / "srv" / "legis"
    (tmp_path / "weft.toml").write_text(
        f'[legis]\nstore_dir = "{abs_dir.as_posix()}"\n', encoding="utf-8"
    )
    assert config.governance_db_url() == "sqlite:///.weft/legis/legis-governance.db"


def test_weft_toml_without_legis_section_uses_defaults(_clear_db_env, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "weft.toml").write_text('[filigree]\ndb = "x"\n', encoding="utf-8")
    assert config.governance_db_url() == "sqlite:///.weft/legis/legis-governance.db"


def test_malformed_weft_toml_is_not_load_bearing(_clear_db_env, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "weft.toml").write_text("this is = = not valid toml [[[", encoding="utf-8")
    assert config.governance_db_url() == "sqlite:///.weft/legis/legis-governance.db"


def test_computing_db_url_creates_no_directories(_clear_db_env, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _ = config.governance_db_url()
    _ = config.check_db_url()
    _ = config.binding_db_url()
    _ = config.pull_db_url()
    assert not (tmp_path / ".weft").exists()


def test_ensure_sqlite_parent_creates_dir_for_relative_file_url(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config.ensure_sqlite_parent("sqlite:///.weft/legis/legis-checks.db")
    assert (tmp_path / ".weft" / "legis").is_dir()


def test_ensure_sqlite_parent_creates_dir_for_absolute_file_url(tmp_path):
    target = tmp_path / "a" / "b" / "x.db"
    config.ensure_sqlite_parent(f"sqlite:///{target.as_posix()}")
    assert (tmp_path / "a" / "b").is_dir()


def test_ensure_sqlite_parent_is_noop_for_in_memory_and_non_sqlite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config.ensure_sqlite_parent("sqlite://")
    config.ensure_sqlite_parent("sqlite:///:memory:")
    config.ensure_sqlite_parent("postgresql://localhost/x")
    assert list(tmp_path.iterdir()) == []


def test_ensure_sqlite_parent_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config.ensure_sqlite_parent("sqlite:///.weft/legis/legis-checks.db")
    config.ensure_sqlite_parent("sqlite:///.weft/legis/legis-checks.db")
    assert (tmp_path / ".weft" / "legis").is_dir()


def test_suite_isolates_store_locations_to_tmp():
    """Regression guard for legis-3d295a6f7f: the autouse conftest fixture must
    redirect every store env var off the repo-relative `.weft/legis/` default,
    so a test that builds a default-path store can't leak a subtree into the
    working tree."""
    import os

    for var in (
        "LEGIS_CHECK_DB",
        "LEGIS_GOVERNANCE_DB",
        "LEGIS_BINDING_DB",
        "LEGIS_PULL_DB",
    ):
        val = os.environ.get(var, "")
        assert val.startswith("sqlite:"), f"{var} not redirected: {val!r}"
        assert "legis-store" in val, f"{var} not pointed at the isolated tmp dir: {val!r}"
