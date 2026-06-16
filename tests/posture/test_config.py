"""Phase 0 Task 0.2 — posture DB URL + operator-session path resolvers.

Pins the new config resolvers onto the same federated ``.weft/legis`` subtree
and ``STORE_DB_SPECS`` contract the four existing stores use (plan Task 0.2,
design §4/§6). All posture *ledger* unit tests construct the store with an
explicit absolute URL; here we exercise the resolver itself.
"""

from __future__ import annotations

import pytest

from legis import config
from legis.store.audit_store import AuditStore


@pytest.fixture
def _clear_posture_env(monkeypatch):
    monkeypatch.delenv("LEGIS_POSTURE_DB", raising=False)


def test_posture_db_url_default(_clear_posture_env, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert config.posture_db_url() == "sqlite:///.weft/legis/legis-posture.db"


def test_posture_db_url_env_override(monkeypatch):
    monkeypatch.setenv("LEGIS_POSTURE_DB", "sqlite:////tmp/x.db")
    assert config.posture_db_url() == "sqlite:////tmp/x.db"


def test_posture_in_store_specs():
    assert ("LEGIS_POSTURE_DB", "legis-posture.db") in config.STORE_DB_SPECS


def test_operator_session_path(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert config.operator_session_path() == config._store_dir() / "operator_session.json"


def test_operator_age_path(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert config.operator_age_path() == config._store_dir() / "operator.age"


def test_posture_db_url_creates_parent_dir(_clear_posture_env, tmp_path, monkeypatch):
    """The cwd-relative ``_store_dir`` trap: opening the store must create the
    ``.weft/legis/`` parent dir, not raise "unable to open database file"."""
    monkeypatch.chdir(tmp_path)
    AuditStore(config.posture_db_url(), initialize=True)
    assert (tmp_path / ".weft" / "legis" / "legis-posture.db").exists()
