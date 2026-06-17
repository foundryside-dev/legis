"""Phase 7 / Task 7.2 — the ``legis operator`` subcommand group + CI bootstrap.

``operator enable`` opens the single elevation session (writing
``operator_session.json``) and appends a keyless ``OPERATOR_SESSION_OPENED``
record. ``operator disable`` deletes the session file. The CI/headless path
(``--insecure-key-in-env`` with ``LEGIS_OPERATOR_KEY`` set) still goes through a
session, so a subsequent ``posture set`` TRANSITION carries a non-null
``session_id`` (D3 — no second auth path bypasses session accountability).

Tests chdir into a tmp dir so ``_store_dir()`` (session + posture store) resolves
there, and point ``LEGIS_POSTURE_DB`` at an absolute sqlite URL.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from legis.cli import main
from legis.config import operator_session_path, posture_db_url
from legis.posture import InsecureEnvKeyWarning
from legis.posture.ledger import PostureLedger


@pytest.fixture
def posture_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db_path = tmp_path / "posture.db"
    monkeypatch.setenv("LEGIS_POSTURE_DB", f"sqlite:///{db_path}")
    return tmp_path


def _genesis(key: bytes) -> str:
    ledger = PostureLedger(posture_db_url(), initialize=True)
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    return fp


def test_operator_enable_opens_session(posture_env, monkeypatch, capsys):
    key_hex = "ab" * 32
    _genesis(bytes.fromhex(key_hex))
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", key_hex)
    with pytest.warns(InsecureEnvKeyWarning):
        rc = main(["operator", "enable", "--ttl", "5m", "--insecure-key-in-env"])
    assert rc == 0
    # Session file written.
    sess_path = operator_session_path()
    assert sess_path.exists()
    data = json.loads(sess_path.read_text())
    assert data["ttl"] == 300
    # An OPERATOR_SESSION_OPENED record was appended.
    records = PostureLedger(posture_db_url(), initialize=False).store.read_all()
    assert records[-1].payload["kind"] == "OPERATOR_SESSION_OPENED"
    # Output names the operator + the window.
    out = capsys.readouterr().out.lower()
    assert "operator" in out
    assert "300" in out or "5m" in out


def test_operator_disable_ends_session(posture_env, monkeypatch):
    key_hex = "ab" * 32
    _genesis(bytes.fromhex(key_hex))
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", key_hex)
    with pytest.warns(InsecureEnvKeyWarning):
        main(["operator", "enable", "--insecure-key-in-env"])
    assert operator_session_path().exists()
    rc = main(["operator", "disable"])
    assert rc == 0
    assert not operator_session_path().exists()


def test_enable_default_ttl_5m(posture_env, monkeypatch):
    key_hex = "ab" * 32
    _genesis(bytes.fromhex(key_hex))
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", key_hex)
    with pytest.warns(InsecureEnvKeyWarning):
        rc = main(["operator", "enable", "--insecure-key-in-env"])
    assert rc == 0
    data = json.loads(operator_session_path().read_text())
    assert data["ttl"] == 300


def test_ci_env_backend_opens_session_with_id(posture_env, monkeypatch, capsys):
    key_hex = "cd" * 32
    _genesis(bytes.fromhex(key_hex))
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", key_hex)

    with pytest.warns(InsecureEnvKeyWarning):
        rc = main(["operator", "enable", "--insecure-key-in-env"])
    assert rc == 0
    out = capsys.readouterr().out.lower()
    # The plaintext warning is surfaced to the operator.
    assert "plaintext" in out or "insecure" in out
    # Session file records the env backend.
    data = json.loads(operator_session_path().read_text())
    assert data["backend_id"] == "env"

    # A subsequent posture set produces a TRANSITION carrying a non-null session_id.
    with pytest.warns(InsecureEnvKeyWarning):
        rc2 = main(["posture", "set", "structured"])
    assert rc2 == 0
    records = PostureLedger(posture_db_url(), initialize=False).store.read_all()
    transition = records[-1]
    assert transition.payload["kind"] == "TRANSITION"
    assert transition.payload["session_id"] is not None
    assert transition.payload["session_id"] == data["session_id"]
