"""Phase 7 / Task 7.1 — the ``legis posture`` subcommand group.

``posture show`` reads the current floor (keyless, no session needed).
``posture set <cell>`` is the change gate: per D3 it REFUSES without an open
elevation session, and succeeds only with an open session backed by the
current-epoch key. There is NO direct-sign path.

Tests redirect both the posture store (``LEGIS_POSTURE_DB``) and the
``_store_dir()``-rooted session/age files into a per-test tmp dir by chdir-ing
into it, so no test touches the real ``.weft/legis`` subtree.
"""

from __future__ import annotations

import hashlib

import pytest

from legis.cli import main
from legis.posture import session as session_mod
from legis.posture.ledger import PostureLedger


@pytest.fixture
def posture_env(tmp_path, monkeypatch):
    """Isolate the posture store + session/age files into ``tmp_path``.

    Chdir into tmp_path so ``_store_dir()`` (cwd-relative ``.weft/legis``)
    resolves there, and point ``LEGIS_POSTURE_DB`` at an absolute sqlite URL.
    """
    monkeypatch.chdir(tmp_path)
    db_path = tmp_path / "posture.db"
    monkeypatch.setenv("LEGIS_POSTURE_DB", f"sqlite:///{db_path}")
    return tmp_path


def _genesis(key: bytes) -> str:
    """Write a GENESIS into the configured posture store; return the fingerprint."""
    from legis.config import posture_db_url

    ledger = PostureLedger(posture_db_url(), initialize=True)
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    return fp


def test_posture_show_keyless(posture_env, capsys):
    # Fresh genesis -> floor is the keyless default "chill".
    _genesis(b"k" * 32)
    rc = main(["posture", "show"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "chill" in out


def test_posture_set_requires_session(posture_env, capsys):
    _genesis(b"k" * 32)
    # No open session -> refusal, non-zero exit.
    rc = main(["posture", "set", "structured"])
    assert rc != 0
    err = (capsys.readouterr().err + capsys.readouterr().out).lower()
    assert "session" in err
    # Floor unchanged.
    from legis.config import posture_db_url

    assert PostureLedger(posture_db_url(), initialize=False).read_floor() == "chill"


def test_posture_set_with_session(posture_env, capsys, monkeypatch):
    key_hex = "ab" * 32
    key = bytes.fromhex(key_hex)
    fp = _genesis(key)
    # Open an env-backed session and put the matching key in the env so the CLI
    # can build an EnvSigner whose fingerprint matches the ledger epoch.
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", key_hex)
    session_mod.open_session(
        ttl=300,
        operator_id="operator@example",
        backend_id="env",
        unlock_ref=None,
    )
    from legis.posture import InsecureEnvKeyWarning

    with pytest.warns(InsecureEnvKeyWarning):
        rc = main(["posture", "set", "structured"])
    assert rc == 0
    from legis.config import posture_db_url

    assert PostureLedger(posture_db_url(), initialize=False).read_floor() == "structured"
    assert fp  # sanity: a real fingerprint was minted


def test_posture_rekey_preserves_existing_floor(posture_env, capsys, monkeypatch):
    # Phase 11 / Task 11.1 — `legis posture rekey` mints a new epoch while
    # preserving the standing floor and history. The env backend's sink is a
    # no-op (the new key goes to LEGIS_OPERATOR_KEY out of band), so no prior key
    # is needed — rekey is the lost-key recovery path.
    from legis.config import posture_db_url

    key_hex = "ab" * 32
    key = bytes.fromhex(key_hex)
    fp0 = _genesis(key)
    # Move the floor up so a reset-downgrade regression is visible.
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", key_hex)
    session_mod.open_session(
        ttl=300, operator_id="op@example", backend_id="env", unlock_ref=None
    )
    from legis.posture import InsecureEnvKeyWarning

    with pytest.warns(InsecureEnvKeyWarning):
        assert main(["posture", "set", "structured"]) == 0
    assert PostureLedger(posture_db_url(), initialize=False).read_floor() == "structured"

    rc = main(["posture", "rekey", "--backend", "env"])
    assert rc == 0
    ledger = PostureLedger(posture_db_url(), initialize=False)
    assert ledger.read_floor() == "structured"
    # New epoch minted; history preserved + chain intact.
    assert ledger.current_epoch_fingerprint() != fp0
    assert ledger.store.verify_integrity() is True


def test_posture_rekey_needs_no_session(posture_env, capsys):
    # Rekey requires NO open elevation session and NO old key — it is the
    # recovery path for a lost custody key.
    from legis.config import posture_db_url

    _genesis(b"k" * 32)
    rc = main(["posture", "rekey", "--backend", "env"])
    assert rc == 0
    assert PostureLedger(posture_db_url(), initialize=False).read_floor() == "chill"
    # Doctor would now flag the unacknowledged reset (Task 10.2); the CLI says so.
    out = capsys.readouterr().out.lower()
    assert "rekey" in out or "reset" in out or "floor preserved" in out
