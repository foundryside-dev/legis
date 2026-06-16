"""Phase 3 — elevation-session model (plan Tasks 3.1 / 3.2).

The persisted ``operator_session.json`` is the accountability record for a
time-boxed operator-elevation window (design §6). It holds ONLY metadata + a
backend-specific unlock reference — never key plaintext, never a passphrase,
never a raw age blob. Per D3 a session is required for every ``posture set``;
per D5 only the keychain backend stores a non-null ``unlock_ref``.
"""

from __future__ import annotations

import json
import time

import pytest

from legis.posture import session as session_mod
from legis.posture.records import KIND_SESSION_OPENED


@pytest.fixture
def session_path(tmp_path, monkeypatch):
    """Point ``operator_session_path()`` at a tmp file for every session call."""
    target = tmp_path / "operator_session.json"
    monkeypatch.setattr(
        session_mod, "operator_session_path", lambda: target
    )
    return target


# -- Task 3.1: persisted session-file model ----------------------------------


def test_enable_writes_session_file(session_path):
    session_mod.open_session(
        ttl=300,
        operator_id="alice",
        backend_id="keychain",
        unlock_ref="keychain-item-7",
    )
    assert session_path.exists()
    data = json.loads(session_path.read_text(encoding="utf-8"))
    # Exactly the metadata keys — and nothing key-bearing.
    assert set(data) == {
        "session_id",
        "operator_id",
        "opened_at",
        "ttl",
        "expires_at",
        "backend_id",
        "unlock_ref",
    }
    assert "key" not in data
    assert "passphrase" not in data
    # No raw blob plaintext smuggled into any value.
    blob = json.dumps(data).lower()
    assert "passphrase" not in blob


def test_age_backend_unlock_ref_is_none(session_path):
    # D5: re-prompt is the unlock mechanism for age-file; only keychain stores
    # a non-null item id.
    session_mod.open_session(
        ttl=300,
        operator_id="alice",
        backend_id="age-file",
        unlock_ref=None,
    )
    data = json.loads(session_path.read_text(encoding="utf-8"))
    assert data["backend_id"] == "age-file"
    assert data["unlock_ref"] is None


def test_session_active_within_ttl(session_path):
    session_mod.open_session(
        ttl=300, operator_id="alice", backend_id="age-file", unlock_ref=None
    )
    loaded = session_mod.load_session()
    assert loaded is not None
    assert loaded.is_active() is True


def test_session_expired_after_ttl(session_path):
    session_mod.open_session(
        ttl=1, operator_id="alice", backend_id="age-file", unlock_ref=None
    )
    # Force the file's expiry into the past without sleeping.
    data = json.loads(session_path.read_text(encoding="utf-8"))
    data["expires_at"] = time.time() - 10
    session_path.write_text(json.dumps(data), encoding="utf-8")
    assert session_mod.load_session() is None
    # past-TTL load self-deletes the stale file.
    assert not session_path.exists()


def test_load_session_double_expire_is_safe(session_path):
    session_mod.open_session(
        ttl=1, operator_id="alice", backend_id="age-file", unlock_ref=None
    )
    data = json.loads(session_path.read_text(encoding="utf-8"))
    data["expires_at"] = time.time() - 10
    session_path.write_text(json.dumps(data), encoding="utf-8")
    # Twice past TTL: both return None, the self-delete catches FileNotFoundError.
    assert session_mod.load_session() is None
    assert session_mod.load_session() is None


def test_disable_ends_early(session_path):
    session_mod.open_session(
        ttl=300, operator_id="alice", backend_id="age-file", unlock_ref=None
    )
    assert session_path.exists()
    session_mod.end_session()
    assert not session_path.exists()
    # Idempotent: ending an already-ended session does not raise.
    session_mod.end_session()


def test_unique_session_id(session_path):
    s1 = session_mod.open_session(
        ttl=300, operator_id="alice", backend_id="age-file", unlock_ref=None
    )
    s2 = session_mod.open_session(
        ttl=300, operator_id="alice", backend_id="age-file", unlock_ref=None
    )
    assert s1.session_id != s2.session_id


def test_second_enable_replaces_first(session_path):
    s1 = session_mod.open_session(
        ttl=300, operator_id="alice", backend_id="age-file", unlock_ref=None
    )
    s2 = session_mod.open_session(
        ttl=300, operator_id="bob", backend_id="keychain", unlock_ref="kc-1"
    )
    # Exactly one authoritative session file — the second overwrites the first.
    data = json.loads(session_path.read_text(encoding="utf-8"))
    assert data["session_id"] == s2.session_id
    assert data["session_id"] != s1.session_id
    assert data["operator_id"] == "bob"
    loaded = session_mod.load_session()
    assert loaded is not None
    assert loaded.session_id == s2.session_id


def test_load_malformed_file_is_none(session_path):
    session_path.parent.mkdir(parents=True, exist_ok=True)
    session_path.write_text("{not json", encoding="utf-8")
    # A corrupt session file reads as no-session (fail-closed), never raises.
    assert session_mod.load_session() is None


def test_load_missing_required_key_is_none(session_path):
    session_path.parent.mkdir(parents=True, exist_ok=True)
    # Valid JSON but missing required fields -> None (not a partial Session).
    session_path.write_text('{"session_id": "x"}', encoding="utf-8")
    assert session_mod.load_session() is None


def test_load_missing_file_is_none(session_path):
    # No file at all -> None.
    assert session_mod.load_session() is None


def test_is_active_module_helper(session_path):
    assert session_mod.is_active() is False
    session_mod.open_session(
        ttl=300, operator_id="alice", backend_id="age-file", unlock_ref=None
    )
    assert session_mod.is_active() is True


def test_session_is_active_explicit_now(session_path):
    s = session_mod.open_session(
        ttl=300, operator_id="alice", backend_id="age-file", unlock_ref=None
    )
    assert s.is_active(now=s.opened_at + 100) is True
    assert s.is_active(now=s.expires_at + 1) is False


def test_atomic_write_json_cleans_temp_on_failure(tmp_path, monkeypatch):
    target = tmp_path / "sub" / "out.json"

    def boom(_src, _dst):
        raise OSError("replace failed")

    monkeypatch.setattr(session_mod.os, "replace", boom)
    with pytest.raises(OSError, match="replace failed"):
        session_mod._atomic_write_json(target, {"a": 1})
    # No dangling .tmp file left behind in the destination directory.
    leftovers = list(target.parent.glob("*.tmp"))
    assert leftovers == []


# -- Task 3.2: OPERATOR_SESSION_OPENED ledger record -------------------------


def test_enable_writes_opened_record(tmp_path):
    from legis.posture.ledger import PostureLedger

    url = f"sqlite:///{tmp_path}/posture.db"
    ledger = PostureLedger(url, initialize=True)
    ledger.genesis(
        key_fingerprint="fp-genesis",
        agent_id="installer",
        recorded_at="2026-06-16T00:00:00Z",
    )
    ledger.session_opened(
        operator_id="alice",
        enabled_at="2026-06-16T14:02:00Z",
        ttl=300,
        keychain_auth_ref="keychain-item-7",
        session_id="sess-abc",
    )
    records = ledger.store.read_all()
    opened = [r for r in records if r.payload["kind"] == KIND_SESSION_OPENED]
    assert len(opened) == 1
    payload = opened[0].payload
    assert payload["operator_id"] == "alice"
    assert payload["enabled_at"] == "2026-06-16T14:02:00Z"
    assert payload["ttl"] == 300
    assert payload["keychain_auth_ref"] == "keychain-item-7"
    assert payload["session_id"] == "sess-abc"
    # Keyless: the enable IS the operator's countersignature; no operator_sig.
    assert payload.get("operator_sig") is None
    # The chain stays intact after the append.
    assert ledger.store.verify_integrity() is True
