"""Phase 11 / Task 11.1 — posture rekey (lost-key / epoch-reset path).

Fail-closed/loud contract (design §8): a rekey changes the key epoch without
lowering the standing floor, needs NO old key and NO open session, preserves all
prior history, chains a single ``KEY_RESET`` record carrying a fresh epoch
fingerprint, and doctor flags it non-zero until an acknowledging signed
transition under the new epoch.

Unit tests construct the store with an explicit absolute sqlite URL (matching
tests/store/test_audit_store.py / tests/posture/test_ledger.py), never via
posture_db_url().
"""

from __future__ import annotations

import hashlib

import pytest

from legis.install import OperatorKeyCustodyError
from legis.posture.ledger import PostureLedger
from legis.posture.records import KIND_GENESIS, KIND_KEY_RESET


def _url(tmp_path):
    return f"sqlite:///{tmp_path}/posture.db"


def _genesis_ledger(tmp_path):
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    key = b"k" * 32
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    return ledger, fp


def _custody_sink():
    handed: list[tuple[str, str]] = []

    def sink(key_hex: str, backend: str) -> None:
        handed.append((key_hex, backend))

    return handed, sink


class _MemSigner:
    def __init__(self, key):
        self._key = key

    def fingerprint(self):
        return hashlib.sha256(self._key).hexdigest()

    def sign(self, fields):
        from legis.enforcement import signing as enf_signing

        return enf_signing.sign(fields, self._key, version="v3")


def test_rekey_preserves_existing_floor(tmp_path):
    ledger, fp0 = _genesis_ledger(tmp_path)
    # Move the floor up first so a reset-downgrade regression is visible.
    from legis.posture.ledger import _Signer  # type: ignore  # noqa: F401

    ledger.transition(
        "structured",
        signer=_MemSigner(b"k" * 32),
        session_id="sess",
        key_fingerprint=fp0,
        agent_id="op",
        rationale="tighten",
        recorded_at="t1",
    )
    assert ledger.read_floor() == "structured"

    _handed, sink = _custody_sink()
    ledger.rekey(agent_id="op", recorded_at="t2", key_sink=sink, backend="age-file")
    assert ledger.read_floor() == "structured"
    reset = ledger.store.read_all()[-1].payload
    assert reset["kind"] == KIND_KEY_RESET
    assert reset["floor"] == "structured"


def test_rekey_preserves_floor_after_session_opened_tail(tmp_path):
    ledger, fp0 = _genesis_ledger(tmp_path)
    key = b"k" * 32
    ledger.transition(
        "protected",
        signer=_MemSigner(key),
        session_id="sess-1",
        key_fingerprint=fp0,
        agent_id="op",
        rationale="tighten",
        recorded_at="t1",
    )
    ledger.session_opened(
        operator_id="alice",
        enabled_at="t2",
        ttl=300,
        keychain_auth_ref=None,
        session_id="sess-2",
    )

    _handed, sink = _custody_sink()
    ledger.rekey(agent_id="op", recorded_at="t3", key_sink=sink, backend="age-file")

    assert ledger.read_floor() == "protected"
    reset = ledger.store.read_all()[-1].payload
    assert reset["kind"] == KIND_KEY_RESET
    assert reset["floor"] == "protected"


def test_rekey_mints_new_epoch(tmp_path):
    ledger, fp0 = _genesis_ledger(tmp_path)
    handed, sink = _custody_sink()

    ledger.rekey(agent_id="op", recorded_at="t2", key_sink=sink, backend="age-file")
    new_fp = ledger.current_epoch_fingerprint()
    assert new_fp != fp0
    # The freshly-minted key was handed to the backend (and only its fingerprint
    # is stored in the ledger).
    assert len(handed) == 1
    minted_hex, backend = handed[0]
    assert backend == "age-file"
    assert hashlib.sha256(bytes.fromhex(minted_hex)).hexdigest() == new_fp


def test_rekey_refuses_without_custody_sink(tmp_path):
    ledger, fp0 = _genesis_ledger(tmp_path)

    with pytest.raises(OperatorKeyCustodyError):
        ledger.rekey(agent_id="op", recorded_at="t2")

    records = ledger.store.read_all()
    assert len(records) == 1
    assert records[0].payload["kind"] == KIND_GENESIS
    assert ledger.current_epoch_fingerprint() == fp0


def test_rekey_preserves_history(tmp_path):
    ledger, fp0 = _genesis_ledger(tmp_path)
    before = ledger.store.read_all()
    assert len(before) == 1

    _handed, sink = _custody_sink()
    ledger.rekey(agent_id="op", recorded_at="t2", key_sink=sink, backend="age-file")

    after = ledger.store.read_all()
    # KEY_RESET chained ONTO the existing history (not a fresh DB): the original
    # GENESIS is still present at seq 1.
    assert len(after) == 2
    assert after[0].payload["kind"] == KIND_GENESIS
    assert after[0].payload["key_fingerprint"] == fp0
    assert after[1].payload["kind"] == KIND_KEY_RESET
    # Chain integrity holds over the whole (preserved) history.
    assert ledger.store.verify_integrity() is True


def test_rekey_needs_no_old_key(tmp_path):
    # No open session, no signer, no prior key available — rekey still succeeds.
    ledger, _ = _genesis_ledger(tmp_path)
    _handed, sink = _custody_sink()
    ledger.rekey(agent_id="op", recorded_at="t2", key_sink=sink, backend="age-file")
    assert ledger.read_floor() == "chill"
    assert ledger.current_epoch_fingerprint() is not None


def test_rekey_writes_key_reset_record(tmp_path):
    ledger, fp0 = _genesis_ledger(tmp_path)
    _handed, sink = _custody_sink()
    ledger.rekey(
        agent_id="recovery-agent",
        recorded_at="t2",
        key_sink=sink,
        backend="age-file",
    )
    records = ledger.store.read_all()
    resets = [r for r in records if r.payload["kind"] == KIND_KEY_RESET]
    assert len(resets) == 1
    rec = resets[0].payload
    # A genesis-only ledger is already chill; rekey records the standing floor
    # instead of using the reset to downgrade a stricter floor.
    assert rec["floor"] == "chill"
    assert rec["key_fingerprint"] != fp0
    assert rec["agent_id"] == "recovery-agent"
    assert rec["recorded_at"] == "t2"
    # Keyless record — the reset IS the loud signal, carries no operator_sig.
    assert rec["operator_sig"] is None


def test_doctor_flags_rekey(tmp_path, monkeypatch):
    # After a rekey, doctor exits non-zero (unacknowledged KEY_RESET, Task 10.2)
    # until a signed transition acknowledges the new epoch.
    import pathlib

    from legis.doctor import check_posture_key_reset, run_doctor

    url = _url(tmp_path)
    monkeypatch.setenv("LEGIS_POSTURE_DB", url)
    monkeypatch.delenv("LEGIS_OPERATOR_KEY", raising=False)

    ledger = PostureLedger(url, initialize=True)
    ledger.genesis(key_fingerprint="ab" * 32, agent_id="installer", recorded_at="t0")
    _handed, sink = _custody_sink()
    ledger.rekey(agent_id="op", recorded_at="t2", key_sink=sink, backend="age-file")

    check = check_posture_key_reset(pathlib.Path("."))
    assert check.ok is False
    assert run_doctor(pathlib.Path("."), repair=False, fmt="json") != 0
