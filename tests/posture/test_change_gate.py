"""Phase 5 / Task 5.1 — the change gate (``posture set`` transition).

Fail-closed (design §7): no open session -> refuse; fingerprint mismatch ->
refuse; signer error -> refuse; floor unchanged; exactly one outcome, no silent
pass. Per D3 a session is REQUIRED for every ``posture set`` — there is no
direct-sign path.

The change gate is :func:`legis.posture.ledger.set_floor`. It resolves the
current-epoch ``key_fingerprint`` from the last GENESIS/KEY_RESET record (a tail
read, BEFORE entering ``append_signed`` per Q-M5), checks it against the open
session and the signer's fingerprint, then appends exactly one ``TRANSITION``.

All unit tests construct the store with an explicit absolute sqlite URL (matching
tests/store/test_audit_store.py), never via posture_db_url().
"""

from __future__ import annotations

import hashlib
import json
import time

import pytest

from legis.clock import FixedClock
from legis.enforcement import signing as enf_signing
from legis.posture import session as session_mod
from legis.posture.ledger import PostureLedger, set_floor
from legis.posture.signing import (
    AgeFileSigner,
    key_fingerprint,
    mint_key,
    wrap_key,
)


def _url(tmp_path):
    return f"sqlite:///{tmp_path}/posture.db"


class _MemSigner:
    """In-memory test signer: holds a key, signs canonical fields at v3."""

    def __init__(self, key: bytes):
        self._key = key

    def fingerprint(self) -> str:
        return hashlib.sha256(self._key).hexdigest()

    def sign(self, fields: dict) -> str:
        return enf_signing.sign(fields, self._key, version="v3")


class _BoomSigner:
    """A signer whose fingerprint matches the epoch but whose sign() raises.

    Used to prove signer failure inside ``append_signed`` is fail-closed: the
    fingerprint check passes (so we reach the sign step) but the sign step
    raises, and no row is committed.
    """

    def __init__(self, key: bytes):
        self._key = key

    def fingerprint(self) -> str:
        return hashlib.sha256(self._key).hexdigest()

    def sign(self, fields: dict) -> str:
        raise RuntimeError("signer backend exploded")


class _FakeFingerprintSigner:
    """Claims the epoch fingerprint but cannot sign with the epoch key."""

    def __init__(self, fingerprint: str):
        self._fingerprint = fingerprint

    def fingerprint(self) -> str:
        return self._fingerprint

    def sign(self, fields: dict) -> str:
        return "hmac-sha256:v3:" + "0" * 64


@pytest.fixture(autouse=True)
def _session_dir(tmp_path, monkeypatch):
    """Point operator_session_path() at a per-test tmp dir.

    set_floor() reads the session via session.load_session(), which resolves
    operator_session_path() from config; redirect it so tests don't touch the
    real .weft/legis/operator_session.json.
    """
    sess_path = tmp_path / "operator_session.json"
    monkeypatch.setattr(
        session_mod, "operator_session_path", lambda: sess_path
    )
    # config.operator_session_path is what session_mod imported at module load;
    # the monkeypatch above rebinds the name in session_mod's namespace.
    return sess_path


def _genesis(tmp_path, key: bytes):
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    return ledger, fp


def _open_session(*, backend_id: str = "keychain", unlock_ref=None, signer=None):
    if signer is None:
        signer = _MemSigner(b"k" * 32)
    return session_mod.open_session(
        ttl=300,
        operator_id="operator@example",
        backend_id=backend_id,
        unlock_ref=unlock_ref,
        signer=signer,
    )


def test_set_refused_without_session(tmp_path):
    key = b"k" * 32
    ledger, fp = _genesis(tmp_path, key)
    # No open session at all.
    result = set_floor(
        "structured",
        ledger=ledger,
        signer=_MemSigner(key),
        agent_id="op",
        rationale="tighten",
        clock=FixedClock("t1"),
    )
    assert result.accepted is False
    # Ledger unchanged: only the GENESIS.
    assert len(ledger.store.read_all()) == 1
    assert ledger.read_floor() == "chill"


def test_set_refused_with_forged_session_file(tmp_path, _session_dir):
    key = b"k" * 32
    ledger, fp = _genesis(tmp_path, key)
    _session_dir.write_text(
        json.dumps(
            {
                "session_id": "forged-session",
                "operator_id": "attacker@example",
                "opened_at": time.time(),
                "ttl": 300,
                "expires_at": time.time() + 300,
                "backend_id": "keychain",
                "unlock_ref": None,
            }
        ),
        encoding="utf-8",
    )

    result = set_floor(
        "structured",
        ledger=ledger,
        signer=_MemSigner(key),
        agent_id="op",
        rationale="tighten",
        clock=FixedClock("t1"),
    )

    assert result.accepted is False
    assert len(ledger.store.read_all()) == 1
    assert ledger.read_floor() == "chill"


def test_set_refused_when_signer_self_attests_fingerprint(tmp_path):
    key = b"k" * 32
    ledger, fp = _genesis(tmp_path, key)
    _open_session()

    result = set_floor(
        "structured",
        ledger=ledger,
        signer=_FakeFingerprintSigner(fp),
        agent_id="op",
        rationale="tighten",
        clock=FixedClock("t1"),
    )

    assert result.accepted is False
    assert len(ledger.store.read_all()) == 1
    assert ledger.read_floor() == "chill"


def test_set_refused_fingerprint_mismatch(tmp_path):
    key = b"k" * 32
    ledger, fp = _genesis(tmp_path, key)
    _open_session()
    # Signer for a DIFFERENT key than the ledger's current epoch.
    other = _MemSigner(b"other-key-bytes-................")
    result = set_floor(
        "structured",
        ledger=ledger,
        signer=other,
        agent_id="op",
        rationale="tighten",
        clock=FixedClock("t1"),
    )
    assert result.accepted is False
    assert len(ledger.store.read_all()) == 1  # no record
    assert ledger.read_floor() == "chill"


def test_set_refused_on_signer_error(tmp_path):
    key = b"k" * 32
    ledger, fp = _genesis(tmp_path, key)
    _open_session()
    result = set_floor(
        "structured",
        ledger=ledger,
        signer=_BoomSigner(key),  # right fingerprint, sign() raises
        agent_id="op",
        rationale="tighten",
        clock=FixedClock("t1"),
    )
    assert result.accepted is False
    # No half-written record (append_signed not committed).
    assert len(ledger.store.read_all()) == 1
    assert ledger.read_floor() == "chill"


def test_set_refused_on_wrong_passphrase(tmp_path):
    # Age-file backend whose passphrase callback returns the WRONG passphrase:
    # unwrap raises mid-callback and must leave no partial state.
    key = mint_key()
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    fp = key_fingerprint(key)
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    _open_session(backend_id="age-file", signer=_MemSigner(bytes.fromhex(key)))

    blob = wrap_key(key, "correct-passphrase")
    signer = AgeFileSigner(blob=blob, passphrase_cb=lambda: "WRONG-passphrase")

    before = len(ledger.store.read_all())
    result = set_floor(
        "structured",
        ledger=ledger,
        signer=signer,
        agent_id="op",
        rationale="tighten",
        clock=FixedClock("t1"),
    )
    assert result.accepted is False
    assert len(ledger.store.read_all()) == before  # unchanged
    assert ledger.read_floor() == "chill"


def test_set_accepted_with_valid_session(tmp_path):
    key = b"k" * 32
    ledger, fp = _genesis(tmp_path, key)
    sess = _open_session()
    result = set_floor(
        "structured",
        ledger=ledger,
        signer=_MemSigner(key),
        agent_id="op",
        rationale="tighten",
        clock=FixedClock("t1"),
    )
    assert result.accepted is True
    # Exactly one TRANSITION appended.
    records = ledger.store.read_all()
    assert len(records) == 2
    rec = records[-1]
    assert rec.payload["kind"] == "TRANSITION"
    assert rec.payload["floor"] == "structured"
    assert ledger.read_floor() == "structured"
    # session_id matches the open session.
    assert rec.payload["session_id"] == sess.session_id
    # operator_sig verifies (v3 position binding via chain_seq=seq).
    sig = rec.payload["operator_sig"]
    assert sig is not None
    fields = {k: v for k, v in rec.payload.items() if k != "operator_sig"}
    fields["chain_seq"] = rec.seq
    assert enf_signing.verify(fields, sig, key) is True


def test_every_signature_carries_session_id(tmp_path):
    key = b"k" * 32
    ledger, fp = _genesis(tmp_path, key)
    sess = _open_session()
    set_floor(
        "coached",
        ledger=ledger,
        signer=_MemSigner(key),
        agent_id="op",
        rationale="r",
        clock=FixedClock("t1"),
    )
    rec = ledger.store.read_by_seq(2)
    assert rec is not None
    assert rec.payload["session_id"] is not None
    assert rec.payload["session_id"] == sess.session_id

    # A transition produced with NO session is refused (no second record).
    session_mod.end_session()
    result = set_floor(
        "structured",
        ledger=ledger,
        signer=_MemSigner(key),
        agent_id="op",
        rationale="r2",
        clock=FixedClock("t2"),
    )
    assert result.accepted is False
    assert len(ledger.store.read_all()) == 2  # still just genesis + one transition


def test_exactly_one_record_per_outcome(tmp_path):
    key = b"k" * 32
    ledger, fp = _genesis(tmp_path, key)

    # Refusal (no session) adds 0 records.
    before = len(ledger.store.read_all())
    r1 = set_floor(
        "structured",
        ledger=ledger,
        signer=_MemSigner(key),
        agent_id="op",
        rationale="r",
        clock=FixedClock("t1"),
    )
    assert r1.accepted is False
    assert len(ledger.store.read_all()) == before

    # Success adds exactly 1.
    _open_session()
    r2 = set_floor(
        "structured",
        ledger=ledger,
        signer=_MemSigner(key),
        agent_id="op",
        rationale="r",
        clock=FixedClock("t2"),
    )
    assert r2.accepted is True
    assert len(ledger.store.read_all()) == before + 1


def test_set_refused_fingerprint_checked_against_ledger_epoch(tmp_path):
    """Fingerprint is checked against the LEDGER epoch (last GENESIS/KEY_RESET),
    not the session's own recorded field (Quality critical: concurrent-session /
    epoch race). A signer for the current ledger epoch is accepted; a signer for
    a different key is refused even with a valid open session.
    """
    key = b"k" * 32
    ledger, fp = _genesis(tmp_path, key)
    _open_session()
    # Wrong-epoch signer -> refused.
    refused = set_floor(
        "structured",
        ledger=ledger,
        signer=_MemSigner(b"z" * 32),
        agent_id="op",
        rationale="r",
        clock=FixedClock("t1"),
    )
    assert refused.accepted is False
    assert len(ledger.store.read_all()) == 1
    # Right-epoch signer -> accepted.
    accepted = set_floor(
        "structured",
        ledger=ledger,
        signer=_MemSigner(key),
        agent_id="op",
        rationale="r",
        clock=FixedClock("t2"),
    )
    assert accepted.accepted is True
