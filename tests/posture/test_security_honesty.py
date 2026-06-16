"""Phase 12 — security / honesty test suite (cross-cutting).

These tests pin the published honesty guarantees of the posture-ratchet feature
(design §6, §8, §9, §10): the operator key never reaches the caller and never
lands in logs; every floor transition is accountable to an open elevation
session; the env escape hatch is loud and explicit; the age-file backend fails
closed on a wrong/absent passphrase; and a rekey can never land above ``chill``.

They are deliberately *behavioral*, not aspirational (per the Quality reviews):
the key-never-leaks tests sign with a known key and assert that key's hex never
appears in the returned signature, in any public attribute/method value, or in
captured logs at any level.

Unit tests construct the store with an explicit absolute sqlite URL (matching
tests/store/test_audit_store.py / tests/posture/test_change_gate.py), never via
posture_db_url(); the session file is redirected to a per-test tmp path.
"""

from __future__ import annotations

import hashlib
import logging

import pytest

from legis.clock import FixedClock
from legis.enforcement import signing as enf_signing
from legis.posture import session as session_mod
from legis.posture.ledger import (
    REFUSED_NO_SESSION,
    PostureLedger,
    set_floor,
)
from legis.posture.records import KIND_KEY_RESET, KIND_TRANSITION
from legis.posture.signing import (
    AgeFileSigner,
    EnvSigner,
    InsecureEnvKeyWarning,
    KeychainSigner,
    key_fingerprint,
    mint_key,
    wrap_key,
)

_OPERATOR_KEY_ENV = "LEGIS_OPERATOR_KEY"


def _url(tmp_path):
    return f"sqlite:///{tmp_path}/posture.db"


@pytest.fixture(autouse=True)
def _session_dir(tmp_path, monkeypatch):
    """Redirect operator_session_path() to a per-test tmp file.

    set_floor() / load_session() resolve the session via this path; redirect it
    so tests never touch the real .weft/legis/operator_session.json.
    """
    sess_path = tmp_path / "operator_session.json"
    monkeypatch.setattr(session_mod, "operator_session_path", lambda: sess_path)
    return sess_path


class _MemSigner:
    """In-memory test signer: holds a key, signs canonical fields at v3."""

    def __init__(self, key: bytes):
        self._key = key

    def fingerprint(self) -> str:
        return hashlib.sha256(self._key).hexdigest()

    def sign(self, fields: dict) -> str:
        return enf_signing.sign(fields, self._key, version="v3")


def _genesis(tmp_path, *, key_hex: str):
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    fp = key_fingerprint(key_hex)
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    return ledger, fp


def _open_session(*, backend_id: str = "keychain", unlock_ref=None):
    return session_mod.open_session(
        ttl=300,
        operator_id="operator@example",
        backend_id=backend_id,
        unlock_ref=unlock_ref,
    )


def _all_backends(key_hex: str):
    """Construct one of each custody backend over the SAME known key.

    Returns ``(backend_id, signer)`` pairs. The env backend is constructed by
    the caller (it needs an env var set) so it is omitted here and exercised
    explicitly where needed.
    """
    blob = wrap_key(key_hex, "pw")

    class _Store:
        def get(self, item_id: str) -> str:
            return key_hex

    return [
        ("age-file", AgeFileSigner(blob=blob, passphrase_cb=lambda: "pw")),
        ("keychain", KeychainSigner(item_id="kc-1", store=_Store())),
    ]


# -- test_tty_session_expiry -------------------------------------------------


def test_tty_session_expiry(tmp_path):
    """Past TTL, load_session() returns None and deletes the file; a posture set
    after expiry is refused, floor unchanged (design §6/§7).
    """
    import json
    import time

    key_hex = mint_key()
    key_bytes = bytes.fromhex(key_hex)
    ledger, _ = _genesis(tmp_path, key_hex=key_hex)
    sess_path = session_mod.operator_session_path()

    _open_session()
    # Force the window's expiry into the past without sleeping.
    data = json.loads(sess_path.read_text(encoding="utf-8"))
    data["expires_at"] = time.time() - 10
    sess_path.write_text(json.dumps(data), encoding="utf-8")

    # The expired session reads as None AND self-deletes the stale file.
    assert session_mod.load_session() is None
    assert not sess_path.exists()

    # A posture set after expiry is refused (no open session); floor unchanged.
    result = set_floor(
        "structured",
        ledger=ledger,
        signer=_MemSigner(key_bytes),
        agent_id="op",
        rationale="tighten",
        clock=FixedClock("t1"),
    )
    assert result.accepted is False
    assert result.reason == REFUSED_NO_SESSION
    assert len(ledger.store.read_all()) == 1  # only GENESIS
    assert ledger.read_floor() == "chill"


# -- test_key_never_returned_to_caller ---------------------------------------


def test_key_never_returned_to_caller():
    """No backend exposes raw key bytes; sign() returns only a prefixed
    signature and fingerprint() returns a hash. Behavioral: the returned
    signature must not contain the key hex, and no public attr/method value may
    equal the key (design §6).
    """
    key_hex = mint_key()
    fields = {"kind": KIND_TRANSITION, "floor": "structured", "chain_seq": 2}

    for backend_id, signer in _all_backends(key_hex):
        sig = signer.sign(fields)
        fp = signer.fingerprint()
        # The signature is a prefixed HMAC string, not the key.
        assert isinstance(sig, str)
        assert key_hex not in sig, backend_id
        # The fingerprint is the hash, never the key itself.
        assert fp == key_fingerprint(key_hex)
        assert key_hex not in fp
        # No public attribute value equals the key (private slots are mangled /
        # underscored; we scan the *public* surface the caller can reach).
        public_attrs = [a for a in dir(signer) if not a.startswith("_")]
        for name in public_attrs:
            value = getattr(signer, name)
            if callable(value):
                continue
            assert value != key_hex, f"{backend_id}.{name} exposed the key"
        # The two public methods do not return the raw key.
        assert signer.fingerprint() != key_hex
        assert signer.sign(fields) != key_hex


# -- test_rekey_resets_to_chill ----------------------------------------------


def test_rekey_resets_to_chill(tmp_path):
    """(Cross-ref Phase 11) a rekey can never land above chill — even from an
    elevated floor, the post-reset floor is chill (design §8).
    """
    key_hex = mint_key()
    key_bytes = bytes.fromhex(key_hex)
    ledger, _ = _genesis(tmp_path, key_hex=key_hex)

    # Elevate the floor first so the reset visibly drops it back to chill.
    _open_session()
    set_floor(
        "protected",
        ledger=ledger,
        signer=_MemSigner(key_bytes),
        agent_id="op",
        rationale="tighten",
        clock=FixedClock("t1"),
    )
    assert ledger.read_floor() == "protected"

    # Rekey resets to chill regardless of the prior (elevated) floor.
    ledger.rekey(agent_id="op", recorded_at="t2")
    assert ledger.read_floor() == "chill"
    # The KEY_RESET record itself carries floor="chill" (cannot land above).
    resets = [r for r in ledger.store.read_all() if r.payload["kind"] == KIND_KEY_RESET]
    assert len(resets) == 1
    assert resets[0].payload["floor"] == "chill"


# -- test_every_signature_carries_session_id ---------------------------------


def test_every_signature_carries_session_id(tmp_path):
    """Every TRANSITION in a window carries session_id == the open session's id;
    a no-session transition is refused. Includes the env-backend path (D3): an
    EnvSigner transition still carries session_id (design §6, §7).
    """
    key_hex = mint_key()
    key_bytes = bytes.fromhex(key_hex)
    ledger, _ = _genesis(tmp_path, key_hex=key_hex)

    sess = _open_session()
    set_floor(
        "structured",
        ledger=ledger,
        signer=_MemSigner(key_bytes),
        agent_id="op",
        rationale="r1",
        clock=FixedClock("t1"),
    )
    transitions = [
        r for r in ledger.store.read_all() if r.payload["kind"] == KIND_TRANSITION
    ]
    assert len(transitions) == 1
    assert transitions[0].payload["session_id"] == sess.session_id

    # No-session transition is refused (no record appended).
    session_mod.end_session()
    refused = set_floor(
        "coached",
        ledger=ledger,
        signer=_MemSigner(key_bytes),
        agent_id="op",
        rationale="r2",
        clock=FixedClock("t2"),
    )
    assert refused.accepted is False
    assert refused.reason == REFUSED_NO_SESSION

    # Env-backend path (D3): an EnvSigner transition still carries a session_id.
    import os

    os.environ[_OPERATOR_KEY_ENV] = key_hex
    try:
        env_sess = _open_session(backend_id="env")
        with pytest.warns(InsecureEnvKeyWarning):
            env_signer = EnvSigner(insecure_env=True)
        env_result = set_floor(
            "structured",
            ledger=ledger,
            signer=env_signer,
            agent_id="ci",
            rationale="ci-raise",
            clock=FixedClock("t3"),
        )
    finally:
        del os.environ[_OPERATOR_KEY_ENV]
    assert env_result.accepted is True
    assert env_result.session_id == env_sess.session_id
    last = ledger.store.read_all()[-1].payload
    assert last["kind"] == KIND_TRANSITION
    assert last["session_id"] == env_sess.session_id


# -- test_env_escape_hatch_warns ---------------------------------------------


def test_env_escape_hatch_warns(monkeypatch):
    """EnvSigner requires explicit --insecure-key-in-env (insecure_env=True) and
    emits an honest warning (design §6/§9).
    """
    key_hex = mint_key()
    monkeypatch.setenv(_OPERATOR_KEY_ENV, key_hex)

    # Without the explicit opt-in: refused, no warning path, no signer.
    with pytest.raises(ValueError, match="insecure_env=True"):
        EnvSigner(insecure_env=False)

    # With the opt-in: an honest InsecureEnvKeyWarning is emitted.
    with pytest.warns(InsecureEnvKeyWarning):
        signer = EnvSigner(insecure_env=True)
    # The warning is honest, not silent: it constructs a usable signer over the
    # env key whose fingerprint matches the env key.
    assert signer.fingerprint() == key_fingerprint(key_hex)


# -- test_age_file_passphrase_required ---------------------------------------


def test_age_file_passphrase_required():
    """Age-file unlock with a wrong/absent passphrase fails closed — no
    signature is produced (design §6).
    """
    key_hex = mint_key()
    blob = wrap_key(key_hex, "correct-passphrase")
    fields = {"kind": KIND_TRANSITION, "floor": "structured", "chain_seq": 2}

    # Correct passphrase round-trips: a signature is produced.
    good = AgeFileSigner(blob=blob, passphrase_cb=lambda: "correct-passphrase")
    assert isinstance(good.sign(fields), str)

    # Wrong passphrase: AES-GCM tag mismatch raises; no signature returned.
    wrong = AgeFileSigner(blob=blob, passphrase_cb=lambda: "WRONG")
    with pytest.raises(Exception):
        wrong.sign(fields)
    with pytest.raises(Exception):
        wrong.fingerprint()

    # Absent passphrase (empty string) also fails closed — never silently signs.
    absent = AgeFileSigner(blob=blob, passphrase_cb=lambda: "")
    with pytest.raises(Exception):
        absent.sign(fields)


# -- test_operator_key_never_in_logs -----------------------------------------


def test_operator_key_never_in_logs(caplog):
    """Concrete (not aspirational): with DEBUG capture and propagation on, calling
    each backend's sign() on a known key must never put key.hex() in the captured
    log text at any level. Deterministic; catches regressions when log statements
    are added to the signing path (design §6/§9, Quality high).
    """
    key_hex = mint_key()
    fields = {"kind": KIND_TRANSITION, "floor": "structured", "chain_seq": 2}

    backends = list(_all_backends(key_hex))

    # Env backend too — it is the riskiest (key already resident plaintext).
    import os

    os.environ[_OPERATOR_KEY_ENV] = key_hex
    try:
        with pytest.warns(InsecureEnvKeyWarning):
            backends.append(("env", EnvSigner(insecure_env=True)))

        for backend_id, signer in backends:
            caplog.clear()
            with caplog.at_level(logging.DEBUG):
                # Force propagation so any module logger surfaces in caplog.text.
                logging.getLogger("legis").propagate = True
                logging.getLogger("legis.posture").propagate = True
                signer.sign(fields)
                signer.fingerprint()
            assert key_hex not in caplog.text, backend_id
    finally:
        del os.environ[_OPERATOR_KEY_ENV]
