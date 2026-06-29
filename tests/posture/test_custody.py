"""Phase 2 Task 2.2 — custody backends: keychain, age-file, env escape hatch.

age crypto round-trip is REAL (scrypt + AES-GCM, no shell-out). The keychain
availability probe is injected/mocked (no live D-Bus on CI); the real-keychain
round-trip is marked ``@pytest.mark.integration`` and excluded from CI.
"""

from __future__ import annotations

from hashlib import sha256

import pytest

from legis.crypto import signing as enf_signing
from legis.posture import signing


# -- env escape hatch --------------------------------------------------------


def test_env_signer_emits_warning(monkeypatch, caplog) -> None:
    key = signing.mint_key()
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", key)

    with pytest.warns(signing.InsecureEnvKeyWarning):
        signer = signing.EnvSigner(insecure_env=True)

    # It signs (key sourced from env) and carries the right fingerprint.
    sig = signer.sign({"kind": "TRANSITION", "chain_seq": 1})
    assert sig.startswith(enf_signing.SIG_PREFIX_V3)
    assert signer.fingerprint() == sha256(bytes.fromhex(key)).hexdigest()


def test_env_signer_requires_explicit_opt_in(monkeypatch) -> None:
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", signing.mint_key())
    with pytest.raises(ValueError):
        signing.EnvSigner(insecure_env=False)


def test_env_signer_missing_key_raises(monkeypatch) -> None:
    monkeypatch.delenv("LEGIS_OPERATOR_KEY", raising=False)
    with pytest.raises(ValueError):
        signing.EnvSigner(insecure_env=True)


# -- age-file backend (real scrypt + AES-GCM) --------------------------------


def test_age_file_roundtrip() -> None:
    key = signing.mint_key()
    blob = signing.wrap_key(key, "correct horse battery staple")
    recovered = signing.unwrap_key(blob, "correct horse battery staple")
    assert recovered == key

    with pytest.raises(Exception):
        signing.unwrap_key(blob, "wrong passphrase")


def test_age_file_never_persists_plaintext() -> None:
    key = signing.mint_key()
    blob = signing.wrap_key(key, "pw")
    # Raw key (hex string bytes AND the decoded 32 bytes) absent from the blob.
    assert key.encode("utf-8") not in blob
    assert bytes.fromhex(key) not in blob


def test_age_file_signer_roundtrip_signs() -> None:
    key = signing.mint_key()
    blob = signing.wrap_key(key, "pw")
    signer = signing.AgeFileSigner(blob=blob, passphrase_cb=lambda: "pw")

    fields = {"kind": "TRANSITION", "floor": "structured", "chain_seq": 2}
    sig = signer.sign(fields)
    assert enf_signing.verify(fields, sig, bytes.fromhex(key)) is True
    assert signer.fingerprint() == sha256(bytes.fromhex(key)).hexdigest()
    # The signer holds no plaintext key attribute.
    assert not hasattr(signer, "key")


# -- keychain backend (mocked secure store) ----------------------------------


def test_keychain_signer_mocked() -> None:
    key = signing.mint_key()

    class _FakeStore:
        def __init__(self) -> None:
            self._items = {"legis-operator": key}

        def get(self, item_id: str) -> str:
            return self._items[item_id]

    signer = signing.KeychainSigner(item_id="legis-operator", store=_FakeStore())
    fields = {"kind": "TRANSITION", "chain_seq": 5}
    sig = signer.sign(fields)

    assert enf_signing.verify(fields, sig, bytes.fromhex(key)) is True
    assert signer.fingerprint() == sha256(bytes.fromhex(key)).hexdigest()
    # No plaintext key crosses the caller boundary as an attribute.
    assert not hasattr(signer, "key")


# -- backend selection -------------------------------------------------------


def test_custody_default_selection() -> None:
    assert signing.select_backend(keychain_available=True) == "keychain"
    assert signing.select_backend(keychain_available=False) == "age-file"
    assert (
        signing.select_backend(keychain_available=False, insecure_env=True) == "env"
    )
    # env requires explicit opt-in even when keychain is unavailable.
    assert signing.select_backend(keychain_available=False) != "env"


@pytest.mark.integration
def test_keychain_real_roundtrip() -> None:  # pragma: no cover - excluded on CI
    """Real OS-keychain round-trip — only runs under the integration marker."""
    pytest.skip("integration: requires a live OS keychain")
