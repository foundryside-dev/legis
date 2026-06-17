"""Phase 2 Task 2.1 — PostureSigner protocol + key primitives.

The custody seam: the key is held by the backend, never passed by the caller.
``sign(fields)`` returns a v3-prefixed HMAC; ``fingerprint()`` is the sha256 of
the held key. ``mint_key()`` / ``key_fingerprint()`` are the install-time key
primitives.
"""

from __future__ import annotations

from hashlib import sha256

from legis.enforcement import signing as enf_signing
from legis.posture import signing


class _InMemorySigner:
    """A minimal in-memory backend for the protocol tests (no custody store)."""

    def __init__(self, key: bytes) -> None:
        self._key = key

    def fingerprint(self) -> str:
        return sha256(self._key).hexdigest()

    def sign(self, fields: dict) -> str:
        return enf_signing.sign(fields, self._key, version="v3")


def test_sign_returns_prefixed_signature() -> None:
    key_hex = bytes(range(32)).hex()
    signer = signing._RawKeySigner(key_hex)
    sig = signer.sign({"kind": "TRANSITION", "floor": "structured", "chain_seq": 4})
    assert sig.startswith(enf_signing.SIG_PREFIX_V3)


def test_sign_never_returns_key() -> None:
    """No ``key`` attribute, and no public surface leaks the raw key bytes/hex."""
    key = bytes(range(32))
    key_hex = key.hex()
    signer = signing._RawKeySigner(key_hex)

    assert not hasattr(signer, "key")

    sig = signer.sign({"a": 1, "chain_seq": 0})
    # The signature itself must not embed the key.
    assert key_hex not in sig
    assert key.hex() not in sig

    # Behavioral leak check: no public attribute value and no zero-arg public
    # method return equals the raw key (bytes or hex). Tolerant of __slots__
    # objects (no __dict__), which is itself a leak-resistance property.
    for name in dir(signer):
        if name.startswith("_"):
            continue
        attr = getattr(signer, name)
        if not callable(attr):
            assert attr != key
            assert attr != key_hex
            continue
        try:
            result = attr()
        except TypeError:
            # Requires arguments (e.g. sign) — skip; sign tested above.
            continue
        assert result != key
        assert result != key_hex


def test_signature_verifies_against_fingerprint_key() -> None:
    key = bytes(range(1, 33))
    signer = signing._RawKeySigner(key.hex())
    fields = {"kind": "TRANSITION", "floor": "protected", "chain_seq": 7}
    sig = signer.sign(fields)

    assert enf_signing.verify(fields, sig, key) is True
    assert signer.fingerprint() == sha256(key).hexdigest()


def test_mint_key_is_32_bytes_hex() -> None:
    minted = signing.mint_key()
    assert isinstance(minted, str)
    assert len(minted) == 64
    # round-trips as 32 bytes
    assert len(bytes.fromhex(minted)) == 32
    # two mints differ
    assert signing.mint_key() != signing.mint_key()


def test_key_fingerprint_matches_sha256() -> None:
    minted = signing.mint_key()
    key_bytes = bytes.fromhex(minted)
    assert signing.key_fingerprint(minted) == sha256(key_bytes).hexdigest()
