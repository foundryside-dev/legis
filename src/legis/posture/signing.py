"""PostureSigner seam + custody backends (design §6/§7, plan Phase 2).

The operator-authority key is *minted at install* and handed to a custody
backend; from then on the agent process never sees the key bytes. The change
gate (Phase 5) hands a signer canonical record fields and receives an
``operator_sig``; the signer holds the key and signs internally.

**The key never lands in the caller's hands.** Every backend exposes
:meth:`fingerprint` (sha256 of the held key, safe to surface), :meth:`sign` (a
v3 HMAC over the caller's fields), and may expose :meth:`verify` to prove a
signature against backend-owned key material without returning it. No backend
exposes a ``key`` attribute or returns key bytes from any public method
(test-pinned).

**``chain_seq`` is mandatory in the signed fields.** The caller folds the
record's chain position (``chain_seq=seq``) into the fields it hands ``sign``;
the v3 signature binds content *and* position (see
:mod:`legis.crypto.signing`). Omitting ``chain_seq`` silently signs the
wrong base and the verifier — which reconstructs ``chain_seq`` from the seq
column — will not match. Backends do not add it; the change gate does.

Custody backends (v1):

* :class:`KeychainSigner` — key held in an OS secure store (macOS Keychain /
  Secret Service / Windows Credential Manager) via an injectable seam; loaded
  into a local var per ``sign`` and discarded.
* :class:`AgeFileSigner` — key wrapped at rest with scrypt + AES-GCM
  (:func:`wrap_key` / :func:`unwrap_key`, no ``age`` CLI shell-out); unwrapped
  per ``sign`` and discarded.
* :class:`EnvSigner` — the ``LEGIS_OPERATOR_KEY`` plaintext escape hatch for
  CI/headless; constructed only behind an explicit ``insecure_env=True`` and
  emits an honest :class:`InsecureEnvKeyWarning`.

:func:`select_backend` is the install-time default chooser: keychain if
available, else age-file; env only on explicit opt-in.
"""

from __future__ import annotations

import os
import secrets
import warnings
from hashlib import sha256
from typing import Callable, Protocol, runtime_checkable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from legis.crypto import signing as _enf_signing

# -- key primitives ----------------------------------------------------------


def mint_key() -> str:
    """Mint a fresh 32-byte operator key as 64 hex chars (design §5).

    ``secrets.token_hex(32)`` — cryptographically strong, the install-time
    opt-in moment. Returned as hex so it round-trips cleanly through custody
    (env var, age blob, keychain item) without binary-encoding hazards.
    """
    return secrets.token_hex(32)


def key_fingerprint(key: str) -> str:
    """The ``sha256`` of the key bytes, hex — what the ledger trusts per epoch.

    ``key`` is the hex form from :func:`mint_key`; the fingerprint is taken over
    the *decoded* bytes so it matches ``sha256(key_bytes)`` used everywhere the
    raw key is held in memory.
    """
    return sha256(bytes.fromhex(key)).hexdigest()


# -- the signer seam ---------------------------------------------------------


@runtime_checkable
class PostureSigner(Protocol):
    """The custody-backend signer contract (design §6).

    The key is held by the backend, never passed by the caller. ``sign`` is
    handed canonical record fields *including* ``chain_seq`` and returns a v3
    HMAC string; ``fingerprint`` is the sha256 of the held key.
    """

    def fingerprint(self) -> str: ...

    def sign(self, fields: dict) -> str: ...


@runtime_checkable
class PostureVerifier(PostureSigner, Protocol):
    """Optional custody-backend verifier contract.

    Non-extractable backends can verify signatures internally without exposing
    raw key material to the caller. Legacy/raw test signers that lack this
    method still go through the local fallback below.
    """

    def verify(self, fields: dict, signature: str) -> bool: ...


def _sign_with_key(fields: dict, key_hex: str) -> str:
    """v3-sign ``fields`` with a hex key, discarding the bytes on return.

    The single internal join to :func:`legis.crypto.signing.sign` — every
    backend funnels through here so the version tag (``v3``) and the
    bytes-from-hex decode are defined once.
    """
    key_bytes = bytes.fromhex(key_hex)
    return _enf_signing.sign(fields, key_bytes, version="v3")


class _RawKeySigner:
    """A signer holding a raw hex key in a private slot (base for env/test).

    Not a public custody backend on its own — :class:`KeychainSigner` /
    :class:`AgeFileSigner` load the key per ``sign`` rather than holding it — but
    :class:`EnvSigner` subclasses it because the env key is, by its nature,
    already resident plaintext. The key lives only in a name-mangled private
    attribute; no public attribute or method surfaces it.
    """

    __slots__ = ("_key_hex",)

    def __init__(self, key_hex: str) -> None:
        self._key_hex = key_hex

    def fingerprint(self) -> str:
        return key_fingerprint(self._key_hex)

    def sign(self, fields: dict) -> str:
        return _sign_with_key(fields, self._key_hex)

    def verify(self, fields: dict, signature: str) -> bool:
        return _enf_signing.verify(fields, signature, bytes.fromhex(self._key_hex))


# -- env escape hatch --------------------------------------------------------

_OPERATOR_KEY_ENV = "LEGIS_OPERATOR_KEY"


class InsecureEnvKeyWarning(UserWarning):
    """Raised when the operator key is sourced from a plaintext env var.

    Honest disclosure (design §6/§9): a key in ``LEGIS_OPERATOR_KEY`` is
    readable by the very agent process it is meant to gate. The env backend is
    an escape hatch for CI/headless only, behind an explicit opt-in.
    """


class EnvSigner(_RawKeySigner):
    """The ``LEGIS_OPERATOR_KEY`` plaintext escape hatch (CI/headless only).

    Constructed only behind ``insecure_env=True`` and emits an
    :class:`InsecureEnvKeyWarning`. The key value is never stored in the session
    file; it lives in the env the operator already chose to expose.
    """

    def __init__(self, *, insecure_env: bool) -> None:
        if not insecure_env:
            raise ValueError(
                "EnvSigner requires explicit insecure_env=True "
                "(the --insecure-key-in-env opt-in): the operator key would be "
                "plaintext in the agent's environment"
            )
        key_hex = os.environ.get(_OPERATOR_KEY_ENV)
        if not key_hex:
            raise ValueError(
                f"{_OPERATOR_KEY_ENV} is not set; cannot open the env signer"
            )
        warnings.warn(
            f"{_OPERATOR_KEY_ENV} holds the operator key in plaintext, readable "
            "by this process; use the keychain or age-file backend in production",
            InsecureEnvKeyWarning,
            stacklevel=2,
        )
        super().__init__(key_hex)


# -- age-encrypted file backend ----------------------------------------------

# Blob layout: salt(16) | nonce(12) | ciphertext+tag. scrypt KDF parameters are
# fixed (interactive-strength, OWASP-recommended n=2**15) and embedded by
# construction; only the random salt/nonce vary, so they ride in the header.
_AGE_SALT_LEN = 16
_AGE_NONCE_LEN = 12
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1


def _derive_age_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def wrap_key(key: str, passphrase: str) -> bytes:
    """Encrypt the hex operator ``key`` under ``passphrase`` (scrypt + AES-GCM).

    Returns an opaque blob (``salt | nonce | ciphertext+tag``) safe to persist
    at ``operator.age``. The blob never contains the plaintext key
    (test-pinned). No ``age`` CLI shell-out — pure :mod:`cryptography`.
    """
    salt = secrets.token_bytes(_AGE_SALT_LEN)
    nonce = secrets.token_bytes(_AGE_NONCE_LEN)
    derived = _derive_age_key(passphrase, salt)
    ciphertext = AESGCM(derived).encrypt(nonce, key.encode("utf-8"), None)
    return salt + nonce + ciphertext


def unwrap_key(blob: bytes, passphrase: str) -> str:
    """Decrypt a :func:`wrap_key` blob back to the hex key.

    Raises on a wrong passphrase (AES-GCM tag mismatch ->
    :class:`cryptography.exceptions.InvalidTag`) or a truncated blob — there is
    no silent fallback to a wrong key.
    """
    if len(blob) < _AGE_SALT_LEN + _AGE_NONCE_LEN:
        raise ValueError("age blob is truncated")
    salt = blob[:_AGE_SALT_LEN]
    nonce = blob[_AGE_SALT_LEN : _AGE_SALT_LEN + _AGE_NONCE_LEN]
    ciphertext = blob[_AGE_SALT_LEN + _AGE_NONCE_LEN :]
    derived = _derive_age_key(passphrase, salt)
    plaintext = AESGCM(derived).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


class AgeFileSigner:
    """Signer over an age-wrapped key blob; unwraps per ``sign`` and discards.

    Holds the encrypted ``blob`` and a ``passphrase_cb`` (re-prompt per sign for
    the age-file-without-keychain case, design §6). The plaintext key is never
    held as an attribute — it lives only in a local var inside :meth:`sign` /
    :meth:`fingerprint` and is discarded on return.
    """

    __slots__ = ("_blob", "_passphrase_cb")

    def __init__(self, *, blob: bytes, passphrase_cb: Callable[[], str]) -> None:
        self._blob = blob
        self._passphrase_cb = passphrase_cb

    def _key(self) -> str:
        return unwrap_key(self._blob, self._passphrase_cb())

    def fingerprint(self) -> str:
        return key_fingerprint(self._key())

    def sign(self, fields: dict) -> str:
        return _sign_with_key(fields, self._key())

    def verify(self, fields: dict, signature: str) -> bool:
        return _enf_signing.verify(fields, signature, bytes.fromhex(self._key()))


class _KeychainStore(Protocol):
    """The OS-keychain seam: get a stored secret by item id (injectable)."""

    def get(self, item_id: str) -> str: ...


class KeychainSigner:
    """Signer over an OS-keychain item; loads the key per ``sign`` and discards.

    The ``store`` is the injectable secure-store seam (mocked in CI, a real
    Secret Service / Keychain / Credential Manager adapter in production). The
    key is fetched into a local var per call and never held as an attribute.
    """

    __slots__ = ("_item_id", "_store")

    def __init__(self, *, item_id: str, store: _KeychainStore) -> None:
        self._item_id = item_id
        self._store = store

    def _key(self) -> str:
        return self._store.get(self._item_id)

    def fingerprint(self) -> str:
        return key_fingerprint(self._key())

    def sign(self, fields: dict) -> str:
        return _sign_with_key(fields, self._key())

    def verify(self, fields: dict, signature: str) -> bool:
        return _enf_signing.verify(fields, signature, bytes.fromhex(self._key()))


def _verification_key_hex(signer: PostureSigner) -> str:
    """Extract the held key from supported custody signers for local verification.

    This compatibility fallback stays inside the posture module boundary:
    callers still receive only a signer object, while older local/test signers
    that lack ``verify()`` can still prove the produced signature verifies under
    key material whose fingerprint matches the standing epoch.
    """
    if isinstance(signer, _RawKeySigner):
        return signer._key_hex
    if isinstance(signer, (AgeFileSigner, KeychainSigner)):
        return signer._key()
    key = getattr(signer, "_key", None)
    if isinstance(key, bytes):
        return key.hex()
    if isinstance(key, str):
        return key
    raise TypeError("unsupported posture signer backend")


def verify_signer_signature(
    signer: PostureSigner,
    fields: dict,
    signature: str,
    *,
    expected_fingerprint: str,
) -> bool:
    """True iff *signature* verifies under the signer's actual held key.

    A self-attested ``fingerprint()`` is not enough: the key material used for
    verification must hash to the epoch fingerprint and must validate the HMAC.
    """
    try:
        if signer.fingerprint() != expected_fingerprint:
            return False
        verifier = getattr(signer, "verify", None)
        if callable(verifier):
            return bool(verifier(fields, signature))
        key_hex = _verification_key_hex(signer)
        if key_fingerprint(key_hex) != expected_fingerprint:
            return False
        return _enf_signing.verify(fields, signature, bytes.fromhex(key_hex))
    except Exception:  # noqa: BLE001 - custody faults fail closed
        return False


# -- backend selection -------------------------------------------------------


def select_backend(
    *, keychain_available: bool, insecure_env: bool = False
) -> str:
    """Pick the default custody backend id at install (design §6).

    Keychain if available, else the age-file backend; the env escape hatch only
    on an explicit ``insecure_env=True`` opt-in — never auto-selected, even
    headless, because it puts the key in plaintext.
    """
    if insecure_env:
        return "env"
    if keychain_available:
        return "keychain"
    return "age-file"
