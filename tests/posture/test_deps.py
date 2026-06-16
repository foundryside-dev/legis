"""Phase 0 Task 0.1 — ``cryptography`` is a hard dependency.

The age-file custody backend (scrypt KDF + AES-GCM) makes encrypted-at-rest
key custody core to the posture feature, so ``cryptography`` is mandatory, not
an optional extra (design §6, plan Task 0.1).
"""

from __future__ import annotations


def test_cryptography_importable() -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # noqa: F401
