"""Legis posture-ratchet package (design 2026-06-16).

The signed posture floor and the operator-elevation-session primitive it is
signed through. Public re-exports grow phase by phase; Phase 1 ships the record
model and the ledger.
"""

from __future__ import annotations

from legis.posture.ledger import PostureLedger
from legis.posture.records import (
    KIND_GENESIS,
    KIND_KEY_RESET,
    KIND_SESSION_OPENED,
    KIND_TRANSITION,
    PostureRecord,
)
from legis.posture.signing import (
    AgeFileSigner,
    EnvSigner,
    InsecureEnvKeyWarning,
    KeychainSigner,
    PostureSigner,
    key_fingerprint,
    mint_key,
    select_backend,
    unwrap_key,
    wrap_key,
)

__all__ = [
    "KIND_GENESIS",
    "KIND_KEY_RESET",
    "KIND_SESSION_OPENED",
    "KIND_TRANSITION",
    "AgeFileSigner",
    "EnvSigner",
    "InsecureEnvKeyWarning",
    "KeychainSigner",
    "PostureLedger",
    "PostureRecord",
    "PostureSigner",
    "key_fingerprint",
    "mint_key",
    "select_backend",
    "unwrap_key",
    "wrap_key",
]
