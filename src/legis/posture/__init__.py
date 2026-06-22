"""Legis posture-ratchet package (design 2026-06-16).

The signed posture floor and the operator-elevation-session primitive it is
signed through. Public re-exports grow phase by phase; Phase 1 ships the record
model and the ledger.
"""

from __future__ import annotations

from legis.posture.floor import FlooredRegistry, floored_registry
from legis.posture.ledger import (
    REFUSED_SESSION_NOT_RECORDED,
    PostureLedger,
    PostureSetResult,
    set_floor,
)
from legis.posture.records import (
    KIND_GENESIS,
    KIND_KEY_RESET,
    KIND_SESSION_OPENED,
    KIND_TRANSITION,
    PostureRecord,
)
from legis.posture.session import (
    Session,
    end_session,
    is_active,
    load_session,
    open_session,
    persist_session,
)
from legis.posture.signing import (
    AgeFileSigner,
    EnvSigner,
    InsecureEnvKeyWarning,
    KeychainSigner,
    PostureSigner,
    PostureVerifier,
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
    "FlooredRegistry",
    "InsecureEnvKeyWarning",
    "KeychainSigner",
    "PostureLedger",
    "PostureRecord",
    "PostureSetResult",
    "PostureSigner",
    "PostureVerifier",
    "REFUSED_SESSION_NOT_RECORDED",
    "Session",
    "end_session",
    "floored_registry",
    "is_active",
    "key_fingerprint",
    "load_session",
    "mint_key",
    "open_session",
    "persist_session",
    "select_backend",
    "set_floor",
    "unwrap_key",
    "wrap_key",
]
