"""Keyed tamper-evidence for protected-cell verdicts.

The Sprint 0 hash chain detects edits by an actor who *cannot* recompute it; an
actor with DB-file access can re-chain a forged record. The HMAC closes that:
without the key, a forged record cannot carry a valid signature. Every signature
carries a version tag so a future canonicalisation or field-set change can be
introduced as a new tag without ambiguity:

  * `v2` pins the audit field set and canonical-JSON v1. It binds record
    *content* only.
  * `v3` (AUD-1) additionally binds the record's chain *position* — the caller
    folds `chain_seq` into the signed fields. This closes the delete-and-rechain
    forgery: an attacker with file access can renumber a record to hide a
    deletion (the chain re-hashes cleanly, the seq stays gap-free), but the v3
    signature bound the original seq and no longer verifies at the new position.
    The signing primitive itself is position-agnostic — it HMACs whatever dict
    it is handed; `v3`-ness is purely the field set the caller commits to and
    the verifier reconstructs (always from the seq *column*, never a payload
    field, or the binding would be forgeable).

Both tags share one HMAC construction, so the cross-tool Wardline artifact
contract (which signs standalone, position-less artifacts at `v2`) is untouched.
"""

from __future__ import annotations

import hashlib
import hmac

from legis.canonical import canonical_json

SIG_PREFIX_V2 = "hmac-sha256:v2:"
SIG_PREFIX_V3 = "hmac-sha256:v3:"
SIG_PREFIX = SIG_PREFIX_V2

_PREFIXES = {"v2": SIG_PREFIX_V2, "v3": SIG_PREFIX_V3}


def _prefix_for(version: str) -> str:
    try:
        return _PREFIXES[version]
    except KeyError:
        raise ValueError(f"unsupported signature version: {version}") from None


def _signed(fields: dict, key: bytes, prefix: str) -> str:
    mac = hmac.new(
        key, canonical_json(fields).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{prefix}{mac}"


def sign(fields: dict, key: bytes, *, version: str = "v2") -> str:
    return _signed(fields, key, _prefix_for(version))


def verify(fields: dict, signature: str, key: bytes) -> bool:
    for prefix in (SIG_PREFIX_V2, SIG_PREFIX_V3):
        if signature.startswith(prefix):
            return hmac.compare_digest(_signed(fields, key, prefix), signature)
    return False
