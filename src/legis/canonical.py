"""Canonical JSON + content hashing (leaf module — no legis imports).

v1 uses sorted-key, tight-separator JSON for deterministic hashing. RFC 8785 is
a future hardening (elspeth uses RFC 8785); legis should converge there before
the protected cell ships cryptographic guarantees (see ADR-0001 / ADR-0002).

Q-L4 deferral (assessed 2026-06-06; clause corrected 2026-06-06): RFC-8785 is
gated on "when cross-language verification is needed." One consumer verifies a
hash this module did NOT produce — ``wardline/ingest.verify_wardline_artifact``
checks the ``artifact_signature`` Wardline computes in its OWN repo/process over
``canonical_json(scan-minus-signature)``. That is genuinely cross-repo and
cross-process, but it is NOT cross-language: Wardline's signer
(``wardline/src/wardline/core/legis.py``) is a deliberate byte-for-byte Python
replica using the same ``ensure_ascii=False`` params. Two guarantees back this,
and they are NOT the same: a golden HMAC vector captured from the real legis
signer is the *cross-impl* pin (it proves the two signers agree byte-for-byte —
but its payload is ASCII-only today); a separate ``"é"`` canonicalization unit
test on each side proves that side preserves a non-ASCII char as the literal
byte rather than a ``\\uXXXX`` escape. Because both serializers are the identical
Python ``json.dumps`` call, non-ASCII findings round-trip and verify — the
``ensure_ascii=False`` choice is what makes them match, not a hazard. The
*cross-impl non-ASCII* case is therefore guaranteed by construction but not yet
pinned by a golden vector; doing so (a non-ASCII payload in the shared golden
HMAC vector) is a Wardline-side follow-up, because that vector lives in
Wardline's repo and only Wardline's repo can detect Wardline drifting. RFC-8785
is needed only the day a *non-Python* verifier lands; because this is the single
canonicalization choke point, that upgrade stays a one-file change. The
companion Q-L5 fingerprint
reconciliation (decorator.py / boundary_scan.py) is independent and is done —
those fingerprints are a content hash of a version-stable AST serialization
(``decorator._stable_ast_repr``, which superseded the interpreter-fragile
``ast.dump`` per legis-13b4e97bf4), not cross-language JSON, so RFC-8785 does not
apply to them.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
