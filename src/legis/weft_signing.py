"""Shared Weft-component transport-HMAC seam.

The Loomweave SEI client (``identity/loomweave_client.py``) authenticates
protected requests with ``X-Weft-Component: <name>:<hmac>`` plus
``X-Weft-Timestamp`` and ``X-Weft-Nonce``, where the HMAC is computed over
``METHOD\\npath?query\\nsha256(body)\\ntimestamp\\nnonce``. This module is the
single definition of that scheme for live HMAC transports and historical vectors.

Canonicalization contract: the signed body bytes are
``json.dumps(body, sort_keys=True, separators=(",", ":"))`` with the default
``ensure_ascii=True``. This is deliberately **NOT** ``canonical.canonical_json``,
whose ``ensure_ascii=False`` is the byte-for-byte HMAC contract shared with
Wardline; routing a transport body through it would change every signed
request's bytes. The wire transport MUST send exactly ``weft_body_bytes(body)``
and a verifier MUST recanonicalize identically before hashing.

Per-channel posture (the one place a future third channel reads before deciding
signed-vs-open):
  * Loomweave SEI channel — **signed**: emits + (server-side) verifies X-Weft-*.
  * Filigree classic entity-association channel — **transport-open** since G11
    (weft-c7e3486246): the route does not verify X-Weft-*, so Legis does **not**
    emit transport-HMAC headers on Filigree binds. The app-level
    ``binding_signature`` still travels in the JSON body and remains the
    governance attestation; integrity rests on loopback/TLS transport and on
    legis's own ``BindingLedger`` (the authoritative, locally-verifiable
    record), not on a sibling checking a transport signature.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.parse


def weft_body_bytes(body: dict | None) -> bytes:
    """Serialize a request body to the exact bytes the signature commits to."""
    if body is None:
        return b""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def weft_path_and_query(url: str) -> str:
    """The path (plus query, if any) the signed message commits to."""
    parsed = urllib.parse.urlsplit(url)
    path_and_query = parsed.path or "/"
    if parsed.query:
        path_and_query = f"{path_and_query}?{parsed.query}"
    return path_and_query


def sign_weft_request(
    component: str,
    key: bytes,
    method: str,
    url: str,
    body: dict | None,
    *,
    timestamp: int,
    nonce: str,
) -> dict[str, str]:
    """Return the Weft-component HMAC request headers for ``component``.

    ``timestamp`` and ``nonce`` are injected (not generated here) so the
    signature is deterministically testable.
    """
    body_hash = hashlib.sha256(weft_body_bytes(body)).hexdigest()
    message = (
        f"{method}\n{weft_path_and_query(url)}\n{body_hash}\n{timestamp}\n{nonce}"
    ).encode("utf-8")
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    return {
        "X-Weft-Component": f"{component}:{signature}",
        "X-Weft-Timestamp": str(timestamp),
        "X-Weft-Nonce": nonce,
    }


def weft_hmac_key_from_env(component_env_var: str) -> bytes | None:
    """Resolve a channel HMAC key without making it mandatory.

    The channel-specific variable (e.g. ``LEGIS_LOOMWEAVE_HMAC_KEY``) wins; an
    absent channel key falls back to the shared ``LEGIS_HMAC_KEY``; absent both,
    the channel is unsigned (backward compatible with deployments that have not
    provisioned a key yet).
    """
    value = os.environ.get(component_env_var) or os.environ.get("LEGIS_HMAC_KEY")
    return value.encode("utf-8") if value else None
