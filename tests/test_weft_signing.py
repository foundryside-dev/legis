"""The shared Weft-component transport-HMAC seam.

These pin the live Loomweave wire definition. Filigree classic binds are
transport-open after G11, so ``filigree/client`` no longer emits these headers
and the Filigree-side formula helper has been deleted (no live caller).
"""

from __future__ import annotations

import hashlib
import hmac

from legis.identity.loomweave_client import sign_loomweave_request
from legis.weft_signing import (
    sign_weft_request,
    weft_body_bytes,
    weft_hmac_key_from_env,
    weft_path_and_query,
)


def test_weft_body_bytes_is_compact_sorted_ascii():
    # The signed bytes are compact, key-sorted, and ASCII-escaped — deliberately
    # NOT canonical.canonical_json (ensure_ascii=False), which would change the
    # signed bytes and break the cross-tool HMAC contract.
    assert weft_body_bytes({"b": 1, "a": "x"}) == b'{"a":"x","b":1}'
    assert weft_body_bytes({"k": "é"}) == b'{"k":"\\u00e9"}'  # escaped, not raw utf-8
    assert weft_body_bytes(None) == b""


def test_weft_path_and_query_carries_query_and_defaults_root():
    assert weft_path_and_query("https://h/api/x?e=1") == "/api/x?e=1"
    assert weft_path_and_query("https://h/api/x") == "/api/x"
    assert weft_path_and_query("https://h") == "/"


def test_sign_weft_request_matches_explicit_hmac_contract():
    key = b"weft-key"
    body = {"locator": "python:function:m.f"}
    headers = sign_weft_request(
        "loomweave", key, "POST", "https://h/api/v1/identity/resolve", body,
        timestamp=1_900_000_000, nonce="nonce-1",
    )
    body_hash = hashlib.sha256(weft_body_bytes(body)).hexdigest()
    message = (
        f"POST\n/api/v1/identity/resolve\n{body_hash}\n1900000000\nnonce-1"
    ).encode("utf-8")
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    assert headers == {
        "X-Weft-Component": f"loomweave:{expected}",
        "X-Weft-Timestamp": "1900000000",
        "X-Weft-Nonce": "nonce-1",
    }


def test_component_namespace_is_the_only_per_channel_difference():
    # Conformance guard: the HMAC is computed over the SAME message regardless of
    # channel; only the ``X-Weft-Component`` namespace prefix differs. (Filigree
    # is transport-open post-G11 and emits nothing, but the formula contract — a
    # future signed third channel must reuse the same message — still holds.)
    key, method, url = b"weft-key", "POST", "https://h/api/issue/I-1/x?q=1"
    body = {"entity_id": "loomweave:eid:abc", "content_hash": "h"}
    kwargs = dict(timestamp=1_700_000_000, nonce="cafef00d")

    loom = sign_loomweave_request(key, method, url, body, **kwargs)
    fil = sign_weft_request("filigree", key, method, url, body, **kwargs)

    assert loom["X-Weft-Component"].startswith("loomweave:")
    assert fil["X-Weft-Component"].startswith("filigree:")
    # Strip the namespace prefix -> the HMACs are byte-identical.
    assert loom["X-Weft-Component"].split(":", 1)[1] == fil["X-Weft-Component"].split(":", 1)[1]
    assert loom["X-Weft-Timestamp"] == fil["X-Weft-Timestamp"]
    assert loom["X-Weft-Nonce"] == fil["X-Weft-Nonce"]


def test_weft_hmac_key_from_env_prefers_channel_then_shared(monkeypatch):
    monkeypatch.delenv("LEGIS_CHAN_KEY", raising=False)
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)
    assert weft_hmac_key_from_env("LEGIS_CHAN_KEY") is None
    monkeypatch.setenv("LEGIS_HMAC_KEY", "shared")
    assert weft_hmac_key_from_env("LEGIS_CHAN_KEY") == b"shared"
    monkeypatch.setenv("LEGIS_CHAN_KEY", "channel")
    assert weft_hmac_key_from_env("LEGIS_CHAN_KEY") == b"channel"  # channel-specific wins
