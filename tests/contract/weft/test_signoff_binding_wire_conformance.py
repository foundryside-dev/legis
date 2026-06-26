"""Shared Weft conformance test: the legis -> Filigree governed sign-off binding wire.

This is the PRODUCER half of a single cross-member golden,
``vectors/signoff_binding.v1.json``. The byte-identical file is vendored into
Filigree at ``filigree/tests/fixtures/contracts/legis-signoff-binding-request.json``;
its consumer oracle drives the REAL ``POST /api/issue/{id}/entity-associations``
route over the same bytes. legis is the AUTHORITY for this request body.

What this wire IS, and why it is a distinct freezable seam (not subsumed by the
existing entity-association oracle):

  * legis binds a cleared governed sign-off to a Filigree issue by POSTing to the
    classic entity-association route (``HttpFiligreeClient.attach`` ->
    ``POST /api/issue/{issue_id}/entity-associations``). The BASE entity-association
    body is ``{entity_id, content_hash, actor}`` — that shape is already exercised
    by the loomweave<->filigree reverse-lookup oracle. The GOVERNED body carries
    two MORE fields, ``signoff_seq`` and ``signature``, which are the legis-specific
    extension (Filigree v25/B1). Those are what filigree's POST handler parses and
    persists into dedicated columns; the existing entity-associations oracle freezes
    only the GET *response* body and never touches ``signoff_seq``/``signature``. So
    this governed REQUEST body is a genuinely uncovered, distinct wire — and the
    golden MUST carry both extension fields or it would re-freeze the already-covered
    base shape.

  * The ``signature`` is ``sign({issue_id, entity_id, content_hash, signoff_seq}, key)``
    (``legis.enforcement.signing.sign`` -> deterministic HMAC-SHA256 over
    ``canonical_json`` of the field dict, tagged ``hmac-sha256:v2:``). It folds in NO
    clock, nonce, or salt, so with a FIXED key it reproduces byte-for-byte — which is
    what makes a byte-pin meaningful. ``issue_id`` is committed by the signature but
    rides the URL PATH, not the body, so it is absent from the frozen body bytes.

  * The body bytes on the wire are ``weft_signing.weft_body_bytes(body)`` —
    ``json.dumps(body, sort_keys=True, separators=(",", ":"))`` with the default
    ``ensure_ascii=True``. The route is transport-open (G11): legis emits no
    ``X-Weft-*`` headers; the app-level ``signature`` travels in the JSON body and
    filigree stores it verbatim WITHOUT verifying (it holds no key).

This file proves the same projection from legis's side, two ways:

1. **Producer-source recheck (non-circular).** Drive the REAL
   ``bind_signoff_to_issue`` over the REAL ``HttpFiligreeClient`` with a FIXED key and
   the golden's own signing inputs, monkeypatching only the socket open
   (``_open_no_redirect``) to capture the exact bytes the transport would POST, and
   assert they equal the canonical bytes of the golden's recorded ``request_body``.
   The full producer path runs (real ``attach`` body assembly -> real ``_urllib_fetch``
   -> real ``_json_body_bytes`` canonicalization -> real ``sign()`` signature), none of
   it copied from the golden, so a rename of any body key in the client, a change to
   the signed-field set, the ``:v2:`` tag, or the canonicalization reds here.

2. **Layer-1 byte-pin.** Recompute the git-blob sha1 of the *frozen* golden file
   in-process and assert it equals ``VENDORED_BLOB_SHA``. Filigree's consumer oracle
   pins the SAME constant against the byte-identical vendored copy, locking both
   repos to one wire shape.

These oracles are fully in-process (the real client with only its socket-open
monkeypatched, no network), so they run in the default suite with no new pytest marker.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

import legis.filigree.client as client_mod
from legis.enforcement.signing import sign
from legis.filigree.client import HttpFiligreeClient
from legis.governance.signoff_binding import bind_signoff_to_issue
from legis.identity.entity_key import EntityKey
from legis.weft_signing import weft_body_bytes

VECTOR_PATH = Path(__file__).parent / "vectors" / "signoff_binding.v1.json"

# The git blob sha1 of the frozen golden bytes:
#   sha1(b"blob <len>\0" + bytes). Recomputed in-process below and by Filigree's
#   consumer oracle over the byte-identical vendored copy. Re-pin only by
#   re-freezing the golden from the real signer and updating BOTH repos' constant.
VENDORED_BLOB_SHA = "8796aeb5b8d7d067c82af17e361aa45fe5007b4e"


def _blob_sha(data: bytes) -> str:
    """git's blob object id for ``data``: ``sha1(b"blob <len>\\0" + data)``."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324 (content addressing, not security)


def _load_golden() -> dict[str, Any]:
    golden: dict[str, Any] = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    return golden


class _CapturingResponse:
    """A minimal urllib response stand-in: enough for ``_decode_json_response``."""

    headers = {"Content-Type": "application/json"}

    def read(self, _n: int) -> bytes:
        return b'{"issue_id":"x","loomweave_entity_id":"x","content_hash_at_attach":"h","attached_at":"t","attached_by":"legis"}'

    def __enter__(self) -> "_CapturingResponse":
        return self

    def __exit__(self, *exc: object) -> Literal[False]:
        return False


def _capture_real_client_wire_bytes(
    monkeypatch: Any,
) -> tuple[HttpFiligreeClient, dict[str, Any]]:
    """Build the REAL ``HttpFiligreeClient`` and capture the exact bytes its transport
    would POST, by monkeypatching ``_open_no_redirect`` to grab ``req.data``.

    This drives the genuine producer path end to end — real ``attach`` assembles the
    body, real ``_urllib_fetch`` builds the request, real ``_json_body_bytes``
    (``weft_body_bytes``) canonicalizes it — so a rename of any body key in the real
    client (``content_hash`` -> ``contentHash``, etc.) reds here. The same byte-capture
    idiom as ``tests/filigree/test_client.py::test_wire_body_is_stable_compact_json``.
    """
    captured: dict[str, Any] = {}

    def fake_open_no_redirect(req: Any) -> _CapturingResponse:
        captured["data"] = req.data
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.header_items())
        return _CapturingResponse()

    monkeypatch.setattr(client_mod, "_open_no_redirect", fake_open_no_redirect)
    client = HttpFiligreeClient("https://filigree.test")
    return client, captured


def test_vendored_golden_blob_sha_is_byte_pinned() -> None:
    """Layer-1: the frozen golden's bytes reproduce VENDORED_BLOB_SHA.

    Tamper the file (any byte: a field value, key order, whitespace, the trailing
    newline) and this reds before any wire drift can ship. Filigree's consumer
    oracle pins the same constant against the byte-identical vendored copy.
    """
    data = VECTOR_PATH.read_bytes()
    recomputed = _blob_sha(data)
    assert recomputed == VENDORED_BLOB_SHA, (
        f"golden bytes changed: {recomputed} != pinned {VENDORED_BLOB_SHA}. "
        "Re-freeze from the real signer and update BOTH repos' constant."
    )


def test_golden_carries_the_distinct_governed_extension_fields() -> None:
    """The golden body must carry ``signoff_seq`` + ``signature`` (the legis-specific
    extension). Without them this would re-freeze the base entity-association shape,
    which the loomweave<->filigree reverse-lookup oracle already covers — a tautology.
    """
    body = _load_golden()["request_body"]
    assert set(body) == {"entity_id", "content_hash", "actor", "signoff_seq", "signature"}
    assert isinstance(body["signoff_seq"], int) and not isinstance(body["signoff_seq"], bool)
    assert body["signature"].startswith("hmac-sha256:v2:")


def test_real_bind_emits_the_golden_request_body_bytes(monkeypatch: Any) -> None:
    """Producer-source recheck (non-circular): drive the REAL
    ``bind_signoff_to_issue`` over the REAL ``HttpFiligreeClient`` with a FIXED key and
    the golden's signing inputs, and assert the bytes legis's transport actually puts
    on the wire equal the canonical bytes of the golden's recorded ``request_body``.

    The full producer path runs: real ``attach`` assembles the body, real
    ``_urllib_fetch`` builds the request, real ``_json_body_bytes`` canonicalizes it,
    and real ``sign()`` (inside ``bind_signoff_to_issue``) cuts the signature — none of
    it copied from the golden. So a drift in the client's body-key names, the signed
    field set, the ``:v2:`` tag, or the canonicalization reds here. ``issue_id`` is
    committed by the signature but rides the URL path, so it is absent from the body
    bytes (it appears in the captured request URL instead).
    """
    golden = _load_golden()
    inputs = golden["signing_inputs"]
    key = bytes.fromhex(inputs["key_hex"])
    signed = inputs["signed_fields"]

    client, captured = _capture_real_client_wire_bytes(monkeypatch)
    out = bind_signoff_to_issue(
        client,
        issue_id=inputs["issue_id"],
        entity_key=EntityKey.from_sei(signed["entity_id"]),
        content_hash=signed["content_hash"],
        signoff_seq=signed["signoff_seq"],
        key=key,
    )

    # The signature the real signer produced, independently of the golden's copy.
    expected_sig = sign(
        {
            "issue_id": inputs["issue_id"],
            "entity_id": signed["entity_id"],
            "content_hash": signed["content_hash"],
            "signoff_seq": signed["signoff_seq"],
        },
        key,
    )
    assert out["binding_signature"] == expected_sig
    assert expected_sig == golden["signing_inputs"]["signature"], (
        "real sign() no longer reproduces the golden signature — the signed-field "
        "set or canonicalization drifted, or the golden is stale."
    )

    # The load-bearing assertion: the REAL transport's emitted wire bytes equal the
    # canonical bytes of the golden's recorded body. ``captured["data"]`` is exactly
    # what ``HttpFiligreeClient`` would have sent over the socket.
    assert captured["data"] == weft_body_bytes(golden["request_body"]), (
        "legis's real client no longer emits the frozen governed sign-off request "
        "body bytes; re-freeze the golden from the real client and update BOTH repos."
    )

    assert captured["data"] == weft_body_bytes(
        {
            "entity_id": signed["entity_id"],
            "content_hash": signed["content_hash"],
            "actor": "legis",
            "signoff_seq": signed["signoff_seq"],
            "signature": expected_sig,
        }
    )

    # The request went to the issue-scoped entity-association route, with issue_id in
    # the PATH (not the body) — the half of the signed tuple the body omits. Proven by
    # the real transport's captured URL + method, not re-derived.
    assert captured["method"] == "POST"
    assert captured["url"] == (
        f"https://filigree.test/api/issue/{inputs['issue_id']}/entity-associations"
    )
