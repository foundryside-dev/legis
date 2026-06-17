"""Filigree entity-association client — legis binds governance to issues.

Stdlib ``urllib`` with an injectable ``fetch`` so tests run offline; no new
dependency. legis binds the opaque SEI as ``entity_id`` (Filigree never parses
it) and hands the entity's content hash for Filigree to store verbatim; drift
comparison stays legis's job.

The Filigree classic entity-association route is intentionally transport-open:
Legis sends the app-level ``binding_signature`` in the JSON body when a governed
sign-off exists, but this client does not emit ``X-Weft-*`` transport HMAC
headers. That avoids a dead handshake where Legis appears to authenticate a
route Filigree has deliberately documented as non-verifying.
"""

from __future__ import annotations

import json
import http.client
import ipaddress
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Protocol, runtime_checkable

from legis.weft_signing import weft_body_bytes

Fetch = Callable[[str, str, "dict | None"], dict]

logger = logging.getLogger(__name__)


class FiligreeError(RuntimeError):
    """A Filigree call failed at the transport or decode layer."""


MAX_RESPONSE_BYTES = 1_000_000


# The ``_json_body_bytes`` alias keeps the internal transport call site stable.
# Filigree's classic entity-association route is transport-open (G11): this
# client does not sign requests, so the X-Weft-* HMAC formula lives solely in
# ``weft_signing`` for the LIVE Loomweave channel.
_json_body_bytes = weft_body_bytes


@runtime_checkable
class FiligreeClient(Protocol):
    def attach(self, issue_id: str, entity_id: str, content_hash: str,
               *, actor: str, signoff_seq: int | None = None,
               signature: str | None = None) -> dict[str, Any]: ...
    def associations_for_entity(self, entity_id: str) -> list[dict[str, Any]]: ...


def _urllib_fetch(
    method: str, url: str, body: dict | None, headers: dict[str, str] | None = None
) -> dict:
    # Send stable compact JSON bytes. Even though the Filigree transport is not
    # signed, keeping a canonical body avoids needless fixture drift and preserves
    # compatibility with the app-level binding_signature payload.
    data = _json_body_bytes(body) if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with _open_no_redirect(req) as resp:  # noqa: S310 (trusted Filigree URL)
            decoded = _decode_json_response(resp, f"{method} {url}")
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise FiligreeError(f"{method} {url} redirect not allowed: {exc.code}") from exc
        raise FiligreeError(f"{method} {url} failed: {exc}") from exc
    except (urllib.error.URLError, ValueError, OSError, http.client.HTTPException) as exc:
        raise FiligreeError(f"{method} {url} failed: {exc}") from exc
    return _require_dict(decoded, f"{method} {url}")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _open_no_redirect(req: urllib.request.Request) -> Any:
    opener = urllib.request.build_opener(_NoRedirectHandler())
    return opener.open(req, timeout=10.0)


def _decode_json_response(resp: Any, context: str) -> Any:
    headers = getattr(resp, "headers", {}) or {}
    content_type = headers.get("Content-Type", "application/json")
    if "json" not in content_type.lower():
        raise FiligreeError(f"{context} returned non-JSON content type: {content_type}")
    raw = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise FiligreeError(f"{context} response too large")
    return json.loads(raw.decode("utf-8"))


def _require_dict(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FiligreeError(f"{context} returned {type(value).__name__}, expected object")
    return value


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_base_url(base_url: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise FiligreeError("Filigree base URL must be an http(s) URL with a host")
    allow_insecure_remote = os.environ.get("LEGIS_ALLOW_INSECURE_REMOTE_HTTP") == "1"
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        if not allow_insecure_remote:
            raise FiligreeError("Filigree base URL must use HTTPS unless it is loopback")
        # ID-SEI-1: plaintext to a remote Filigree. TLS is the only integrity
        # control on responses (the request HMAC authenticates requests, not
        # responses), so an on-path attacker can tamper with what legis reads
        # back. Dev/loopback only; never production.
        logger.warning(
            "LEGIS_ALLOW_INSECURE_REMOTE_HTTP=1 is permitting a plaintext HTTP "
            "connection to non-loopback Filigree host %r; responses are forgeable "
            "without TLS. Dev/loopback use only.",
            parsed.hostname,
        )
    return base_url.rstrip("/")


class HttpFiligreeClient:
    def __init__(
        self,
        base_url: str,
        *,
        fetch: Fetch | None = None,
    ) -> None:
        self._base = _validate_base_url(base_url)
        # Filigree's classic entity-association route is transport-open (G11):
        # there is no request-signing key, so none is accepted.
        self._fetch = fetch if fetch is not None else self._transport_fetch

    def _transport_fetch(self, method: str, url: str, body: dict | None) -> dict:
        return _urllib_fetch(method, url, body, {})

    def attach(self, issue_id: str, entity_id: str, content_hash: str,
               *, actor: str, signoff_seq: int | None = None,
               signature: str | None = None) -> dict[str, Any]:
        quoted_issue_id = urllib.parse.quote(issue_id, safe="")
        body: dict[str, Any] = {
            "entity_id": entity_id,
            "content_hash": content_hash,
            "actor": actor,
        }
        if signoff_seq is not None:
            body["signoff_seq"] = signoff_seq
        if signature is not None:
            body["signature"] = signature
        return _require_dict(
            self._fetch(
                "POST", f"{self._base}/api/issue/{quoted_issue_id}/entity-associations",
                body,
            ),
            "Filigree attach",
        )

    def associations_for_entity(self, entity_id: str) -> list[dict[str, Any]]:
        q = urllib.parse.urlencode({"entity_id": entity_id})
        body = _require_dict(
            self._fetch("GET", f"{self._base}/api/entity-associations?{q}", None),
            "Filigree associations_for_entity",
        )
        associations = body.get("associations", [])
        if not isinstance(associations, list) or not all(
            isinstance(item, dict) for item in associations
        ):
            raise FiligreeError("Filigree returned malformed associations list")
        return list(associations)
