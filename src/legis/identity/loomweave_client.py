"""Loomweave SEI read client — a thin transport seam.

legis consumes Loomweave's SEI surfaces as an HTTP client (the same consumer model
as ``GitSurface`` / the read API). The default transport is stdlib ``urllib`` so
legis adds no dependency; a ``fetch`` callable is injectable so tests run offline.
SEI strings are opaque here — this module never parses them, only forwards them.

Wire contracts (pinned in ``loomweave/docs/federation/contracts.md`` §SEI identity
resolution and §Authentication): ``GET /api/v1/_capabilities`` →
``{"sei": {"supported", "version"}}``;
``POST /api/v1/identity/resolve`` ``{"locator"}`` → ``{sei, current_locator,
content_hash, alive}`` (or ``{"alive": false}``); ``GET /api/v1/identity/sei/:sei``
→ alive or ``{alive:false, lineage}``; ``GET /api/v1/identity/lineage/:sei`` →
``{sei, lineage}``. On a loopback/trusted Loomweave these read routes are
unauthenticated (trust matrix). When an HMAC key is provisioned, protected
routes carry ``X-Weft-Component: loomweave:<hmac>`` plus freshness headers.
"""

from __future__ import annotations

import json
import ipaddress
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Mapping
from typing import Any, Callable, Protocol, runtime_checkable

from legis.weft_signing import (
    sign_weft_request,
    weft_body_bytes,
    weft_hmac_key_from_env,
    weft_path_and_query,
)

Fetch = Callable[[str, str, "dict | None", Mapping[str, str]], dict]

logger = logging.getLogger(__name__)


class LoomweaveError(RuntimeError):
    """A Loomweave identity call failed at the transport or decode layer."""


MAX_RESPONSE_BYTES = 1_000_000


@runtime_checkable
class LoomweaveIdentity(Protocol):
    def capability(self) -> bool: ...
    def resolve_locator(self, locator: str) -> dict[str, Any]: ...
    def resolve_batch(self, locators: list[str]) -> dict[str, Any]: ...
    def resolve_sei(self, sei: str) -> dict[str, Any]: ...
    def lineage(self, sei: str) -> list[dict[str, Any]]: ...


# The Weft-component transport-HMAC scheme is used by the LIVE Loomweave
# channel only — it delegates to ``weft_signing`` so the wire format has a
# single definition. The Filigree channel is transport-open since G11 (it no
# longer signs requests; its governance attestation rides the JSON body and is
# verified by the local BindingLedger), so it does NOT share this scheme.
# (the module-level ``_json_body_bytes`` / ``_path_and_query`` aliases keep the
# internal transport and existing call sites stable).
_json_body_bytes = weft_body_bytes
_path_and_query = weft_path_and_query


def sign_loomweave_request(
    key: bytes,
    method: str,
    url: str,
    body: dict | None,
    *,
    timestamp: int,
    nonce: str,
) -> dict[str, str]:
    """Return Loomweave's current Weft-component HMAC request headers."""
    return sign_weft_request(
        "loomweave", key, method, url, body, timestamp=timestamp, nonce=nonce
    )


def loomweave_hmac_key_from_env() -> bytes | None:
    """Resolve Loomweave HMAC key material from env without making it mandatory."""
    return weft_hmac_key_from_env("LEGIS_LOOMWEAVE_HMAC_KEY")


def _urllib_fetch(
    method: str,
    url: str,
    body: dict | None,
    headers: Mapping[str, str] | None = None,
) -> dict:
    body_bytes = _json_body_bytes(body)
    data = body_bytes if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:  # noqa: S310 (trusted Loomweave URL)
            decoded = _decode_json_response(resp, f"{method} {url}")
    except (urllib.error.URLError, ValueError) as exc:
        raise LoomweaveError(f"{method} {url} failed: {exc}") from exc
    return _require_dict(decoded, f"{method} {url}")


def _decode_json_response(resp: Any, context: str) -> Any:
    headers = getattr(resp, "headers", {}) or {}
    content_type = headers.get("Content-Type", "application/json")
    if "json" not in content_type.lower():
        raise LoomweaveError(f"{context} returned non-JSON content type: {content_type}")
    raw = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise LoomweaveError(f"{context} response too large")
    return json.loads(raw.decode("utf-8"))


def _require_dict(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LoomweaveError(f"{context} returned {type(value).__name__}, expected object")
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
        raise LoomweaveError("Loomweave base URL must be an http(s) URL with a host")
    allow_insecure_remote = os.environ.get("LEGIS_ALLOW_INSECURE_REMOTE_HTTP") == "1"
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        if not allow_insecure_remote:
            raise LoomweaveError("Loomweave base URL must use HTTPS unless it is loopback")
        # ID-SEI-1: the flag is permitting a PLAINTEXT connection to a remote
        # Loomweave. TLS is the ONLY integrity control on SEI *responses* (the
        # request HMAC authenticates requests, not responses), so this voids the
        # SEI/binding custody seal — an on-path attacker can forge a stable
        # identity binding with no TLS break. Dev/loopback only; never production.
        logger.warning(
            "LEGIS_ALLOW_INSECURE_REMOTE_HTTP=1 is permitting a plaintext HTTP "
            "connection to non-loopback Loomweave host %r; this voids the SEI "
            "binding TLS custody seal (responses are forgeable). Dev/loopback use "
            "only.",
            parsed.hostname,
        )
    return base_url.rstrip("/")


class HttpLoomweaveIdentity:
    def __init__(
        self,
        base_url: str,
        *,
        fetch: Fetch | None = None,
        hmac_key: bytes | str | None = None,
        clock: Callable[[], int] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        self._base = _validate_base_url(base_url)
        self._fetch = fetch or _urllib_fetch
        self._hmac_key = hmac_key.encode("utf-8") if isinstance(hmac_key, str) else hmac_key
        self._clock = clock or (lambda: int(time.time()))
        self._nonce_factory = nonce_factory or (lambda: uuid.uuid4().hex)

    def _request(self, method: str, path: str, body: dict | None) -> dict:
        # Every SEI route signs when a key is provisioned and goes bare when not
        # (loopback/trusted). There is deliberately no per-call "unsigned" knob:
        # an opt-out is exactly what left the capability probe spoofable (ID-3).
        url = f"{self._base}{path}"
        headers: dict[str, str] = {}
        if self._hmac_key is not None:
            headers = sign_loomweave_request(
                self._hmac_key,
                method,
                url,
                body,
                timestamp=self._clock(),
                nonce=self._nonce_factory(),
            )
        return self._fetch(method, url, body, headers)

    def capability(self) -> bool:
        # ID-3: sign the probe when keyed, exactly like every other SEI route
        # (``_request`` already no-ops signing when no key is provisioned, so
        # loopback/trusted deployments are unchanged). The capability probe is
        # the trust-establishing handshake — whether legis treats the provider
        # as SEI-capable at all — so it must not be the lone unsigned exception
        # an auth-enforcing Loomweave cannot authenticate. Wire confidentiality
        # against an on-path response rewrite remains TLS's job, which
        # ``_validate_base_url`` enforces for any non-loopback (keyed) host.
        body = _require_dict(
            self._request("GET", "/api/v1/_capabilities", None),
            "Loomweave capability",
        )
        sei = body.get("sei") if isinstance(body, dict) else None
        return isinstance(sei, dict) and sei.get("supported") is True

    def resolve_locator(self, locator: str) -> dict[str, Any]:
        return _require_dict(
            self._request("POST", "/api/v1/identity/resolve", {"locator": locator}),
            "Loomweave resolve_locator",
        )

    def resolve_batch(self, locators: list[str]) -> dict[str, Any]:
        return _require_dict(
            self._request("POST", "/api/v1/identity/resolve:batch", {"locators": locators}),
            "Loomweave resolve_batch",
        )

    def resolve_sei(self, sei: str) -> dict[str, Any]:
        quoted_sei = urllib.parse.quote(sei, safe="")
        return _require_dict(
            self._request("GET", f"/api/v1/identity/sei/{quoted_sei}", None),
            "Loomweave resolve_sei",
        )

    def lineage(self, sei: str) -> list[dict[str, Any]]:
        quoted_sei = urllib.parse.quote(sei, safe="")
        body = _require_dict(
            self._request("GET", f"/api/v1/identity/lineage/{quoted_sei}", None),
            "Loomweave lineage",
        )
        lineage = body.get("lineage", [])
        if not isinstance(lineage, list) or not all(isinstance(item, dict) for item in lineage):
            raise LoomweaveError("Loomweave lineage returned malformed lineage list")
        return list(lineage)
