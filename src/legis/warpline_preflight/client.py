"""Warpline preflight client — legis reads ADVISORY impact/reverify hints.

Stdlib ``urllib`` with an injectable ``fetch`` so tests run offline; no new
dependency. SECURITY: Warpline is PURELY ADVISORY. This client exposes only
read-only GETs; nothing it returns may reach a governance verdict path
(policy_evaluate, the gates, sign-off, or the honesty reads). Governance
verdicts are byte-identical whether WARPLINE_API_URL is set or unset.
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

Fetch = Callable[[str, str, "dict | None"], dict]

logger = logging.getLogger(__name__)


class WarplineError(RuntimeError):
    """A Warpline call failed at the transport or decode layer."""


MAX_RESPONSE_BYTES = 1_000_000


@runtime_checkable
class WarplineClient(Protocol):
    def impact_radius(self, base: str, head: str) -> dict[str, Any]: ...
    def reverify_worklist(self, base: str, head: str) -> dict[str, Any]: ...


def _urllib_fetch(
    method: str, url: str, body: dict | None, headers: dict[str, str] | None = None
) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with _open_no_redirect(req) as resp:  # noqa: S310 (trusted Warpline URL)
            decoded = _decode_json_response(resp, f"{method} {url}")
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise WarplineError(f"{method} {url} redirect not allowed: {exc.code}") from exc
        raise WarplineError(f"{method} {url} failed: {exc}") from exc
    except (urllib.error.URLError, ValueError, OSError, http.client.HTTPException) as exc:
        raise WarplineError(f"{method} {url} failed: {exc}") from exc
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
        raise WarplineError(f"{context} returned non-JSON content type: {content_type}")
    raw = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise WarplineError(f"{context} response too large")
    return json.loads(raw.decode("utf-8"))


def _require_dict(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WarplineError(f"{context} returned {type(value).__name__}, expected object")
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
        raise WarplineError("Warpline base URL must be an http(s) URL with a host")
    allow_insecure_remote = os.environ.get("LEGIS_ALLOW_INSECURE_REMOTE_HTTP") == "1"
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        if not allow_insecure_remote:
            raise WarplineError("Warpline base URL must use HTTPS unless it is loopback")
        # ID-SEI-1: plaintext to a remote Warpline. TLS is the only integrity
        # control on responses (the request HMAC authenticates requests, not
        # responses), so an on-path attacker can tamper with what legis reads
        # back. Dev/loopback only; never production.
        logger.warning(
            "LEGIS_ALLOW_INSECURE_REMOTE_HTTP=1 is permitting a plaintext HTTP "
            "connection to non-loopback Warpline host %r; responses are forgeable "
            "without TLS. Dev/loopback use only.",
            parsed.hostname,
        )
    return base_url.rstrip("/")


class HttpWarplineClient:
    def __init__(
        self,
        base_url: str,
        *,
        fetch: Fetch | None = None,
    ) -> None:
        self._base = _validate_base_url(base_url)
        self._fetch = fetch if fetch is not None else self._transport_fetch

    def _transport_fetch(self, method: str, url: str, body: dict | None) -> dict:
        return _urllib_fetch(method, url, body, {})

    def impact_radius(self, base: str, head: str) -> dict[str, Any]:
        q = urllib.parse.urlencode({"base": base, "head": head})
        return _require_dict(
            self._fetch("GET", f"{self._base}/api/impact-radius?{q}", None),
            "Warpline impact_radius",
        )

    def reverify_worklist(self, base: str, head: str) -> dict[str, Any]:
        q = urllib.parse.urlencode({"base": base, "head": head})
        return _require_dict(
            self._fetch("GET", f"{self._base}/api/reverify-worklist?{q}", None),
            "Warpline reverify_worklist",
        )
