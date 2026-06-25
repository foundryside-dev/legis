# Legis ↔ warpline interfaces — preflight consumer + per-SEI attestation read — TDD implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Legis side of warpline's two requested interfaces — an env-gated advisory HTTP preflight consumer (`warpline_preflight_get`) and a fail-closed per-SEI attestation read (`attestation_get`) — such that warpline data is structurally incapable of reaching any governance verdict path and governance verdicts are byte-identical whether `WARPLINE_API_URL` is set or unset.

**Architecture:** `HttpWarplineClient` is a near-clone of `HttpFiligreeClient` (stdlib `urllib`, injectable `fetch`, loopback/HTTPS gating, response-size bound, no-redirect), held as a plain optional `warpline: Any | None` field on `McpRuntime` and read ONLY inside the new `warpline_preflight_get` handler. The preflight read lives in a new transport-agnostic `service/preflight.py` mirroring `read_identity_gaps`; the attestation read lives in `service/governance.py` next to the other discriminated honesty reads and consumes the existing fail-closed `verified_records` trail path. Both tools return the house discriminated `checked`/`unavailable` shape so no empty ever reads as "nothing impacted" / "never attested".

**Tech Stack:** Python 3.13, stdlib only for the client (`urllib`, `http.client`, `ipaddress`, `json`, `logging`); `pytest` + `jsonschema` (`Draft202012Validator`) for tests; existing Legis MCP adapter (`src/legis/mcp.py`), service layer (`src/legis/service/`), and enforcement trail (`src/legis/enforcement/{protected,signoff}.py`).

---

## Global Constraints

These are load-bearing invariants. Copy them verbatim into every relevant task; do not soften.

- **ADVISORY BOUNDARY.** Legis is the ONLY governance / sign-off / attestation authority. Warpline context is PURELY ADVISORY. `runtime.warpline` may be referenced ONLY inside the `warpline_preflight_get` handler (`_tool_warpline_preflight_get`) and the `read_warpline_preflight` service function. It must be STRUCTURALLY ABSENT from `policy_evaluate` / `_engine` / `_coached_engine` / the gates / sign-off / the honesty reads (`identity_gap_list`, `lineage_integrity_get`, `policy_boundary_check`) and from `read_sei_attestations` / `attestation_get`.
- **BYTE-IDENTICAL ACCEPTANCE.** Governance verdicts are BYTE-IDENTICAL whether `WARPLINE_API_URL` is set or unset. Warpline data must be structurally incapable of reaching a verdict path.
- **ASYMMETRIC ERROR RULE (`attestation_get` feeds warpline's skip-reverify decision).** A FALSE "attested" (surfacing a record a human never cleared) → warpline skips reverify on un-cleared code → SECURITY HOLE. An OMITTED real attestation → warpline reverifies something fine → wasted work, SAFE. Therefore EVERY ambiguous or failure case resolves toward "not attested": OMIT the record, or return the discriminated `status: "unavailable"`, NEVER toward surfacing it. An omission must still NOT read as a silent "never attested" empty — use the discriminated `unavailable` status with a `reason`, never a bare empty list under `status: "checked"` that did not actually check.
- **STDLIB-ONLY CLIENT.** `HttpWarplineClient` uses stdlib `urllib` with an injectable `Fetch = Callable[[str, str, "dict | None"], dict]` so tests run fully offline. No new dependency.
- **LOOPBACK / HTTPS GATING.** `http` to a non-loopback host is rejected (`WarplineError`) unless `LEGIS_ALLOW_INSECURE_REMOTE_HTTP == "1"` (string compare), which logs the same forgeable-responses warning Filigree emits. `localhost` and any `ipaddress.ip_address(host).is_loopback` host are allowed over `http`.
- **`MAX_RESPONSE_BYTES = 1_000_000`.** Responses are read with `resp.read(MAX_RESPONSE_BYTES + 1)` and rejected (`WarplineError`) if larger.
- **NO-REDIRECT.** `_NoRedirectHandler.redirect_request` returns `None`; a 3xx surfaces as `WarplineError("... redirect not allowed: <code>")`.
- **CLONE, do not refactor-share (ticket `legis-bc407a86ed`).** The URL-validation + fetch helpers are duplicated verbatim into `warpline_preflight`, NOT extracted to a shared module. Accepted duplication; do NOT plan a shared-helper refactor.

---

## File Structure

| File | New/Modified | Responsibility |
|---|---|---|
| `src/legis/warpline_preflight/__init__.py` | New | Package marker for the warpline preflight client. |
| `src/legis/warpline_preflight/client.py` | New | `HttpWarplineClient`, `@runtime_checkable WarplineClient` Protocol, `WarplineError`, the cloned `_validate_base_url`/`_urllib_fetch`/`_decode_json_response`/`_require_dict`/`_NoRedirectHandler`/`_open_no_redirect`/`_is_loopback` helpers, `MAX_RESPONSE_BYTES`, `Fetch`. Two read-only GET methods `impact_radius(base, head)` / `reverify_worklist(base, head)`. |
| `src/legis/service/preflight.py` | New | `read_warpline_preflight(warpline_client, base, head)` — transport-agnostic discriminated `checked`/`unavailable` read; catches `WarplineError`, never escapes as `INTERNAL_ERROR`. |
| `src/legis/service/__init__.py` | Modified | Export `read_warpline_preflight` (new `from legis.service.preflight import ...` line + `__all__` entry, per the `route_wardline_scan` precedent) and `read_sei_attestations` (existing governance import block + `__all__`). |
| `src/legis/service/governance.py` | Modified | `read_sei_attestations(verified_runtime_records, sei)` — fail-closed per-SEI attestation classifier (positive admission BLOCKED pending owner ratification; see Task 8). |
| `src/legis/mcp.py` | Modified | `McpRuntime.warpline` field (end of dataclass); `build_runtime` `WARPLINE_API_URL` gating + pass into ctor; `warpline_preflight_get` + `attestation_get` tool definitions, handlers, `_TOOL_HANDLERS` registration, `_AGENT_TOOLS` membership; `_governance_trail_records`-based attestation handler with the protected-gate fail-closed pre-gate. |
| `tests/warpline_preflight/__init__.py` | New | Test package marker. |
| `tests/warpline_preflight/test_client.py` | New | Client unit tests: URL validation, size bound, no-redirect, non-JSON content-type, offline-via-injected-fetch. |
| `tests/service/test_preflight.py` | New | `read_warpline_preflight` service tests. |
| `tests/service/test_governance.py` | Modified | `read_sei_attestations` classifier tests (verified-trail, tamper, SEI/`identity_stable` filters, omit rules). |
| `tests/mcp/test_warpline_advisory_boundary.py` | New | The byte-identical acceptance spine: governance path unset vs hostile-injected warpline. |
| `tests/mcp/test_server.py` | Modified | Dispatch + env-pairing + surface-set literal (22→24) + `runtime.warpline` structural-boundary tests. |
| `tests/mcp/test_output_schema_conformance.py` | Modified | outputSchema conformance vectors for both new tools. |

---

## Task 1 — `HttpWarplineClient` + client unit tests

**Files**
- Create: `src/legis/warpline_preflight/__init__.py`, `src/legis/warpline_preflight/client.py`
- Create test: `tests/warpline_preflight/__init__.py`, `tests/warpline_preflight/test_client.py`

**Interfaces**
- Produces: `class WarplineError(RuntimeError)`; `Fetch = Callable[[str, str, "dict | None"], dict]`; `MAX_RESPONSE_BYTES = 1_000_000`; `@runtime_checkable class WarplineClient(Protocol)` with `impact_radius(self, base: str, head: str) -> dict[str, Any]` and `reverify_worklist(self, base: str, head: str) -> dict[str, Any]`; `class HttpWarplineClient.__init__(self, base_url: str, *, fetch: Fetch | None = None) -> None`.
- Consumes: stdlib only.

Steps:

- [ ] **Write failing test** `tests/warpline_preflight/test_client.py`:
```python
import json

import pytest

from legis.warpline_preflight.client import (
    HttpWarplineClient,
    WarplineClient,
    WarplineError,
    MAX_RESPONSE_BYTES,
)


def _recorder(responses):
    """An injectable Fetch that returns queued dicts and records calls."""
    calls = []

    def fetch(method, url, body):
        calls.append((method, url, body))
        return responses.pop(0)

    fetch.calls = calls
    return fetch


def test_protocol_is_runtime_checkable():
    client = HttpWarplineClient("http://localhost:9100", fetch=_recorder([{}]))
    assert isinstance(client, WarplineClient)


def test_impact_radius_is_a_get_with_base_head_query():
    fetch = _recorder([{"affected": [], "count": 0}])
    client = HttpWarplineClient("http://localhost:9100", fetch=fetch)
    out = client.impact_radius("aaa", "bbb")
    assert out == {"affected": [], "count": 0}
    method, url, body = fetch.calls[0]
    assert method == "GET" and body is None
    assert url == "http://localhost:9100/api/impact-radius?base=aaa&head=bbb"


def test_reverify_worklist_is_a_get_with_base_head_query():
    fetch = _recorder([{"entries": [], "count": 0}])
    client = HttpWarplineClient("http://localhost:9100", fetch=fetch)
    out = client.reverify_worklist("aaa", "bbb")
    assert out == {"entries": [], "count": 0}
    method, url, body = fetch.calls[0]
    assert method == "GET" and body is None
    assert url == "http://localhost:9100/api/reverify-worklist?base=aaa&head=bbb"


def test_non_object_response_is_a_warpline_error():
    client = HttpWarplineClient("http://localhost:9100", fetch=_recorder([["not", "a", "dict"]]))
    with pytest.raises(WarplineError):
        client.impact_radius("a", "b")


def test_loopback_http_ok_remote_http_rejected_unless_optin(monkeypatch):
    monkeypatch.delenv("LEGIS_ALLOW_INSECURE_REMOTE_HTTP", raising=False)
    HttpWarplineClient("http://127.0.0.1:9100")  # loopback IP ok
    HttpWarplineClient("http://localhost:9100")  # localhost ok
    HttpWarplineClient("https://warpline.example.com")  # https ok
    with pytest.raises(WarplineError, match="HTTPS unless it is loopback"):
        HttpWarplineClient("http://warpline.example.com")
    monkeypatch.setenv("LEGIS_ALLOW_INSECURE_REMOTE_HTTP", "1")
    HttpWarplineClient("http://warpline.example.com")  # opt-in permits it


def test_base_url_must_be_http_with_host():
    with pytest.raises(WarplineError, match="http\\(s\\) URL with a host"):
        HttpWarplineClient("ftp://warpline")
    with pytest.raises(WarplineError, match="http\\(s\\) URL with a host"):
        HttpWarplineClient("not-a-url")


def test_response_too_large_via_real_decode_path():
    # Exercise the real _decode_json_response size guard with a fake resp object.
    from legis.warpline_preflight.client import _decode_json_response

    big = json.dumps({"x": "y" * (MAX_RESPONSE_BYTES + 10)}).encode("utf-8")

    class _Resp:
        headers = {"Content-Type": "application/json"}

        def read(self, n):
            return big[:n]

    with pytest.raises(WarplineError, match="response too large"):
        _decode_json_response(_Resp(), "GET test")


def test_non_json_content_type_rejected():
    from legis.warpline_preflight.client import _decode_json_response

    class _Resp:
        headers = {"Content-Type": "text/html"}

        def read(self, n):
            return b"<html></html>"

    with pytest.raises(WarplineError, match="non-JSON content type"):
        _decode_json_response(_Resp(), "GET test")


def test_no_redirect_handler_returns_none():
    from legis.warpline_preflight.client import _NoRedirectHandler

    h = _NoRedirectHandler()
    assert h.redirect_request(None, None, 302, "Found", {}, "http://elsewhere") is None
```

- [ ] **Run to fail:** `uv run pytest tests/warpline_preflight/test_client.py -q` — fails with `ModuleNotFoundError: legis.warpline_preflight`.

- [ ] **Implement** `src/legis/warpline_preflight/__init__.py` (empty) and `src/legis/warpline_preflight/client.py`. CLONE `src/legis/filigree/client.py` exactly, substituting `Filigree`→`Warpline`, DROP the `weft_signing` import (`_json_body_bytes`) — both methods are GET with `body=None`, so use plain `json.dumps(body).encode("utf-8")` in `_urllib_fetch`. Reuse the env var `LEGIS_ALLOW_INSECURE_REMOTE_HTTP` verbatim. Full module:
```python
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
```
> NOTE — INFERRED CONTRACT (spec §6, TO-CONFIRM): the route paths `/api/impact-radius`, `/api/reverify-worklist` and the `base`/`head` query-param names are inferred from the Filigree GET pattern, NOT grounded in a warpline spec. When warpline ships its real shape only this client's URL construction + one fixture change. The shape-validation is intentionally minimal: `_require_dict` rejects a non-object (→ `WarplineError`), fields pass through verbatim.

- [ ] **Add a clone-parity guard.** The clone-not-share decision (ticket `legis-bc407a86ed`) means warpline's SSRF / redirect / DoS primitives can silently diverge from filigree's on a future security patch. Pin them — the repo precedent is the canonical-JSON golden mirror against Wardline. Append to `tests/warpline_preflight/test_client.py`:
```python
import inspect

import legis.filigree.client as fc
import legis.warpline_preflight.client as wc


def _normalize(src):
    # The ONLY intended differences are the sibling name and its error class.
    return src.replace("Filigree", "Warpline").replace("filigree", "warpline")


def test_security_primitives_are_faithful_clones_of_filigree():
    # If a future patch hardens filigree's SSRF/redirect/DoS handling this fails
    # loudly so warpline is patched in lockstep. _urllib_fetch is EXCLUDED — it
    # intentionally drops filigree's weft_signing body bytes (warpline is GET-only).
    for name in ("_validate_base_url", "_is_loopback", "_open_no_redirect", "_decode_json_response"):
        assert _normalize(inspect.getsource(getattr(fc, name))) == inspect.getsource(
            getattr(wc, name)
        ), f"{name} diverged from the filigree clone"
    assert _normalize(inspect.getsource(fc._NoRedirectHandler)) == inspect.getsource(
        wc._NoRedirectHandler
    )
```

- [ ] **Run to pass:** `uv run pytest tests/warpline_preflight/test_client.py -q`.

- [ ] **Commit:** `feat(warpline): add stdlib HttpWarplineClient advisory preflight client`.

---

## Task 2 — `read_warpline_preflight` service function + tests

**Files**
- Create: `src/legis/service/preflight.py`
- Modify: `src/legis/service/__init__.py`
- Create test: `tests/service/test_preflight.py`

**Interfaces**
- Produces: `read_warpline_preflight(warpline_client: WarplineClient | None, base: str, head: str) -> dict[str, Any]` returning either `{"status": "checked", "impact_radius": {...}, "reverify_worklist": {...}}` or `{"status": "unavailable", "unavailable": [{"reason": <str>}]}`.
- Consumes: `legis.warpline_preflight.client.WarplineError` (caught locally, lazy import — mirrors `read_identity_gaps` catching `LoomweaveError`).

Steps:

- [ ] **Write failing test** `tests/service/test_preflight.py`:
```python
from legis.service.preflight import read_warpline_preflight
from legis.warpline_preflight.client import WarplineError


class _OkWarpline:
    def impact_radius(self, base, head):
        return {"affected": [{"sei": "S1"}], "count": 1}

    def reverify_worklist(self, base, head):
        return {"entries": [{"sei": "S1", "reason": "edited"}], "count": 1}


class _ImpactRaisesWarpline:
    def impact_radius(self, base, head):
        raise WarplineError("boom")

    def reverify_worklist(self, base, head):
        return {"entries": [], "count": 0}


class _WorklistRaisesWarpline:
    def impact_radius(self, base, head):
        return {"affected": [], "count": 0}

    def reverify_worklist(self, base, head):
        raise WarplineError("timeout")


def test_checked_when_both_methods_succeed():
    out = read_warpline_preflight(_OkWarpline(), "aaa", "bbb")
    assert out == {
        "status": "checked",
        "impact_radius": {"affected": [{"sei": "S1"}], "count": 1},
        "reverify_worklist": {"entries": [{"sei": "S1", "reason": "edited"}], "count": 1},
    }


def test_unavailable_when_client_is_none_not_a_silent_empty():
    out = read_warpline_preflight(None, "aaa", "bbb")
    assert out["status"] == "unavailable"
    assert out["unavailable"] == [{"reason": "warpline client not configured"}]
    # ASYMMETRIC: never an empty affected-set that reads as "nothing impacted".
    assert "impact_radius" not in out


def test_unavailable_when_impact_radius_raises_warpline_error():
    out = read_warpline_preflight(_ImpactRaisesWarpline(), "aaa", "bbb")
    assert out["status"] == "unavailable"
    assert out["unavailable"][0]["reason"].startswith("warpline check failed:")


def test_unavailable_when_worklist_raises_warpline_error():
    # Partial advisory context is NOT surfaced as checked — either method failing
    # degrades the WHOLE read to unavailable.
    out = read_warpline_preflight(_WorklistRaisesWarpline(), "aaa", "bbb")
    assert out["status"] == "unavailable"
    assert out["unavailable"][0]["reason"].startswith("warpline check failed:")


def test_warpline_error_never_escapes_as_internal_error():
    # The transport error is caught and converted, never re-raised.
    out = read_warpline_preflight(_ImpactRaisesWarpline(), "aaa", "bbb")
    assert out["status"] == "unavailable"  # no exception propagated
```

- [ ] **Run to fail:** `uv run pytest tests/service/test_preflight.py -q` — fails: no `legis.service.preflight`.

- [ ] **Implement** `src/legis/service/preflight.py`:
```python
"""The warpline advisory preflight read — discriminated checked/unavailable.

SECURITY: warpline is PURELY ADVISORY. This read is a SIBLING of the governance
honesty reads, never embedded in one; a failure here is contained as
``unavailable`` and never escapes as INTERNAL_ERROR, exactly as
``read_identity_gaps`` converts a ``LoomweaveError``. An unreachable/unconfigured
warpline → ``unavailable`` with a reason, never an empty affected-set that reads
as "nothing impacted".
"""

from __future__ import annotations

from typing import Any


def read_warpline_preflight(
    warpline_client: Any | None, base: str, head: str
) -> dict[str, Any]:
    from legis.warpline_preflight.client import WarplineError

    if warpline_client is None:
        return {
            "status": "unavailable",
            "unavailable": [{"reason": "warpline client not configured"}],
        }
    try:
        impact = warpline_client.impact_radius(base, head)
        worklist = warpline_client.reverify_worklist(base, head)
    except WarplineError as exc:
        return {
            "status": "unavailable",
            "unavailable": [{"reason": f"warpline check failed: {exc}"}],
        }
    return {
        "status": "checked",
        "impact_radius": impact,
        "reverify_worklist": worklist,
    }
```

- [ ] **Export** in `src/legis/service/__init__.py`: add `from legis.service.preflight import read_warpline_preflight` (following the `from legis.service.wardline import route_wardline_scan` precedent) and add `"read_warpline_preflight"` to `__all__`.

- [ ] **Run to pass:** `uv run pytest tests/service/test_preflight.py -q`.

- [ ] **Commit:** `feat(warpline): add read_warpline_preflight discriminated service read`.

---

## Task 3 — `warpline_preflight_get` tool wiring + `build_runtime` env gating + dispatch tests

**Files**
- Modify: `src/legis/mcp.py`
- Modify test: `tests/mcp/test_server.py`

**Interfaces**
- Produces: MCP tool `warpline_preflight_get` (input `{base: string (required), head?: string}`); handler `_tool_warpline_preflight_get(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]`; `McpRuntime.warpline: Any | None = None`; `build_runtime` wiring gated on `WARPLINE_API_URL`.
- Consumes: `read_warpline_preflight` (Task 2); `HttpWarplineClient` (Task 1); `_tool_result`, `_require`, `_schema`, `_one_of` (mcp.py).

Steps:

- [ ] **Write failing tests** appended to `tests/mcp/test_server.py` (reusing the in-file fixtures `_runtime` at lines 72-92 and `call_tool`):
```python
def test_build_runtime_wires_warpline_from_env(monkeypatch, tmp_path):
    from legis.mcp import build_runtime
    from legis.warpline_preflight.client import HttpWarplineClient

    monkeypatch.setenv("WARPLINE_API_URL", "http://localhost:9100")
    monkeypatch.setenv("LEGIS_SOURCE_ROOT", str(tmp_path))
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)  # engine-only: no protected gate
    # NOTE: build_runtime(agent_id) takes ONLY agent_id (mcp.py:200); source root
    # and DBs are env-driven (LEGIS_SOURCE_ROOT, mcp.py:275). There is NO
    # source_root= kwarg — passing one raises TypeError before any assertion.
    runtime = build_runtime("agent-x")
    assert isinstance(runtime.warpline, HttpWarplineClient)


def test_build_runtime_leaves_warpline_unwired_without_env(monkeypatch, tmp_path):
    from legis.mcp import build_runtime

    monkeypatch.delenv("WARPLINE_API_URL", raising=False)
    monkeypatch.setenv("LEGIS_SOURCE_ROOT", str(tmp_path))
    runtime = build_runtime("agent-x")
    assert runtime.warpline is None


def test_build_runtime_degrades_warpline_to_none_on_bad_url(monkeypatch, tmp_path):
    # A misconfigured ADVISORY url must NOT crash the sole governance authority
    # at startup; it degrades to no advisory context (governance unaffected).
    from legis.mcp import build_runtime

    monkeypatch.setenv("WARPLINE_API_URL", "not-a-valid-url")
    monkeypatch.setenv("LEGIS_SOURCE_ROOT", str(tmp_path))
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)
    runtime = build_runtime("agent-x")
    assert runtime.warpline is None


def test_warpline_preflight_get_unavailable_when_unwired(tmp_path):
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)  # warpline defaults to None
    result = call_tool(runtime, "warpline_preflight_get", {"base": "aaa"})
    assert not result.get("isError")
    assert result["structuredContent"] == {
        "status": "unavailable",
        "unavailable": [{"reason": "warpline client not configured"}],
    }


def test_warpline_preflight_get_checked_with_injected_client(tmp_path):
    from legis.mcp import call_tool

    class _FakeWarpline:
        def impact_radius(self, base, head):
            return {"affected": [{"sei": "S1"}], "count": 1}

        def reverify_worklist(self, base, head):
            return {"entries": [], "count": 0}

    runtime, _store = _runtime(tmp_path)
    runtime.warpline = _FakeWarpline()
    result = call_tool(runtime, "warpline_preflight_get", {"base": "aaa", "head": "bbb"})
    assert not result.get("isError")
    sc = result["structuredContent"]
    assert sc["status"] == "checked"
    assert sc["impact_radius"] == {"affected": [{"sei": "S1"}], "count": 1}
    assert sc["reverify_worklist"] == {"entries": [], "count": 0}
```

- [ ] **Run to fail:** `uv run pytest tests/mcp/test_server.py -q -k warpline_preflight` — fails: `UNKNOWN_TOOL` / no `warpline` field.

- [ ] **Implement (a) the `McpRuntime` field.** At the END of the `McpRuntime` dataclass (after `coached_engine: EnforcementEngine | None = None`, mcp.py:178 — field-order is load-bearing because of the positional ctor at `tests/mcp/test_server.py:150`):
```python
    coached_engine: EnforcementEngine | None = None
    warpline: Any | None = None  # advisory sibling; NEVER read by a verdict path
```

- [ ] **Implement (b) the `build_runtime` env-gating block.** Mirror the FILIGREE block (mcp.py:221-226); insert adjacent to it. UNLIKE the Filigree block, wrap construction in try/except — warpline is PURELY ADVISORY, so a misconfigured URL must never crash the governance authority at startup (degrade to `None`; `import logging` is already present at the top of mcp.py):
```python
    warpline = None
    warpline_url = os.environ.get("WARPLINE_API_URL")
    if warpline_url:
        from legis.warpline_preflight.client import HttpWarplineClient, WarplineError

        try:
            warpline = HttpWarplineClient(warpline_url)
        except WarplineError:
            logging.getLogger(__name__).warning(
                "WARPLINE_API_URL is set but invalid; warpline advisory context "
                "disabled (governance unaffected)."
            )
            warpline = None
```
and add `warpline=warpline,` to the `McpRuntime(...)` return (near the `filigree=filigree,` line, mcp.py:283).

- [ ] **Implement (c) the tool definition** in `tool_definitions()` (mcp.py:351+), modeled on `git_rename_feed_get` (mcp.py:809-840). Use `_one_of` for the discriminated output:
```python
        {
            "name": "warpline_preflight_get",
            "description": (
                "ADVISORY preflight context from the warpline sibling: impact "
                "radius + reverify worklist over base..head. Purely advisory — "
                "NEVER a governance verdict. Discriminated: 'checked' carries the "
                "advisory facts; 'unavailable' (client unconfigured, transport "
                "failure, or payload shape mismatch) carries reasons. Never read a "
                "missing 'checked' as 'nothing impacted'."
            ),
            "inputSchema": _schema(["base"], {"base": string, "head": string}),
            "outputSchema": _one_of(
                [
                    _schema(
                        ["status", "impact_radius", "reverify_worklist"],
                        {
                            "status": {"type": "string", "enum": ["checked"]},
                            "impact_radius": {"type": "object"},
                            "reverify_worklist": {"type": "object"},
                        },
                    ),
                    _schema(
                        ["status", "unavailable"],
                        {
                            "status": {"type": "string", "enum": ["unavailable"]},
                            "unavailable": {
                                "type": "array",
                                "items": _schema(["reason"], {"reason": string}),
                            },
                        },
                    ),
                ]
            ),
        },
```

- [ ] **Implement (d) the handler** (near the other read handlers):
```python
def _tool_warpline_preflight_get(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    from legis.service.preflight import read_warpline_preflight

    return _tool_result(
        read_warpline_preflight(
            runtime.warpline,
            base=_require(args, "base"),
            head=args.get("head", "HEAD"),
        )
    )
```

- [ ] **Implement (e) the three registries** (test `test_tool_registries_are_in_sync` enforces equality):
  - `_AGENT_TOOLS` (mcp.py:81-106): add `"warpline_preflight_get",`.
  - `_TOOL_HANDLERS` (mcp.py:2421-2444): add `"warpline_preflight_get": _tool_warpline_preflight_get,`.
  - tool_definitions(): the entry from step (c).

- [ ] **Run to pass:** `uv run pytest tests/mcp/test_server.py -q -k warpline_preflight`.

- [ ] **Commit:** `feat(mcp): wire warpline_preflight_get advisory sibling tool`.

---

## Task 4 — Byte-identical advisory-boundary acceptance spine (`test_warpline_advisory_boundary.py`)

This is the spine of the whole change. It is its own task and proves the invariant directly.

**Files**
- Create test: `tests/mcp/test_warpline_advisory_boundary.py`

**Interfaces**
- Consumes: `build_runtime`, `call_tool`, the existing runtime/store fixtures.

Steps:

- [ ] **Write failing test** `tests/mcp/test_warpline_advisory_boundary.py`. It runs representative governance paths (a `policy_evaluate`, an override submit, and a sign-off read) twice — with `WARPLINE_API_URL` unset, and again with it set to an injected HOSTILE warpline returning arbitrary impact data — and asserts byte-identical results. Plus the structural-boundary test that `runtime.warpline` is referenced in no verdict-path function:
```python
import inspect
import json

from legis.policy.grammar import AllowlistBoundary, PolicyGrammar


class _HostileWarpline:
    """Returns arbitrary/garbage advisory data to prove it cannot perturb a verdict."""

    def impact_radius(self, base, head):
        return {"affected": [{"sei": "EVERYTHING"}], "count": 9999, "block": True}

    def reverify_worklist(self, base, head):
        return {"entries": [{"sei": "EVERYTHING", "reason": "force"}], "count": 9999}


def _seed_real_verdict_runtime(tmp_path):
    """A runtime that returns REAL, DETERMINISTIC verdicts.

    Uses the _runtime fixture's FixedClock (timestamps identical across runs) and
    registers a real grammar so policy_evaluate returns an actual VIOLATION /
    UNKNOWN verdict — NOT an error envelope. An error envelope on BOTH sides would
    make the byte-identity assertion pass trivially and prove nothing — the exact
    defect the first draft of this test had. Mirrors the seeding in
    test_policy_evaluate_returns_unknown_distinct_from_clear (test_server.py:1225).
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    runtime, _store = _runtime(tmp_path)  # FixedClock("2026-06-02T12:00:00+00:00")
    grammar = PolicyGrammar()
    grammar.register(AllowlistBoundary("imports", frozenset({"json"})))
    runtime.grammar = grammar
    return runtime


def _run_governance_paths(runtime):
    """Drive REAL verdict paths and return their structuredContent blobs."""
    from legis.mcp import call_tool

    blobs = [
        # A real VIOLATION verdict (socket not in the {json} allowlist).
        call_tool(
            runtime, "policy_evaluate", {"policy": "imports", "target": {"value": "socket"}}
        ).get("structuredContent"),
        # A real UNKNOWN verdict (unknown policy -> provenance gap).
        call_tool(
            runtime, "policy_evaluate", {"policy": "missing", "target": {}}
        ).get("structuredContent"),
    ]
    # GUARD: these MUST be real verdicts, never error envelopes — otherwise the
    # byte-identity assertion below is vacuous.
    assert blobs[0]["outcome"] == "VIOLATION" and blobs[0]["provenance_gap"] is False
    assert blobs[1]["outcome"] == "UNKNOWN" and blobs[1]["provenance_gap"] is True
    return blobs


def test_governance_verdicts_byte_identical_warpline_unset_vs_hostile(tmp_path):
    # Everything is held IDENTICAL across the two runtimes (same FixedClock, same
    # seeded grammar) EXCEPT runtime.warpline. If warpline data could reach a
    # verdict path, the hostile side would diverge.
    runtime_unset = _seed_real_verdict_runtime(tmp_path / "a")
    runtime_unset.warpline = None
    unset = _run_governance_paths(runtime_unset)

    runtime_set = _seed_real_verdict_runtime(tmp_path / "b")
    runtime_set.warpline = _HostileWarpline()  # structurally present, hostile
    setval = _run_governance_paths(runtime_set)

    assert json.dumps(unset, sort_keys=True) == json.dumps(setval, sort_keys=True)


def test_runtime_warpline_referenced_in_no_verdict_path_function():
    # STRUCTURAL (defense-in-depth): runtime.warpline must appear in NO
    # verdict-path / honesty-read source. NOTE inspect.getsource is a SHALLOW text
    # scan — it sees only these named functions, not helpers they call — so this
    # COMPLEMENTS, never replaces, the byte-identity test above.
    import legis.mcp as mcp

    verdict_path_fns = [
        mcp._tool_policy_evaluate,
        mcp._engine,
        mcp._coached_engine,
        mcp._governance_trail_records,
        mcp._tool_identity_gap_list,
        mcp._tool_lineage_integrity_get,
        mcp._tool_policy_boundary_check,
        mcp._tool_signoff_status_get,
        mcp._tool_override_submit,
    ]
    for fn in verdict_path_fns:
        src = inspect.getsource(fn)
        assert ".warpline" not in src, f"{fn.__name__} references warpline"
```
> If any function name above differs in the codebase, adjust to the actual symbol; the set MUST cover `policy_evaluate`, `_engine`, `_coached_engine` (mcp.py:1526), the gates, sign-off, and the three honesty reads (`identity_gap_list`, `lineage_integrity_get`, `policy_boundary_check`). Task 5 adds `mcp._tool_attestation_get` to this list once that handler exists.

- [ ] **Run to fail then pass:** Before Task 3 wiring this fails to import the tools; after Task 3 it passes. Run `uv run pytest tests/mcp/test_warpline_advisory_boundary.py -q`. The seeding (`_seed_real_verdict_runtime`) is identical on both sides and produces REAL deterministic verdicts via `FixedClock`, so the byte-identity assertion is meaningful — it would FAIL if warpline presence perturbed a verdict, and the in-test guard rejects a vacuous error-envelope pass.

- [ ] **Commit:** `test(warpline): byte-identical advisory-boundary acceptance spine`.

---

## Task 5 — `attestation_get` structural scaffolding: schema, registries, no-trail `unavailable`, tamper `AUDIT_INTEGRITY_FAILURE`

This task builds everything about `attestation_get` EXCEPT the positive-admission classifier (which is BLOCKED — Task 8). The fail-closed paths, the discriminated schema, and the three-registry registration are concrete and testable now.

**Files**
- Modify: `src/legis/mcp.py`, `src/legis/service/governance.py`, `src/legis/service/__init__.py`
- Modify test: `tests/mcp/test_server.py`, `tests/service/test_governance.py`

**Interfaces**
- Produces: MCP tool `attestation_get` (input `{sei: string (required)}`); handler `_tool_attestation_get(runtime, args)`; service stub `read_sei_attestations(verified_runtime_records, sei) -> dict[str, Any]` returning the discriminated `checked`/`unavailable` shape. The handler applies the FAIL-CLOSED PRE-GATE: `if runtime.protected_gate is None: return unavailable` (cannot verify signatures in an engine-only deployment), then reads through `_governance_trail_records(runtime)` (which raises `AuditIntegrityError` on a tampered protected trail).
- Consumes: `_governance_trail_records` (mcp.py:2173), `verified_records` (governance.py:156), `AuditIntegrityError` (mapped to `AUDIT_INTEGRITY_FAILURE` by the MCP adapter).

Steps:

- [ ] **Write failing tests.** In `tests/mcp/test_server.py` (reusing `_runtime` and `call_tool`; the tamper test defines its OWN inline `_TamperVerifier` / `_FakeProtectedGate` below — do NOT reuse `_TamperedLedger` at test_server.py:2243, which raises `BindingError` from the closure gate, a different model):
```python
def test_attestation_get_unavailable_when_no_protected_gate(tmp_path):
    # ENGINE-ONLY DEPLOYMENT: no LEGIS_HMAC_KEY -> runtime.protected_gate is None.
    # The trail is not signature-verifiable, so attestation_get MUST return a
    # success-envelope unavailable, NOT a silent empty that reads as "never attested".
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)  # no protected gate wired
    assert runtime.protected_gate is None
    result = call_tool(runtime, "attestation_get", {"sei": "mod.fn#1"})
    assert not result.get("isError")
    sc = result["structuredContent"]
    assert sc["status"] == "unavailable"
    assert sc["sei"] == "mod.fn#1"
    assert sc["attestations"] == []
    assert sc["unavailable"] and "reason" in sc["unavailable"][0]


def test_attestation_get_tamper_yields_audit_integrity_failure(tmp_path):
    # FAIL-CLOSED: a tampered protected trail -> AUDIT_INTEGRITY_FAILURE, nothing
    # surfaced. Build a protected runtime whose trail verifier raises TamperError.
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)

    class _TamperVerifier:
        def verify(self, records):
            from legis.enforcement.protected import TamperError

            raise TamperError("record 4 hash mismatch")

    class _FakeProtectedGate:
        def records(self):
            return ["bad-record"]

    runtime.protected_gate = _FakeProtectedGate()
    runtime.trail_verifier = _TamperVerifier()
    result = call_tool(runtime, "attestation_get", {"sei": "mod.fn#1"})
    assert result.get("isError")
    assert result["structuredContent"]["error_code"] == "AUDIT_INTEGRITY_FAILURE"
```
And in `tests/service/test_governance.py` (reusing `_FakeProtectedGate` / `_TamperVerifier` / `verified_records` imports at lines 227-279):
```python
def test_read_sei_attestations_returns_checked_shape_on_empty_verified_trail():
    from legis.service.governance import read_sei_attestations

    out = read_sei_attestations([], "mod.fn#1")
    assert out["status"] == "checked"
    assert out["sei"] == "mod.fn#1"
    assert out["attestations"] == []
```

- [ ] **Run to fail:** `uv run pytest tests/mcp/test_server.py tests/service/test_governance.py -q -k attestation` — fails: `UNKNOWN_TOOL` / no `read_sei_attestations`.

- [ ] **Implement (a) the service stub** in `src/legis/service/governance.py` next to `read_identity_gaps` / `read_lineage_integrity`. The positive-admission classifier body is BLOCKED (Task 8); ship the discriminated skeleton that always returns `checked` with an empty list for now (the no-trail `unavailable` discrimination is owned by the HANDLER pre-gate, not this function, because a pre-materialized `runtime_records` list cannot carry the verified/unverified distinction — validator high finding):
```python
def read_sei_attestations(verified_runtime_records: list, sei: str) -> dict[str, Any]:
    """Per-SEI human-cleared attestation facts from the VERIFIED governance trail.

    ASYMMETRIC ERROR RULE: a FALSE "attested" lets warpline skip reverify on
    un-cleared code (security hole); an OMITTED attestation only wastes work
    (safe). Every ambiguous/failure case therefore resolves toward "not attested"
    — omit the record, never surface it. ``verified_runtime_records`` MUST already
    have come through ``verified_records`` — the handler guarantees this via the
    protected-gate + trail-verifier pre-gate, and a tampered protected trail has
    already raised AuditIntegrityError before this function is called. The
    parameter is named for that contract: a future caller passing raw
    ``_engine(runtime).records`` is then a self-documenting mistake. This function
    takes a MATERIALIZED list (not a callable) — a bare list cannot carry the
    verified/unverified distinction, so the gate decision lives in the handler.

    BLOCKED — positive admission classifier (Task 8): which records count as an
    attestation, and the forge-proof discriminator, await owner ratification.
    Until then this surfaces ZERO attestations (fail-closed: omit everything).
    """
    records = list(verified_runtime_records)
    attestations: list[dict[str, Any]] = []
    # Task 8: classify `records` for `sei` here once the discriminator is ratified.
    return {"status": "checked", "sei": sei, "attestations": attestations}
```
  Export it: add `read_sei_attestations` to the governance import block + `__all__` in `src/legis/service/__init__.py`.

- [ ] **Implement (b) the handler** in `src/legis/mcp.py`, with the FAIL-CLOSED PRE-GATE moved into the handler (validator high finding: the gate-presence decision must precede any record read, since `verified_records` falls through to unverified `engine_records()` when `trail_owner` is `None`):
```python
def _tool_attestation_get(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    from legis.service.governance import read_sei_attestations

    sei = _require(args, "sei")
    # FAIL-CLOSED: attestation is only possible when the trail is signature-
    # verifiable. `verified_records` ONLY runs TrailVerifier.verify when BOTH a
    # protected trail_owner AND a trail_verifier are wired (governance.py:199-205);
    # with a protected_gate but no verifier it returns engine records UNVERIFIED.
    # Gate on BOTH so the invariant holds by construction, not by the convention
    # that build_runtime co-locates them under one `if hmac_key:` block. Return the
    # discriminated unavailable (NEVER a silent empty 'checked' that reads as
    # "never attested", NEVER unverified field values).
    if runtime.protected_gate is None or runtime.trail_verifier is None:
        return _tool_result(
            {
                "status": "unavailable",
                "sei": sei,
                "attestations": [],
                "unavailable": [
                    {"reason": "trail not signature-verifiable (no protected gate / verifier)"}
                ],
            }
        )
    # _governance_trail_records runs verified_records, which raises
    # AuditIntegrityError (-> AUDIT_INTEGRITY_FAILURE) on a tampered protected trail.
    return _tool_result(read_sei_attestations(_governance_trail_records(runtime), sei))
```

- [ ] **Implement (c) the tool definition** via `_one_of` (discriminated, so it routes through `_one_of` per the conformance tests):
```python
        {
            "name": "attestation_get",
            "description": (
                "Per-SEI human-cleared governance attestation FACTS (no proven_good "
                "verdict). Through the same fail-closed verified-trail path the "
                "honesty reads use: a tampered trail -> AUDIT_INTEGRITY_FAILURE; an "
                "engine-only deployment (no protected gate) -> 'unavailable'. Never "
                "read an empty attestations list under 'unavailable' as 'never "
                "attested'; a forged attestation is never returned."
            ),
            "inputSchema": _schema(["sei"], {"sei": string}),
            "outputSchema": _one_of(
                [
                    _schema(
                        ["status", "sei", "attestations"],
                        {
                            "status": {"type": "string", "enum": ["checked"]},
                            "sei": string,
                            "attestations": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["kind", "content_hash", "recorded_at", "seq"],
                                    "properties": {
                                        "kind": {
                                            "type": "string",
                                            "enum": ["signoff_cleared", "operator_override"],
                                        },
                                        "content_hash": string,
                                        "recorded_at": string,
                                        "seq": integer,
                                        "signoff_seq": integer,
                                    },
                                },
                            },
                        },
                    ),
                    _schema(
                        ["status", "sei", "attestations", "unavailable"],
                        {
                            "status": {"type": "string", "enum": ["unavailable"]},
                            "sei": string,
                            "attestations": {"type": "array", "maxItems": 0},
                            "unavailable": {
                                "type": "array",
                                "items": _schema(["reason"], {"reason": string}),
                            },
                        },
                    ),
                ]
            ),
        },
```

- [ ] **Implement (d) the three registries:** add `"attestation_get"` to `_AGENT_TOOLS`, `"attestation_get": _tool_attestation_get` to `_TOOL_HANDLERS`, and the definition above to `tool_definitions()`.

- [ ] **Run to pass:** `uv run pytest tests/mcp/test_server.py tests/service/test_governance.py -q -k attestation`.

- [ ] **Commit:** `feat(mcp): add attestation_get fail-closed scaffolding (classifier BLOCKED)`.

---

## Task 6 — Surface bookkeeping: tool-count bump 22→24 + surface-set literal + structural boundary

**Files**
- Modify test: `tests/mcp/test_server.py`

**Interfaces**
- Consumes: `_AGENT_TOOLS`, `_TOOL_HANDLERS`, `tool_definitions()`.

Steps:

- [ ] **Update the surface-set literal** `test_initialize_and_tools_list_exposes_full_agent_surface` (tests/mcp/test_server.py:266-326): add `"warpline_preflight_get"` and `"attestation_get"` to the `set(by_name) == {...}` literal at lines 282-305 (now 24 names). The binding invariant `test_tool_registries_are_in_sync` (test_server.py:2053-2064: `defined == set(_TOOL_HANDLERS) == set(_AGENT_TOOLS)`) needs NO edit — it is structural and already passes once all three registries carry both new tools (Tasks 3 + 5).

- [ ] **Confirm no new error code is introduced.** Both tools degrade ambiguous/failure cases to a success-envelope `status: "unavailable"`; the only error path is `AUDIT_INTEGRITY_FAILURE`, already in the pinned list (test_server.py:2067-2093) and `_recovery_for`. So `_recovery_for` (mcp.py:1222-1284) and the pinned-code test require NO change. Add an explicit assertion to lock that:
```python
def test_warpline_tools_introduce_no_new_error_codes(tmp_path):
    # warpline_preflight_get / attestation_get degrade to success-envelope
    # status:"unavailable"; their only error path is the pre-existing
    # AUDIT_INTEGRITY_FAILURE. No new error code => no _recovery_for / pinned-code change.
    from legis.mcp import call_tool

    runtime, _store = _runtime(tmp_path)
    assert not call_tool(runtime, "warpline_preflight_get", {"base": "x"}).get("isError")
    assert not call_tool(runtime, "attestation_get", {"sei": "x#1"}).get("isError")
```

- [ ] **Confirm C-8 names pass** (test_c8 at test_server.py:2096-2107): neither `warpline_preflight_get` nor `attestation_get` contains `enable/provision/grant/hmac/sign_key/set_key`. No code change; this test already covers the new names once registered.

- [ ] **Run to pass:** `uv run pytest tests/mcp/test_server.py -q`.

- [ ] **Commit:** `test(mcp): bump agent surface to 24 tools for warpline + attestation`.

---

## Task 7 — outputSchema conformance vectors for both new tools

**Files**
- Modify test: `tests/mcp/test_output_schema_conformance.py`

**Interfaces**
- Consumes: `_conformant(runtime, name, args)` (lines 97-105), `_tool(name)` (75-78), `_runtime` (81-94), `ERROR_ENVELOPE_SCHEMA`, `call_tool` (all imported in-file).

Steps:

- [ ] **Write conformance tests.** The catalog-wide tests (`test_every_tool_declares_a_valid_output_schema`, `test_every_output_schema_declares_top_level_object_type`, `test_one_of_helper_always_injects_top_level_object_type`) auto-cover both new tools because each schema routes through `_one_of` / `_schema`. Add per-tool driven vectors mirroring the `identity_gap_list` unavailable-conformance model (conformance:492-498) and the scan_route error-path model (conformance:418-443):
```python
def test_warpline_preflight_get_unavailable_conforms(tmp_path):
    runtime, _store = _runtime(tmp_path)  # warpline None
    payload = _conformant(runtime, "warpline_preflight_get", {"base": "aaa"})
    assert payload["status"] == "unavailable"


def test_warpline_preflight_get_checked_conforms(tmp_path):
    class _FakeWarpline:
        def impact_radius(self, base, head):
            return {"affected": [], "count": 0}

        def reverify_worklist(self, base, head):
            return {"entries": [], "count": 0}

    runtime, _store = _runtime(tmp_path)
    runtime.warpline = _FakeWarpline()
    payload = _conformant(runtime, "warpline_preflight_get", {"base": "aaa", "head": "bbb"})
    assert payload["status"] == "checked"


def test_attestation_get_unavailable_conforms(tmp_path):
    runtime, _store = _runtime(tmp_path)  # no protected gate
    payload = _conformant(runtime, "attestation_get", {"sei": "mod.fn#1"})
    assert payload["status"] == "unavailable"


def test_attestation_get_tamper_error_conforms_to_envelope(tmp_path):
    from legis.mcp import ERROR_ENVELOPE_SCHEMA, call_tool
    from jsonschema import Draft202012Validator

    runtime, _store = _runtime(tmp_path)

    class _TamperVerifier:
        def verify(self, records):
            from legis.enforcement.protected import TamperError

            raise TamperError("mismatch")

    class _FakeProtectedGate:
        def records(self):
            return ["bad"]

    runtime.protected_gate = _FakeProtectedGate()
    runtime.trail_verifier = _TamperVerifier()
    result = call_tool(runtime, "attestation_get", {"sei": "mod.fn#1"})
    assert result.get("isError")
    Draft202012Validator(ERROR_ENVELOPE_SCHEMA).validate(result["structuredContent"])
```

- [ ] **Run to pass:** `uv run pytest tests/mcp/test_output_schema_conformance.py -q`.

- [ ] **Commit:** `test(mcp): outputSchema conformance vectors for warpline + attestation tools`.

---

## Task 8 — `read_sei_attestations` positive-admission classifier — **BLOCKED pending owner confirmation**

> **STATUS: BLOCKED.** This task does NOT proceed until the owner ratifies the three open questions below. They are SPEC-LEVEL security decisions (they contradict spec lines 92 / 102 / 112), not implementation details deferred to line 116. Do NOT invent a discriminator marker; do NOT surface field values over an unverified trail. The scaffolding (Task 5) ships now and surfaces ZERO attestations (fail-closed) until ratified. The test suite below is written and committed as `@pytest.mark.skip(reason="BLOCKED: owner classifier ratification")`; the skip is removed when the owner answers.

**The three open questions the owner MUST answer:**

1. **Operator-override discriminator (forgeable as a bare field check).** The obvious reading `extensions.judge_verdict == "OVERRIDDEN_BY_OPERATOR"` + `extensions.protected_cell == True` is FORGEABLE: the chill `EnforcementEngine` (engine.py:70-71, `judge is None`) writes caller `extensions` VERBATIM with no server-side override, so a self-clear can carry those fields. A false "attested" → warpline skips reverify on un-cleared code → the exact ASYMMETRIC-RULE security hole. **Recommended resolution:** the classifier admits an operator override ONLY when `extensions.judge_metadata_signature` VERIFIES under the protected key over `signing_fields(payload, seq=rec.seq)` (protected.py:45-92, 186-197) AND the signed `judge_verdict == "OVERRIDDEN_BY_OPERATOR"` — never the bare field value. Because the handler pre-gate (Task 5) already requires `runtime.protected_gate` and reads through `verified_records` (which runs `TrailVerifier.verify` and raises on any forged/unsigned protected record), the additional in-classifier requirement is the PRESENCE of `judge_metadata_signature` in `extensions` (a chill record stuffing ONLY `judge_verdict` carries no such signature, passes the verifier because `_requires_verification` does not select it, and MUST therefore be omitted by the classifier's signature-presence check).

2. **Fail-closed routing in the engine-only deployment.** `verified_records` falls through to UNVERIFIED `engine_records()` when `trail_owner` is `None` (governance.py:205), and only runs `TrailVerifier.verify` when `trail_verifier` is also wired (governance.py:199-205); a pre-materialized records list cannot carry the verified/unverified distinction. **Recommended resolution (already implemented in Task 5):** the handler gates on `runtime.protected_gate is None or runtime.trail_verifier is None → unavailable` BEFORE any records are read; `read_sei_attestations` only ever sees `verified_records` output. Owner must confirm engine-only deployments cannot attest at all (return `unavailable`).

3. **Unsigned structured (procedural) sign-offs.** `signoff.py:104-105` writes a `SIGNED_OFF` record with NO `signoff_signature` when no signer/key is wired (module docstring 4-6: "structured sign-offs are procedural (unsigned)"). **Recommended resolution:** only a verifying-signed sign-off (`signoff_signature` present and verifying, selected + verified by `TrailVerifier`) is admissible; an unsigned structured `SIGNED_OFF` resolves to omission. In an engine-only deployment this is already covered by the handler pre-gate (no protected gate → `unavailable`).

**Files (on ratification)**
- Modify: `src/legis/service/governance.py` (`read_sei_attestations` body)
- Modify test: `tests/service/test_governance.py`, `tests/mcp/test_server.py`

**Interfaces (the ratified shape — recommended)**
- For each surfaced attestation: `{"kind": "signoff_cleared"|"operator_override", "content_hash": <non-empty str>, "recorded_at": <str>, "seq": <int>, "signoff_seq"?: <int>}`. NEVER `content_hash == ""`. SEI is `entity_key.value`; `identity_stable` must be true. Sign-off discriminator is `SignoffState.SIGNED_OFF.value` (`"SIGNED_OFF"`, UPPERCASE — never the spec's lowercase `'signed_off'`, which matches nothing). content_hash for a sign-off is JOINED from the PENDING request via `extensions.request_seq` at `extensions.loomweave.content_hash`; for an operator override it is INLINE at `extensions.loomweave.content_hash`.

**MANDATORY test suite (all `required_test_cases` from the three validators; write now, `@pytest.mark.skip` until ratified):**

- [ ] **Write the (skipped) classifier test suite** in `tests/service/test_governance.py` and `tests/mcp/test_server.py`. Each marked `@pytest.mark.skip(reason="BLOCKED: owner classifier ratification (Task 8)")`. Cases:

  - [ ] **FORGE-NEGATIVE (protected, stuffed full markers).** A chill self-clear record stuffed with `extensions={"judge_verdict": "OVERRIDDEN_BY_OPERATOR", "protected_cell": True}` but NO verifying `judge_metadata_signature` → `_requires_verification` selects it (`protected_cell is True`) → `TrailVerifier.verify` raises `TamperError` → `attestation_get` returns `isError`, `error_code == "AUDIT_INTEGRITY_FAILURE"` (nothing surfaced).
  - [ ] **FORGE-NEGATIVE (subtle — proves the classifier's OWN signature check).** A chill self-clear stuffing ONLY `judge_verdict == "OVERRIDDEN_BY_OPERATOR"` (NO `protected_cell`/`file_fingerprint`/`ast_path`/signature) → NOT selected by `_requires_verification`, so it PASSES the trail verifier → `attestation_get` MUST STILL OMIT it because it lacks a verifying `judge_metadata_signature`. Asserts the classifier requires a verifying signature, not mere passage through `verified_records`.
  - [ ] **ENGINE-ONLY DEPLOYMENT.** A real UNSIGNED structured `SIGNED_OFF` record exists for the SEI, no protected gate / no `LEGIS_HMAC_KEY` → `attestation_get` returns `status == "unavailable"`, ZERO attestations, never a bare empty `checked`. (Already passing via Task 5's pre-gate.)
  - [ ] **POSITIVE (protected operator-override).** A record with a `judge_metadata_signature` that VERIFIES under the protected key over `signing_fields(payload, seq=rec.seq)` AND signed `judge_verdict == "OVERRIDDEN_BY_OPERATOR"` AND inline `extensions.loomweave.content_hash` present → surfaces `kind: "operator_override"` with that `content_hash` and `seq == rec.seq`.
  - [ ] **POSITIVE (protected-cell cleared sign-off).** A `SIGNED_OFF` record with a verifying `signoff_signature`, `identity_stable` true, joined to a PENDING (via `extensions.request_seq`) with non-empty `extensions.loomweave.content_hash` → surfaces `kind: "signoff_cleared"` with the joined `content_hash` and `signoff_seq == request_seq`.
  - [ ] **EXCLUSION (BLOCKED verdict).** A `BLOCKED` verdict record for the SEI → omitted.
  - [ ] **EXCLUSION (ACCEPTED self-clear).** A coached/chill `ACCEPTED` self-clear (`judge_verdict == "ACCEPTED"`, no operator override) → omitted.
  - [ ] **FILTER (`identity_stable`).** A cleared sign-off whose `entity_key.identity_stable` is False (locator-keyed, no rename-stable SEI) → omitted.
  - [ ] **FILTER (SEI scoping).** Records for a DIFFERENT SEI are not surfaced under the queried SEI.
  - [ ] **JOIN-EMPTY (asymmetric omit).** A cleared `SIGNED_OFF` whose joined PENDING has NO `extensions.loomweave.content_hash` → the record is OMITTED (never surfaced with `content_hash == ""`), but the surrounding read still returns `status: "checked"` (the verified trail was read) with that record simply absent — a per-record omit, NOT a whole-read `unavailable`, and NEVER a silent "never attested".
  - [ ] **INLINE-EMPTY (asymmetric omit).** A verifying operator-override with absent inline `extensions.loomweave.content_hash` → OMITTED, never `content_hash == ""`.
  - [ ] **TAMPER at the tool level.** A tampered governance trail → `call_tool(runtime, "attestation_get", {"sei"})` returns `isError`, `error_code == "AUDIT_INTEGRITY_FAILURE"`. (Already passing via Task 5.)
  - [ ] **UNAVAILABLE shape.** No governance trail wired → success envelope `{"status": "unavailable", "sei", "attestations": [], "unavailable": [{"reason"}]}`; assert NOT `isError` and NOT a silent empty `checked`. (Already passing via Task 5.)
  - [ ] **outputSchema conformance.** The discriminated checked/unavailable union routes through `_one_of` (top-level `"type": "object"`); the unavailable path conforms; an `isError` tamper path validates against `ERROR_ENVELOPE_SCHEMA`. (Already passing via Task 7.)
  - [ ] **BYTE-IDENTITY (tool-local sanity).** `attestation_get` reads only the local verified trail and never `runtime.warpline`; a structural test asserts `runtime.warpline` is absent from `read_sei_attestations` and `_tool_attestation_get` source. (Already asserted in Task 4's structural test once `_tool_attestation_get` is added to that function set.)

- [ ] **On ratification:** implement the agreed classifier in `read_sei_attestations` using the verifying-signature discriminator (the recommended resolution above), reusing `_binding_entity_from_backfill`'s iteration idiom (`for rec in records: payload = rec.payload`), `EntityKey.from_dict(payload["entity_key"])` for the SEI/`identity_stable` filter, the `signoff.py` `request_record`/`is_cleared` join for sign-offs, and `verify(signing_fields(payload, seq=rec.seq), sig, key)` for the operator-override signature check. Remove the `@pytest.mark.skip` marks, run the full suite to pass, commit `feat(governance): ratified per-SEI attestation classifier`.

---

## Final verification (run before declaring done)

- [ ] `uv run pytest tests/warpline_preflight tests/service/test_preflight.py tests/service/test_governance.py tests/mcp/test_server.py tests/mcp/test_output_schema_conformance.py tests/mcp/test_warpline_advisory_boundary.py -q` — all green (Task 8 classifier cases skipped pending ratification).
- [ ] `uv run pytest -q` — full suite green (no regression in the 22 pre-existing tools, now 24).
- [ ] Grep guard: `grep -rn "runtime.warpline\|\.warpline" src/legis/mcp.py` shows references ONLY in `_tool_warpline_preflight_get`, the `McpRuntime` dataclass field, and the `build_runtime` gating block — NOWHERE in `_tool_policy_evaluate`, `_engine`, `_coached_engine`, the gates, sign-off, or the honesty reads.
- [ ] Confirm `_AGENT_TOOLS` has exactly 24 members; `test_tool_registries_are_in_sync` green.
