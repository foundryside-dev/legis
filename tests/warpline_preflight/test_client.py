import inspect
import json

import pytest

import legis.filigree.client as fc
import legis.warpline_preflight.client as wc
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
