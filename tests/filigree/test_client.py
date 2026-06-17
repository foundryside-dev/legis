import pytest

import legis.filigree.client as client_mod
from legis.filigree.client import FiligreeError, HttpFiligreeClient


def _fake_fetch(responses):
    calls = []

    def fetch(method, url, body):
        calls.append((method, url, body))
        for (m, suffix), resp in responses.items():
            if method == m and url.split("?")[0].endswith(suffix):
                return resp
        raise FiligreeError(f"no canned response for {method} {url}")

    fetch.calls = calls
    return fetch


def test_attach_posts_entity_id_and_hash():
    resp = {"issue_id": "ISSUE-1", "loomweave_entity_id": "loomweave:eid:abc",
            "content_hash_at_attach": "h", "attached_at": "t", "attached_by": "legis"}
    fetch = _fake_fetch({("POST", "/api/issue/ISSUE-1/entity-associations"): resp})
    c = HttpFiligreeClient("http://localhost", fetch=fetch)
    out = c.attach("ISSUE-1", "loomweave:eid:abc", "h", actor="legis")
    assert out == resp
    assert fetch.calls[-1] == ("POST", "http://localhost/api/issue/ISSUE-1/entity-associations",
                               {"entity_id": "loomweave:eid:abc", "content_hash": "h", "actor": "legis"})


def test_attach_posts_signoff_attestation_when_supplied():
    resp = {"attached": True}
    fetch = _fake_fetch({("POST", "/api/issue/ISSUE-1/entity-associations"): resp})
    c = HttpFiligreeClient("http://localhost", fetch=fetch)
    out = c.attach(
        "ISSUE-1",
        "loomweave:eid:abc",
        "h",
        actor="legis",
        signoff_seq=7,
        signature="hmac-sha256:v2:abc",
    )
    assert out == resp
    assert fetch.calls[-1][2] == {
        "entity_id": "loomweave:eid:abc",
        "content_hash": "h",
        "actor": "legis",
        "signoff_seq": 7,
        "signature": "hmac-sha256:v2:abc",
    }


def test_associations_for_entity_url_encodes_colons():
    fetch = _fake_fetch({("GET", "/api/entity-associations"): {"associations": []}})
    c = HttpFiligreeClient("http://localhost", fetch=fetch)
    assert c.associations_for_entity("loomweave:eid:abc") == []
    url = fetch.calls[-1][1]
    assert "entity_id=loomweave%3Aeid%3Aabc" in url   # colons percent-encoded


def test_attach_escapes_path_traversal_payload():
    resp = {"attached": True}
    # Expected URL has quoted/escaped path traversal characters
    fetch = _fake_fetch({("POST", "/api/issue/..%2F..%2Fadmin%2Fdelete/entity-associations"): resp})
    c = HttpFiligreeClient("http://localhost", fetch=fetch)
    c.attach("../../admin/delete", "loomweave:eid:abc", "h", actor="legis")
    assert fetch.calls[-1][1] == "http://localhost/api/issue/..%2F..%2Fadmin%2Fdelete/entity-associations"


def test_attach_rejects_non_object_response():
    fetch = _fake_fetch({("POST", "/api/issue/ISSUE-1/entity-associations"): []})
    with pytest.raises(FiligreeError):
        HttpFiligreeClient("http://localhost", fetch=fetch).attach(
            "ISSUE-1", "loomweave:eid:abc", "h", actor="legis"
        )


def test_associations_rejects_non_object_and_non_list_response():
    fetch = _fake_fetch({("GET", "/api/entity-associations"): []})
    with pytest.raises(FiligreeError):
        HttpFiligreeClient("http://localhost", fetch=fetch).associations_for_entity("loomweave:eid:abc")

    fetch = _fake_fetch({("GET", "/api/entity-associations"): {"associations": "bad"}})
    with pytest.raises(FiligreeError):
        HttpFiligreeClient("http://localhost", fetch=fetch).associations_for_entity("loomweave:eid:abc")


def test_client_rejects_unsafe_base_urls():
    for url in ("file:///tmp/filigree.json", "http://example.com", "not-a-url"):
        with pytest.raises(FiligreeError):
            HttpFiligreeClient(url)


# --- G11: the Filigree transport is open (unsigned) ---

def test_real_transport_does_not_emit_dead_hmac_headers(monkeypatch):
    # G11: Filigree's classic entity-association route is transport-open, so the
    # default transport must not emit X-Weft-* headers even if old key knobs are
    # present. The app-level binding_signature still travels in the JSON body.
    import legis.filigree.client as client_mod

    captured = {}

    def capture(method, url, body, headers=None):
        captured["headers"] = headers or {}
        captured["body"] = body or {}
        return {"ok": True}

    monkeypatch.setattr(client_mod, "_urllib_fetch", capture)
    monkeypatch.setenv("LEGIS_FILIGREE_HMAC_KEY", "legacy-channel")
    monkeypatch.setenv("LEGIS_HMAC_KEY", "shared")

    client = HttpFiligreeClient("https://filigree.example")
    client.attach(
        "ISSUE-1",
        "loomweave:eid:abc",
        "h",
        actor="legis",
        signoff_seq=7,
        signature="hmac-sha256:v2:abc",
    )
    assert "X-Weft-Component" not in captured["headers"]
    assert captured["body"]["signature"] == "hmac-sha256:v2:abc"
    assert captured["body"]["signoff_seq"] == 7


def test_wire_body_is_stable_compact_json_but_unsigned(monkeypatch):
    # G11 keeps the transport unsigned, but still sends stable compact JSON so
    # body-level binding_signature fixtures do not drift with dict insertion
    # order or json.dumps spacing.
    import legis.filigree.client as client_mod

    captured = {}

    class _FakeResp:
        headers = {"Content-Type": "application/json"}

        def read(self, _n):
            return b'{"ok": true}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_open_no_redirect(req):
        captured["data"] = req.data
        captured["headers"] = dict(req.header_items())
        return _FakeResp()

    monkeypatch.setattr(client_mod, "_open_no_redirect", fake_open_no_redirect)

    c = HttpFiligreeClient("https://filigree.example")
    c.attach("ISSUE-1", "loomweave:eid:abc", "h", actor="legis")

    assert captured["data"] == client_mod._json_body_bytes(
        {"entity_id": "loomweave:eid:abc", "content_hash": "h", "actor": "legis"}
    )
    headers = {k.lower(): v for k, v in captured["headers"].items()}
    assert "x-weft-component" not in headers
    assert "x-weft-timestamp" not in headers
    assert "x-weft-nonce" not in headers


# --- roadmap 13: transport / error-path branches (the surface a security
# reviewer cares about, and the unsigned-transport seam tied to Q-M4) ---

def test_json_body_bytes_none_is_empty():
    # A None body sends zero bytes (the stable-compact-JSON helper maps None->b"").
    assert client_mod._json_body_bytes(None) == b""


def test_urllib_fetch_wraps_transport_error(monkeypatch):
    # A urllib URLError (DNS failure, connection refused, timeout) surfaces as a
    # typed FiligreeError, never an unhandled urllib exception.
    import urllib.error

    def boom(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(client_mod, "_open_no_redirect", boom)
    with pytest.raises(FiligreeError, match="connection refused"):
        client_mod._urllib_fetch("GET", "https://filigree.example/api/x", None)


def test_urllib_fetch_rejects_redirects_before_hmac_headers_can_leak():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    captured = {}

    class _RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/leak")
                self.end_headers()
                return
            if self.path == "/leak":
                captured["headers"] = dict(self.headers)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
                return
            self.send_error(404)

        def log_message(self, _format, *args):  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/start"
        headers = {
            "X-Weft-Component": "filigree:secret",
            "X-Weft-Timestamp": "1700000000",
            "X-Weft-Nonce": "nonce",
        }
        with pytest.raises(FiligreeError, match="redirect not allowed"):
            client_mod._urllib_fetch("GET", url, None, headers)
        assert "headers" not in captured
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_decode_rejects_non_json_content_type():
    # A proxy/error page returning text/html must not be json-parsed; it is a
    # typed transport error.
    class _HtmlResp:
        headers = {"Content-Type": "text/html; charset=utf-8"}

        def read(self, _n):  # pragma: no cover - not reached; type check first
            return b"<html>503</html>"

    with pytest.raises(FiligreeError, match="non-JSON content type"):
        client_mod._decode_json_response(_HtmlResp(), "GET /api/x")


def test_decode_rejects_oversized_response():
    # A response larger than MAX_RESPONSE_BYTES is rejected before decode so a
    # hostile/buggy Filigree cannot exhaust memory.
    big = b"x" * (client_mod.MAX_RESPONSE_BYTES + 1)

    class _BigResp:
        headers = {"Content-Type": "application/json"}

        def read(self, n):
            return big[:n]

    with pytest.raises(FiligreeError, match="response too large"):
        client_mod._decode_json_response(_BigResp(), "GET /api/x")


def test_insecure_remote_http_warns_when_flag_bypasses_https(monkeypatch, caplog):
    import logging

    # ID-SEI-1: plaintext to a remote Filigree leaves responses forgeable (no TLS);
    # the flag must warn loudly rather than bypass silently.
    monkeypatch.setenv("LEGIS_ALLOW_INSECURE_REMOTE_HTTP", "1")
    with caplog.at_level(logging.WARNING):
        HttpFiligreeClient("http://remote.example:9000")
    assert any(
        "LEGIS_ALLOW_INSECURE_REMOTE_HTTP" in r.getMessage() for r in caplog.records
    )


def test_remote_http_without_flag_still_raises(monkeypatch):
    monkeypatch.delenv("LEGIS_ALLOW_INSECURE_REMOTE_HTTP", raising=False)
    with pytest.raises(FiligreeError):
        HttpFiligreeClient("http://remote.example")
