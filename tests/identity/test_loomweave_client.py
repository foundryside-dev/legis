import hashlib
import hmac
import logging

import pytest

from legis.identity.loomweave_client import (
    LoomweaveError,
    HttpLoomweaveIdentity,
    loomweave_hmac_key_from_env,
    sign_loomweave_request,
    _urllib_fetch,
)


def _fake_fetch(responses):
    calls = []

    def fetch(method, url, body, headers):
        calls.append((method, url, body, dict(headers)))
        for (m, suffix), resp in responses.items():
            if method == m and url.endswith(suffix):
                return resp
        raise LoomweaveError(f"no canned response for {method} {url}")

    fetch.calls = calls
    return fetch


def test_capability_true_when_sei_supported():
    fetch = _fake_fetch({("GET", "/api/v1/_capabilities"): {"sei": {"supported": True, "version": 1}}})
    assert HttpLoomweaveIdentity("http://localhost", fetch=fetch).capability() is True


def test_capability_false_when_absent_or_unsupported():
    fetch = _fake_fetch({("GET", "/api/v1/_capabilities"): {"registry_backend": True}})
    assert HttpLoomweaveIdentity("http://localhost", fetch=fetch).capability() is False


def test_resolve_locator_alive_passthrough():
    body = {"sei": "loomweave:eid:abc", "current_locator": "python:function:m.f", "content_hash": "h", "alive": True}
    fetch = _fake_fetch({("POST", "/api/v1/identity/resolve"): body})
    c = HttpLoomweaveIdentity("http://localhost", fetch=fetch)
    assert c.resolve_locator("python:function:m.f") == body
    assert fetch.calls[-1] == (
        "POST",
        "http://localhost/api/v1/identity/resolve",
        {"locator": "python:function:m.f"},
        {},
    )


def test_resolve_batch_posts_locators_to_loomweave_batch_endpoint():
    body = {
        "resolved": {
            "python:function:m.f": {
                "sei": "loomweave:eid:abc",
                "current_locator": "python:function:m.f",
                "content_hash": "h",
                "alive": True,
            }
        },
        "invalid": ["malformed"],
        "not_found": ["python:function:gone"],
    }
    fetch = _fake_fetch({("POST", "/api/v1/identity/resolve:batch"): body})
    c = HttpLoomweaveIdentity("http://localhost", fetch=fetch)

    assert c.resolve_batch(["python:function:m.f", "python:function:gone"]) == body
    assert fetch.calls[-1] == (
        "POST",
        "http://localhost/api/v1/identity/resolve:batch",
        {"locators": ["python:function:m.f", "python:function:gone"]},
        {},
    )


def test_resolve_sei_orphaned_carries_lineage():
    body = {"sei": "loomweave:eid:abc", "alive": False, "lineage": [{"event": "orphaned"}]}
    fetch = _fake_fetch({("GET", "/api/v1/identity/sei/loomweave%3Aeid%3Aabc"): body})
    assert HttpLoomweaveIdentity("http://localhost", fetch=fetch).resolve_sei("loomweave:eid:abc") == body


def test_lineage_returns_event_list():
    body = {"sei": "loomweave:eid:abc", "lineage": [{"event": "born"}, {"event": "locator_changed"}]}
    fetch = _fake_fetch({("GET", "/api/v1/identity/lineage/loomweave%3Aeid%3Aabc"): body})
    assert HttpLoomweaveIdentity("http://localhost", fetch=fetch).lineage("loomweave:eid:abc") == body["lineage"]


def test_resolve_sei_escapes_path_traversal_payload():
    body = {"alive": False}
    # Expected URL has quoted/escaped path traversal characters
    fetch = _fake_fetch({("GET", "/api/v1/identity/sei/..%2F..%2Fadmin%2Fdelete"): body})
    c = HttpLoomweaveIdentity("http://localhost", fetch=fetch)
    c.resolve_sei("../../admin/delete")
    assert fetch.calls[-1][1] == "http://localhost/api/v1/identity/sei/..%2F..%2Fadmin%2Fdelete"


def test_sign_loomweave_request_matches_loomweave_hmac_contract():
    body = {"locator": "python:function:m.f"}
    body_bytes = b'{"locator":"python:function:m.f"}'
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    message = (
        "POST\n/api/v1/identity/resolve\n"
        f"{body_hash}\n1900000000\nnonce-1"
    ).encode("utf-8")
    expected = hmac.new(b"s3cr3t", message, hashlib.sha256).hexdigest()

    headers = sign_loomweave_request(
        b"s3cr3t",
        "POST",
        "http://localhost/api/v1/identity/resolve",
        body,
        timestamp=1_900_000_000,
        nonce="nonce-1",
    )

    assert headers == {
        "X-Weft-Component": f"loomweave:{expected}",
        "X-Weft-Timestamp": "1900000000",
        "X-Weft-Nonce": "nonce-1",
    }


def test_capability_probe_is_signed_when_key_is_provisioned():
    # ID-3: the capability probe is the trust-establishing handshake — it decides
    # whether legis treats the provider as SEI-capable at all. When a key is
    # provisioned it must carry the Weft-component HMAC like every other route;
    # an unsigned probe is the one route an auth-enforcing Loomweave cannot
    # authenticate, and the lone unsigned exception in a keyed deployment.
    fetch = _fake_fetch({("GET", "/api/v1/_capabilities"): {"sei": {"supported": True, "version": 1}}})
    c = HttpLoomweaveIdentity(
        "http://localhost",
        fetch=fetch,
        hmac_key="s3cr3t",
        clock=lambda: 1_900_000_000,
        nonce_factory=lambda: "nonce-1",
    )

    assert c.capability() is True

    headers = fetch.calls[-1][3]
    expected = sign_loomweave_request(
        b"s3cr3t",
        "GET",
        "http://localhost/api/v1/_capabilities",
        None,
        timestamp=1_900_000_000,
        nonce="nonce-1",
    )
    assert headers == expected


def test_capability_probe_stays_unsigned_when_no_key():
    # Keyless (loopback/trusted) deployments are unchanged: no key → no headers.
    fetch = _fake_fetch({("GET", "/api/v1/_capabilities"): {"sei": {"supported": True, "version": 1}}})
    assert HttpLoomweaveIdentity("http://localhost", fetch=fetch).capability() is True
    assert fetch.calls[-1][3] == {}


def test_resolve_locator_sends_weft_hmac_headers_when_key_is_provisioned():
    body = {"sei": "loomweave:eid:abc", "current_locator": "python:function:m.f", "content_hash": "h", "alive": True}
    fetch = _fake_fetch({("POST", "/api/v1/identity/resolve"): body})
    c = HttpLoomweaveIdentity(
        "http://localhost",
        fetch=fetch,
        hmac_key="s3cr3t",
        clock=lambda: 1_900_000_000,
        nonce_factory=lambda: "nonce-1",
    )

    assert c.resolve_locator("python:function:m.f") == body

    headers = fetch.calls[-1][3]
    expected = sign_loomweave_request(
        b"s3cr3t",
        "POST",
        "http://localhost/api/v1/identity/resolve",
        {"locator": "python:function:m.f"},
        timestamp=1_900_000_000,
        nonce="nonce-1",
    )
    assert headers == expected


def test_loomweave_hmac_key_from_env_prefers_loomweave_specific_key(monkeypatch):
    monkeypatch.setenv("LEGIS_HMAC_KEY", "general-secret")
    monkeypatch.setenv("LEGIS_LOOMWEAVE_HMAC_KEY", "loomweave-secret")

    assert loomweave_hmac_key_from_env() == b"loomweave-secret"


def test_resolve_locator_rejects_non_object_response():
    fetch = _fake_fetch({("POST", "/api/v1/identity/resolve"): []})
    with pytest.raises(LoomweaveError):
        HttpLoomweaveIdentity("http://localhost", fetch=fetch).resolve_locator("python:function:m.f")


def test_lineage_rejects_non_object_and_non_list_lineage():
    fetch = _fake_fetch({("GET", "/api/v1/identity/lineage/loomweave%3Aeid%3Aabc"): []})
    with pytest.raises(LoomweaveError):
        HttpLoomweaveIdentity("http://localhost", fetch=fetch).lineage("loomweave:eid:abc")

    fetch = _fake_fetch({("GET", "/api/v1/identity/lineage/loomweave%3Aeid%3Aabc"): {"lineage": "bad"}})
    with pytest.raises(LoomweaveError):
        HttpLoomweaveIdentity("http://localhost", fetch=fetch).lineage("loomweave:eid:abc")


def test_client_rejects_unsafe_base_urls():
    for url in ("file:///tmp/loomweave.json", "http://example.com", "not-a-url"):
        with pytest.raises(LoomweaveError):
            HttpLoomweaveIdentity(url)


def test_urllib_fetch_rejects_oversized_responses(monkeypatch):
    class Response:
        headers = {"Content-Type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size=-1):
            return b"{" + (b" " * 1_100_000)

    def fake_urlopen(req, timeout):
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(LoomweaveError, match="too large"):
        _urllib_fetch("GET", "http://localhost/api/v1/_capabilities", None)


def test_insecure_remote_http_warns_when_flag_bypasses_https(monkeypatch, caplog):
    # ID-SEI-1: the flag permits plaintext to a REMOTE host — which voids the SEI
    # response TLS custody seal — so it must warn loudly (it was silent before).
    monkeypatch.setenv("LEGIS_ALLOW_INSECURE_REMOTE_HTTP", "1")
    with caplog.at_level(logging.WARNING):
        HttpLoomweaveIdentity("http://remote.example:9000")
    assert any(
        "LEGIS_ALLOW_INSECURE_REMOTE_HTTP" in r.getMessage() for r in caplog.records
    )


def test_no_insecure_warning_for_loopback_or_https(monkeypatch, caplog):
    monkeypatch.setenv("LEGIS_ALLOW_INSECURE_REMOTE_HTTP", "1")
    with caplog.at_level(logging.WARNING):
        HttpLoomweaveIdentity("http://localhost:9000")   # loopback plaintext is fine
        HttpLoomweaveIdentity("https://remote.example")  # remote but TLS-protected
    assert caplog.records == []


def test_remote_http_without_flag_still_raises(monkeypatch):
    monkeypatch.delenv("LEGIS_ALLOW_INSECURE_REMOTE_HTTP", raising=False)
    with pytest.raises(LoomweaveError):
        HttpLoomweaveIdentity("http://remote.example")
