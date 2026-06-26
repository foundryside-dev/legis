"""Live cross-impl Weft HMAC wire conformance: legis signer <-> loomweave verifier.

This is the genuinely uncovered half of the Loomweave SEI read-API transport seam.

What is ALREADY covered (and therefore NOT re-pinned here):

  * The SEI *semantics* (resolve / sei / lineage / capability response shapes,
    carry-vs-orphan behaviour) are frozen by ``tests/conformance/test_sei_oracle.py``
    against an in-process ``FakeLoomweave`` and the vendored §8 fixture. Those drive
    no HTTP and no HMAC.
  * legis's OWN HMAC formula is already pinned by
    ``tests/identity/test_loomweave_client.py::test_sign_loomweave_request_matches_loomweave_hmac_contract``
    and ``tests/test_weft_signing.py`` — both recompute the canonical message in
    Python and assert ``sign_loomweave_request`` reproduces it. That is a legis-side
    *drift detector*; it proves legis is internally consistent, NOT that legis agrees
    with loomweave's real verifier.

What is NOT covered anywhere, and is the seam this file freezes: that legis's REAL
``sign_loomweave_request`` produces a signature loomweave's REAL Rust verifier
(``component_hmac_hex`` / ``canonical_hmac_message`` in
``crates/loomweave-cli/src/http_read/auth.rs``) ACCEPTS, byte-for-byte. The verifier
helpers are ``pub(crate)`` — they cannot be called in-process from Python, and
re-implementing the format string in Python (a third copy) would be exactly the
tautology the conformance program forbids. So the only non-circular proof is to run
the real loomweave binary and let its verifier adjudicate a real legis signature.

Why a single accept/reject pair proves the WHOLE canonical message, not just the
HMAC primitive: the verifier hashes ``METHOD\npath?query\nsha256_hex(body)\nts\nnonce``
and HMACs it under the shared secret. If legis diverged on the method, the
path-and-query projection, the body canonicalization (compact, sorted, ascii-escaped
``weft_body_bytes``), the lowercase-hex SHA-256 of the body, the timestamp rendering,
the nonce, OR the HMAC itself, the reconstructed message would differ and the compare
would fail closed -> 401. A 200 (auth passed) is therefore byte-exact agreement across
the entire formula; a tampered signature -> 401 is the negative control.

The positive assertion is on the AUTH outcome (request admitted past the HMAC guard),
NOT on resolve semantics: an unknown locator legitimately returns ``{"alive": false}``
with HTTP 200, and re-pinning that body would re-enter the SEI oracle's territory.

Gating: this spins up a real ``loomweave serve`` and is opt-in. It runs only when
``LEGIS_LIVE_LOOMWEAVE=1`` AND a loomweave binary is discoverable; otherwise it
skips clean (no marker — the suite registers none, and ``filterwarnings=["error"]``
would turn an unknown marker into a collection error). Operators enable it with
``LEGIS_LIVE_LOOMWEAVE=1`` (optionally ``LEGIS_LOOMWEAVE_BIN=/path/to/loomweave``).
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from legis.identity.loomweave_client import (
    HttpLoomweaveIdentity,
    sign_loomweave_request,
)

# ---------------------------------------------------------------------------
# Gating: opt-in env + a discoverable loomweave binary.
# ---------------------------------------------------------------------------

_SECRET = "weft-hmac-wire-conformance-secret"
_IDENTITY_ENV = "WEFT_LIVE_WIRE_IDENTITY_SECRET"
_READY_TIMEOUT_S = 20.0


def _discover_loomweave_bin() -> str | None:
    explicit = os.environ.get("LEGIS_LOOMWEAVE_BIN")
    if explicit and Path(explicit).is_file() and os.access(explicit, os.X_OK):
        return explicit
    candidates = [
        Path(__file__).resolve().parents[3] / "loomweave" / "target" / "release" / "loomweave",
        Path(__file__).resolve().parents[3] / "loomweave" / "target" / "debug" / "loomweave",
    ]
    for cand in candidates:
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    found = shutil.which("loomweave")
    return found


_LIVE_ENABLED = os.environ.get("LEGIS_LIVE_LOOMWEAVE") == "1"
_LOOMWEAVE_BIN = _discover_loomweave_bin()

# Gates only the two LIVE tests (those that spin up the real binary). The Layer-2
# source recheck below has no live/binary dependency and runs in the default suite
# (it carries its own skip-clean when the loomweave source is not present).
_requires_live_loomweave = pytest.mark.skipif(
    not (_LIVE_ENABLED and _LOOMWEAVE_BIN),
    reason=(
        "live loomweave HMAC wire conformance is opt-in: set LEGIS_LIVE_LOOMWEAVE=1 "
        "and provide a loomweave binary (LEGIS_LOOMWEAVE_BIN or a built "
        "../loomweave/target/{release,debug}/loomweave)"
    ),
)


def _free_loopback_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _http_status(url: str, *, method: str, body: bytes | None,
                 headers: dict[str, str]) -> int:
    """Send a raw request and return the HTTP status (no legis decode layer)."""
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    for name, value in headers.items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:  # noqa: S310 (loopback test server)
            resp.read()
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        exc.read()
        exc.close()
        return int(exc.code)


@pytest.fixture
def live_loomweave(tmp_path: Path) -> Iterator[str]:
    """Stand up a real ``loomweave serve`` with HMAC identity on loopback.

    Yields the base URL. Tears down by terminating ONLY this fixture's own child
    process (the host runs other sessions' ``loomweave serve`` instances — a
    pattern-kill would destroy their work) and closing every owned resource so
    ``filterwarnings=["error"]`` does not trip on a leaked pipe.
    """
    assert _LOOMWEAVE_BIN is not None  # narrowed by the module skipif
    project = tmp_path / "proj"
    project.mkdir()

    # `loomweave install` creates .weft/loomweave/loomweave.db (the serve target).
    subprocess.run(
        [_LOOMWEAVE_BIN, "install", "--path", str(project)],
        check=True, capture_output=True, text=True,
    )

    port = _free_loopback_port()
    bind = f"127.0.0.1:{port}"
    base_url = f"http://{bind}"
    # The HMAC secret is read from the env var NAMED by `identity_token_env`
    # (loomweave http_read.rs resolution), exactly the serve.rs HMAC recipe.
    (project / "loomweave.yaml").write_text(
        "version: 1\n"
        "serve:\n"
        "  http:\n"
        "    enabled: true\n"
        f'    bind: "{bind}"\n'
        f'    identity_token_env: "{_IDENTITY_ENV}"\n',
        encoding="utf-8",
    )

    env = {**os.environ, _IDENTITY_ENV: _SECRET}
    # `serve` runs an MCP stdio loop; a closed stdin (DEVNULL) makes it exit and
    # tears the HTTP thread down with it, so we hold an open stdin pipe.
    proc = subprocess.Popen(
        [_LOOMWEAVE_BIN, "serve", "--path", str(project)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        # Readiness: poll the UNPROTECTED capabilities route until it answers.
        deadline = time.monotonic() + _READY_TIMEOUT_S
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(
                    f"loomweave serve exited early with code {proc.returncode}"
                )
            try:
                status = _http_status(
                    f"{base_url}/api/v1/_capabilities",
                    method="GET", body=None, headers={},
                )
            except urllib.error.URLError:
                time.sleep(0.1)
                continue
            if status == 200:
                ready = True
                break
            time.sleep(0.1)
        if not ready:
            raise RuntimeError("loomweave HTTP read API did not become ready in time")
        yield base_url
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        proc.terminate()
        try:
            proc.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10.0)


@_requires_live_loomweave
def test_real_legis_signature_is_accepted_by_real_loomweave_verifier(
    live_loomweave: str,
) -> None:
    """POSITIVE: legis's REAL client, signing with the REAL ``sign_loomweave_request``
    under the shared secret, is admitted past loomweave's REAL HMAC guard on a
    PROTECTED route (``POST /api/v1/identity/resolve``).

    legis's ``_urllib_fetch`` raises ``LoomweaveError`` on any non-2xx (a 401 from a
    rejected signature included), so a clean dict return is proof the request passed
    the HMAC verifier. We assert on auth admission, not resolve semantics: an unknown
    locator's ``{"alive": false}`` is a perfectly valid admitted response.
    """
    client = HttpLoomweaveIdentity(live_loomweave, hmac_key=_SECRET)
    # An arbitrary locator that does not exist in the freshly-installed (un-analyzed)
    # project: the route still runs auth first, then answers alive=false at 200.
    resolved = client.resolve_locator("python:function:nonexistent.module.fn")
    # The load-bearing fact is that no LoomweaveError was raised: ``_urllib_fetch``
    # raises on any non-2xx (a 401 from a rejected signature included), so a clean
    # dict return is proof the request was admitted past the HMAC verifier. We do NOT
    # assert on the resolve verdict itself (alive/sei/...) — the SEI oracle owns those
    # semantics, and coupling the auth proof to them would re-pin covered behaviour.
    assert isinstance(resolved, dict)


@_requires_live_loomweave
def test_tampered_legis_signature_is_rejected_by_real_loomweave_verifier(
    live_loomweave: str,
) -> None:
    """NEGATIVE control: take a REAL legis signature and flip one hex character of the
    HMAC; the REAL verifier must reject it with 401 UNAUTHENTICATED.

    This proves the positive result is not vacuous (the route really is guarded and
    really checks the signature), and that the agreement is byte-exact: a single-bit
    perturbation of the otherwise-correct signature fails closed.
    """
    url = f"{live_loomweave}/api/v1/identity/resolve"
    body = {"locator": "python:function:nonexistent.module.fn"}
    body_bytes = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    # A fresh timestamp + nonce so the rejection is attributable to the bad signature,
    # not the freshness window or replay cache.
    headers = sign_loomweave_request(
        _SECRET.encode("utf-8"),
        "POST",
        url,
        body,
        timestamp=int(time.time()),
        nonce=uuid.uuid4().hex,
    )
    component = headers["X-Weft-Component"]
    last = component[-1]
    headers["X-Weft-Component"] = component[:-1] + ("0" if last != "0" else "1")

    status = _http_status(url, method="POST", body=body_bytes, headers=headers)
    assert status == 401, f"tampered signature should be rejected with 401, got {status}"


def test_loomweave_canonical_hmac_template_is_unchanged() -> None:
    """Layer-2 (skip-clean) source recheck: tie the agreement to loomweave's REAL
    verifier source, not just to a running binary.

    Reads loomweave's ``http_read/auth.rs`` and asserts ``canonical_hmac_message``
    still builds ``METHOD\\npath?query\\nsha256_hex(body)\\nts\\nnonce`` in that order.
    If loomweave changes the canonical message, this reds with a clear pointer even
    when the live binary is not being run. Skips clean when the source is not present.
    """
    auth_rs = (
        Path(__file__).resolve().parents[3]
        / "loomweave" / "crates" / "loomweave-cli" / "src" / "http_read" / "auth.rs"
    )
    if not auth_rs.is_file():
        pytest.skip("loomweave auth.rs source not present; skip the formula recheck")
    src = auth_rs.read_text(encoding="utf-8")
    assert "fn canonical_hmac_message" in src, (
        "loomweave canonical_hmac_message verifier helper was renamed or removed"
    )
    # Anchor on the format! literal itself, then read its argument list (everything
    # up to the closing paren of the format! call). This scopes the order check to
    # the message construction and excludes the function signature's param order.
    fmt_literal = '"{}\\n{}\\n{}\\n{}\\n{}"'
    assert fmt_literal in src, (
        "loomweave canonical_hmac_message format string changed; the legis signer's "
        "5-field message layout may no longer agree with the verifier"
    )
    # Scope to the canonical_hmac_message function body: from the format! literal up
    # to the next top-level `fn ` (the inner expression has nested parens, so slicing
    # to "the first )" would truncate `Sha256::digest(body)`).
    after_literal = src.split(fmt_literal, 1)[1]
    fmt_args = after_literal.split("\nfn ", 1)[0].split("\npub(crate) fn ", 1)[0]
    # The body field is the lowercase hex of the SHA-256 of the raw body bytes.
    assert "hex_lower(&Sha256::digest(body))" in fmt_args, (
        "loomweave no longer hashes the body as lowercase-hex SHA-256 inside the "
        "canonical message; the legis signer's body_hash step may have diverged"
    )
    # Argument order inside the format! call: method, path_and_query,
    # <hex sha256 of body>, timestamp, nonce.
    order = ["method", "path_and_query", "Sha256::digest(body)", "timestamp", "nonce"]
    positions = [fmt_args.index(tok) for tok in order]
    assert positions == sorted(positions), (
        "loomweave canonical_hmac_message argument order changed; the legis signer's "
        f"field order may no longer agree with the verifier (positions={positions})"
    )
