"""Tests for StdioMcpInvoke — the production stdio JSON-RPC transport.

Fault paths: every transport/parse fault must raise WarplineError (fail closed).
DoD gate: test_replays_a_REAL_captured_session exercises bytes from a real
warpline-mcp 1.2.0 session (see fixtures/PROVENANCE.md + warpline-mcp-live-session.jsonl).
"""
import pathlib
import sys
import textwrap

import pytest

from legis.warpline_preflight.client import StdioMcpInvoke, WarplineError


def _script(tmp_path, body):
    p = tmp_path / "fake.py"
    p.write_text(textwrap.dedent(body))
    return [sys.executable, str(p)]


_OK = '''
    import sys, json
    for line in sys.stdin:
        m = json.loads(line); mid = m.get("id")
        if m.get("method") == "initialize":
            print(json.dumps({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"f","version":"0"}}}), flush=True)
        elif m.get("method") == "tools/call":
            env = {"schema":"warpline.impact_radius.v1","ok":True,"query":m["params"]["arguments"],"data":{"affected":[{"sei":"x"}],"completeness":"FULL","staleness":{"commits_behind":0}},"warnings":[],"next_actions":{},"enrichment":{},"meta":{"local_only":True,"peer_side_effects":[]}}
            print(json.dumps({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":"{}"}],"structuredContent":env,"isError":False}}), flush=True)
'''


def test_round_trips_against_fake_server(tmp_path):
    env = StdioMcpInvoke(command=_script(tmp_path, _OK))("warpline_impact_radius_get", {"rev_range": "a..b"})
    assert env["data"]["affected"] == [{"sei": "x"}]


def test_replays_a_REAL_captured_session(tmp_path):
    """DoD GATE: this fixture is bytes captured from a live `warpline-mcp` session
    (see PROVENANCE). A green here means the real message order + result shape
    (structuredContent vs content[].text + protocolVersion) were exercised, not a
    legis-shaped assumption. If no live capture exists, this test FAILS (xfail is
    not allowed) and Task 2 is not done — escalate (see the gate note).

    PROVENANCE: captured from warpline-mcp 1.2.0 on 2026-06-26 in /home/john/legis.
    Exit-on-EOF: YES (rc=0). Interleaved I/O: NOT required (batch accepted).
    Real protocolVersion from server: "2025-03-26".
    Result shape: structuredContent (dict) present; notifications/initialized
    returns id:null error (valid JSON, id != 2 -> silently skipped by _read_jsonrpc_result).
    NOTE: warpline_impact_radius_get requires a "repo" arg; WarplineMcpClient (Task 1)
    does not yet supply it — flagged as a Task-1/Task-3 concern, not fixed here.
    """
    fixture = pathlib.Path(__file__).parent / "fixtures" / "warpline-mcp-live-session.jsonl"
    assert fixture.exists(), f"live session fixture missing: {fixture}"
    stub = tmp_path / "replay.py"
    stub.write_text(textwrap.dedent(f"""
        import sys
        sys.stdin.read()  # consume all stdin to EOF before responding
        with open({str(fixture)!r}) as fh:
            for line in fh:
                line = line.rstrip('\\n')
                if line:
                    print(line, flush=True)
    """))
    env = StdioMcpInvoke(command=[sys.executable, str(stub)])(
        "warpline_impact_radius_get", {"rev_range": "HEAD~1..HEAD", "repo": "/test"}
    )
    # assertions on known fields from the real captured envelope
    assert env["schema"] == "warpline.impact_radius.v1"
    assert env["ok"] is True
    assert env["data"]["completeness"] == "NO_SNAPSHOT"
    assert env["meta"]["local_only"] is True
    assert env["meta"]["peer_side_effects"] == []


@pytest.mark.parametrize("body,match", [
    ('import sys\n', "no JSON-RPC response"),                                 # empty stdout
    ('print("not json", flush=True)\n', "non-JSON line"),                     # non-JSON line
    ('import json;print(json.dumps({"jsonrpc":"2.0","id":2,"result":7}))\n', "result"),  # scalar result
    ('import json;print(json.dumps({"jsonrpc":"2.0","id":2,"result":{"isError":True,"content":[]}}))\n', "error result"),  # isError
    ('import json;print(json.dumps({"jsonrpc":"2.0","id":2,"error":{"code":-1,"message":"boom"}}))\n', "boom"),  # jsonrpc error
])
def test_fault_paths_all_raise_warpline_error(tmp_path, body, match):
    with pytest.raises(WarplineError, match=match):
        StdioMcpInvoke(command=_script(tmp_path, body))("warpline_impact_radius_get", {"rev_range": "a..b"})


def test_missing_executable_is_warpline_error(tmp_path):
    with pytest.raises(WarplineError):
        StdioMcpInvoke(command=[str(tmp_path / "nope")])("warpline_impact_radius_get", {"rev_range": "a..b"})


def test_empty_command_is_warpline_error():
    with pytest.raises(WarplineError, match="empty"):
        StdioMcpInvoke(command=[])("warpline_impact_radius_get", {"rev_range": "a..b"})


def test_timeout_is_warpline_error(tmp_path):
    with pytest.raises(WarplineError):
        StdioMcpInvoke(command=_script(tmp_path, "import time;time.sleep(5)\n"), timeout=0.3)(
            "warpline_impact_radius_get", {"rev_range": "a..b"}
        )


def test_oversize_stdout_is_warpline_error(tmp_path):
    body = 'import sys;sys.stdout.buffer.write(b"x"*2_000_000)\n'
    with pytest.raises(WarplineError, match="too large"):
        StdioMcpInvoke(command=_script(tmp_path, body))("warpline_impact_radius_get", {"rev_range": "a..b"})
