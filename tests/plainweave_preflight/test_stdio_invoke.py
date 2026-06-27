"""Tests for StdioMcpInvoke — the production stdio JSON-RPC transport.

Fault paths: every transport/parse fault must raise PlainweaveError (fail closed).
The total exception conversion here is what lets read_plainweave_preflight catch
ONLY PlainweaveError and still guarantee "never escapes as INTERNAL_ERROR".

NOTE: unlike the warpline transport test, there is no real captured plainweave-mcp
session fixture — a live capture is a flagged follow-up in a legis-rooted session
(the hub session's MCP wiring misroutes plainweave). These tests exercise the real
message order + result shape against a fake server, which is sufficient for the
transport contract; the live capture validates the end-to-end seam.
"""
import sys
import textwrap

import pytest

from legis.plainweave_preflight.client import StdioMcpInvoke, PlainweaveError

_PREFLIGHT_ENV = (
    '{"schema":"weft.plainweave.preflight_facts.v1","ok":true,'
    '"data":{"freshness":"partial","facts":[],'
    '"authority_boundary":{"local_only":true,"live_peer_calls":false,"governance_verdicts":false}},'
    '"warnings":[],"meta":{}}'
)


def _script(tmp_path, body):
    p = tmp_path / "fake.py"
    p.write_text(textwrap.dedent(body))
    return [sys.executable, str(p)]


_OK = f'''
    import sys, json
    for line in sys.stdin:
        m = json.loads(line); mid = m.get("id")
        if m.get("method") == "initialize":
            print(json.dumps({{"jsonrpc":"2.0","id":mid,"result":{{"protocolVersion":"2025-06-18","capabilities":{{}},"serverInfo":{{"name":"f","version":"0"}}}}}}), flush=True)
        elif m.get("method") == "tools/call":
            env = json.loads({_PREFLIGHT_ENV!r})
            print(json.dumps({{"jsonrpc":"2.0","id":mid,"result":{{"content":[{{"type":"text","text":"{{}}"}}],"structuredContent":env,"isError":False}}}}), flush=True)
'''


def test_round_trips_against_fake_server(tmp_path):
    env = StdioMcpInvoke(command=_script(tmp_path, _OK))(
        "plainweave_preflight_facts_get", {"scope_kind": "commit_range", "base": "a", "head": "b"}
    )
    assert env["schema"] == "weft.plainweave.preflight_facts.v1"
    assert env["data"]["facts"] == []
    assert env["data"]["authority_boundary"]["local_only"] is True


def test_content_text_fallback_parse(tmp_path):
    """When structuredContent is absent, StdioMcpInvoke must parse the envelope
    from content[0].text."""
    env_file = tmp_path / "envelope.json"
    env_file.write_text(_PREFLIGHT_ENV, encoding="utf-8")
    body = f'''
        import sys, json
        env_text = open({str(env_file)!r}, encoding="utf-8").read()
        for line in sys.stdin:
            m = json.loads(line); mid = m.get("id")
            if m.get("method") == "initialize":
                print(json.dumps({{"jsonrpc":"2.0","id":mid,"result":{{"protocolVersion":"2025-06-18","capabilities":{{}},"serverInfo":{{"name":"f","version":"0"}}}}}}), flush=True)
            elif m.get("method") == "tools/call":
                print(json.dumps({{"jsonrpc":"2.0","id":mid,"result":{{"content":[{{"type":"text","text":env_text}}],"isError":False}}}}), flush=True)
    '''
    env = StdioMcpInvoke(command=_script(tmp_path, body))(
        "plainweave_preflight_facts_get", {"scope_kind": "commit_range", "base": "a", "head": "b"}
    )
    assert env["schema"] == "weft.plainweave.preflight_facts.v1"
    assert env["data"]["freshness"] == "partial"


@pytest.mark.parametrize("body,match", [
    ('import sys\n', "no JSON-RPC response"),                                 # empty stdout
    ('print("not json", flush=True)\n', "non-JSON line"),                     # non-JSON line
    ('import json;print(json.dumps({"jsonrpc":"2.0","id":2,"result":7}))\n', "result"),  # scalar result
    ('import json;print(json.dumps({"jsonrpc":"2.0","id":2,"result":{"isError":True,"content":[]}}))\n', "error result"),  # isError
    ('import json;print(json.dumps({"jsonrpc":"2.0","id":2,"error":{"code":-1,"message":"boom"}}))\n', "boom"),  # jsonrpc error
])
def test_fault_paths_all_raise_plainweave_error(tmp_path, body, match):
    with pytest.raises(PlainweaveError, match=match):
        StdioMcpInvoke(command=_script(tmp_path, body))(
            "plainweave_preflight_facts_get", {"scope_kind": "commit_range", "base": "a", "head": "b"}
        )


def test_no_usable_envelope_is_plainweave_error(tmp_path):
    # result has neither structuredContent nor a content[].text block.
    body = (
        'import json,sys\n'
        'for line in sys.stdin:\n'
        '    m=json.loads(line); mid=m.get("id")\n'
        '    if m.get("method")=="tools/call":\n'
        '        print(json.dumps({"jsonrpc":"2.0","id":mid,"result":{"content":[],"isError":False}}), flush=True)\n'
    )
    with pytest.raises(PlainweaveError, match="no usable envelope"):
        StdioMcpInvoke(command=_script(tmp_path, body))(
            "plainweave_preflight_facts_get", {"scope_kind": "commit_range", "base": "a", "head": "b"}
        )


def test_missing_executable_is_plainweave_error(tmp_path):
    with pytest.raises(PlainweaveError):
        StdioMcpInvoke(command=[str(tmp_path / "nope")])(
            "plainweave_preflight_facts_get", {"scope_kind": "commit_range", "base": "a", "head": "b"}
        )


def test_empty_command_is_plainweave_error():
    with pytest.raises(PlainweaveError, match="empty"):
        StdioMcpInvoke(command=[])(
            "plainweave_preflight_facts_get", {"scope_kind": "commit_range", "base": "a", "head": "b"}
        )


def test_timeout_is_plainweave_error(tmp_path):
    with pytest.raises(PlainweaveError):
        StdioMcpInvoke(command=_script(tmp_path, "import time;time.sleep(5)\n"), timeout=0.3)(
            "plainweave_preflight_facts_get", {"scope_kind": "commit_range", "base": "a", "head": "b"}
        )


def test_oversize_stdout_is_plainweave_error(tmp_path):
    body = 'import sys;sys.stdout.buffer.write(b"x"*2_000_000)\n'
    with pytest.raises(PlainweaveError, match="too large"):
        StdioMcpInvoke(command=_script(tmp_path, body))(
            "plainweave_preflight_facts_get", {"scope_kind": "commit_range", "base": "a", "head": "b"}
        )
