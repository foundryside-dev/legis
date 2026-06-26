# Warpline Preflight: MCP-Stdio Transport + Real Envelope — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace legis's phantom-HTTP warpline preflight client with a minimal stdio JSON-RPC client that consumes the **extant** `warpline_impact_radius_get` / `warpline_reverify_worklist_get` MCP tools with `rev_range`, parses warpline's **real frozen envelope** (`warpline.impact_radius.v1` / `warpline.reverify_worklist.v1`), verifies the GV-LG-3 `meta` invariant, fails SAFE on every fault, and keeps the advisory boundary byte-identical — so the sanctioned SEAM 4 §4A preflight seam actually works against real warpline (legis-a53d92507d). warpline reimplements nothing; legis conforms to what warpline already serves.

**Architecture:** Today `HttpWarplineClient` (`src/legis/warpline_preflight/client.py`) issues `GET {WARPLINE_API_URL}/api/impact-radius` over `urllib` — a wire **warpline never served** (it has only MCP + CLI). The hub interface-lock SEAM 4 §4A pins the seam to "*same wire shape as `warpline_impact_radius_get`*" (the envelope), and **GV-LG-3** requires legis to read `meta.local_only`/`meta.peer_side_effects` off that envelope (the flat shape has no `meta`). So the transport becomes **MCP-stdio** (owner-confirmed 2026-06-26): a subprocess speaks JSON-RPC over stdio to `warpline-mcp`, calls one tool per verb with `rev_range="<base>..<head>"`, and returns the parsed envelope. The fix preserves the seams that are CORRECT: the `WarplineClient` Protocol (`impact_radius`/`reverify_worklist` → dict), the injectable-transport pattern (today `fetch`; now an injectable `invoke`), and `read_warpline_preflight`'s fail-safe discipline (`service/preflight.py`: `None`/`WarplineError` → `unavailable`, never an empty affected-set).

**Threat model shift (HTTP → local process):** the HTTP SSRF / redirect / TLS surface (`_validate_base_url`, `_is_loopback`, `_open_no_redirect`, `_NoRedirectHandler`, and the filigree-clone test) is **moot** and is removed. The new surface is local-process: (1) **no shell, list-argv** — `rev_range` travels as a JSON-RPC *param*, never as a CLI argument, so `shell=False` + a list `argv` makes argument/shell injection structurally impossible (note: `WARPLINE_MCP_CMD="warpline-mcp"` IS an implicit `PATH` lookup — `shell=False` eliminates *shell* injection, not PATH ambiguity; **recommend an absolute path**, and reject an empty command); (2) **output bound** — `subprocess.run` buffers stdout, so the size check is **post-capture + timeout-bounded** (a true *incremental* read bound requires the Popen variant — see Task 2's escalation note; the cap is on **bytes**, `text=False`); (3) **timeout** — bound the child (10s) and let `TimeoutExpired` → `WarplineError`; (4) **isolation** — a missing exe / crash / non-zero exit / garbage / oversize / timeout is a `WarplineError` → `unavailable`, never an escape, and the error carries the child's `returncode` + truncated `stderr` for operator diagnosis.

**Tech Stack:** Python 3.12, stdlib `subprocess` + `json` (NO new dependency — legis's sibling-client ethos), `uv`, pytest.

**Prerequisites:**
- Work on a feature branch / worktree, NOT `main` (e.g. `git switch -c fix/warpline-preflight-mcp`). The merge + any 1.3.0 publish is owner-gated; **do NOT release 1.3.0 with the old mis-frozen seam**.
- `uv sync --dev` already run.
- **A live `warpline-mcp` is REQUIRED for Task 2's DoD gate** (capture one real session transcript — see Task 2). Confirm it is runnable; if it is not reachable, Task 2 cannot complete its gate and you escalate before Task 3 (do not ship an unverified transport).
- Read context (grounded): `src/legis/warpline_preflight/client.py` (the `WarplineClient` Protocol 34-37, `WarplineError` 27, `HttpWarplineClient` 118-143, `MAX_RESPONSE_BYTES` 31, the `fetch` seam at client.py:76 doing the real incremental `resp.read(MAX_RESPONSE_BYTES+1)` bound the new path loosens — call that out), `src/legis/service/preflight.py` (the fail-safe pass-through — KEEP; calls BOTH verbs at 27-28), `src/legis/mcp.py:231-243` (the `WARPLINE_API_URL` wiring) + `:893-905` (preflight output schema — bare `{"type":"object"}`, no downstream ripple), `tests/warpline_preflight/test_client.py` (HTTP-specific; rewritten), `tests/warpline_preflight/fixtures/{warpline-preflight-golden.json,PROVENANCE.md}` + `test_warpline_preflight_oracle.py` (the mis-frozen flat golden + inverted obligation + `GOLDEN_BLOB_SHA` byte-pin at oracle:49 + the deleted-symbol imports `HttpWarplineClient`/`_decode_json_response`), `tests/mcp/test_warpline_advisory_boundary.py:74-99` (`_HostileWarpline` + byte-identity test) **and `:143-174`** (the structural boundary test derived from `_TOOL_HANDLERS` — a load-bearing invariant to PRESERVE), `tests/mcp/test_output_schema_conformance.py:635-639` (flat stub), `tests/mcp/test_server.py:3388,3397` (an `HttpWarplineClient` import + an `isinstance` assertion that must become `WarplineMcpClient`).

**warpline's REAL surface (authoritative — verified vs warpline source 2026-06-26; treat as the contract):**
- MCP tools (stdio, `warpline-mcp`): `warpline_impact_radius_get` (shim `blast_radius`) → `warpline.impact_radius.v1`; `warpline_reverify_worklist_get` (shim `reverify`) → `warpline.reverify_worklist.v1`. Both accept `arguments.rev_range="<base>..<head>"`.
- Envelope: `{schema, ok:true, query, data, warnings, next_actions, enrichment, meta}`. impact: `data.affected` (list); reverify: `data.items` (NOT `entries`). **No top-level `count`.** `data.completeness` + `data.staleness` mandatory honesty fields. `meta.local_only` + `meta.peer_side_effects` = the GV-LG-3 invariant.

**Scope fence:** Do NOT change a federation contract (CONFORMS to the already-frozen SEAM 4 §4A). Do NOT let warpline output reach a governance verdict path (advisory-only). Do NOT freeze a `reverify_worklist` dependency before wardline rules (§2A names filigree as the reverify consumer; reverify stays keep-or-drop). Do NOT touch `service/preflight.py`'s fail-safe discipline. Do NOT add a dependency (unless the Task-2 escalation explicitly approves the `mcp` SDK).

---

### Task 1: domain client `WarplineMcpClient` over an injectable `invoke` seam (envelope parse + GV-LG-3 + degraded-floor, all fail-closed)

**Files:** Rewrite `src/legis/warpline_preflight/client.py` (keep `WarplineClient` Protocol + `WarplineError` + `MAX_RESPONSE_BYTES`; replace `HttpWarplineClient` and all HTTP helpers with `WarplineMcpClient` + an `Invoke` seam; the real stdio invoker is Task 2). Rewrite `tests/warpline_preflight/test_client.py` (drop every HTTP test incl. the filigree-clone test; new tests inject a fake `invoke`).

**Step 1: failing tests** (offline — inject a recorder `invoke`). Include the fault paths so guardrail-(b) is TESTED, not just asserted:

```python
import pytest
from legis.warpline_preflight.client import WarplineMcpClient, WarplineClient, WarplineError

_VALID_META = {"local_only": True, "peer_side_effects": []}
_KEEP = object()   # sentinel: "use the valid default meta" — DISTINCT from None (None IS a test case)
def _env(schema, data_key, items, *, meta=_KEEP, completeness="FULL"):
    data = {data_key: items, "staleness": {"commits_behind": 0}}
    if completeness is not None:
        data["completeness"] = completeness
    return {"schema": schema, "ok": True, "query": {"rev_range": "aaa..bbb"}, "data": data,
            "warnings": [], "next_actions": {}, "enrichment": {"sei": "present"},
            "meta": dict(_VALID_META) if meta is _KEEP else meta}   # meta=None -> {"meta": None}, a real case

def _recorder(responses):
    calls = []
    def invoke(tool, arguments):
        calls.append((tool, arguments)); return responses.pop(0)
    invoke.calls = calls; return invoke

def test_protocol_is_runtime_checkable():
    assert isinstance(WarplineMcpClient(invoke=_recorder([{}])), WarplineClient)

def test_impact_radius_calls_tool_with_rev_range_and_passes_envelope_through():
    e = _env("warpline.impact_radius.v1", "affected", [{"sei": "loomweave:eid:" + "a"*32}])
    inv = _recorder([e]); out = WarplineMcpClient(invoke=inv).impact_radius("aaa", "bbb")
    assert out == e
    assert inv.calls[0] == ("warpline_impact_radius_get", {"rev_range": "aaa..bbb"})

def test_reverify_calls_reverify_tool():
    e = _env("warpline.reverify_worklist.v1", "items", [])
    inv = _recorder([e]); WarplineMcpClient(invoke=inv).reverify_worklist("a", "b")
    assert inv.calls[0][0] == "warpline_reverify_worklist_get"

@pytest.mark.parametrize("bad", [["not", "dict"], "str", 7, None])
def test_non_dict_envelope_is_warpline_error(bad):
    with pytest.raises(WarplineError):
        WarplineMcpClient(invoke=_recorder([bad])).impact_radius("a", "b")

def test_wrong_schema_or_not_ok_is_warpline_error():
    wrong = _env("warpline.reverify_worklist.v1", "items", [])  # wrong schema for impact
    with pytest.raises(WarplineError, match="schema"):
        WarplineMcpClient(invoke=_recorder([wrong])).impact_radius("a", "b")
    notok = _env("warpline.impact_radius.v1", "affected", []); notok["ok"] = False
    with pytest.raises(WarplineError, match="ok"):
        WarplineMcpClient(invoke=_recorder([notok])).impact_radius("a", "b")

def test_gv_lg_3_hostile_or_malformed_meta_is_refused_fail_closed():
    e = _env("warpline.impact_radius.v1", "affected", []); e["meta"] = {"local_only": True, "peer_side_effects": ["did_a_thing"]}
    with pytest.raises(WarplineError, match="side effect"):
        WarplineMcpClient(invoke=_recorder([e])).impact_radius("a", "b")
    for bad_meta in ({"local_only": False, "peer_side_effects": []}, {"peer_side_effects": []}, "not-a-dict", None, 5):
        em = _env("warpline.impact_radius.v1", "affected", [], meta=bad_meta)
        with pytest.raises(WarplineError):   # non-dict / missing / False local_only all refuse
            WarplineMcpClient(invoke=_recorder([em])).impact_radius("a", "b")

def test_degraded_envelope_missing_completeness_is_warpline_error():
    e = _env("warpline.impact_radius.v1", "affected", [], completeness=None)  # completeness omitted
    with pytest.raises(WarplineError, match="completeness"):
        WarplineMcpClient(invoke=_recorder([e])).impact_radius("a", "b")
```

**Step 2: RED** (`WarplineMcpClient` missing). **Step 3: implement.** Delete `HttpWarplineClient`, `_urllib_fetch`, `_open_no_redirect`, `_NoRedirectHandler`, `_decode_json_response`, `_is_loopback`, `_validate_base_url`, and the `urllib`/`http.client`/`ipaddress` imports. Keep `WarplineError`, `MAX_RESPONSE_BYTES`, the Protocol. Add:

```python
Invoke = Callable[[str, "dict[str, Any]"], "Any"]   # returns the parsed tool result (validated below)
_IMPACT = ("warpline.impact_radius.v1", "warpline_impact_radius_get")
_REVERIFY = ("warpline.reverify_worklist.v1", "warpline_reverify_worklist_get")

class WarplineMcpClient:
    """Consume warpline's EXTANT MCP tools (advisory preflight). Pass the frozen
    envelope through verbatim (the bare-object MCP output schema makes pass-through
    lossless). Advisory-ONLY; every contract fault fails CLOSED -> WarplineError."""
    def __init__(self, *, invoke: "Invoke") -> None:
        self._invoke = invoke
    def impact_radius(self, base: str, head: str) -> dict[str, Any]:
        return self._call(*_IMPACT, base, head)
    def reverify_worklist(self, base: str, head: str) -> dict[str, Any]:
        return self._call(*_REVERIFY, base, head)
    def _call(self, schema: str, tool: str, base: str, head: str) -> dict[str, Any]:
        env = self._invoke(tool, {"rev_range": f"{base}..{head}"})
        if not isinstance(env, dict):
            raise WarplineError(f"{tool} returned {type(env).__name__}, expected an envelope object")
        if env.get("schema") != schema:
            raise WarplineError(f"{tool} returned schema {env.get('schema')!r}, expected {schema!r}")
        if env.get("ok") is not True:
            raise WarplineError(f"{tool} envelope is not ok=true: {env.get('ok')!r}")
        meta = env.get("meta")
        if not isinstance(meta, dict):                       # malformed meta fails closed (GV-LG-3 input)
            raise WarplineError(f"{tool} envelope meta is {type(meta).__name__}, expected an object")
        if meta.get("local_only") is not True:
            raise WarplineError(f"{tool} meta.local_only is not true: {meta.get('local_only')!r}")
        if meta.get("peer_side_effects"):
            raise WarplineError(f"{tool} claims a peer side effect (GV-LG-3): {meta.get('peer_side_effects')!r}")
        data = env.get("data")
        if not isinstance(data, dict) or "completeness" not in data:   # degraded -> unavailable, not bare empty 'checked'
            raise WarplineError(f"{tool} envelope data is missing the mandatory 'completeness' field")
        return env
```

**Why these checks:** `isinstance(meta, dict)` closes the non-dict-meta escape (a truthy non-dict would otherwise `AttributeError` past the GV-LG-3 gate). Requiring `data.completeness` means a *degraded* warpline degrades to `unavailable` rather than a bare empty `checked` (rank-8 honesty floor; `staleness` is surfaced via pass-through). Pass-through keeps `service/preflight.py` and the bare-object output schema unchanged. `impact_radius`/`reverify_worklist` stay independent so reverify is keep-or-drop.

**Step 4: GREEN. Step 5: commit.** **DoD:** parses `data.affected`/`data.items` via pass-through; schema/ok/meta(incl. non-dict)/completeness all fail closed to `WarplineError`; HTTP code + filigree-clone test deleted; Protocol/Error/cap preserved; the fault tests above are GREEN; committed.

---

### Task 2: production stdio JSON-RPC invoker (`StdioMcpInvoke`) — hardened fail-safe + a LIVE-capture DoD gate

**Files:** Modify `client.py` (add `StdioMcpInvoke` + `_read_jsonrpc_result`). Test `tests/warpline_preflight/test_stdio_invoke.py` (new).

**Step 1: failing tests** — drive the real subprocess+stdio path against tiny fake `warpline-mcp` stub scripts in `tmp_path`, AND (DoD gate) against a captured **live** transcript. Every fault asserts `WarplineError`:

```python
import sys, json, textwrap, pytest
from legis.warpline_preflight.client import StdioMcpInvoke, WarplineError

def _script(tmp_path, body):
    p = tmp_path / "fake.py"; p.write_text(textwrap.dedent(body)); return [sys.executable, str(p)]

_OK = '''
    import sys, json
    for line in sys.stdin:
        m = json.loads(line); mid = m.get("id")
        if m.get("method") == "initialize":
            print(json.dumps({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"f","version":"0"}}}), flush=True)
        elif m.get("method") == "tools/call":
            env = {"schema":"warpline.impact_radius.v1","ok":True,"query":m["params"]["arguments"],"data":{"affected":[{"sei":"x"}],"completeness":"FULL","staleness":{"commits_behind":0}},"warnings":[],"next_actions":{},"enrichment":{},"meta":{"local_only":True,"peer_side_effects":[]}}
            print(json.dumps({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":json.dumps(env)}],"structuredContent":env,"isError":False}}), flush=True)
'''

def test_round_trips_against_fake_server(tmp_path):
    env = StdioMcpInvoke(command=_script(tmp_path, _OK))("warpline_impact_radius_get", {"rev_range": "a..b"})
    assert env["data"]["affected"] == [{"sei": "x"}]

def test_replays_a_REAL_captured_session(tmp_path):
    """DoD GATE: this fixture is bytes captured from a live `warpline-mcp` session
    (see PROVENANCE). A green here means the real message order + result shape
    (structuredContent vs content[].text + protocolVersion) were exercised, not a
    legis-shaped assumption. If no live capture exists, this test FAILS (xfail is
    not allowed) and Task 2 is not done — escalate (see the gate note)."""
    # Replace this body with bytes captured from a REAL warpline-mcp session.
    # Until then it FAILS (not passes, not xfails) so the gate cannot be skipped:
    pytest.fail("Wire a REAL captured warpline-mcp transcript here — Task 2 HARD DoD GATE; do NOT skip/xfail. See the gate note below.")

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
        StdioMcpInvoke(command=_script(tmp_path, "import time;time.sleep(5)\n"), timeout=0.3)("warpline_impact_radius_get", {"rev_range": "a..b"})

def test_oversize_stdout_is_warpline_error(tmp_path):
    body = 'import sys;sys.stdout.buffer.write(b"x"*2_000_000)\n'
    with pytest.raises(WarplineError, match="too large"):
        StdioMcpInvoke(command=_script(tmp_path, body))("warpline_impact_radius_get", {"rev_range": "a..b"})
```

**Step 2: RED. Step 3: implement** — list-argv, no shell, `text=False` (so the cap is a BYTE count), empty-argv rejected, the ENTIRE post-spawn parse wrapped so any fault → `WarplineError`, and `stderr`/`returncode` surfaced:

```python
import subprocess

def _read_jsonrpc_result(stdout_text: str, response_id: int) -> dict:
    for line in stdout_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError as exc:
            raise WarplineError(f"warpline-mcp emitted a non-JSON line: {exc}") from exc
        if isinstance(msg, dict) and msg.get("id") == response_id:
            if "error" in msg:
                raise WarplineError(f"warpline-mcp returned a JSON-RPC error: {msg['error']}")
            result = msg.get("result")
            if not isinstance(result, dict):
                raise WarplineError(f"warpline-mcp result is {type(result).__name__}, expected an object")
            return result
    raise WarplineError(f"warpline-mcp produced no JSON-RPC response for id={response_id}")

class StdioMcpInvoke:
    """Production Invoke: a stdio JSON-RPC call to warpline-mcp. Fail-safe: EVERY
    fault -> WarplineError. shell=False + list argv (rev_range is a JSON param, never
    an argv token); explicit command (absolute path recommended; empty rejected);
    text=False byte-bounded stdout (post-capture; see the cap note); 10s timeout."""
    def __init__(self, *, command: list[str], timeout: float = 10.0) -> None:
        self._command = command
        self._timeout = timeout
    def __call__(self, tool: str, arguments: dict) -> dict:
        if not self._command:
            raise WarplineError("warpline-mcp command is empty (WARPLINE_MCP_CMD blank?)")
        msgs = (
            {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"legis","version":"1"}}},
            {"jsonrpc":"2.0","method":"notifications/initialized"},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool,"arguments":arguments}},
        )
        stdin = ("".join(json.dumps(m) + "\n" for m in msgs)).encode("utf-8")
        try:
            proc = subprocess.run(self._command, input=stdin, capture_output=True,
                                  timeout=self._timeout, shell=False, check=False)  # text=False -> bytes
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise WarplineError(f"warpline-mcp spawn/timeout failed: {exc}") from exc
        if len(proc.stdout) > MAX_RESPONSE_BYTES:
            raise WarplineError("warpline-mcp response too large")
        err = (proc.stderr or b"")[:400].decode("utf-8", "replace")
        try:
            result = _read_jsonrpc_result(proc.stdout.decode("utf-8", "replace"), response_id=2)
            if result.get("isError"):
                raise WarplineError(f"warpline tool {tool} returned an error result (rc={proc.returncode}, stderr={err!r})")
            sc = result.get("structuredContent")
            if isinstance(sc, dict):
                return sc
            for block in result.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "text":
                    return json.loads(block["text"])
            raise WarplineError(f"warpline tool {tool} result had no usable envelope (rc={proc.returncode}, stderr={err!r})")
        except WarplineError:
            raise
        except Exception as exc:   # ANY parse fault fails closed
            raise WarplineError(f"warpline tool {tool} result parse failed: {exc} (rc={proc.returncode}, stderr={err!r})") from exc
```

> **HARD DoD GATE (rank-3) — verify against a LIVE `warpline-mcp` before this task is done.** Capture one real session: send the three messages above to a real `warpline-mcp`, save its stdout transcript, and wire it into `test_replays_a_REAL_captured_session` (and into the golden capture for Task 4). Confirm: (a) the server **exits on stdin-EOF** (else `subprocess.run` blocks to timeout on every call); (b) it does **not** require interleaved I/O (read the `initialize` response before the client sends `tools/call`); (c) the real `protocolVersion`; (d) result shape (`structuredContent` vs `content[0].text`). **If (a) or (b) fails, STOP and escalate to the owner the `subprocess.run` → `Popen` (interleaved read-loop + true incremental byte bound) vs `mcp`-SDK-dependency decision BEFORE Task 3 — do not ship an unverified/flaky transport.** The Popen variant also delivers the real incremental read bound that the post-capture `subprocess.run` size check only approximates (the HTTP path's `resp.read(MAX_RESPONSE_BYTES+1)` was a true bound — this loosens it within the 10s window; the oversize test asserts the post-capture guard still fails closed).

**Step 4: GREEN (fake + live replay). Step 5: commit.** **DoD:** the live-capture replay test is GREEN (or the escalation branch was taken); all fault variants raise `WarplineError`; no shell, list argv, empty-argv rejected, `text=False` byte cap, timeout, `stderr`/`returncode` in messages; committed.

---

### Task 3: rewire `mcp.py` — `WARPLINE_MCP_CMD` config + construction + fail-safe

**Files:** Modify `src/legis/mcp.py:231-243`; update `tests/mcp/test_server.py:3388,3397` (the `HttpWarplineClient` import + the `isinstance(..., HttpWarplineClient)` assertion → `WarplineMcpClient`).

Replace the `WARPLINE_API_URL` block (it's the wrong config for a non-HTTP transport):
```python
    warpline = None
    warpline_cmd = os.environ.get("WARPLINE_MCP_CMD")
    if warpline_cmd:
        import shlex
        from legis.warpline_preflight.client import StdioMcpInvoke, WarplineError, WarplineMcpClient
        try:
            argv = shlex.split(warpline_cmd)
            if not argv:
                raise WarplineError("WARPLINE_MCP_CMD is blank")
            warpline = WarplineMcpClient(invoke=StdioMcpInvoke(command=argv), repo=_legis_repo_root())
        except (WarplineError, ValueError) as exc:
            logging.getLogger(__name__).warning(
                "WARPLINE_MCP_CMD is set but invalid (%s); warpline advisory context "
                "disabled (governance unaffected).", exc)
            warpline = None
```
**(DISCOVERED at Task 2 — the live capture caught this; REQUIRED) Thread the `repo` argument.** Real `warpline_impact_radius_get` / `warpline_reverify_worklist_get` REQUIRE a `"repo"` argument (a non-empty repo path; without it warpline returns JSON-RPC `-32602 invalid params` → the client fail-safes to `WarplineError` → `unavailable`, i.e. the seam is dead-on-arrival again, just a different reason than the old HTTP one). So: (1) give `WarplineMcpClient.__init__` a `repo: str` param and have `_call` send `arguments={"repo": self._repo, "rev_range": f"{base}..{head}"}` (the live envelope confirms warpline echoes `query.repo` and fills `depth`/etc. server-side defaults). (2) Update the Task-1 `test_client.py` assertions that check `args == {"rev_range": ...}` to expect the `repo` key too. (3) In `mcp.py`, supply the repo value from **legis's existing repo-root resolution** — find it (`config.py` / the git surface / the runtime root; the captured session used `/home/john/legis`). Do NOT invent a config knob if legis already resolves its repo root — reuse it; replace the `_legis_repo_root()` placeholder above with the real resolver. This is the load-bearing reason the seam works end-to-end against real warpline.

Note: construction only stores the command; a bad command's failure surfaces at *call* time (caught by `read_warpline_preflight` → `unavailable`). The empty-`shlex.split` case is rejected up front. **Tests:** unset `WARPLINE_MCP_CMD` → `warpline is None` → preflight `unavailable`; blank/`"   "` → fail-safe `None`. Grep `tests/` for `WARPLINE_API_URL` and update; fix `test_server.py:3388/3397` (`HttpWarplineClient` → `WarplineMcpClient`). **Commit.** **DoD:** runtime builds `WarplineMcpClient(repo=...)` from `WARPLINE_MCP_CMD`; the `repo` arg is sent (sourced from legis's repo-root resolver) and the Task-1 tests assert it; unset/blank/invalid → `None` (fail-safe); no `WARPLINE_API_URL`/`HttpWarplineClient` in `src/`; `test_server.py` symbols updated; full `mypy src/legis` + `pytest` collection now succeed (the Task-1 cross-task breaks are resolved here); committed.

---

### Task 4: replace the mis-frozen fixtures with REAL envelopes; a NON-CIRCULAR oracle; reverse the producer-obligation

**Files:** Replace `tests/warpline_preflight/fixtures/warpline-preflight-golden.json` (flat → real envelopes). Rewrite `fixtures/PROVENANCE.md`. Rewrite `tests/warpline_preflight/test_warpline_preflight_oracle.py`. Update `tests/mcp/test_warpline_advisory_boundary.py:74-99`. Update `tests/mcp/test_output_schema_conformance.py:635-639`.

**(rank-1 — the load-bearing blocker) The oracle must be NON-CIRCULAR.** The whole point of this fix is that a golden must be validated by flowing through legis's REAL parse path with HARDCODED assertions — never `json.loads(golden)` re-parsed and asserted against itself. Specify it explicitly:
```python
def test_golden_flows_through_the_real_parser_with_hardcoded_assertions(tmp_path):
    """Drive the FROZEN golden bytes through WarplineMcpClient._call (the real
    schema/ok/meta/completeness validation), via a fake invoke replaying the bytes.
    Assert HARDCODED values from the golden — NEVER a re-parse of the golden."""
    golden = json.loads((FIX / "warpline-preflight-golden.json").read_text())
    impact = WarplineMcpClient(invoke=lambda tool, args: golden["impact_radius"]).impact_radius("b", "h")
    assert impact["schema"] == "warpline.impact_radius.v1"
    assert impact["data"]["affected"][0]["sei"] == "loomweave:eid:<the EXACT sei in the golden>"   # hardcoded
    assert impact["meta"]["local_only"] is True and impact["meta"]["peer_side_effects"] == []
    assert impact["data"]["completeness"] == "FULL"
    reverify = WarplineMcpClient(invoke=lambda tool, args: golden["reverify_worklist"]).reverify_worklist("b", "h")
    assert reverify["data"]["items"][0]["sei"] == "loomweave:eid:<the EXACT sei>"   # hardcoded, NOT re-parsed
```
Keep a **Layer-1 byte-pin** (`GOLDEN_BLOB_SHA` at oracle:49 — **re-pin it** after the golden changes; self-catching via the byte-pin test) and a **Layer-2** `test_golden_matches_warpline_source` that points at **warpline's MCP contract fixture** (not the old REST path) and `pytest.skip`s cleanly when absent.

**Capture the golden from a LIVE warpline run** (use the Task-2 transcript or `warpline blast-radius/reverify --json`), saved verbatim as real `warpline.impact_radius.v1`/`warpline.reverify_worklist.v1` envelopes. **(rank-6) Add a machine-readable provenance marker** to the golden, e.g. a top-level `"_provenance": {"source": "live-captured" | "pending-live-capture"}`, and a CI-visible test that **FAILS when `source == "pending-live-capture"` unless an explicit escape env var is set** — so "pending" can never silently masquerade as vendored (the discipline does not rely on prose). Name the var `LEGIS_WARPLINE_GOLDEN_PENDING_OK`; skeleton: `if golden.get("_provenance", {}).get("source") == "pending-live-capture" and not os.environ.get("LEGIS_WARPLINE_GOLDEN_PENDING_OK"): pytest.fail("golden is pending live capture — set LEGIS_WARPLINE_GOLDEN_PENDING_OK=1 only as a temporary escape")`. If no live warpline is reachable, construct from the §-spec, set `source: "pending-live-capture"`, record it in PROVENANCE.md, and let that CI assertion hold the line.

**(rank-5) `_HostileWarpline` + the conformance stub** must both return a real envelope **with a GV-LG-3-VALID meta** (`local_only:true, peer_side_effects:[]`) — so the *advisory payload* (hostile values in `data.affected`/etc.), not a contract violation, is what's proven inert (a GV-LG-3-violating meta would now be REFUSED → `unavailable`, silently making the byte-identity test vacuous). Apply this to BOTH `test_warpline_advisory_boundary.py:74-81` AND `test_output_schema_conformance.py:635-639` (the latter asserts `status=='checked'`, so an invalid-meta stub would flip it to `unavailable`). **Add a guard** in the byte-identity test that the hostile-warpline side actually reached `status=='checked'` (not `'unavailable'`), so the comparison cannot silently degrade to `unavailable==unavailable` — concretely, in the test's governance-paths helper after the `policy_evaluate` calls: `pf = call_tool(runtime, "warpline_preflight_get", {...}); assert pf["structuredContent"]["status"] == "checked"`. **Add a positive test** that an invalid-meta envelope yields `unavailable` (pins GV-LG-3 end-to-end). **State explicitly** that the structural boundary test (`test_warpline_advisory_boundary.py:143-174`, derived from `_TOOL_HANDLERS`) is **preserved unchanged** — it is the load-bearing "warpline can't reach a verdict" invariant.

**Rewrite PROVENANCE.md:** delete the "WARPLINE PRODUCER-SIDE OBLIGATION"; record that legis conforms to warpline's extant envelope (live-captured), cite SEAM 4 §4A + GV-LG-3. Remove the oracle's deleted-symbol imports (`HttpWarplineClient`, `_decode_json_response`). **Commit** in logical groups. **DoD:** no flat `{affected,count}`/`{entries,count}` anywhere; the oracle flows the golden through the real parser with hardcoded assertions (non-circular); golden carries a machine-checked provenance marker; conformance/boundary stubs carry a valid meta + the byte-identity guard + a GV-LG-3 positive test; the structural boundary test preserved; PROVENANCE reversed; committed.

---

### Task 5: full verification (suite + the 1.2.0 invariants + corrected coverage floors + gates)

**Files:** `scripts/check_coverage_floors.py` (add a `src/legis/warpline_preflight/` floor, ~85%, once the new client lands — the package currently has **no** floor entry, so it's guarded only by the global 88%). Otherwise verification only.

Run, expecting green:
```bash
uv run pytest tests/warpline_preflight tests/mcp -q
uv run pytest tests/mcp/test_warpline_advisory_boundary.py -q       # byte-identity + structural (143-174) invariants
uv run pytest --cov=legis --cov-fail-under=88
uv run python scripts/check_coverage_floors.py                       # NOTE actual floors: mcp.py 80, service/ 92 (the v1 plan's "~92/95" was wrong)
uv run mypy src/legis
uv run ruff check src
uv run legis governance-gate
uv run legis policy-boundary-check --root src --repo-root .
uv run pytest tests/conformance/test_sei_oracle.py
```
**Watch:** the 1.2.0 advisory-boundary byte-identity + attestation forge-resistance invariants stay green. **Grep `src/ tests/`** for any lingering `WARPLINE_API_URL`, `/api/impact-radius`, `/api/reverify-worklist`, `"count"`, `"entries"`, `HttpWarplineClient`, or `_decode_json_response` in the warpline path — none should remain. **DoD:** all gates green; a `warpline_preflight/` coverage floor added; the 1.2.0 invariants hold; no HTTP/`count`/`entries`/deleted-symbol residue; branch ready for review (NOT merged — owner-gated).

---

## After execution — acceptance + closeout (product-owner, post-merge)
- Close `legis-a53d92507d`. This is a **federation-seam-quality** bet, **NOT** a north-star (governance-honesty) item — it fails safe; do not move the north-star.
- **Do NOT release 1.3.0 until this is merged** (the 1.3.0-prep carries the mis-frozen golden).
- **reverify stays gated on wardline** (§2A names filigree). If drop: remove `reverify_worklist` from `service/preflight.py:28` + the client method (clean, independent). If bless: stays. Do not freeze it before wardline rules.

## Revision history + validate-before-execution
**Round 1 (7-agent + synthesizer, 2026-06-26): CHANGES_REQUESTED** — no cardinal-sin risk (advisory boundary, fail-open, GV-LG-3 all confirmed sound), but two verification-layer blockers, now fixed: **(blocker 1)** the oracle is re-specified NON-CIRCULAR (golden flows through `WarplineMcpClient._call` with hardcoded assertions, Layer-2 points at warpline's MCP contract fixture); **(blocker 2)** guardrail-(b) fail-safe is closed in CODE (non-dict-meta guard, the whole post-spawn parse wrapped → `WarplineError`, empty-argv rejected, `_read_jsonrpc_result` tightened) AND in TESTS (the `...` isError stub completed + non-dict-meta/scalar-result/non-JSON-line/empty-argv/timeout/oversize variants, all asserting `WarplineError` → `unavailable`). Folded in: the live-capture HARD DoD gate + Popen/SDK escalation branch (rank 3), the honest output-cap wording + `text=False` byte bound (rank 4), the conformance-stub valid-meta + byte-identity guard + GV-LG-3 positive test + structural-invariant statement (rank 5), the machine-readable golden provenance marker (rank 6), `stderr`/`returncode` in errors (rank 7), the `data.completeness` degraded-floor (rank 8), corrected coverage floors + a new `warpline_preflight` floor (rank 9), and the missed symbols + corrected PATH/threat-model wording (rank 10). **Re-run `/review-plan` (the ultracode review) on this revision before executing** — round 1's synthesis does not carry forward.
