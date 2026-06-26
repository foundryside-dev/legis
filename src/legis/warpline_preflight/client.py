"""Warpline preflight client — legis reads ADVISORY impact/reverify hints.

Injectable ``invoke`` seam (MCP stdio invoker is Task 2). SECURITY: Warpline
is PURELY ADVISORY. Nothing it returns may reach a governance verdict path
(policy_evaluate, the gates, sign-off, or the honesty reads). Governance
verdicts are byte-identical whether warpline is available or not. Every
contract fault fails CLOSED → WarplineError.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Callable, Protocol, runtime_checkable

Invoke = Callable[[str, "dict[str, Any]"], "Any"]   # returns the parsed tool result (validated below)

MAX_RESPONSE_BYTES = 1_000_000


class WarplineError(RuntimeError):
    """A Warpline call failed at the transport or contract layer."""


@runtime_checkable
class WarplineClient(Protocol):
    def impact_radius(self, base: str, head: str) -> dict[str, Any]: ...
    def reverify_worklist(self, base: str, head: str) -> dict[str, Any]: ...


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
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "legis", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": arguments}},
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
