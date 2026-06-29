"""Plainweave preflight client — legis reads ADVISORY requirement/intent facts.

Injectable ``invoke`` seam (a stdio JSON-RPC invoker for production). SECURITY:
Plainweave is PURELY ADVISORY. Nothing it returns may reach a governance verdict
path (policy_evaluate, the gates, sign-off, or the honesty reads). Governance
verdicts are byte-identical whether plainweave is available or not. Every
contract fault fails CLOSED → PlainweaveError.

Plainweave's ONE implemented producer is ``plainweave_preflight_facts_get`` →
envelope ``weft.plainweave.preflight_facts.v1`` (ADR-006). Legis is a CONSUMER of
that frozen envelope: it validates the envelope shape (schema / ok /
data.authority_boundary / data.freshness / data.facts) and passes it through
verbatim — it does NOT interpret, re-shape, or act on the facts. Plainweave's
``meta`` carries no ``local_only``/``peer_side_effects`` (those are warpline's);
the boundary assertions live in ``data.authority_boundary`` instead
(``local_only`` / ``live_peer_calls`` / ``governance_verdicts``), so the GV-LG-3
fail-closed gate validates THOSE fields.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Callable, Protocol, runtime_checkable

Invoke = Callable[[str, "dict[str, Any]"], "Any"]   # returns the parsed tool result (validated below)

MAX_RESPONSE_BYTES = 1_000_000

PREFLIGHT_SCHEMA = "weft.plainweave.preflight_facts.v1"
PREFLIGHT_TOOL = "plainweave_preflight_facts_get"


class PlainweaveError(RuntimeError):
    """A Plainweave call failed at the transport or contract layer."""


@runtime_checkable
class PlainweaveClient(Protocol):
    def preflight_facts(self, base: str, head: str) -> dict[str, Any]: ...


class PlainweaveMcpClient:
    """Consume plainweave's EXTANT preflight-facts MCP tool (advisory preflight).
    Pass the frozen ``weft.plainweave.preflight_facts.v1`` envelope through verbatim
    (the bare-object MCP output schema makes pass-through lossless). Advisory-ONLY;
    every contract fault fails CLOSED -> PlainweaveError."""

    def __init__(self, *, invoke: "Invoke", repo: str) -> None:
        self._invoke = invoke
        self._repo = repo

    def preflight_facts(self, base: str, head: str) -> dict[str, Any]:
        return self._call(PREFLIGHT_SCHEMA, PREFLIGHT_TOOL, base, head)

    def _call(self, schema: str, tool: str, base: str, head: str) -> dict[str, Any]:
        # The producer tool takes NO 'repo' arg (its signature is scope_kind/base/
        # head/requirement_ids/entity_refs/baseline_id); the "which plainweave" is
        # implicit in what the launched MCP command roots on. A commit-range scope
        # advertises base..head; the producer never resolves the live diff itself
        # (it honestly reports freshness "partial"). Sending an unknown kwarg would
        # be rejected by the producer, so the args are exactly scope_kind/base/head.
        env = self._invoke(tool, {"scope_kind": "commit_range", "base": base, "head": head})
        if not isinstance(env, dict):
            raise PlainweaveError(f"{tool} returned {type(env).__name__}, expected an envelope object")
        if env.get("schema") != schema:
            raise PlainweaveError(f"{tool} returned schema {env.get('schema')!r}, expected {schema!r}")
        if env.get("ok") is not True:                          # error envelope / degraded -> unavailable
            raise PlainweaveError(f"{tool} envelope is not ok=true: {env.get('ok')!r}")
        data = env.get("data")
        if not isinstance(data, dict):
            raise PlainweaveError(f"{tool} envelope data is {type(data).__name__}, expected an object")
        boundary = data.get("authority_boundary")
        if not isinstance(boundary, dict):                     # malformed boundary fails closed (GV-LG-3 input)
            raise PlainweaveError(
                f"{tool} data.authority_boundary is {type(boundary).__name__}, expected an object"
            )
        if boundary.get("local_only") is not True:
            raise PlainweaveError(
                f"{tool} authority_boundary.local_only is not true: {boundary.get('local_only')!r}"
            )
        if boundary.get("live_peer_calls") is not False:       # a live peer call is a side effect (GV-LG-3)
            raise PlainweaveError(
                f"{tool} authority_boundary.live_peer_calls is not false: {boundary.get('live_peer_calls')!r}"
            )
        if boundary.get("governance_verdicts") is not False:   # this producer must NEVER claim a verdict (GV-LG-3)
            raise PlainweaveError(
                f"{tool} authority_boundary.governance_verdicts is not false: "
                f"{boundary.get('governance_verdicts')!r}"
            )
        if "freshness" not in data or "facts" not in data:     # degraded -> unavailable, not bare empty 'checked'
            raise PlainweaveError(
                f"{tool} envelope data is missing the mandatory 'freshness'/'facts' fields"
            )
        return env


def _read_jsonrpc_result(stdout_text: str, response_id: int) -> dict:
    for line in stdout_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError as exc:
            raise PlainweaveError(f"plainweave-mcp emitted a non-JSON line: {exc}") from exc
        if isinstance(msg, dict) and msg.get("id") == response_id:
            if "error" in msg:
                raise PlainweaveError(f"plainweave-mcp returned a JSON-RPC error: {msg['error']}")
            result = msg.get("result")
            if not isinstance(result, dict):
                raise PlainweaveError(f"plainweave-mcp result is {type(result).__name__}, expected an object")
            return result
    raise PlainweaveError(f"plainweave-mcp produced no JSON-RPC response for id={response_id}")


class StdioMcpInvoke:
    """Production Invoke: a stdio JSON-RPC call to plainweave-mcp. Fail-safe: EVERY
    fault -> PlainweaveError. shell=False + list argv (arguments are JSON params,
    never argv tokens); explicit command (absolute path recommended; empty
    rejected); text=False byte-bounded stdout (post-capture); 10s timeout."""

    def __init__(self, *, command: list[str], timeout: float = 10.0) -> None:
        self._command = command
        self._timeout = timeout

    def __call__(self, tool: str, arguments: dict) -> dict:
        if not self._command:
            raise PlainweaveError("plainweave-mcp command is empty (PLAINWEAVE_MCP_CMD blank?)")
        msgs = (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "legis", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": arguments}},
        )
        stdin = ("".join(json.dumps(m) + "\n" for m in msgs)).encode("utf-8")
        try:
            proc = subprocess.run(self._command, input=stdin, capture_output=True,
                                  timeout=self._timeout, shell=False, check=False, text=False)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise PlainweaveError(f"plainweave-mcp spawn/timeout failed: {exc}") from exc
        if len(proc.stdout) > MAX_RESPONSE_BYTES:
            raise PlainweaveError("plainweave-mcp response too large")
        err = (proc.stderr or b"")[:400].decode("utf-8", "replace")
        try:
            result = _read_jsonrpc_result(proc.stdout.decode("utf-8", "replace"), response_id=2)
            if result.get("isError"):
                raise PlainweaveError(f"plainweave tool {tool} returned an error result (rc={proc.returncode}, stderr={err!r})")
            sc = result.get("structuredContent")
            if isinstance(sc, dict):
                return sc
            for block in result.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "text":
                    return json.loads(block["text"])
            raise PlainweaveError(f"plainweave tool {tool} result had no usable envelope (rc={proc.returncode}, stderr={err!r})")
        except PlainweaveError:
            raise
        except Exception as exc:   # ANY parse fault fails closed
            raise PlainweaveError(f"plainweave tool {tool} result parse failed: {exc} (rc={proc.returncode}, stderr={err!r})") from exc
