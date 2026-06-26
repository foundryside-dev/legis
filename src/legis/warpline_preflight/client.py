"""Warpline preflight client — legis reads ADVISORY impact/reverify hints.

Injectable ``invoke`` seam (MCP stdio invoker is Task 2). SECURITY: Warpline
is PURELY ADVISORY. Nothing it returns may reach a governance verdict path
(policy_evaluate, the gates, sign-off, or the honesty reads). Governance
verdicts are byte-identical whether warpline is available or not. Every
contract fault fails CLOSED → WarplineError.
"""

from __future__ import annotations

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
