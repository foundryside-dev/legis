"""Agent-programmable policy grammar (Sprint 4).

Layering: the sanctioned direction is ``service`` -> ``policy`` — the service
truth-layer depends on this grammar/cell registry, never the reverse at module
load. ``policy`` therefore takes NO *module-level* import of ``service``: an
eager one would risk a cycle, since ``service.__init__`` pulls in modules that
import ``policy``.

There is one sanctioned exception (architecture handover B4 / H-4):
``boundary_scan.assert_within_boundary`` raises
``service.errors.InvalidArgumentError`` so the MCP adapter can map a rejected
scan root to an ``INVALID_ARGUMENT`` envelope (fail-closed — never a silent
PASS). It imports that type at CALL time, not module level, which keeps the
dependency cycle-safe (see the comment at its import site). That deferred,
fail-closed import is the only ``policy`` -> ``service`` edge and is the accepted
pattern. Do NOT add an *eager* ``policy`` -> ``service`` import; if more coupling
appears, move the shared error types to a leaf both layers import downward.
"""
