"""Agent-programmable policy grammar (Sprint 4).

Layering: ``policy`` is a *leaf* with respect to ``service``. The sanctioned
direction is ``service`` -> ``policy`` (the service truth-layer depends on this
grammar/cell registry); ``policy`` must NOT import ``service``. The architecture
handover (B4 / H-4) flagged a suspected ``policy`` -> ``service`` deferred import
of ``service.errors``; it was verified ABSENT in the tree (no reference to
``service`` anywhere under ``policy/``), so no change was needed. Keep it that
way — if ``policy`` ever needs a ``service`` error type, move that type to a leaf
both can import downward rather than importing ``service`` upward.
"""
