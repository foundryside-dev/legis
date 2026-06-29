"""Dependency-free cryptographic leaf for Legis.

Keyed tamper-evidence (HMAC-SHA256) shared by the audit ``store`` and the
``enforcement`` engine. It lives in its own leaf package — depending only on
:mod:`legis.canonical` — so neither consumer creates an upward edge on the
other. Relocating the signing primitive here removed the historical
``store`` ↔ ``enforcement`` bidirectional import (architecture handover B3 /
H-1): ``store`` now imports ``crypto`` *downward*, exactly as ``enforcement``
does, and a future ``from legis.enforcement.signing import ...`` in ``store``
fails loudly instead of silently re-opening the cycle.
"""
