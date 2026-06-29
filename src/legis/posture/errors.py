"""Posture-domain error types (leaf module, zero ``legis`` imports).

These live here — not in the 1500-LOC :mod:`legis.install` setup module — so the
posture package and other consumers can raise or catch operator-key custody
failures without importing ``install`` (architecture handover B5 / H-2).
:mod:`legis.install` re-exports :class:`OperatorKeyCustodyError` for backward
compatibility, so ``install.OperatorKeyCustodyError`` and
``from legis.install import OperatorKeyCustodyError`` keep resolving.
"""

from __future__ import annotations


class OperatorKeyCustodyError(RuntimeError):
    """The minted operator key could not be placed in custody.

    Raised by the default key sink when a backend cannot persist the key (no age
    passphrase, no shipped keychain adapter). Install treats this as fail-closed:
    NO ``GENESIS`` is written (the sink runs before the genesis append), so the
    ledger never carries a fingerprint the operator cannot later sign against. A
    bare ``legis install`` reports this as a *deferred* posture step (re-run with
    custody configured), not a hard failure of the whole install.
    """
