"""Bind a cleared governed sign-off to a Filigree issue, keyed on SEI.

legis governs; Filigree owns issue state. This attaches the attestation as an
entity-association (``entity_id`` = the SEI, opaque to Filigree) so the code↔
governance binding survives rename/move. It does NOT mutate Filigree issue
status — lifecycle transitions remain Filigree's authority (locked decision 5).
A locator-keyed sign-off is rejected: an unstable binding would orphan on rename,
defeating the point.

Binding availability is therefore coupled to identity stability (an SEI, which
Loomweave produces). The contract for a degraded Loomweave is ADR-0003: the
``bind-issue`` handler first tries to resolve a locator through a ``SEI_BACKFILL``
event (recovery), and otherwise **fails closed** (HTTP 409) rather than recording
a rename-fragile placeholder. The sign-off itself is always recorded; only the
Filigree pointer waits for a stable identity. See
``docs/design/adr/0003-filigree-binding-availability.md``.

When a ``ledger`` is supplied, the order is validate → attach → record: after a
successful attach, a tamper-bound ``BindingRecord`` is appended to the ledger and
its sequence number is returned to the caller as ``binding_seq``. The Filigree row
stays an opaque pointer; the ledger is where the binding's integrity lives.
"""

from __future__ import annotations

from typing import Any

from legis.crypto.signing import sign
from legis.filigree.client import FiligreeClient
from legis.governance.binding_ledger import BindingLedger
from legis.identity.entity_key import EntityKey

BINDING_ACTOR = "legis"


def bind_signoff_to_issue(
    filigree: FiligreeClient,
    *,
    issue_id: str,
    entity_key: EntityKey,
    content_hash: str,
    signoff_seq: int,
    key: bytes | None = None,
    ledger: BindingLedger | None = None,
) -> dict[str, Any]:
    if not entity_key.identity_stable:
        raise ValueError(
            "cannot bind a sign-off on an identity_stable=False (locator) key — "
            "the binding would orphan on rename; resolve to an SEI first"
        )
    signature = None
    if key is not None:
        signature = sign(
            {
                "issue_id": issue_id,
                "entity_id": entity_key.value,
                "content_hash": content_hash,
                "signoff_seq": signoff_seq,
            },
            key,
        )
    result = filigree.attach(
        issue_id,
        entity_key.value,
        content_hash,
        actor=BINDING_ACTOR,
        signoff_seq=signoff_seq,
        signature=signature,
    )
    out = {**result, "signoff_seq": signoff_seq, "binding_signature": signature}
    if ledger is not None:
        # Validate → attach → record. If this record() raises after attach() succeeded,
        # Filigree already holds the pointer while legis has no local binding record;
        # there is no compensating delete (accepted trade-off — a binding with no
        # verifiable ledger entry is exactly what the ledger's verify() surfaces).
        out["binding_seq"] = ledger.record(
            signoff_seq=signoff_seq,
            issue_id=issue_id,
            entity_key=entity_key,
            content_hash=content_hash,
        )
    return out
