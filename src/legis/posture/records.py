"""Posture-ledger record model (design §4).

A ``PostureRecord`` is the domain shape of one row in the signed posture-floor
ledger. It serializes to a flat payload that the record-agnostic
:class:`~legis.store.audit_store.AuditStore` chains; the store owns ``seq`` /
``prev_hash`` / ``chain_hash``, so those are deliberately absent from the
payload — including them would shift the content hash and break
``verify_integrity``.

Modeled on :class:`~legis.records.override_record.OverrideRecord`: a frozen
dataclass with a single ``to_payload()`` method, keyless fields (``operator_sig``
/ ``session_id``) default to ``None`` so GENESIS / KEY_RESET / OPERATOR_SESSION_OPENED
records carry no signature.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Record kinds (design §4, plan Task 1.1).
KIND_GENESIS = "GENESIS"
KIND_TRANSITION = "TRANSITION"
KIND_KEY_RESET = "KEY_RESET"
KIND_SESSION_OPENED = "OPERATOR_SESSION_OPENED"


@dataclass(frozen=True)
class PostureRecord:
    kind: str
    floor: str
    key_fingerprint: str
    agent_id: str
    recorded_at: str
    rationale: str
    operator_sig: str | None = None
    session_id: str | None = None

    def to_payload(self) -> dict[str, Any]:
        """The canonical content payload handed to ``AuditStore.append``.

        Exactly the eight domain fields — never ``seq``/``prev_hash``/
        ``chain_hash`` (the store adds those; see module docstring).
        """
        return {
            "kind": self.kind,
            "floor": self.floor,
            "key_fingerprint": self.key_fingerprint,
            "operator_sig": self.operator_sig,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "recorded_at": self.recorded_at,
            "rationale": self.rationale,
        }
