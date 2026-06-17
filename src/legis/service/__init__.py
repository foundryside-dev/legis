"""Transport-agnostic governance service layer.

The decision logic that both the HTTP adapter (``legis.api.app``) and the MCP
adapter (``legis.mcp``, WP-M3) drive. Functions here raise ``ServiceError``
subclasses — never ``HTTPException`` and never a JSON-RPC error — so each
transport adapter owns its own error translation.
"""

from legis.service.errors import (
    AuditIntegrityError,
    BindingUnavailableError,
    InvalidArgumentError,
    NoSuchRequestError,
    NotClearedError,
    NotEnabledError,
    NotFoundError,
    ServiceError,
)
from legis.service.explain import PolicyExplanation, RequiredInput, explain_policy
from legis.service.governance import (
    bind_signoff_issue,
    compute_override_rate,
    evaluate_policy,
    read_identity_gaps,
    read_lineage_integrity,
    request_signoff,
    resolve_for_record,
    submit_override,
    submit_operator_override,
    submit_protected_override,
    verified_records,
)
from legis.service.wardline import route_wardline_scan

__all__ = [
    "ServiceError",
    "AuditIntegrityError",
    "BindingUnavailableError",
    "InvalidArgumentError",
    "NoSuchRequestError",
    "NotClearedError",
    "NotEnabledError",
    "NotFoundError",
    "PolicyExplanation",
    "RequiredInput",
    "bind_signoff_issue",
    "compute_override_rate",
    "read_identity_gaps",
    "read_lineage_integrity",
    "evaluate_policy",
    "explain_policy",
    "request_signoff",
    "resolve_for_record",
    "submit_override",
    "submit_operator_override",
    "submit_protected_override",
    "route_wardline_scan",
    "verified_records",
]
