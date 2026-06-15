"""Domain exceptions for the service layer.

Adapters switch on the exception *type*, never on message text. The HTTP
adapter maps these to status codes; the MCP adapter maps them to ``isError``
result envelopes (WP-M3).
"""

class ServiceError(RuntimeError):
    """Base for every governance service error."""


class AuditIntegrityError(ServiceError):
    """A verified trail failed tamper verification — non-retryable.

    HTTP maps this to 500; MCP maps it to ``error_code: AUDIT_INTEGRITY_FAILURE``.
    """


class NotEnabledError(ServiceError):
    """A required gate/dependency is not wired on this deployment."""


class NotFoundError(ServiceError):
    """A referenced resource (record, request, PR) does not exist."""


class NoSuchRequestError(NotFoundError):
    """A sign-off sequence references no recorded request.

    A ``NotFoundError`` (HTTP keeps its 404) with a narrower MCP mapping:
    ``NO_SUCH_REQUEST``, whose recovery hint points back at the sequence
    returned by ``override_submit``.
    """


class NotClearedError(ServiceError):
    """A sign-off exists but has not been cleared by an operator yet.

    A state conflict, not a caller bug: HTTP maps it to 409; MCP maps it to
    ``SIGNOFF_NOT_CLEARED`` with poll-then-retry guidance.
    """


class BindingUnavailableError(ServiceError):
    """A cleared sign-off cannot be rename-stably bound (ADR-0003 fail-closed).

    The sign-off is locator-keyed (no stable SEI) and no ``SEI_BACKFILL``
    recovery resolved it. HTTP maps this to 409; MCP to ``BINDING_UNAVAILABLE``.
    """


class InvalidArgumentError(ServiceError):
    """Caller input is structurally valid for the transport but invalid for Legis."""


class UnresolvedInputError(ServiceError):
    """An inline-supplied entity SEI did not resolve to a stable, alive identity.

    The weft SEI-on-entry doctrine: a surface that lets the agent bind an SEI at
    the point of entry must, on a non-resolving input, return a ``weft-reason``
    ``unresolved_input {cause, fix}`` and create NOTHING — never an
    unbound-but-looks-bound record. Carries ``cause`` and ``fix`` strings so the
    adapter can surface the structured weft-reason without parsing message text.
    HTTP maps this to 422; MCP to ``UNRESOLVED_INPUT``.
    """

    def __init__(self, cause: str, fix: str) -> None:
        super().__init__(f"{cause} — {fix}")
        self.cause = cause
        self.fix = fix


class WardlineRoutingError(ServiceError):
    """A Wardline scan-routing request is not permitted or is malformed.

    Carries a ``kind`` discriminator so each adapter can preserve its own
    taxonomy without re-implementing the decision: the HTTP adapter maps
    ``server_misconfigured`` → 500, ``server_owned`` → 403, ``malformed`` → 422,
    while the MCP adapter collapses all three to ``INVALID_CELL_SPEC``. Adapters
    switch on the ``kind`` attribute, never on message text.
    """

    SERVER_MISCONFIGURED = "server_misconfigured"
    SERVER_OWNED = "server_owned"
    MALFORMED = "malformed"

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


class ProtectedKeyRequiredError(ServiceError):
    """A protected trail was read without the HMAC key needed to verify it.

    Fail-closed: a trail carrying protected records cannot be scored without the
    key that proves it untampered (Q-H2 / 07cf54e). The cli gate maps this to a
    non-zero exit.
    """
