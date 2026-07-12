"""Minimal MCP-over-stdio adapter for Legis.

The adapter is deliberately stdlib-only: one JSON-RPC object per line on stdin,
one response per line on stdout. Tool calls are thin transport mappings over the
service layer and the launch-bound ``agent_id``; tool schemas never accept actor
identity from call arguments.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import json
import logging
import os
from pathlib import Path
import sys
from typing import TYPE_CHECKING, Any, TextIO

if TYPE_CHECKING:
    from legis.plainweave_preflight.client import PlainweaveClient

from legis import __version__
from legis.canonical import content_hash
from legis.checks.models import CheckOutcome, CheckRun
from legis.checks.surface import CheckSurface
from legis.clock import SystemClock
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.judge_factory import build_judge_from_env
from legis.enforcement.lifecycle import GateStatus
from legis.enforcement.protected import ProtectedGate, TrailVerifier, TamperError
from legis.enforcement.signoff import SignoffGate
from legis.enforcement.verdict import SignoffState, Verdict
from legis.filigree.client import FiligreeError
from legis.git.surface import GitError, GitSurface
from legis.governance.binding_ledger import BindingError
from legis.policy.cells import (
    CELL_TIER_ORDER,
    PolicyCellRegistry,
    fail_closed_policy_cells,
    load_policy_cell_registry,
)
from legis.policy.grammar import PolicyGrammar, PolicyResult, default_grammar
from legis.posture.floor import FlooredRegistry, _max_tier, floored_registry
from legis.provenance import Provenance
from legis.pulls.models import PullRequestState
from legis.pulls.surface import PullSurface
from legis.wardline.governor import WardlineCellPolicy
from legis.service.errors import (
    AuditIntegrityError,
    BindingUnavailableError,
    InvalidArgumentError,
    NoSuchRequestError,
    NotClearedError,
    NotEnabledError,
    NotFoundError,
    ServiceError,
    UnresolvedInputError,
    WardlineRoutingError,
)
from legis.service.explain import explain_cell, explain_policy
from legis.service.governance import (
    bind_signoff_issue,
    compute_override_rate,
    evaluate_policy,
    read_identity_gaps,
    read_lineage_integrity,
    submit_override,
    submit_protected_override,
    request_signoff,
    verified_records as service_verified_records,
)
from legis.service.wardline import resolve_scan_routing, route_wardline_scan
from legis.store.audit_store import AuditStore
from legis.wardline.ingest import (
    ArtifactStatus,
    ArtifactStatusReason,
    ScanOutcome,
    WardlineDirtyTreeError,
)


_AGENT_TOOLS = frozenset(
    {
        "policy_explain",
        "policy_list",
        "override_submit",
        "signoff_status_get",
        "signoff_bind_issue",
        "policy_evaluate",
        "scan_route",
        "git_branch_list",
        "git_commit_get",
        "git_rename_list",
        "git_rename_feed_get",
        "pull_request_get",
        "check_list",
        "override_rate_get",
        "filigree_closure_gate_get",
        "identity_gap_list",
        "lineage_integrity_get",
        "check_report",
        "override_list",
        "doctor_get",
        "policy_boundary_check",
        "posture_get",
        "warpline_preflight_get",
        "plainweave_preflight_get",
        "attestation_get",
        "governance_read",
    }
)
_OVERRIDE_RATE_NOTE = "measures operator force-pasts; not movable by agent retries"
# Single source for check_list's target_type: the schema enum and the handler's
# dispatch/rejection both read this, so tools/list can never advertise a value
# the handler rejects (legis-40a0ff7799).
_CHECK_TARGET_TYPES = ("commit", "branch", "pr")
_SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26")
_DEFAULT_PROTOCOL_VERSION = _SUPPORTED_PROTOCOL_VERSIONS[-1]

# Upper bound on a single JSON-RPC line read from stdin. The hand-rolled framing
# is one object per line; without a bound a peer (or a corrupted pipe) sending a
# line with no newline forces an unbounded read into memory. 16 MiB comfortably
# fits a maximal scan_route request (MAX_FINDINGS=500 with properties) while
# refusing a pathological one. Override with LEGIS_MCP_MAX_REQUEST_BYTES.
_DEFAULT_MAX_REQUEST_BYTES = 16 * 1024 * 1024

logger = logging.getLogger(__name__)


def _max_request_bytes() -> int:
    raw = os.environ.get("LEGIS_MCP_MAX_REQUEST_BYTES")
    if raw:
        try:
            value = int(raw)
        except ValueError:
            logger.warning(
                "LEGIS_MCP_MAX_REQUEST_BYTES=%r is not an integer; ignoring it "
                "and using the default %d-byte bound",
                raw,
                _DEFAULT_MAX_REQUEST_BYTES,
            )
            return _DEFAULT_MAX_REQUEST_BYTES
        if value > 0:
            return value
        # A non-positive bound (a fat-fingered 0 or negative) would otherwise
        # fall through silently — the operator meant to lower the cap and it was
        # ignored. Say so.
        logger.warning(
            "LEGIS_MCP_MAX_REQUEST_BYTES=%r is not positive; ignoring it and "
            "using the default %d-byte bound",
            raw,
            _DEFAULT_MAX_REQUEST_BYTES,
        )
    return _DEFAULT_MAX_REQUEST_BYTES


@dataclass
class McpRuntime:
    agent_id: str
    initialized: bool = False
    protocol_version: str | None = None
    engine: EnforcementEngine | None = None
    identity: Any | None = None
    protected_gate: ProtectedGate | None = None
    trail_verifier: TrailVerifier | None = None
    signoff_gate: Any | None = None
    cell_registry: PolicyCellRegistry | None = None
    check_surface: CheckSurface | None = None
    git_surface: GitSurface | None = None
    pull_surface: PullSurface | None = None
    grammar: PolicyGrammar | None = None
    source_root: str | Path | None = None
    wardline_artifact_key: bytes | None = None
    wardline_allow_dirty: bool = False
    binding_ledger: Any | None = None
    filigree: Any | None = None
    binding_key: bytes | None = None
    # The posture-floor ledger HANDLE (D2): held once on the runtime, never a
    # cached floor *value*. read_floor() is called fresh at each cell-resolution
    # site via _floored_registry. None on a runtime built without posture wiring,
    # which _floored_registry treats fail-closed as a missing ledger (structured).
    posture_ledger: Any | None = None
    coached_engine: EnforcementEngine | None = None
    warpline: Any | None = None  # advisory sibling; NEVER read by a verdict path
    plainweave: "PlainweaveClient | None" = (
        None  # advisory sibling; NEVER read by a verdict path
    )


def build_runtime(agent_id: str) -> McpRuntime:
    from legis.config import (
        binding_db_url,
        governance_db_url,
        posture_db_url,
        protected_policies,
    )
    from legis.posture.ledger import PostureLedger

    clock = SystemClock()
    engine = None
    identity = None
    loomweave_url = os.environ.get("LOOMWEAVE_API_URL")
    if loomweave_url:
        from legis.identity.loomweave_client import (
            HttpLoomweaveIdentity,
            loomweave_hmac_key_from_env,
        )
        from legis.identity.resolver import IdentityResolver

        identity = IdentityResolver(
            HttpLoomweaveIdentity(loomweave_url, hmac_key=loomweave_hmac_key_from_env())
        )

    filigree = None
    filigree_url = os.environ.get("FILIGREE_API_URL")
    if filigree_url:
        from legis.filigree.client import HttpFiligreeClient

        filigree = HttpFiligreeClient(filigree_url)

    warpline = None
    warpline_cmd = os.environ.get("WARPLINE_MCP_CMD")
    if warpline_cmd:
        import shlex
        from legis.warpline_preflight.client import (
            StdioMcpInvoke,
            WarplineError,
            WarplineMcpClient,
        )

        try:
            argv = shlex.split(warpline_cmd)
            if not argv:
                raise WarplineError("WARPLINE_MCP_CMD is blank")
            from legis.config import project_root

            warpline = WarplineMcpClient(
                invoke=StdioMcpInvoke(command=argv), repo=str(project_root())
            )
        except (WarplineError, ValueError) as exc:
            logging.getLogger(__name__).warning(
                "WARPLINE_MCP_CMD is set but invalid (%s); warpline advisory context "
                "disabled (governance unaffected).",
                exc,
            )
            warpline = None

    import shlex
    from legis.config import project_root
    from legis.plainweave_binding import discover_plainweave
    from legis.plainweave_preflight.client import (
        PlainweaveError,
        PlainweaveMcpClient,
        StdioMcpInvoke as PlainweaveStdioMcpInvoke,
    )

    plainweave = None
    root = project_root()
    discovery = discover_plainweave(root)
    if discovery.command is not None:
        try:
            argv = shlex.split(discovery.command)
            if not argv:
                raise PlainweaveError("plainweave-mcp command is empty")
            plainweave = PlainweaveMcpClient(
                invoke=PlainweaveStdioMcpInvoke(command=argv),
                repo=str(root),
            )
        except (PlainweaveError, ValueError) as exc:
            logging.getLogger(__name__).warning(
                "Plainweave runtime autodiscovery produced an invalid command (%s); "
                "plainweave advisory context disabled (governance unaffected).",
                exc,
            )
            plainweave = None
    elif discovery.error is not None:
        logging.getLogger(__name__).warning(
            "Plainweave runtime autodiscovery failed (%s); plainweave advisory context "
            "disabled (governance unaffected).",
            discovery.error,
        )

    protected_gate = None
    trail_verifier = None
    signoff_gate = None
    binding_ledger = None
    binding_key = None
    hmac_key = os.environ.get("LEGIS_HMAC_KEY")
    if hmac_key:
        key = hmac_key.encode("utf-8")
        # Same fallback the HTTP adapter uses: the binding attestation key is
        # the governance HMAC key unless a dedicated one is injected.
        binding_key = key
        store = AuditStore(governance_db_url())
        protected = protected_policies()
        trail_verifier = TrailVerifier(key, protected)

        # Protected cell: the LLM judge is advisory only (Q-H3). With no
        # deterministic validator wired, ANY judge ACCEPTED in this cell is
        # downgraded fail-closed and the agent must escalate to operator sign-off
        # — unconditionally, regardless of protected_policies membership (the set
        # drives only a config-hygiene warning + the read-side signature
        # requirement). See ProtectedGate (finding JUDGE-3).
        protected_gate = ProtectedGate(
            store,
            clock,
            build_judge_from_env("MCP"),
            key,
            protected_policies=protected,
        )
        signoff_gate = SignoffGate(store, clock, signer=True, key=key)

        from legis.governance.binding_ledger import BindingLedger

        binding_ledger = BindingLedger(
            AuditStore(binding_db_url()),
            clock,
            key,
        )

    return McpRuntime(
        agent_id=agent_id,
        engine=engine,
        identity=identity,
        protected_gate=protected_gate,
        trail_verifier=trail_verifier,
        signoff_gate=signoff_gate,
        cell_registry=load_policy_cell_registry(),
        check_surface=None,
        git_surface=GitSurface(os.environ.get("LEGIS_SOURCE_ROOT") or os.getcwd()),
        pull_surface=None,
        grammar=default_grammar(),
        source_root=os.environ.get("LEGIS_SOURCE_ROOT") or os.getcwd(),
        wardline_artifact_key=(
            os.environ["LEGIS_WARDLINE_ARTIFACT_KEY"].encode("utf-8")
            if os.environ.get("LEGIS_WARDLINE_ARTIFACT_KEY")
            else None
        ),
        wardline_allow_dirty=os.environ.get("LEGIS_WARDLINE_ALLOW_DIRTY") == "1",
        binding_ledger=binding_ledger,
        filigree=filigree,
        binding_key=binding_key,
        # D2: hold the ledger HANDLE only; each cell-resolution site reads
        # read_floor() fresh (never the floor VALUE). initialize=False so
        # launching the server never creates posture.db — genesis is an
        # install-time action (Phase 6) and build_runtime must not create local
        # state (audit H6 / the no-local-state-on-init invariant).
        posture_ledger=PostureLedger(posture_db_url(), initialize=False),
        warpline=warpline,
        plainweave=plainweave,
    )


def _schema(
    required: list[str], properties: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


def _one_of(variants: list[dict[str, Any]]) -> dict[str, Any]:
    """A discriminated-outcome outputSchema.

    MCP requires every tool's outputSchema to declare ``"type": "object"`` at the
    top level — Claude Code's zod validator rejects the ENTIRE tools/list (all 21
    tools vanish from the session) when any tool omits it (dogfood-4 A6). A bare
    ``{"oneOf": [...]}`` omits it. Routing every discriminated schema through this
    helper makes the bug unrepresentable: the top-level ``"type": "object"`` is
    injected here, in one place, instead of being a literal line each call site
    must remember. The variants all describe objects, so the type is sound.
    """
    return {"type": "object", "oneOf": variants}


# The uniform error envelope (structuredContent of every isError:true result,
# built by _tool_error). One shared definition rather than a per-tool clause:
# tools' outputSchema declarations describe SUCCESS payloads only; clients
# validate error results against this. The text content mirrors it as
# "{code}: {message}\nnext_action: …" (LEG-2).
#
# weft_reason is the OPTIONAL structured cause/fix the SEI-on-entry doctrine
# attaches to a non-resolving inline identity (UNRESOLVED_INPUT): present only on
# surfaces that bind a SEI, absent everywhere else. It is listed here so the
# strict (additionalProperties:False) envelope admits it — otherwise a client or
# conformance check validating that error rejects the documented recovery path.
# The inner object stays open (no additionalProperties:False) so the weft reason
# vocabulary can grow without a lockstep schema bump.
ERROR_ENVELOPE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["error_code", "message", "recoverable", "next_action"],
    "properties": {
        "error_code": {"type": "string"},
        "message": {"type": "string"},
        "recoverable": {"type": "boolean"},
        "next_action": {"type": "string"},
        "weft_reason": {
            "type": "object",
            "properties": {
                "kind": {"type": "string"},
                "cause": {"type": "string"},
                "fix": {"type": "string"},
            },
        },
    },
}


def tool_definitions() -> list[dict[str, Any]]:
    string = {"type": "string"}
    integer = {"type": "integer", "minimum": 1}
    object_schema = {"type": "object"}

    # --- outputSchema fragments (legis-49b4ca4166) ---
    # Every outputSchema describes the SUCCESS structuredContent; isError:true
    # results carry the shared ERROR_ENVELOPE_SCHEMA instead. The conformance
    # vector (tests/mcp/test_output_schema_conformance.py) drives each tool and
    # validates the emitted payload against these — a payload/schema drift
    # fails there, not in a client.
    boolean = {"type": "boolean"}
    plain_integer = {"type": "integer"}
    nullable_string = {"type": ["string", "null"]}
    nullable_integer = {"type": ["integer", "null"]}
    string_array = {"type": "array", "items": string}
    cell_enum = {"type": "string", "enum": list(CELL_TIER_ORDER)}
    required_inputs_array = {
        "type": "array",
        "items": _schema(["field", "how"], {"field": string, "how": string}),
    }
    # The check-run read shape (_check_to_dict): recorded_by/provenance are NOT
    # on the read payloads today (filed: legis-fa9c60c660); check_report's echo
    # adds them on top.
    check_run_properties: dict[str, Any] = {
        "check_name": string,
        "run_id": string,
        "commit_sha": string,
        "outcome": {"type": "string", "enum": [o.value for o in CheckOutcome]},
        "branch": nullable_string,
        "pr": nullable_integer,
        "ran_against": nullable_string,
        "rule_set": nullable_string,
        "policy_version": nullable_string,
        "started_at": nullable_string,
        "finished_at": nullable_string,
    }
    checks_array = {
        "type": "array",
        "items": _schema(sorted(check_run_properties), check_run_properties),
    }
    # The policy/cell explanation payload (PolicyExplanation.to_payload):
    # policy_explain always routes via explain_policy, so policy_known is
    # always present there; the per-cell rows in policy_list never carry it.
    explanation_out = _schema(
        [
            "cell",
            "judge_inline",
            "self_clearable",
            "human_in_loop",
            "enabled",
            "available_moves",
            "required_inputs",
            "matched_rule",
            "policy_known",
        ],
        {
            "cell": cell_enum,
            "judge_inline": boolean,
            "self_clearable": boolean,
            "human_in_loop": boolean,
            "enabled": boolean,
            "available_moves": string_array,
            "required_inputs": required_inputs_array,
            "matched_rule": nullable_string,
            "policy_known": boolean,
        },
    )
    judged_fields: dict[str, Any] = {
        "judge_model": nullable_string,
        "judge_rationale": nullable_string,
    }
    # Discriminated-outcome schema: _one_of injects the mandatory top-level
    # "type": "object" (see its docstring / dogfood-4 A6).
    override_submit_out = _one_of(
        [
            _schema(
                ["outcome", "cell", "seq", "note"],
                {
                    "outcome": {"const": "ACCEPTED_SELF"},
                    "cell": {"const": "chill"},
                    "seq": integer,
                    "note": string,
                    # Optional D4 idempotent-replay-after-floor-rise note.
                    "floor_warning": string,
                },
            ),
            _schema(
                ["outcome", "cell", "seq", "judge_model", "judge_rationale", "note"],
                {
                    "outcome": {"const": "ACCEPTED_BY_JUDGE"},
                    "cell": {"type": "string", "enum": ["coached", "protected"]},
                    "seq": integer,
                    **judged_fields,
                    "note": string,
                    "floor_warning": string,
                },
            ),
            _schema(
                [
                    "outcome",
                    "cell",
                    "seq",
                    "judge_model",
                    "judge_rationale",
                    "blocked_reason_code",
                    "self_clearable",
                    "next_actions",
                    "note",
                ],
                {
                    "outcome": {"const": "BLOCKED"},
                    "cell": {"type": "string", "enum": ["coached", "protected"]},
                    "seq": integer,
                    **judged_fields,
                    "blocked_reason_code": {
                        "type": "string",
                        "enum": [
                            "RATIONALE_INSUFFICIENT",
                            "CODE_VIOLATION",
                            "POLICY_HARD_BLOCK",
                            "UNCLASSIFIED",
                        ],
                    },
                    "self_clearable": {"const": False},
                    "next_actions": string_array,
                    "note": string,
                    "floor_warning": string,
                },
            ),
            _schema(
                [
                    "outcome",
                    "cell",
                    "seq",
                    "cleared",
                    "human_required",
                    "operator_instruction",
                    "poll_tool",
                    "poll_handle",
                ],
                {
                    "outcome": {"const": "ESCALATED_PENDING"},
                    "cell": {"const": "structured"},
                    "seq": integer,
                    "cleared": boolean,
                    "human_required": boolean,
                    "operator_instruction": string,
                    "poll_tool": {"const": "signoff_status_get"},
                    "poll_handle": integer,
                    "floor_warning": string,
                },
            ),
            _schema(
                ["outcome", "cell", "required_inputs"],
                {
                    "outcome": {"const": "NEED_INPUTS"},
                    "cell": {"const": "protected"},
                    "required_inputs": required_inputs_array,
                },
            ),
        ]
    )
    routed_item = {
        "type": "object",
        "additionalProperties": False,
        "required": ["mode", "fingerprint", "seq"],
        "properties": {
            "mode": {
                "type": "string",
                "enum": [cell.value for cell in WardlineCellPolicy],
            },
            "fingerprint": string,
            "seq": integer,
            "cleared": boolean,
            "accepted": boolean,
            "surfaced": boolean,
        },
    }
    # Discriminated-outcome schema: _one_of injects the top-level type (A6).
    scan_route_out = _one_of(
        [
            _schema(
                ["outcome", "routed", "artifact_status", "artifact_status_reason"],
                {
                    "outcome": {"const": ScanOutcome.ROUTED.value},
                    "routed": {"type": "array", "items": routed_item},
                    "artifact_status": {
                        "type": "string",
                        "enum": [status.value for status in ArtifactStatus],
                    },
                    "artifact_status_reason": {
                        "type": "string",
                        "enum": [reason.value for reason in ArtifactStatusReason],
                    },
                },
            ),
        ]
    )
    rename_item = _schema(
        ["commit_sha", "old_path", "new_path", "similarity", "old_blob", "new_blob"],
        {
            "commit_sha": string,
            "old_path": string,
            "new_path": string,
            "similarity": plain_integer,
            "old_blob": string,
            "new_blob": string,
        },
    )
    rename_array = {"type": "array", "items": rename_item}

    return [
        {
            "name": "policy_explain",
            "description": (
                "Explain which governance cell controls a policy/entity pair, "
                "whether that cell is enabled on this server, and which move the "
                "agent may make next. policy_known:false means no routing rule "
                "matched the name — the name may be unrecognized/hallucinated "
                "and was routed to default_cell."
            ),
            "inputSchema": _schema(
                ["policy", "entity"],
                {"policy": string, "entity": string},
            ),
            "outputSchema": explanation_out,
        },
        {
            "name": "policy_list",
            "description": (
                "List the policy-to-cell routing table (default_cell plus the "
                "configured pattern rules) and each governance cell's real "
                "enabled state on this server. enabled reflects actual "
                "enablement: the complex tier (structured/protected) reports "
                "enabled:false without LEGIS_HMAC_KEY."
            ),
            "inputSchema": _schema([], {}),
            "outputSchema": _schema(
                ["default_cell", "rules", "cells"],
                {
                    "default_cell": cell_enum,
                    "rules": {
                        "type": "array",
                        "items": _schema(
                            ["pattern", "cell"],
                            {"pattern": string, "cell": cell_enum},
                        ),
                    },
                    "cells": {
                        "type": "array",
                        "items": _schema(
                            [
                                "cell",
                                "enabled",
                                "judge_inline",
                                "self_clearable",
                                "human_in_loop",
                            ],
                            {
                                "cell": cell_enum,
                                "enabled": boolean,
                                "judge_inline": boolean,
                                "self_clearable": boolean,
                                "human_in_loop": boolean,
                            },
                        ),
                    },
                },
            ),
        },
        {
            "name": "override_submit",
            "description": (
                "Submit an override as the launch-bound agent. The server "
                "routes to the governing cell and returns a discriminated "
                "outcome envelope. Identity (weft SEI-on-entry): pass entity as "
                "a locator/symbol for legis to resolve (L2, degrades to a "
                "locator key if Loomweave can't resolve it), OR pass entity_sei "
                "to bind a SEI you already hold at the point of entry (L1) — "
                "legis verifies the SEI is alive and that entity resolves live "
                "to the same SEI before keying the governance record on it. A "
                "non-resolving or unbound entity_sei returns UNRESOLVED_INPUT "
                "(weft-reason unresolved_input) and records NOTHING, never a "
                "locator-keyed record masquerading as a stable bind or evidence "
                "on an unrelated stable identity. entity is still required (it "
                "carries the source-path used for the protected-cell fingerprint "
                "binding)."
            ),
            "inputSchema": _schema(
                ["policy", "entity", "rationale"],
                {
                    "policy": string,
                    "entity": string,
                    "rationale": string,
                    "entity_sei": string,
                    "file_fingerprint": string,
                    "ast_path": string,
                    "idempotency_key": string,
                },
            ),
            "outputSchema": override_submit_out,
        },
        {
            "name": "signoff_status_get",
            "description": (
                "Poll whether a structured sign-off request has been cleared. "
                "When cleared and the binding ledger is enabled, the payload "
                "also carries the recorded Filigree binding for the seq "
                "(binding: object, or null when not yet bound)."
            ),
            "inputSchema": _schema(["seq"], {"seq": integer}),
            # signed_by/signed_at appear on cleared payloads with a signed
            # record; binding appears only when the ledger is wired (null =
            # wired but not yet bound — distinguishable from no-ledger).
            "outputSchema": _schema(
                ["cleared", "seq"],
                {
                    "cleared": boolean,
                    "seq": integer,
                    "signed_by": nullable_string,
                    "signed_at": nullable_string,
                    "binding": {"type": ["object", "null"]},
                },
            ),
        },
        {
            "name": "signoff_bind_issue",
            "description": (
                "Bind a CLEARED structured sign-off to a Filigree issue. The "
                "bound entity identity (SEI) and content hash come from the "
                "recorded sign-off — never from the caller. Records the "
                "verified binding evidence that filigree_closure_gate_get "
                "reads, completing the sign-off → Filigree closure flow. The "
                "sign-off must first be cleared by an operator (poll "
                "signoff_status_get with the seq from override_submit)."
            ),
            "inputSchema": _schema(
                ["seq", "issue_id"], {"seq": integer, "issue_id": string}
            ),
            # Open object: the Filigree attach response is merged in verbatim
            # (Filigree owns that shape); legis pins only its own keys.
            "outputSchema": {
                "type": "object",
                "additionalProperties": True,
                "required": ["signoff_seq", "binding_signature"],
                "properties": {
                    "signoff_seq": integer,
                    "binding_signature": nullable_string,
                    "binding_seq": integer,
                },
            },
        },
        {
            "name": "policy_evaluate",
            "description": (
                "Evaluate a policy against a target without recording an override."
            ),
            "inputSchema": _schema(
                ["policy", "target"], {"policy": string, "target": object_schema}
            ),
            "outputSchema": _schema(
                ["outcome", "detail", "provenance_gap"],
                {
                    "outcome": {
                        "type": "string",
                        "enum": [result.value for result in PolicyResult],
                    },
                    "detail": string,
                    "provenance_gap": boolean,
                },
            ),
        },
        {
            "name": "scan_route",
            "description": (
                "Route Wardline scan findings through one cell, a severity_map "
                "policy, or a cell plus fail_on threshold. Returns a discriminated "
                "success outcome: ROUTED (governed). An unsigned dirty-tree dev "
                "artifact in the default keyless posture is governed and stamped "
                "artifact_status=dirty. Where signed provenance is required, a dirty "
                "artifact returns SKIPPED_DIRTY_TREE with isError:true; commit for a "
                "signed artifact, or set LEGIS_WARDLINE_ALLOW_DIRTY=1 to govern it "
                "unsigned in dev."
            ),
            "inputSchema": _schema(
                ["scan"],
                {
                    "scan": object_schema,
                    "cell": {
                        "type": "string",
                        "description": (
                            "Request-side routing cell. Gated behind "
                            "LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING and rejected "
                            "(INVALID_CELL_SPEC) when the server owns routing "
                            "(LEGIS_WARDLINE_CELL / LEGIS_WARDLINE_CELL_BY_SEVERITY)."
                        ),
                    },
                    "severity_map": {
                        "type": "object",
                        "description": (
                            "Request-side per-severity routing map. Gated behind "
                            "LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING and rejected "
                            "(INVALID_CELL_SPEC) when the server owns routing."
                        ),
                    },
                    "fail_on": {
                        "type": "string",
                        "description": (
                            "Request-side fail-on severity threshold (used with "
                            "cell). Gated behind "
                            "LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING and rejected "
                            "(INVALID_CELL_SPEC) when the server owns routing."
                        ),
                    },
                },
            ),
            "outputSchema": scan_route_out,
        },
        {
            "name": "git_branch_list",
            "description": "List local git branches and upstream divergence facts.",
            "inputSchema": _schema([], {}),
            "outputSchema": _schema(
                ["branches"],
                {
                    "branches": {
                        "type": "array",
                        "items": _schema(
                            [
                                "name",
                                "head_sha",
                                "is_current",
                                "upstream",
                                "ahead",
                                "behind",
                            ],
                            {
                                "name": string,
                                "head_sha": string,
                                "is_current": boolean,
                                "upstream": nullable_string,
                                "ahead": nullable_integer,
                                "behind": nullable_integer,
                            },
                        ),
                    }
                },
            ),
        },
        {
            "name": "git_commit_get",
            "description": "Read one git commit by SHA or safe ref.",
            "inputSchema": _schema(["sha"], {"sha": string}),
            "outputSchema": _schema(
                ["commit"],
                {
                    "commit": _schema(
                        [
                            "sha",
                            "author_name",
                            "author_email",
                            "message",
                            "committed_at",
                            "parents",
                            "files_changed",
                            "insertions",
                            "deletions",
                        ],
                        {
                            "sha": string,
                            "author_name": string,
                            "author_email": string,
                            "message": string,
                            "committed_at": string,
                            "parents": string_array,
                            "files_changed": plain_integer,
                            "insertions": plain_integer,
                            "deletions": plain_integer,
                        },
                    )
                },
            ),
        },
        {
            "name": "git_rename_list",
            "description": "List git rename evidence for a revision range.",
            "inputSchema": _schema(["rev_range"], {"rev_range": string}),
            "outputSchema": _schema(["renames"], {"renames": rename_array}),
        },
        {
            "name": "git_rename_feed_get",
            "description": (
                "Loomweave-ready rename feed: committed renames over base..head plus "
                "optional uncommitted working-tree renames."
            ),
            "inputSchema": _schema(
                ["base"],
                {
                    "base": string,
                    "head": string,
                    "include_worktree": {"type": "boolean"},
                },
            ),
            "outputSchema": _schema(
                [
                    "status",
                    "worktree_checked",
                    "base",
                    "head",
                    "committed",
                    "working_tree",
                ],
                {
                    "status": {
                        "type": "string",
                        "enum": ["committed_only", "committed_and_worktree"],
                    },
                    "worktree_checked": boolean,
                    "base": string,
                    "head": string,
                    "committed": rename_array,
                    "working_tree": rename_array,
                },
            ),
        },
        {
            "name": "filigree_closure_gate_get",
            "description": "Read whether legis holds verified binding evidence for closing a Filigree issue.",
            "inputSchema": _schema(["issue_id"], {"issue_id": string}),
            "outputSchema": _schema(
                ["allowed", "issue_id", "reason", "evidence"],
                {
                    "allowed": boolean,
                    "issue_id": string,
                    "reason": string,
                    "evidence": {
                        "type": ["object", "null"],
                        "additionalProperties": False,
                        "required": ["signoff_seq", "content_hash", "recorded_at"],
                        "properties": {
                            "signoff_seq": nullable_integer,
                            "content_hash": nullable_string,
                            "recorded_at": nullable_string,
                        },
                    },
                },
            ),
        },
        {
            "name": "warpline_preflight_get",
            "description": (
                "ADVISORY preflight context from the warpline sibling: impact "
                "radius + reverify worklist over base..head. Purely advisory — "
                "NEVER a governance verdict. Discriminated: 'checked' carries the "
                "advisory facts; 'unavailable' (client unconfigured, transport "
                "failure, or payload shape mismatch) carries reasons. Never read a "
                "missing 'checked' as 'nothing impacted'."
            ),
            "inputSchema": _schema(["base"], {"base": string, "head": string}),
            "outputSchema": _one_of(
                [
                    _schema(
                        ["status", "impact_radius", "reverify_worklist"],
                        {
                            "status": {"type": "string", "enum": ["checked"]},
                            "impact_radius": {"type": "object"},
                            "reverify_worklist": {"type": "object"},
                        },
                    ),
                    _schema(
                        ["status", "unavailable"],
                        {
                            "status": {"type": "string", "enum": ["unavailable"]},
                            "unavailable": {
                                "type": "array",
                                "items": _schema(["reason"], {"reason": string}),
                            },
                        },
                    ),
                ]
            ),
        },
        {
            "name": "plainweave_preflight_get",
            "description": (
                "ADVISORY preflight context from the plainweave sibling: scoped "
                "requirement/intent facts (envelope weft.plainweave.preflight_facts.v1, "
                "ADR-006) over base..head. Purely advisory — NEVER a governance "
                "verdict (plainweave emits facts only; Legis owns policy/audit). "
                "Discriminated: 'checked' carries the advisory facts envelope; "
                "'unavailable' (client unconfigured, transport failure, error "
                "envelope, or payload shape mismatch) carries reasons. Never read a "
                "missing 'checked' as 'nothing impacted'. Follow the producer's "
                "scope.requirement_page.next_offset with requirement_offset when "
                "has_more is true; pages stay bounded and are never auto-aggregated."
            ),
            "inputSchema": _schema(
                ["base"],
                {
                    "base": string,
                    "head": string,
                    "requirement_limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                    },
                    "requirement_offset": {"type": "integer", "minimum": 0},
                },
            ),
            "outputSchema": _one_of(
                [
                    _schema(
                        ["status", "preflight_facts"],
                        {
                            "status": {"type": "string", "enum": ["checked"]},
                            "preflight_facts": {"type": "object"},
                        },
                    ),
                    _schema(
                        ["status", "unavailable"],
                        {
                            "status": {"type": "string", "enum": ["unavailable"]},
                            "unavailable": {
                                "type": "array",
                                "items": _schema(["reason"], {"reason": string}),
                            },
                        },
                    ),
                ]
            ),
        },
        {
            "name": "identity_gap_list",
            "description": (
                "List governance attestations whose SEI Loomweave now reports "
                "dead (orphaned). Honest two-state payload: status 'checked' "
                "(checked, possibly zero gaps) vs 'unavailable' (could not "
                "check, with reasons) — never read an empty gaps list as "
                "all-clear without status 'checked'."
            ),
            "inputSchema": _schema([], {}),
            # "unavailable" (the reasons list) is present only on the
            # could-not-check path — a checked payload carries status+gaps.
            "outputSchema": _schema(
                ["status", "gaps"],
                {
                    "status": {"type": "string", "enum": ["checked", "unavailable"]},
                    "gaps": {
                        "type": "array",
                        "items": _schema(
                            ["sei", "reason", "lineage"],
                            {
                                "sei": string,
                                "reason": string,
                                "lineage": {
                                    "type": "array",
                                    "items": {"type": "object"},
                                },
                            },
                        ),
                    },
                    "unavailable": {
                        "type": "array",
                        "items": _schema(["reason"], {"reason": string}),
                    },
                },
            ),
        },
        {
            "name": "lineage_integrity_get",
            "description": (
                "Verify each recorded lineage snapshot is still a prefix of "
                "the entity's current Loomweave lineage. Three-way status with "
                "diverged > unverified > verified precedence: any divergence "
                "wins, any unverifiable lineage blocks 'verified'. Appends "
                "(rename/move) are legitimate; a removed or mutated prior "
                "event is divergence."
            ),
            "inputSchema": _schema([], {}),
            "outputSchema": _schema(
                ["status", "divergences", "unavailable"],
                {
                    "status": {
                        "type": "string",
                        "enum": ["diverged", "unverified", "verified", "unavailable"],
                    },
                    "divergences": {
                        "type": "array",
                        "items": _schema(
                            ["sei", "recorded_length", "current_length"],
                            {
                                "sei": string,
                                "recorded_length": plain_integer,
                                "current_length": plain_integer,
                            },
                        ),
                    },
                    "unavailable": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["reason"],
                            "properties": {"sei": string, "reason": string},
                        },
                    },
                },
            ),
        },
        {
            "name": "pull_request_get",
            "description": "Read recorded pull-request metadata with joined check outcomes.",
            "inputSchema": _schema(["number"], {"number": integer}),
            "outputSchema": _schema(
                [
                    "number",
                    "title",
                    "base",
                    "head",
                    "state",
                    "url",
                    "recorded_by",
                    "provenance",
                    "checks",
                ],
                {
                    "number": integer,
                    "title": string,
                    "base": string,
                    "head": string,
                    "state": {
                        "type": "string",
                        "enum": [state.value for state in PullRequestState],
                    },
                    "url": nullable_string,
                    "recorded_by": nullable_string,
                    "provenance": {
                        "type": "string",
                        "enum": [p.value for p in Provenance],
                    },
                    "checks": checks_array,
                },
            ),
        },
        {
            "name": "check_list",
            "description": (
                "Read recorded CI/check outcomes for a commit, branch, or pull "
                "request target."
            ),
            "inputSchema": _schema(
                ["target_type", "target"],
                {
                    "target_type": {
                        "type": "string",
                        "enum": list(_CHECK_TARGET_TYPES),
                        "description": (
                            "Target kind. target_type 'pr' requires an "
                            "integer-coercible target (the PR number)."
                        ),
                    },
                    "target": string,
                },
            ),
            "outputSchema": _schema(
                ["target_type", "target", "checks"],
                {
                    "target_type": {
                        "type": "string",
                        "enum": list(_CHECK_TARGET_TYPES),
                    },
                    # Echoed as given for commit/branch, coerced to int for pr.
                    "target": {"type": ["string", "integer"]},
                    "checks": checks_array,
                },
            ),
        },
        {
            "name": "override_rate_get",
            "description": "Read the fixed operator force-past override-rate gate.",
            "inputSchema": _schema([], {}),
            "outputSchema": _schema(
                ["status", "rate", "sample_size", "note"],
                {
                    "status": {
                        "type": "string",
                        "enum": [status.value for status in GateStatus],
                    },
                    "rate": {"type": "number"},
                    "sample_size": {"type": "integer", "minimum": 0},
                    "note": {"const": _OVERRIDE_RATE_NOTE},
                },
            ),
        },
        {
            "name": "override_list",
            "description": (
                "Read the verified governance trail (the same records GET "
                "/overrides serves): prior overrides, sign-off requests, and "
                "governance events, each with its seq handle. Optional exact-"
                "match filters narrow by policy, entity (the recorded "
                "entity_key value — SEI or locator), or submitted_by (the "
                "recorded agent_id; a read filter — the caller's own identity "
                "stays launch-bound and is never a call argument). Verified-"
                "records-only honesty: a tampered trail is "
                "AUDIT_INTEGRITY_FAILURE, never silently read."
            ),
            "inputSchema": _schema(
                [],
                {"policy": string, "entity": string, "submitted_by": string},
            ),
            # Items are the recorded payloads plus seq — open objects: the
            # trail carries heterogeneous record kinds (overrides, sign-off
            # events, SEI_BACKFILL, …) whose shapes the records own.
            "outputSchema": _schema(
                ["overrides"],
                {
                    "overrides": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": True,
                            "required": ["seq"],
                            "properties": {"seq": integer},
                        },
                    }
                },
            ),
        },
        {
            "name": "doctor_get",
            "description": (
                "Report-only legis install/config health read — the same JSON "
                "`legis doctor --format json` emits (ok, checks, "
                "next_actions), run against the server's source root. Never "
                "repairs anything: fixes stay operator/CLI (`legis doctor "
                "--fix` for [auto-fixable] items; [operator] items need "
                "out-of-band config and a relaunch)."
            ),
            "inputSchema": _schema([], {}),
            "outputSchema": _schema(
                ["ok", "checks", "next_actions"],
                {
                    "ok": boolean,
                    "checks": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["id", "status", "fixed", "repairable"],
                            "properties": {
                                "id": string,
                                "status": {
                                    "type": "string",
                                    "enum": ["ok", "warn", "error"],
                                },
                                "fixed": boolean,
                                "repairable": boolean,
                                "message": string,
                            },
                        },
                    },
                    "next_actions": string_array,
                },
            ),
        },
        {
            "name": "policy_boundary_check",
            "description": (
                "Read-only scan validating @policy_boundary declarations "
                "against current behavioural evidence (the policy-authoring "
                "loop's `legis policy-boundary-check`). Returns a "
                "discriminated outcome: PASS (>=1 file scanned, no findings), "
                "FINDINGS with the findings list, or NO_ROOT when the scan "
                "looked at nothing — the resolved root does not exist OR holds "
                "zero analyzable Python files. A zero-file scan is NEVER a clean "
                "PASS; on NO_ROOT pass an explicit `root` (and `repo_root` if "
                "needed). root defaults to <repo_root>/src and repo_root to the "
                "server's source root (its launch working directory); relative "
                "paths resolve against repo_root. The result always echoes "
                "`scanned_root` and `repo_root` so a wrong-but-existing default "
                "(e.g. the server's own source) is visible, not silently trusted."
            ),
            "inputSchema": _schema(
                [],
                {"root": string, "repo_root": string},
            ),
            "outputSchema": _schema(
                ["outcome", "findings"],
                {
                    "outcome": {
                        "type": "string",
                        "enum": ["PASS", "FINDINGS", "NO_ROOT"],
                    },
                    "findings": {
                        "type": "array",
                        "items": _schema(
                            ["rule_id", "file_path", "line", "qualname", "reason"],
                            {
                                "rule_id": string,
                                "file_path": string,
                                "line": {"type": "integer", "minimum": 0},
                                "qualname": string,
                                "reason": string,
                            },
                        ),
                    },
                    "scanned_root": string,
                    "repo_root": string,
                    "detail": string,
                },
            ),
        },
        # Named decision (legis-e5c57dedd1): check recording IS on the agent
        # surface — the agent that ran the check is the natural source of that
        # claim, and the launch-bound agent_id is stronger attribution than the
        # HTTP writer token. PR recording is NOT: the forge, not the agent, is
        # the source of truth for PR state; the legis PR store is a CI/forge-
        # integration mirror and stays HTTP-writer-only (POST /git/pulls).
        {
            "name": "check_report",
            "description": (
                "Record a CI/check outcome as the launch-bound agent (the "
                "agent that ran the check is the natural recorder; "
                "recorded_by is the launch-bound agent_id, never a call "
                "argument). The recorded fact is a writer-supplied claim with "
                "provenance 'unauthenticated' — readers must not treat it as "
                "forge-attested."
            ),
            "inputSchema": _schema(
                ["check_name", "run_id", "commit_sha", "outcome"],
                {
                    "check_name": string,
                    "run_id": string,
                    "commit_sha": string,
                    "outcome": {
                        "type": "string",
                        "enum": [o.value for o in CheckOutcome],
                    },
                    "branch": string,
                    "pr": integer,
                    "ran_against": string,
                    "rule_set": string,
                    "policy_version": string,
                    "started_at": string,
                    "finished_at": string,
                },
            ),
            # The recorded check echoed back, plus the recorded posture: who
            # the launch binding attributed the claim to and that it is
            # unauthenticated (Q-M2).
            "outputSchema": _schema(
                [*sorted(check_run_properties), "recorded_by", "provenance"],
                {
                    **check_run_properties,
                    "recorded_by": string,
                    "provenance": {
                        "type": "string",
                        "enum": [p.value for p in Provenance],
                    },
                },
            ),
        },
        {
            "name": "posture_get",
            "description": (
                "Read the governing posture floor and, for a named policy, the "
                "floored effective cell (max(floor, registry cell)) the agent "
                "will actually be routed to. Read-only: there is NO posture_set "
                "over MCP — moving the floor is an operator/CLI action behind an "
                "elevation session. A missing/empty ledger reports floor "
                "'structured' (fail-closed, never chill). "
                "epoch_reset_unacknowledged:true means an operator key was reset "
                "(rekey) and no signed transition has acknowledged the new epoch "
                "yet — the same pending-operator signal doctor exits non-zero on."
            ),
            "inputSchema": _schema([], {"policy": string}),
            "outputSchema": _schema(
                ["floor", "epoch_reset_unacknowledged"],
                {
                    "floor": cell_enum,
                    "effective_cell": cell_enum,
                    "epoch_reset_unacknowledged": boolean,
                },
            ),
        },
        {
            "name": "attestation_get",
            "description": (
                "Per-SEI human-cleared governance attestation FACTS (no proven_good "
                "verdict). Through the same fail-closed verified-trail path the "
                "honesty reads use: a tampered trail -> AUDIT_INTEGRITY_FAILURE; an "
                "engine-only deployment (no protected gate) -> 'unavailable'. Never "
                "read an empty attestations list under 'unavailable' as 'never "
                "attested'; a forged attestation is never returned."
            ),
            "inputSchema": _schema(["sei"], {"sei": string}),
            "outputSchema": _one_of(
                [
                    _schema(
                        ["status", "sei", "attestations"],
                        {
                            "status": {"type": "string", "enum": ["checked"]},
                            "sei": string,
                            "attestations": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": [
                                        "kind",
                                        "content_hash",
                                        "recorded_at",
                                        "seq",
                                    ],
                                    "properties": {
                                        "kind": {
                                            "type": "string",
                                            "enum": [
                                                "signoff_cleared",
                                                "operator_override",
                                            ],
                                        },
                                        "content_hash": string,
                                        "recorded_at": string,
                                        "seq": integer,
                                        "signoff_seq": integer,
                                    },
                                },
                            },
                        },
                    ),
                    _schema(
                        ["status", "sei", "attestations", "unavailable"],
                        {
                            "status": {"type": "string", "enum": ["unavailable"]},
                            "sei": string,
                            "attestations": {"type": "array", "maxItems": 0},
                            "unavailable": {
                                "type": "array",
                                "items": _schema(["reason"], {"reason": string}),
                            },
                        },
                    ),
                ]
            ),
        },
        {
            "name": "governance_read",
            "description": (
                "Per-SEI VERIFIED governance CLEARANCE facts (governance_read.v1). "
                "Advisory — never gate on this. records:[] under 'checked' = no "
                "verified clearance for this SEI on the verified trail, NOT "
                "'ungoverned'; 'unavailable' = trail not signature-verifiable, "
                "NOT 'absent'. A tampered trail -> AUDIT_INTEGRITY_FAILURE. "
                "Distinct from attestation_get: projects clearance_record shape "
                "(disposition/posture/authority/as_of/reasons), not raw attestation "
                "fields (kind/seq)."
            ),
            "inputSchema": _schema(["sei"], {"sei": string}),
            "outputSchema": _one_of(
                [
                    # checked variant: verified trail read; records may be empty
                    _schema(
                        ["status", "sei", "records"],
                        {
                            "status": {"type": "string", "enum": ["checked"]},
                            "sei": string,
                            "records": {
                                "type": "array",
                                "items": _schema(
                                    [
                                        "sei",
                                        "disposition",
                                        "posture",
                                        "authority",
                                        "as_of",
                                        "reasons",
                                        "content_hash",
                                    ],
                                    {
                                        "sei": string,
                                        "disposition": {
                                            "type": "string",
                                            "enum": ["cleared"],
                                        },
                                        "posture": {
                                            "type": "string",
                                            "enum": [
                                                "protected_override",
                                                "operator_signoff",
                                            ],
                                        },
                                        "authority": {
                                            "type": "string",
                                            "enum": ["operator"],
                                        },
                                        "as_of": string,
                                        "reasons": {
                                            "type": "array",
                                            "minItems": 1,
                                            "items": {
                                                "type": "string",
                                                "enum": [
                                                    "operator_override",
                                                    "signoff_cleared",
                                                ],
                                            },
                                        },
                                        "content_hash": string,
                                    },
                                ),
                            },
                        },
                    ),
                    # unavailable variant: trail not signature-verifiable
                    _schema(
                        ["status", "sei", "records", "unavailable"],
                        {
                            "status": {"type": "string", "enum": ["unavailable"]},
                            "sei": string,
                            "records": {"type": "array", "maxItems": 0},
                            "unavailable": {
                                "type": "array",
                                "items": _schema(["reason"], {"reason": string}),
                            },
                        },
                    ),
                ]
            ),
        },
    ]


def _tool_result(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(value, sort_keys=True)}],
        "structuredContent": value,
    }


def _recovery_for(code: str) -> dict[str, Any]:
    recoverable = code not in {"AUDIT_INTEGRITY_FAILURE", "INTERNAL_ERROR"}
    next_actions = {
        "INVALID_ARGUMENT": "Correct the tool arguments and retry.",
        "INVALID_CELL_SPEC": (
            "scan_route routing is server-owned and unconfigured by default. The "
            "operator sets LEGIS_WARDLINE_CELL (e.g. =surface_only) or "
            "LEGIS_WARDLINE_CELL_BY_SEVERITY out-of-band, then relaunches. "
            "(Request-side routing requires the LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING "
            "opt-in — discouraged.) The error message names which kind of cell "
            "spec was rejected."
        ),
        "WARDLINE_DIRTY_TREE": (
            "Commit the working tree and rerun Wardline to produce a signed "
            "artifact, or set LEGIS_WARDLINE_ALLOW_DIRTY=1 out-of-band for a "
            "dev-only unsigned dirty artifact. Nothing was governed."
        ),
        "CELL_NOT_ENABLED": (
            "Two enablement tiers, by cell — both operator-enabled, out-of-band. "
            "Simple tier is reachable WITHOUT a signing key: the operator maps "
            "the policy to a cell via policy/cells.toml or LEGIS_POLICY_CELLS "
            "(LEGIS_DEV_DEFAULT_CELLS=1 selects the chill dev default), then "
            "relaunches; coached also needs LEGIS_JUDGE_PROVIDER and its "
            "provider credentials set out-of-band. Complex tier "
            "(structured/protected and the binding ledger) additionally needs "
            "LEGIS_HMAC_KEY set by the operator out-of-band, then a relaunch. "
            "The error message names which cell is unenabled."
        ),
        "UNRESOLVED_INPUT": (
            "The inline entity_sei did not resolve to a live, stable identity, "
            "or it was not bound to the submitted entity, so nothing was recorded "
            "(weft SEI-on-entry fail-closed). See the weft_reason.fix: confirm "
            "the SEI is alive and matches the entity in Loomweave, or drop "
            "entity_sei and submit the entity as a locator/symbol for legis to "
            "resolve."
        ),
        "NO_SUCH_REQUEST": "Poll a known sign-off sequence returned by override_submit.",
        "SIGNOFF_NOT_CLEARED": (
            "The sign-off has not been cleared by an operator yet. Poll "
            "signoff_status_get until cleared:true, then retry "
            "signoff_bind_issue."
        ),
        "BINDING_UNAVAILABLE": (
            "The cleared sign-off is locator-keyed (no stable SEI), so a "
            "rename-stable Filigree binding would orphan (ADR-0003, "
            "fail-closed). The sign-off itself stands. Ask the operator to "
            "wire Loomweave identity (LOOMWEAVE_API_URL) so requests resolve "
            "to an SEI, or retry after an SEI_BACKFILL recovery event."
        ),
        "FILIGREE_UNAVAILABLE": (
            "The Filigree call failed at the transport layer; nothing was "
            "bound. Check that Filigree is reachable at FILIGREE_API_URL and "
            "retry."
        ),
        "NOT_FOUND": "Refresh the target identifier and retry.",
        "UNKNOWN_TOOL": "Call tools/list and use one of the advertised tool names.",
        "AUDIT_INTEGRITY_FAILURE": "Stop and ask an operator to inspect the governance trail.",
        "GIT_ERROR": "Check the git ref or revision range and retry.",
    }
    return {
        "recoverable": recoverable,
        "next_action": next_actions.get(
            code, "Inspect the error message before retrying."
        ),
    }


def _tool_error(
    code: str, message: str, *, weft_reason: dict[str, Any] | None = None
) -> dict[str, Any]:
    recovery = _recovery_for(code)
    # LEG-2: the recovery hint rides in the text content too — text-only MCP
    # clients never see structuredContent, so a hint kept there alone is
    # invisible to them. The "{code}: {message}" first line is a stable prefix
    # clients may parse; the next_action is appended after it.
    structured: dict[str, Any] = {
        "error_code": code,
        "message": message,
        **recovery,
    }
    # weft SEI-on-entry doctrine: a non-resolving inline identity carries a
    # structured weft-reason {kind, cause, fix} so the agent can repair the input
    # without parsing message text. Present only on the surfaces that bind a SEI.
    if weft_reason is not None:
        structured["weft_reason"] = weft_reason
    return {
        "isError": True,
        "content": [
            {
                "type": "text",
                "text": f"{code}: {message}\nnext_action: {recovery['next_action']}",
            }
        ],
        "structuredContent": structured,
    }


def _tool_dirty_tree_error(exc: WardlineDirtyTreeError) -> dict[str, Any]:
    payload = exc.to_payload()
    return _tool_error(
        "WARDLINE_DIRTY_TREE",
        (
            f"{payload['reason']}: {payload['detail']} "
            f"(posture={payload['posture']}, cause={payload['cause']})"
        ),
    )


def _service_error(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, AuditIntegrityError):
        return _tool_error("AUDIT_INTEGRITY_FAILURE", str(exc))
    if isinstance(exc, BindingError):
        return _tool_error("AUDIT_INTEGRITY_FAILURE", str(exc))
    if isinstance(exc, NotEnabledError):
        return _tool_error("CELL_NOT_ENABLED", str(exc))
    if isinstance(exc, NoSuchRequestError):
        # Subclass of NotFoundError — must precede it to keep the sign-off
        # flow's NO_SUCH_REQUEST code (same as signoff_status_get).
        return _tool_error("NO_SUCH_REQUEST", str(exc))
    if isinstance(exc, NotFoundError):
        return _tool_error("NOT_FOUND", str(exc))
    if isinstance(exc, NotClearedError):
        return _tool_error("SIGNOFF_NOT_CLEARED", str(exc))
    if isinstance(exc, BindingUnavailableError):
        return _tool_error("BINDING_UNAVAILABLE", str(exc))
    if isinstance(exc, FiligreeError):
        # A down/unreachable Filigree is an expected operational state for an
        # agent — typed and recoverable, not an INTERNAL_ERROR.
        return _tool_error("FILIGREE_UNAVAILABLE", str(exc))
    if isinstance(exc, UnresolvedInputError):
        # weft SEI-on-entry: an inline entity_sei that did not resolve. Nothing
        # was recorded; the weft_reason carries the structured cause/fix.
        return _tool_error(
            "UNRESOLVED_INPUT",
            str(exc),
            weft_reason={
                "kind": "unresolved_input",
                "cause": exc.cause,
                "fix": exc.fix,
            },
        )
    if isinstance(exc, InvalidArgumentError):
        return _tool_error("INVALID_ARGUMENT", str(exc))
    if isinstance(exc, WardlineRoutingError):
        # All three routing kinds (server-misconfigured / server-owned /
        # malformed) collapse to one MCP code; the HTTP adapter splits them by
        # status. Must precede the generic ServiceError case below.
        return _tool_error("INVALID_CELL_SPEC", str(exc))
    if isinstance(exc, GitError):
        return _tool_error("GIT_ERROR", str(exc))
    if isinstance(exc, ServiceError):
        return _tool_error("SERVICE_ERROR", str(exc))
    if isinstance(exc, ValueError):
        return _tool_error("INVALID_ARGUMENT", str(exc))
    # Unexpected: the typed cases above are expected and reach the caller as their
    # own codes, so they stay quiet. This fall-through is a genuine surprise — the
    # caller gets INTERNAL_ERROR, but the operator/Sentry would see nothing unless
    # we log it here with the exception. (exc_info=exc, not True: _service_error
    # may be called outside an active except block.)
    logger.error("unhandled MCP tool error: %s", exc, exc_info=exc)
    return _tool_error("INTERNAL_ERROR", str(exc))


def _allowed_tool_arguments(name: str) -> set[str] | None:
    for tool in tool_definitions():
        if tool["name"] == name:
            return set(tool["inputSchema"].get("properties", {}))
    return None


def _validate_argument_keys(name: str, args: dict[str, Any]) -> None:
    allowed = _allowed_tool_arguments(name)
    if allowed is None:
        return
    unexpected = sorted(set(args) - allowed)
    if unexpected:
        joined = ", ".join(unexpected)
        raise InvalidArgumentError(f"unexpected argument(s) for {name}: {joined}")


def _arguments(params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if not isinstance(params, dict):
        raise ValueError("tools/call params must be an object")
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str):
        raise ValueError("tools/call requires a string tool name")
    if not isinstance(arguments, dict):
        raise ValueError("tools/call arguments must be an object")
    return name, arguments


def _require(args: dict[str, Any], key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"argument {key!r} must be a non-empty string")
    return value


def _optional_string(args: dict[str, Any], key: str) -> str | None:
    value = args.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"argument {key!r} must be a non-empty string when provided")
    return value


def _optional_int(
    args: dict[str, Any], key: str, *, minimum: int, maximum: int | None = None
) -> int | None:
    if key not in args:
        return None
    value = args[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidArgumentError(f"argument {key!r} must be an integer")
    if value < minimum:
        raise InvalidArgumentError(f"argument {key!r} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise InvalidArgumentError(f"argument {key!r} must be at most {maximum}")
    return value


def _require_int(args: dict[str, Any], key: str) -> int:
    raw = args.get(key)
    if isinstance(raw, int) and not isinstance(raw, bool):
        value = raw
    elif isinstance(raw, str) and raw:
        try:
            value = int(raw)
        except ValueError as exc:
            raise InvalidArgumentError(f"argument {key!r} must be an integer") from exc
    else:
        raise InvalidArgumentError(f"argument {key!r} must be an integer")
    if value < 1:
        raise InvalidArgumentError(f"argument {key!r} must be a positive integer")
    return value


def _require_object(args: dict[str, Any], key: str) -> dict[str, Any]:
    value = args.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"argument {key!r} must be an object")
    return value


def _check_to_dict(run: CheckRun) -> dict[str, Any]:
    return {
        "check_name": run.check_name,
        "run_id": run.run_id,
        "commit_sha": run.commit_sha,
        "outcome": run.outcome.value,
        "branch": run.branch,
        "pr": run.pr,
        "ran_against": run.ran_against,
        "rule_set": run.rule_set,
        "policy_version": run.policy_version,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
    }


def _registry(runtime: McpRuntime) -> PolicyCellRegistry:
    # Defensive fallback if a runtime was built without a registry: fail closed
    # rather than self-clear (Q-M7 / audit H6).
    return runtime.cell_registry or fail_closed_policy_cells()


class _NoLedger:
    """Stand-in for a runtime with no posture ledger handle (fail-closed).

    read_floor() -> None maps to the structured floor in floored_registry, so a
    runtime built without posture wiring never self-clears below structured.
    """

    def read_floor(self) -> str | None:
        return None


def _floored_registry(runtime: McpRuntime) -> FlooredRegistry:
    """The agent-visible registry with the current posture floor applied (D0).

    Built FRESH at every cell-resolution site: floored_registry reads
    read_floor() at call time (D2), so the floor is never cached. A missing
    ledger (None handle or empty store) maps to structured, never chill.
    """
    ledger = runtime.posture_ledger or _NoLedger()
    return floored_registry(_registry(runtime), ledger)


def _explanation_payload(explanation) -> dict[str, Any]:
    payload = explanation.to_payload()
    payload["available_moves"] = [
        move for move in payload["available_moves"] if move in _AGENT_TOOLS
    ]
    return payload


def _grammar(runtime: McpRuntime) -> PolicyGrammar:
    if runtime.grammar is None:
        runtime.grammar = default_grammar()
    return runtime.grammar


def _git(runtime: McpRuntime) -> GitSurface:
    if runtime.git_surface is None:
        runtime.git_surface = GitSurface(
            os.environ.get("LEGIS_SOURCE_ROOT") or os.getcwd()
        )
    return runtime.git_surface


def _engine(runtime: McpRuntime) -> EnforcementEngine:
    if runtime.engine is None:
        from legis.config import governance_db_url

        store = AuditStore(governance_db_url())
        runtime.engine = EnforcementEngine(store, SystemClock())
    return runtime.engine


def _coached_engine(runtime: McpRuntime) -> EnforcementEngine | None:
    if runtime.coached_engine is not None:
        return runtime.coached_engine
    if runtime.engine is not None and runtime.engine.has_judge:
        return runtime.engine
    from legis.config import governance_db_url
    from legis.enforcement.judge_factory import configured_judge_from_env

    judge = configured_judge_from_env("MCP")
    if judge is None:
        return None
    runtime.coached_engine = EnforcementEngine(
        AuditStore(governance_db_url()), SystemClock(), judge
    )
    return runtime.coached_engine


def _simple_engine_for_cell(runtime: McpRuntime, cell: str) -> EnforcementEngine | None:
    return _coached_engine(runtime) if cell == "coached" else _engine(runtime)


def _checks(runtime: McpRuntime) -> CheckSurface:
    if runtime.check_surface is None:
        from legis.config import check_db_url

        runtime.check_surface = CheckSurface(check_db_url())
    return runtime.check_surface


def _pulls(runtime: McpRuntime) -> PullSurface:
    if runtime.pull_surface is None:
        from legis.config import pull_db_url

        runtime.pull_surface = PullSurface(pull_db_url())
    return runtime.pull_surface


def _blocked_reason_code(judge_rationale: str | None) -> str:
    text = (judge_rationale or "").lower()
    if "rationale" in text or "justification" in text or "insufficient" in text:
        return "RATIONALE_INSUFFICIENT"
    if "code" in text or "violation" in text or "eval" in text or "untrusted" in text:
        return "CODE_VIOLATION"
    if "hard block" in text or "forbidden" in text or "never allow" in text:
        return "POLICY_HARD_BLOCK"
    return "UNCLASSIFIED"


def _judged_result_payload(
    *,
    cell: str,
    seq: int,
    accepted: bool,
    judge_model: str | None,
    judge_rationale: str | None,
) -> dict[str, Any]:
    if accepted:
        return {
            "outcome": "ACCEPTED_BY_JUDGE",
            "cell": cell,
            "seq": seq,
            "judge_model": judge_model,
            "judge_rationale": judge_rationale,
            "note": "may be re-judged later",
        }
    return {
        "outcome": "BLOCKED",
        "cell": cell,
        "seq": seq,
        "judge_model": judge_model,
        "judge_rationale": judge_rationale,
        "blocked_reason_code": _blocked_reason_code(judge_rationale),
        "self_clearable": False,
        "next_actions": ["REVISE_CODE", "REVISE_RATIONALE"],
        "note": "this attempt does not count toward your override-rate",
    }


def _override_idempotency_request_hash(
    *,
    agent_id: str,
    policy: str,
    entity: str,
    rationale: str,
    cell: str,
    file_fingerprint: str | None,
    ast_path: str | None,
    entity_sei: str | None = None,
) -> str:
    # version 2 adds entity_sei: an L1 SEI-bound submit and an L2 locator submit
    # that differ only in entity_sei are different requests and must not collide
    # on one idempotency key. (Absent entity_sei is carried as None, so a v1-shaped
    # locator-only submit hashes distinctly from its v1 self by design — the bump
    # is a clean break, consistent with weft's no-stale-data / fresh-dogfood rule.)
    return content_hash(
        {
            "version": 2,
            "agent_id": agent_id,
            "policy": policy,
            "entity": entity,
            "entity_sei": entity_sei,
            "rationale": rationale,
            "cell": cell,
            "file_fingerprint": file_fingerprint,
            "ast_path": ast_path,
        }
    )


def _existing_idempotent_record(
    runtime: McpRuntime, key: str, request_hash: str
) -> Any | None:
    # The O(N) hash + HMAC cost of the scan below is `_verified_records`' whole-
    # trail tamper check, paid deliberately on this interactive path — NOT a
    # keyed single-row lookup, which would skip verification (the optimization
    # operator-confirmed declined in rc4 review #7; see service.verified_records'
    # cost note). The scan itself is over the already-verified list.
    for rec in _verified_records(runtime):
        ext = rec.payload.get("extensions", {})
        if ext.get("mcp_idempotency_key") != key:
            continue
        if ext.get("mcp_idempotency_request_hash") == request_hash:
            return rec
        raise InvalidArgumentError(
            "idempotency key already references a different override request"
        )
    return None


def _idempotent_override_response(payload: dict[str, Any], seq: int) -> dict[str, Any]:
    ext = payload.get("extensions", {})
    cell = ext.get("mcp_cell")
    if cell == "chill":
        return {
            "outcome": "ACCEPTED_SELF",
            "cell": "chill",
            "seq": seq,
            "note": "self-cleared; human reviews asynchronously",
        }
    if cell == "structured":
        return {
            "outcome": "ESCALATED_PENDING",
            "cell": "structured",
            "seq": seq,
            "cleared": False,
            "human_required": True,
            "operator_instruction": f"Human sign-off required for seq {seq}.",
            "poll_tool": "signoff_status_get",
            "poll_handle": seq,
        }
    if cell in ("coached", "protected"):
        verdict = ext.get("judge_verdict")
        return _judged_result_payload(
            cell=cell,
            seq=seq,
            accepted=verdict == Verdict.ACCEPTED.value,
            judge_model=ext.get("judge_model"),
            judge_rationale=ext.get("judge_rationale"),
        )
    raise InvalidArgumentError("idempotency key references an unsupported record")


def _signoff_signed_record(
    runtime: McpRuntime, request_seq: int
) -> dict[str, Any] | None:
    gate = runtime.signoff_gate
    records = gate.records() if gate is not None and hasattr(gate, "records") else []
    for rec in records:
        ext = rec.payload.get("extensions", {})
        if (
            ext.get("signoff_state") == SignoffState.SIGNED_OFF.value
            and ext.get("request_seq") == request_seq
        ):
            return rec.payload
    return None


def _dedupe_records(records: list[Any]) -> list[Any]:
    deduped = []
    seen = set()
    for rec in records:
        key = (
            getattr(rec, "seq", None),
            getattr(rec, "content_hash", None),
            getattr(rec, "chain_hash", None),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rec)
    return deduped


def _simple_engine_records(runtime: McpRuntime) -> list[Any]:
    records = []
    for engine in (runtime.engine, runtime.coached_engine):
        if engine is not None:
            records.extend(engine.records())
    if records or runtime.engine is not None or runtime.coached_engine is not None:
        return _dedupe_records(records)
    return _engine(runtime).records()


def _verified_records(runtime: McpRuntime) -> list[Any]:
    if runtime.protected_gate is not None:
        return service_verified_records(
            runtime.protected_gate,
            runtime.trail_verifier,
            lambda: [],
        )
    if runtime.signoff_gate is not None and runtime.engine is None:
        if (
            hasattr(runtime.signoff_gate, "verify_integrity")
            and not runtime.signoff_gate.verify_integrity()
        ):
            raise AuditIntegrityError(
                "audit integrity failure: database hash chain verification failed"
            )
        records = runtime.signoff_gate.records()
        if runtime.trail_verifier is not None:
            try:
                runtime.trail_verifier.verify(records)
            except TamperError as exc:
                raise AuditIntegrityError(f"audit integrity failure: {exc}") from exc
        return records
    return _simple_engine_records(runtime)


def _tool_policy_explain(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    # D0: explain through the FlooredRegistry — explain_policy floors
    # transparently because FlooredRegistry IS-A PolicyCellRegistry (D1).
    policy = _require(args, "policy")
    registry = _floored_registry(runtime)
    cell = registry.cell_for(policy)
    explanation = explain_policy(
        registry,
        policy=policy,
        entity=_require(args, "entity"),
        engine=_simple_engine_for_cell(runtime, cell)
        if cell in ("chill", "coached")
        else None,
        protected_gate=runtime.protected_gate,
        signoff_gate=runtime.signoff_gate,
    )
    return _tool_result(_explanation_payload(explanation))


def _tool_policy_list(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    # D0: report the FLOORED effective cell for the default and each rule, so an
    # agent reading policy_list plans against the real routing — not the raw
    # registry cell that the floor would silently raise. rule.pattern stays the
    # raw matched rule (D1); only the cell is the floored effective cell.
    registry = _floored_registry(runtime)
    cells = []
    # CELL_TIER_ORDER is the canonical cell membership in tier order (it backs
    # VALID_CELLS), so the cells block always covers every governance cell — a
    # new cell cannot be silently omitted from policy_list.
    for cell in CELL_TIER_ORDER:
        # Same source explain_policy uses for the per-cell fields, fed the SAME
        # raw runtime gates _tool_policy_explain passes — so policy_list and
        # policy_explain can never disagree, and the complex tier honestly
        # reports enabled:false without LEGIS_HMAC_KEY (no false-green).
        explanation = explain_cell(
            cell,
            engine=_simple_engine_for_cell(runtime, cell)
            if cell in ("chill", "coached")
            else None,
            protected_gate=runtime.protected_gate,
            signoff_gate=runtime.signoff_gate,
        )
        cells.append(
            {
                "cell": explanation.cell,
                "enabled": explanation.enabled,
                "judge_inline": explanation.judge_inline,
                "self_clearable": explanation.self_clearable,
                "human_in_loop": explanation.human_in_loop,
            }
        )
    return _tool_result(
        {
            "default_cell": registry.default_cell,
            "rules": [
                {
                    "pattern": rule.pattern,
                    "cell": _max_tier(registry.floor, rule.cell),
                }
                for rule in registry.rules
            ],
            "cells": cells,
        }
    )


def _tool_override_submit(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    policy = _require(args, "policy")
    entity = _require(args, "entity")
    rationale = _require(args, "rationale")
    entity_sei = _optional_string(args, "entity_sei")
    idempotency_key = _optional_string(args, "idempotency_key")
    # D0: route through the FlooredRegistry. dispatch_cell is the floored
    # effective cell — engine selection and the whole dispatch below key on it,
    # never on an unfloored registry cell (so a chill rule under a structured
    # floor escalates instead of self-clearing).
    registry = _floored_registry(runtime)
    dispatch_cell = registry.cell_for(policy)
    # The idempotency key is floor-INSENSITIVE (D4): hash on the RAW registry
    # cell, not the floored dispatch cell, so a posture-floor change between an
    # original submit and a retry does not break the idempotency match — a
    # genuine retry returns the original outcome (with a floor_warning below).
    raw_cell = _registry(runtime).cell_for(policy)
    simple_engine = (
        _simple_engine_for_cell(runtime, dispatch_cell)
        if dispatch_cell in ("chill", "coached")
        else None
    )
    explanation = explain_policy(
        registry,
        policy=policy,
        entity=entity,
        engine=simple_engine,
        protected_gate=runtime.protected_gate,
        signoff_gate=runtime.signoff_gate,
    )
    if not explanation.enabled:
        # LEG-2: name the enabling knob in the message where it is unambiguous.
        # Complex tier enablement is the operator-held key — an operator action,
        # never an agent one (C-8). The simple tier's knob depends on which
        # half is unwired (engine vs judge config), so it stays generic; the
        # CELL_NOT_ENABLED next_action covers both tiers.
        message = f"cell {explanation.cell!r} is not enabled for override submission"
        if explanation.cell in ("structured", "protected"):
            message += (
                ": ask the operator to set LEGIS_HMAC_KEY (out-of-band) and relaunch"
            )
        raise NotEnabledError(message)
    idempotency_request_hash = (
        _override_idempotency_request_hash(
            agent_id=runtime.agent_id,
            policy=policy,
            entity=entity,
            rationale=rationale,
            cell=raw_cell,
            file_fingerprint=_optional_string(args, "file_fingerprint"),
            ast_path=_optional_string(args, "ast_path"),
            entity_sei=entity_sei,
        )
        if idempotency_key is not None
        else None
    )
    extra_extensions = (
        {
            "mcp_idempotency_key": idempotency_key,
            "mcp_idempotency_request_hash": idempotency_request_hash,
            "mcp_cell": explanation.cell,
        }
        if idempotency_key is not None
        else {"mcp_cell": explanation.cell}
    )
    if idempotency_key is not None and idempotency_request_hash is not None:
        existing = _existing_idempotent_record(
            runtime, idempotency_key, idempotency_request_hash
        )
        if existing is not None:
            response = _idempotent_override_response(existing.payload, existing.seq)
            original_cell = existing.payload.get("extensions", {}).get("mcp_cell")
            # D4 (warning variant): the replay returns the ORIGINAL outcome (the
            # record cannot be unwritten), but if the posture floor has RISEN
            # since it was written, say so — never a silent grandfather past a
            # raised floor.
            if (
                original_cell in CELL_TIER_ORDER
                and dispatch_cell != original_cell
                and _max_tier(dispatch_cell, original_cell) == dispatch_cell
            ):
                response["floor_warning"] = (
                    f"idempotent replay recorded at cell {original_cell!r}; the "
                    f"posture floor now raises this policy to {dispatch_cell!r}. "
                    f"The original outcome is returned unchanged; a fresh "
                    f"submission would route to {dispatch_cell!r}."
                )
            return _tool_result(response)
    if explanation.cell in ("chill", "coached"):
        assert simple_engine is not None
        override_result = submit_override(
            simple_engine,
            identity=runtime.identity,
            policy=policy,
            entity=entity,
            rationale=rationale,
            agent_id=runtime.agent_id,
            extra_extensions=extra_extensions,
            entity_sei=entity_sei,
        )
        if explanation.cell == "chill":
            return _tool_result(
                {
                    "outcome": "ACCEPTED_SELF",
                    "cell": "chill",
                    "seq": override_result.seq,
                    "note": "self-cleared; human reviews asynchronously",
                }
            )
        return _tool_result(
            _judged_result_payload(
                cell="coached",
                seq=override_result.seq,
                accepted=override_result.accepted,
                judge_model=override_result.judge_model,
                judge_rationale=override_result.judge_rationale,
            )
        )
    if explanation.cell == "structured":
        signoff = request_signoff(
            runtime.signoff_gate,
            identity=runtime.identity,
            policy=policy,
            entity=entity,
            rationale=rationale,
            agent_id=runtime.agent_id,
            extra_extensions=extra_extensions,
            entity_sei=entity_sei,
        )
        return _tool_result(
            {
                "outcome": "ESCALATED_PENDING",
                "cell": "structured",
                "seq": signoff.seq,
                "cleared": signoff.cleared,
                "human_required": True,
                "operator_instruction": (
                    f"Human sign-off required for seq {signoff.seq}."
                ),
                "poll_tool": "signoff_status_get",
                "poll_handle": signoff.seq,
            }
        )
    if explanation.cell == "protected":
        missing = [
            item.to_payload()
            for item in explanation.required_inputs
            if not _optional_string(args, item.field)
        ]
        if missing:
            return _tool_result(
                {
                    "outcome": "NEED_INPUTS",
                    "cell": "protected",
                    "required_inputs": missing,
                }
            )
        protected = submit_protected_override(
            runtime.protected_gate,
            identity=runtime.identity,
            policy=policy,
            entity=entity,
            rationale=rationale,
            agent_id=runtime.agent_id,
            file_fingerprint=_require(args, "file_fingerprint"),
            ast_path=_require(args, "ast_path"),
            source_root=runtime.source_root,
            extra_extensions=extra_extensions,
            entity_sei=entity_sei,
        )
        return _tool_result(
            _judged_result_payload(
                cell="protected",
                seq=protected.seq,
                accepted=protected.accepted,
                judge_model=protected.judge_model,
                judge_rationale=protected.judge_rationale,
            )
        )
    raise NotEnabledError(f"unsupported policy cell {explanation.cell!r}")


def _tool_signoff_status_get(
    runtime: McpRuntime, args: dict[str, Any]
) -> dict[str, Any]:
    seq = _require_int(args, "seq")
    if runtime.signoff_gate is None:
        # LEG-2: the message names the operator knob (C-8: operator action).
        raise NotEnabledError(
            "structured cell not enabled: ask the operator to set "
            "LEGIS_HMAC_KEY (out-of-band) and relaunch"
        )
    request = runtime.signoff_gate.request_record(seq)
    if request is None:
        return _tool_error("NO_SUCH_REQUEST", f"no sign-off request at seq {seq}")
    if not runtime.signoff_gate.is_cleared(seq):
        return _tool_result({"cleared": False, "seq": seq})
    signed = _signoff_signed_record(runtime, seq)
    payload: dict[str, Any] = {"cleared": True, "seq": seq}
    if signed is not None:
        payload["signed_by"] = signed.get("agent_id")
        payload["signed_at"] = signed.get("recorded_at")
    # The binding read rides in the cleared payload (legis-428f05c9ca): present
    # only when the ledger is wired, so "not bound yet" (null) stays
    # distinguishable from "no binding ledger on this deployment" (key absent).
    # A BindingError propagates to AUDIT_INTEGRITY_FAILURE — never read forged.
    if runtime.binding_ledger is not None:
        payload["binding"] = runtime.binding_ledger.get(seq)
    return _tool_result(payload)


def _tool_signoff_bind_issue(
    runtime: McpRuntime, args: dict[str, Any]
) -> dict[str, Any]:
    seq = _require_int(args, "seq")
    issue_id = _require(args, "issue_id")
    # The bind decision (fail-closed trail verification, cleared request,
    # SEI/content_hash from the record, SEI_BACKFILL recovery) is the single
    # service decision shared with the HTTP bind-issue route (Q-H2). The
    # attestation key and ledger are server-held — never call arguments (C-8).
    return _tool_result(
        bind_signoff_issue(
            runtime.signoff_gate,
            runtime.trail_verifier,
            runtime.filigree,
            issue_id=issue_id,
            request_seq=seq,
            key=runtime.binding_key,
            ledger=runtime.binding_ledger,
        )
    )


def _tool_policy_evaluate(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    ev = evaluate_policy(
        _grammar(runtime),
        engine=_engine(runtime),
        policy=_require(args, "policy"),
        target=_require_object(args, "target"),
    )
    return _tool_result(
        {
            "outcome": ev.result.value,
            "detail": ev.detail,
            "provenance_gap": ev.provenance_gap,
        }
    )


def _tool_scan_route(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    # "severity_map" must be an object if present (transport-type check); the
    # governance decision — is request routing allowed, and is the spec
    # well-formed? — lives in resolve_scan_routing, shared with the HTTP adapter.
    # A WardlineRoutingError propagates to call_tool's translator → INVALID_CELL_SPEC.
    request_severity_map = (
        _require_object(args, "severity_map") if "severity_map" in args else None
    )
    routing = resolve_scan_routing(
        server_cell=os.environ.get("LEGIS_WARDLINE_CELL"),
        server_cell_by_severity=os.environ.get("LEGIS_WARDLINE_CELL_BY_SEVERITY"),
        request_cell=args.get("cell"),
        request_severity_map=request_severity_map,
        request_fail_on=args.get("fail_on"),
        allow_request_routing=(
            os.environ.get("LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING") == "1"
        ),
    )
    scan = _require_object(args, "scan")
    try:
        result = route_wardline_scan(
            scan,
            agent_id=runtime.agent_id,
            identity=runtime.identity,
            engine=_engine(runtime),
            signoff=runtime.signoff_gate,
            policy=routing.policy,
            cell_map=routing.cell_map,
            fail_on=routing.fail_on,
            artifact_key=(
                runtime.wardline_artifact_key
                or (
                    os.environ["LEGIS_WARDLINE_ARTIFACT_KEY"].encode("utf-8")
                    if os.environ.get("LEGIS_WARDLINE_ARTIFACT_KEY")
                    else None
                )
            ),
            allow_dirty=(
                runtime.wardline_allow_dirty
                or os.environ.get("LEGIS_WARDLINE_ALLOW_DIRTY") == "1"
            ),
        )
    except WardlineDirtyTreeError as exc:
        # Environment-not-ready, not success: nothing was governed, so MCP must
        # emit isError=true while keeping a distinct, recoverable error code.
        return _tool_dirty_tree_error(exc)
    # Echo the scan-level posture at the root (opp #6): a keyless dev pass
    # (`unverified`/`dirty`) is distinguishable from a CI-signed `verified` pass,
    # even when nothing routed.
    return _tool_result(
        {
            "outcome": ScanOutcome.ROUTED,
            "routed": result.routed,
            "artifact_status": result.artifact_status,
            # The honesty surface: distinguishes key-absent (verification
            # DISABLED) from a key that failed to verify (PDR-0023). Always
            # present — no status without its reason.
            "artifact_status_reason": result.artifact_status_reason,
        }
    )


def _tool_git_branch_list(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    return _tool_result(
        {"branches": [asdict(branch) for branch in _git(runtime).branches()]}
    )


def _tool_git_commit_get(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    return _tool_result({"commit": asdict(_git(runtime).commit(_require(args, "sha")))})


def _tool_git_rename_list(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    return _tool_result(
        {
            "renames": [
                asdict(rename)
                for rename in _git(runtime).renames(_require(args, "rev_range"))
            ]
        }
    )


def _tool_git_rename_feed_get(
    runtime: McpRuntime, args: dict[str, Any]
) -> dict[str, Any]:
    from legis.git.rename_feed import build_rename_feed

    return _tool_result(
        build_rename_feed(
            runtime.source_root or os.getcwd(),
            base=_require(args, "base"),
            head=args.get("head", "HEAD"),
            include_worktree=bool(args.get("include_worktree", False)),
        )
    )


def _tool_filigree_closure_gate_get(
    runtime: McpRuntime, args: dict[str, Any]
) -> dict[str, Any]:
    from legis.governance.filigree_gate import evaluate_issue_closure

    if runtime.binding_ledger is None:
        # LEG-2: the message names the operator knob (C-8: operator action).
        raise NotEnabledError(
            "binding ledger not enabled: ask the operator to set "
            "LEGIS_HMAC_KEY (out-of-band) and relaunch"
        )
    return _tool_result(
        evaluate_issue_closure(
            runtime.binding_ledger, issue_id=_require(args, "issue_id")
        )
    )


def _tool_warpline_preflight_get(
    runtime: McpRuntime, args: dict[str, Any]
) -> dict[str, Any]:
    from legis.service.preflight import read_warpline_preflight

    return _tool_result(
        read_warpline_preflight(
            runtime.warpline,
            base=_require(args, "base"),
            head=args.get("head", "HEAD"),
        )
    )


def _tool_plainweave_preflight_get(
    runtime: McpRuntime, args: dict[str, Any]
) -> dict[str, Any]:
    from legis.service.preflight import read_plainweave_preflight

    return _tool_result(
        read_plainweave_preflight(
            runtime.plainweave,
            base=_require(args, "base"),
            head=args.get("head", "HEAD"),
            requirement_limit=_optional_int(
                args, "requirement_limit", minimum=1, maximum=100
            ),
            requirement_offset=_optional_int(args, "requirement_offset", minimum=0),
        )
    )


def _governance_trail_records(runtime: McpRuntime) -> list[Any]:
    """The verified governance trail the SEI lineage-honesty reads consume.

    Mirrors the HTTP adapter's ``verified_governance_records``: the protected
    store when a protected gate is wired, the engine store otherwise — read
    through ``_engine`` so a fresh runtime sees records an earlier session
    persisted (not call-order-dependent; same bug class as the
    pull_request_get fresh-runtime fix).
    """
    return service_verified_records(
        runtime.protected_gate,
        runtime.trail_verifier,
        lambda: _engine(runtime).records(),
    )


def _tool_attestation_get(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    from legis.service.governance import read_sei_attestations

    sei = _require(args, "sei")
    # FAIL-CLOSED: attestation is only possible when the trail is signature-
    # verifiable. `verified_records` ONLY runs TrailVerifier.verify when BOTH a
    # protected trail_owner AND a trail_verifier are wired (governance.py:199-205);
    # with a protected_gate but no verifier it returns engine records UNVERIFIED.
    # Gate on BOTH so the invariant holds by construction, not by the convention
    # that build_runtime co-locates them under one `if hmac_key:` block. Return the
    # discriminated unavailable (NEVER a silent empty 'checked' that reads as
    # "never attested", NEVER unverified field values).
    if runtime.protected_gate is None or runtime.trail_verifier is None:
        return _tool_result(
            {
                "status": "unavailable",
                "sei": sei,
                "attestations": [],
                "unavailable": [
                    {
                        "reason": "trail not signature-verifiable (no protected gate / verifier)"
                    }
                ],
            }
        )
    # _governance_trail_records runs verified_records, which raises
    # AuditIntegrityError (-> AUDIT_INTEGRITY_FAILURE) on a tampered protected trail.
    return _tool_result(read_sei_attestations(_governance_trail_records(runtime), sei))


def _tool_governance_read(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    from legis.service.governance import (
        governance_read_unavailable,
        read_governance_for_sei,
    )

    sei = _require(args, "sei")
    # FAIL-CLOSED pre-gate (same invariant as attestation_get): a verifiable answer
    # needs BOTH a protected gate AND a trail_verifier. Missing either -> unavailable
    # (discriminated), never a silent checked/[] that reads as "no clearance".
    if runtime.protected_gate is None or runtime.trail_verifier is None:
        return _tool_result(
            governance_read_unavailable(
                sei, "trail not signature-verifiable (no protected gate / verifier)"
            )
        )
    # _governance_trail_records runs verified_records, which runs BOTH
    # verify_integrity (chain/delete-reorder-truncate) AND TrailVerifier.verify
    # (signatures), raising AuditIntegrityError (-> AUDIT_INTEGRITY_FAILURE) on a
    # tampered protected trail (loud, never a result).
    return _tool_result(
        read_governance_for_sei(_governance_trail_records(runtime), sei)
    )


def _tool_identity_gap_list(
    runtime: McpRuntime, args: dict[str, Any]
) -> dict[str, Any]:
    return _tool_result(
        read_identity_gaps(runtime.identity, lambda: _governance_trail_records(runtime))
    )


def _tool_lineage_integrity_get(
    runtime: McpRuntime, args: dict[str, Any]
) -> dict[str, Any]:
    return _tool_result(
        read_lineage_integrity(
            runtime.identity, lambda: _governance_trail_records(runtime)
        )
    )


def _tool_pull_request_get(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    number = _require_int(args, "number")
    pull = _pulls(runtime).get(number)
    if pull is None:
        return _tool_error("NOT_FOUND", f"unknown PR: {number}")
    pull_payload = asdict(pull)
    pull_payload["state"] = pull.state.value
    # Build the check surface unconditionally — `_checks()` lazily initialises it
    # from LEGIS_CHECK_DB. Guarding on `runtime.check_surface is not None` made the
    # result call-order-dependent: a fresh runtime (build_runtime sets it to None)
    # reported no checks until some other tool happened to initialise the surface
    # first, so an agent could be told a PR is clean when checks exist and fail.
    pull_checks = _checks(runtime).for_pr(number)
    pull_payload["checks"] = [_check_to_dict(run) for run in pull_checks]
    return _tool_result(pull_payload)


def _tool_check_list(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    check_surface = _checks(runtime)
    target_type = _require(args, "target_type")
    target = _require(args, "target")
    if target_type == "commit":
        checks = check_surface.for_commit(target)
        response_target: str | int = target
    elif target_type == "branch":
        checks = check_surface.for_branch(target)
        response_target = target
    elif target_type == "pr":
        try:
            pr_number = int(target)
        except ValueError as exc:
            raise InvalidArgumentError(
                "target_type 'pr' requires an integer target"
            ) from exc
        checks = check_surface.for_pr(pr_number)
        response_target = pr_number
    else:
        raise InvalidArgumentError(
            "target_type must be one of: " + ", ".join(_CHECK_TARGET_TYPES)
        )
    return _tool_result(
        {
            "target_type": target_type,
            "target": response_target,
            "checks": [_check_to_dict(run) for run in checks],
        }
    )


def _tool_check_report(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    raw_outcome = _require(args, "outcome")
    try:
        outcome = CheckOutcome(raw_outcome)
    except ValueError as exc:
        valid = ", ".join(o.value for o in CheckOutcome)
        raise InvalidArgumentError(
            f"outcome {raw_outcome!r} is not a check outcome; must be one of: {valid}"
        ) from exc
    run = CheckRun(
        check_name=_require(args, "check_name"),
        run_id=_require(args, "run_id"),
        commit_sha=_require(args, "commit_sha"),
        outcome=outcome,
        branch=_optional_string(args, "branch"),
        pr=_require_int(args, "pr") if "pr" in args else None,
        ran_against=_optional_string(args, "ran_against"),
        rule_set=_optional_string(args, "rule_set"),
        policy_version=_optional_string(args, "policy_version"),
        started_at=_optional_string(args, "started_at"),
        finished_at=_optional_string(args, "finished_at"),
        recorded_by=runtime.agent_id,
    )
    _checks(runtime).record(run)
    # The result echoes the recorded posture: who the launch binding attributed
    # the claim to, and that it is unauthenticated (Q-M2) — the recorder is
    # never led to believe its own report became forge-attested evidence.
    return _tool_result(
        {
            **_check_to_dict(run),
            "recorded_by": run.recorded_by,
            "provenance": run.provenance,
        }
    )


def _tool_override_rate_get(
    runtime: McpRuntime, args: dict[str, Any]
) -> dict[str, Any]:
    rate = compute_override_rate(_verified_records(runtime))
    return _tool_result(
        {
            "status": rate.status.value,
            "rate": rate.rate,
            "sample_size": rate.sample_size,
            "note": _OVERRIDE_RATE_NOTE,
        }
    )


def _tool_override_list(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    policy = _optional_string(args, "policy")
    entity = _optional_string(args, "entity")
    # "submitted_by", not "agent_id": no tool schema ever accepts an agent_id
    # argument (launch-binding invariant, pinned by the surface test). This is
    # a read filter over the RECORDED agent_id, not caller identity.
    submitted_by = _optional_string(args, "submitted_by")
    # The same verified trail GET /overrides serves (via _governance_trail_records
    # so a fresh runtime lazily opens the engine store — never a false-empty
    # "no prior overrides"). Filters are exact-match on the recorded payload;
    # records without the filtered key (e.g. bare events) simply don't match.
    overrides = []
    for rec in _governance_trail_records(runtime):
        payload = rec.payload
        if policy is not None and payload.get("policy") != policy:
            continue
        if entity is not None:
            entity_key = payload.get("entity_key")
            if not isinstance(entity_key, dict) or entity_key.get("value") != entity:
                continue
        if submitted_by is not None and payload.get("agent_id") != submitted_by:
            continue
        overrides.append({"seq": rec.seq, **payload})
    return _tool_result({"overrides": overrides})


def _tool_doctor_get(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    from legis.doctor import collect_checks, doctor_payload

    # Report-only by construction: repair=False is hardwired and the schema
    # carries no fix/repair knob — repairs stay operator/CLI (C-8).
    root = Path(runtime.source_root or os.getcwd())
    return _tool_result(doctor_payload(collect_checks(root, repair=False)))


def _tool_policy_boundary_check(
    runtime: McpRuntime, args: dict[str, Any]
) -> dict[str, Any]:
    from legis.policy.boundary_scan import (
        assert_within_boundary,
        count_source_files,
        scan_policy_boundaries,
    )

    source_root = Path(runtime.source_root or os.getcwd())
    repo_root_arg = _optional_string(args, "repo_root")
    repo_root = Path(repo_root_arg) if repo_root_arg else source_root
    if not repo_root.is_absolute():
        repo_root = source_root / repo_root
    root_arg = _optional_string(args, "root")
    root = Path(root_arg) if root_arg else repo_root / "src"
    if not root.is_absolute():
        root = repo_root / root
    # Containment (legis-0186c23a2c): an MCP caller supplies these roots, so an
    # absolute or ..-bearing root must not let Legis walk arbitrary trees outside
    # the server's configured source boundary. Fail closed (INVALID_ARGUMENT)
    # BEFORE any filesystem walk; never scan-then-report an out-of-bounds tree.
    assert_within_boundary(source_root, repo_root, root)
    # Gate honesty (cf. weft-ef2e898642 silent-clean-on-zero-scope): a scan that
    # looked at NOTHING yields zero findings, which would otherwise read as a
    # clean PASS — a vacuous green, the exact failure class of the prior
    # --root-empty silent-clean bug. Two ways to scan nothing: the root does not
    # exist, or it exists but holds zero analyzable .py files. Both bite when no
    # `root` is given and the default `<repo_root>/src` is wrong — a project
    # whose source lives elsewhere (e.g. `specimen/`), or a federation server
    # whose repo_root is not its own source. Surface NO_ROOT instead of PASS so
    # the caller knows nothing was scanned, and always echo what WAS scanned so a
    # wrong-but-existing root (e.g. the server's own source) is visible rather
    # than silently trusted.
    source_file_count = count_source_files(root)
    if source_file_count == 0:
        if not root.exists():
            detail = (
                f"scan root {root} does not exist; nothing was scanned. Pass an "
                "explicit `root` (and `repo_root` if needed) pointing at the "
                "project's Python source — the default <repo_root>/src was not found."
            )
        else:
            detail = (
                f"scan root {root} contains no analyzable Python files; nothing "
                "was scanned. Pass an explicit `root` (and `repo_root` if needed) "
                "pointing at the project's Python source — a zero-file scan is "
                "never a clean PASS."
            )
        return _tool_result(
            {
                "outcome": "NO_ROOT",
                "findings": [],
                "scanned_root": str(root),
                "repo_root": str(repo_root),
                "detail": detail,
            }
        )
    findings = scan_policy_boundaries(root, repo_root=repo_root)
    return _tool_result(
        {
            "outcome": "FINDINGS" if findings else "PASS",
            "findings": [finding.to_dict() for finding in findings],
            "scanned_root": str(root),
            "repo_root": str(repo_root),
        }
    )


def _tool_posture_get(runtime: McpRuntime, args: dict[str, Any]) -> dict[str, Any]:
    # D0/D2: read the floor FRESH off the held ledger handle (never cached). The
    # posture REPORT is fail-closed at the posture layer (cross-cutting checklist
    # #1): an absent/empty ledger reports the floor as 'structured', never chill
    # — independent of the dev registry default. The FlooredRegistry routing
    # chokepoint uses the same None -> structured fallback.
    ledger = runtime.posture_ledger
    raw_floor = ledger.read_floor() if ledger is not None else None
    floor = "structured" if raw_floor is None else raw_floor
    payload: dict[str, Any] = {
        "floor": floor,
        # Pending-operator signal: a KEY_RESET with no acknowledging transition.
        # A missing ledger handle has nothing to acknowledge -> False.
        "epoch_reset_unacknowledged": bool(
            ledger is not None and ledger.epoch_reset_unacknowledged()
        ),
    }
    policy = _optional_string(args, "policy")
    if policy is not None:
        # The floored effective cell == max(floor, registry.cell_for(policy)),
        # using the SAME FlooredRegistry the routing/explain/list sites use so
        # posture_get can never disagree with the cell an override would route
        # to. _floored_registry is fail-closed structured on a missing ledger
        # via _registry()'s fail_closed default, matching the reported floor.
        payload["effective_cell"] = _max_tier(
            floor, _registry(runtime).cell_for(policy)
        )
    return _tool_result(payload)


_TOOL_HANDLERS: dict[str, Callable[["McpRuntime", dict[str, Any]], dict[str, Any]]] = {
    "policy_explain": _tool_policy_explain,
    "policy_list": _tool_policy_list,
    "override_submit": _tool_override_submit,
    "signoff_status_get": _tool_signoff_status_get,
    "signoff_bind_issue": _tool_signoff_bind_issue,
    "policy_evaluate": _tool_policy_evaluate,
    "scan_route": _tool_scan_route,
    "git_branch_list": _tool_git_branch_list,
    "git_commit_get": _tool_git_commit_get,
    "git_rename_list": _tool_git_rename_list,
    "git_rename_feed_get": _tool_git_rename_feed_get,
    "filigree_closure_gate_get": _tool_filigree_closure_gate_get,
    "identity_gap_list": _tool_identity_gap_list,
    "lineage_integrity_get": _tool_lineage_integrity_get,
    "pull_request_get": _tool_pull_request_get,
    "check_list": _tool_check_list,
    "check_report": _tool_check_report,
    "override_rate_get": _tool_override_rate_get,
    "override_list": _tool_override_list,
    "doctor_get": _tool_doctor_get,
    "policy_boundary_check": _tool_policy_boundary_check,
    "posture_get": _tool_posture_get,
    "warpline_preflight_get": _tool_warpline_preflight_get,
    "plainweave_preflight_get": _tool_plainweave_preflight_get,
    "attestation_get": _tool_attestation_get,
    "governance_read": _tool_governance_read,
}


def call_tool(runtime: McpRuntime, name: str, args: dict[str, Any]) -> dict[str, Any]:
    try:
        _validate_argument_keys(name, args)
        handler = _TOOL_HANDLERS.get(name)
        if handler is None:
            return _tool_error("UNKNOWN_TOOL", f"unknown tool: {name}")
        return handler(runtime, args)
    except Exception as exc:
        return _service_error(exc)


def handle_request(
    request: dict[str, Any], runtime: McpRuntime
) -> dict[str, Any] | None:
    request_id = request.get("id")
    method = request.get("method")
    if request_id is None:
        if method == "notifications/initialized":
            runtime.initialized = True
        return None
    result: dict[str, Any]
    if method == "initialize":
        params = request.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32602,
                    "message": "initialize params must be an object",
                },
            }
        requested = params.get("protocolVersion")
        if requested in _SUPPORTED_PROTOCOL_VERSIONS:
            runtime.protocol_version = requested
        else:
            # MCP spec: when the client requests a protocolVersion the server
            # does not support (or omits it), the server responds with a version
            # it does support and lets the client decide whether to proceed —
            # it must not hard-error. Hard-erroring here made newer clients
            # (e.g. those negotiating 2025-06-18) fail to connect entirely.
            runtime.protocol_version = _DEFAULT_PROTOCOL_VERSION
        runtime.initialized = True
        result = {
            "protocolVersion": runtime.protocol_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "legis", "version": __version__},
        }
    elif not runtime.initialized:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32002,
                "message": "MCP server is not initialized; call initialize first",
            },
        }
    elif method == "tools/list":
        result = {"tools": tool_definitions()}
    elif method == "tools/call":
        try:
            name, args = _arguments(request.get("params", {}))
            result = call_tool(runtime, name, args)
        except Exception as exc:
            result = _service_error(exc)
    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"method not found: {method}"},
        }
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _read_bounded_line(stream: TextIO, max_bytes: int) -> tuple[str, bool]:
    """Read one newline-terminated record, bounded to ``max_bytes`` UTF-8 bytes.

    Returns ``(line, overflow)``. ``overflow`` is True when the record exceeded
    the bound. ``readline(max_bytes + 1)`` caps the *character* read — a decoded
    ``str`` holds at most 4 bytes per char, so this keeps the in-memory read
    bounded — and is the cheap first gate: a record longer than the cap in
    characters comes back without a trailing newline, so its physical remainder
    is drained to the next newline to keep framing aligned. A record that fits in
    characters but whose UTF-8 encoding still exceeds ``max_bytes`` (multibyte
    content) is rejected too, so the limit means bytes as its name promises.
    Returns ``("", False)`` at EOF.
    """
    line = stream.readline(max_bytes + 1)
    if line == "":
        return "", False
    if len(line) > max_bytes and not line.endswith("\n"):
        # Truncated mid-record at the character cap: drain the rest of the
        # physical line so the next read starts on a record boundary.
        while True:
            extra = stream.readline(max_bytes + 1)
            if extra == "" or extra.endswith("\n"):
                break
        return line, True
    if len(line.encode("utf-8")) > max_bytes:
        # Complete record (newline-terminated, or the final EOF record with no
        # trailing newline) but over the byte budget; framing is already aligned
        # — nothing follows the read — so no drain is needed.
        return line, True
    return line, False


def run_jsonrpc(
    input_stream: TextIO, output_stream: TextIO, runtime: McpRuntime
) -> None:
    max_bytes = _max_request_bytes()
    while True:
        line, overflow = _read_bounded_line(input_stream, max_bytes)
        if not line:
            break  # EOF
        if overflow:
            output_stream.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32700,
                            "message": f"request exceeds maximum size of {max_bytes} bytes",
                        },
                    },
                    separators=(",", ":"),
                )
                + "\n"
            )
            output_stream.flush()
            continue
        if not line.strip():
            continue
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("JSON-RPC request must be an object")
            response = handle_request(request, runtime)
        except Exception as exc:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": str(exc)},
            }
        if response is not None:
            output_stream.write(json.dumps(response, separators=(",", ":")) + "\n")
            output_stream.flush()


def main(agent_id: str) -> int:
    run_jsonrpc(sys.stdin, sys.stdout, build_runtime(agent_id))
    return 0
