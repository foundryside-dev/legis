"""FastAPI application factory.

The read API mirrors Loomweave's consumer model: consumers are HTTP clients.
Sprint 1 mounts the two operating-picture surfaces:

* ``/git/*``    — the stateless git/change surface (WP-1.1)
* ``/checks/*`` — the recorded CI/check surface (WP-1.2)

Dependencies are injected for testability: ``repo_path`` selects the git repo
(default: the process CWD, so a standalone server describes its own repo), and
``check_surface`` supplies the check store (lazily defaulted to a file DB so a
no-arg app never creates state until a check route is used).
"""

from __future__ import annotations

import os
import hmac
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Response, Security
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from legis import __version__
# Store-location resolvers live in the transport-agnostic config module, not the
# HTTP layer, so `mcp` and any other composition root share one source (Q-H2).
from legis.config import (
    binding_db_url,
    check_db_url,
    governance_db_url,
    protected_policies,
    pull_db_url,
)
from legis.checks.models import CheckOutcome, CheckRun
from legis.checks.surface import CheckSurface
from legis.enforcement.engine import EnforcementEngine
from legis.enforcement.protected import ProtectedGate, TrailVerifier
from legis.enforcement.signoff import SignoffGate
from legis.git.pull_request import PullRequestSource
from legis.git.rename_feed import build_rename_feed
from legis.git.surface import GitError, GitSurface
from legis.filigree.client import FiligreeClient
from legis.governance.binding_ledger import BindingError, BindingLedger
from legis.identity.entity_key import EntityKey
from legis.identity.resolver import IdentityResolver
from legis.service.errors import (
    AuditIntegrityError,
    BindingUnavailableError,
    InvalidArgumentError,
    NotClearedError,
    NotEnabledError,
    NotFoundError,
    UnresolvedInputError,
    WardlineRoutingError,
)
from legis.service.governance import bind_signoff_issue as _bind_signoff_issue
from legis.service.governance import compute_override_rate as _compute_override_rate
from legis.service.governance import read_identity_gaps as _read_identity_gaps
from legis.service.governance import read_lineage_integrity as _read_lineage_integrity
from legis.service.governance import evaluate_policy as _evaluate_policy
from legis.service.governance import request_signoff as _request_signoff
from legis.service.governance import resolve_for_record as _resolve_for_record
from legis.service.governance import sign_off as _sign_off
from legis.service.governance import submit_operator_override as _submit_operator_override
from legis.service.governance import submit_override as _submit_override
from legis.service.governance import submit_protected_override as _submit_protected_override
from legis.service.governance import verified_records as _verified_records
from legis.service.wardline import (
    resolve_scan_routing,
    route_wardline_scan as _route_wardline_scan,
)
from legis.policy.grammar import PolicyGrammar, default_grammar
from legis.pulls.models import PullRequest, PullRequestState
from legis.pulls.surface import PullSurface
from legis.wardline.governor import WardlineCellPolicy
from legis.wardline.ingest import (
    ScanOutcome,
    WardlineDirtyTreeError,
    WardlinePayloadError,
)

security = HTTPBearer(auto_error=False)


def _token_actor_from_mapping(
    credentials: HTTPAuthorizationCredentials | None,
    default_actor: str,
    required_scope: str,
) -> str | None:
    mapping = os.environ.get("LEGIS_API_TOKEN_ACTORS")
    if not mapping:
        return None
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API secret token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    for entry in mapping.split(","):
        actor_spec, sep, token = entry.partition("=")
        if not sep:
            continue
        if hmac.compare_digest(credentials.credentials, token):
            actor, scope_sep, scope_raw = actor_spec.partition(":")
            scopes = {scope.strip() for scope in scope_raw.split("|") if scope.strip()}
            # AUTH-1: an unscoped actor entry (no ``:scope`` segment) is rejected by
            # default. The ``LEGIS_ALLOW_UNSCOPED_API_TOKENS=1`` escape hatch restores
            # the pre-H7 compat behaviour where an unscoped token is accepted — and
            # because the scope check below only fires when ``scope_sep`` is truthy, an
            # unscoped token then satisfies *every* required_scope, **operator
            # included**. The flag name does not say so: enabling it grants unscoped
            # tokens full operator authority. It is a human-set env var (never
            # agent-reachable, C-8); prefer explicit ``actor:writer=``/``actor:operator=``
            # scoping and leave this off unless you intend that authority.
            if not scope_sep and os.environ.get("LEGIS_ALLOW_UNSCOPED_API_TOKENS") != "1":
                raise HTTPException(
                    status_code=403,
                    detail="API token actor mappings must declare an explicit scope.",
                )
            if scope_sep and required_scope not in scopes:
                raise HTTPException(
                    status_code=403,
                    detail=f"Token is not authorized for {required_scope!r} operations.",
                )
            return actor.strip() or default_actor
    raise HTTPException(
        status_code=401,
        detail="Invalid or missing API secret token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _verify_secret(
    credentials: HTTPAuthorizationCredentials | None,
    default_actor: str,
    required_scope: str,
) -> str:
    mapped_actor = _token_actor_from_mapping(credentials, default_actor, required_scope)
    if mapped_actor is not None:
        return mapped_actor
    secret = os.environ.get("LEGIS_API_SECRET")
    if secret:
        if not credentials or not hmac.compare_digest(credentials.credentials, secret):
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing API secret token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # A single shared secret cannot intrinsically represent a writer/operator
        # split, so single-secret mode declares its authority via
        # LEGIS_API_SECRET_SCOPE (pipe-separated), defaulting to writer-only.
        # Operator routes therefore fail closed unless a deployment explicitly
        # grants the operator scope — mirroring the scoped-token model (Q-H1).
        scope_raw = os.environ.get("LEGIS_API_SECRET_SCOPE", "writer")
        secret_scopes = {scope.strip() for scope in scope_raw.split("|") if scope.strip()}
        if required_scope not in secret_scopes:
            raise HTTPException(
                status_code=403,
                detail=f"The API secret is not authorized for {required_scope!r} operations.",
            )
        return os.environ.get("LEGIS_API_ACTOR", default_actor)
    if _unsafe_dev_auth_enabled():
        return default_actor
    raise HTTPException(
        status_code=401,
        detail="Authentication is required; set LEGIS_UNSAFE_DEV_AUTH=1 only for local development.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _authenticated_actor_configured() -> bool:
    return bool(os.environ.get("LEGIS_API_SECRET") or os.environ.get("LEGIS_API_TOKEN_ACTORS"))


def _unsafe_dev_auth_enabled() -> bool:
    return os.environ.get("LEGIS_UNSAFE_DEV_AUTH") == "1"


def _recorded_actor(authenticated_actor: str, body_actor: str | None) -> str:
    return authenticated_actor if _authenticated_actor_configured() else (body_actor or authenticated_actor)


def _unresolved_input_http(exc: UnresolvedInputError) -> HTTPException:
    """422 for a non-resolving inline entity_sei (weft SEI-on-entry fail-closed).

    The structured weft-reason rides in the detail so the agent can repair the
    input without parsing message text; nothing was recorded.
    """
    return HTTPException(
        status_code=422,
        detail={
            "error": str(exc),
            "weft_reason": {
                "kind": "unresolved_input",
                "cause": exc.cause,
                "fix": exc.fix,
            },
        },
    )


def verify_writer(credentials: HTTPAuthorizationCredentials | None = Security(security)) -> str:
    return _verify_secret(credentials, "agent", "writer")


def verify_operator(credentials: HTTPAuthorizationCredentials | None = Security(security)) -> str:
    return _verify_secret(credentials, "operator", "operator")


class OverrideIn(BaseModel):
    policy: str
    entity: str  # a locator/symbol (L2 resolve); identity_stable=False if unresolved
    rationale: str
    agent_id: str | None = None
    # weft SEI-on-entry (L1): an SEI the agent already holds, bound at the point of
    # entry. When set, legis verifies it is alive and keys the record on it; a
    # non-resolving value is rejected (422 unresolved_input) and records nothing.
    entity_sei: str | None = None


class ProtectedIn(BaseModel):
    policy: str
    entity: str
    rationale: str
    agent_id: str | None = None
    file_fingerprint: str
    ast_path: str
    entity_sei: str | None = None


class OperatorOverrideIn(BaseModel):
    policy: str
    entity: str
    rationale: str
    operator_id: str | None = None
    file_fingerprint: str
    ast_path: str
    entity_sei: str | None = None


class SignoffRequestIn(BaseModel):
    policy: str
    entity: str
    rationale: str
    agent_id: str | None = None
    entity_sei: str | None = None


class SignoffSignIn(BaseModel):
    operator_id: str | None = None
    rationale: str = ""


class PolicyEvalIn(BaseModel):
    policy: str
    target: dict = {}


class ScanResultsIn(BaseModel):
    agent_id: str | None = None
    scan: dict
    cell: str | None = None
    cell_by_severity: dict[str, str] | None = None
    fail_on: str | None = None


class BindIssueIn(BaseModel):
    issue_id: str


class PullRequestIn(BaseModel):
    number: int
    title: str
    base: str
    head: str
    state: PullRequestState
    url: str | None = None


class CheckRunIn(BaseModel):
    check_name: str
    run_id: str
    commit_sha: str
    outcome: CheckOutcome
    branch: str | None = None
    pr: int | None = None
    ran_against: str | None = None
    rule_set: str | None = None
    policy_version: str | None = None
    started_at: str | None = None
    finished_at: str | None = None


# Wardline scan-routing rejections (raised by service.resolve_scan_routing) map
# to HTTP status by kind; the MCP adapter collapses the same kinds to one code.
_WARDLINE_ROUTING_STATUS = {
    WardlineRoutingError.SERVER_MISCONFIGURED: 500,
    WardlineRoutingError.SERVER_OWNED: 403,
    WardlineRoutingError.MALFORMED: 422,
}


def _check_to_dict(run: CheckRun) -> dict:
    d = asdict(run)
    d["outcome"] = run.outcome.value
    return d


def _pull_to_dict(pr: PullRequest) -> dict:
    d = asdict(pr)
    d["state"] = pr.state.value
    return d


def create_app(
    repo_path: str | Path | None = None,
    check_surface: CheckSurface | None = None,
    enforcement: EnforcementEngine | None = None,
    protected_gate: ProtectedGate | None = None,
    signoff_gate: SignoffGate | None = None,
    trail_verifier: TrailVerifier | None = None,
    grammar: PolicyGrammar | None = None,
    identity: IdentityResolver | None = None,
    filigree: FiligreeClient | None = None,
    binding_ledger: BindingLedger | None = None,
    binding_key: bytes | None = None,
    pull_requests: PullRequestSource | None = None,
    pull_surface: PullSurface | None = None,
) -> FastAPI:
    app = FastAPI(title="legis", version=__version__)
    source_root = Path(repo_path) if repo_path is not None else Path(os.getcwd())

    # Fallback configuration loaders from environment variables if not injected
    if identity is None:
        loomweave_url = os.environ.get("LOOMWEAVE_API_URL")
        if loomweave_url:
            from legis.identity.loomweave_client import HttpLoomweaveIdentity, loomweave_hmac_key_from_env
            from legis.identity.resolver import IdentityResolver
            identity = IdentityResolver(
                HttpLoomweaveIdentity(loomweave_url, hmac_key=loomweave_hmac_key_from_env())
            )

    if filigree is None:
        filigree_url = os.environ.get("FILIGREE_API_URL")
        if filigree_url:
            from legis.filigree.client import HttpFiligreeClient
            filigree = HttpFiligreeClient(filigree_url)

    hmac_key_str = os.environ.get("LEGIS_HMAC_KEY")
    hmac_key = hmac_key_str.encode("utf-8") if hmac_key_str else None
    if binding_key is None:
        binding_key = hmac_key

    if hmac_key:
        from legis.clock import SystemClock
        from legis.store.audit_store import AuditStore

        gov_db_url = governance_db_url()
        gov_store = AuditStore(gov_db_url)
        clock = SystemClock()

        protected = protected_policies()

        if trail_verifier is None:
            from legis.enforcement.protected import TrailVerifier
            trail_verifier = TrailVerifier(hmac_key, protected)

        if protected_gate is None:
            from legis.enforcement.judge_factory import build_judge_from_env
            from legis.enforcement.protected import ProtectedGate

            # For protected policies the LLM judge is advisory only (Q-H3): no
            # deterministic validator is wired by default, so a judge ACCEPTED is
            # downgraded and the agent must obtain operator sign-off.
            protected_gate = ProtectedGate(
                gov_store, clock, build_judge_from_env("API"), hmac_key,
                protected_policies=protected,
            )

        if signoff_gate is None:
            from legis.enforcement.signoff import SignoffGate
            signoff_gate = SignoffGate(gov_store, clock, signer=True, key=hmac_key)

        if binding_ledger is None:
            from legis.governance.binding_ledger import BindingLedger
            bind_db_url = binding_db_url()
            binding_ledger = BindingLedger(AuditStore(bind_db_url), clock, hmac_key)
    state: dict[str, Any] = {
        "checks": check_surface,
        "enforcement": enforcement,
        "grammar": grammar,
        "pulls": pull_surface,
    }

    def git() -> GitSurface:
        return GitSurface(repo_path or os.getcwd())

    def checks() -> CheckSurface:
        if state["checks"] is None:
            check_db = check_db_url()
            state["checks"] = CheckSurface(check_db)
        return state["checks"]

    def pulls() -> PullSurface:
        if state["pulls"] is None:
            pull_db = pull_db_url()
            state["pulls"] = PullSurface(pull_db)
        return state["pulls"]

    def engine() -> EnforcementEngine:
        if state["enforcement"] is None:
            from legis.clock import SystemClock
            from legis.store.audit_store import AuditStore

            gov_db_url = governance_db_url()
            state["enforcement"] = EnforcementEngine(
                AuditStore(gov_db_url), SystemClock()
            )
        return state["enforcement"]

    def grammar_() -> PolicyGrammar:
        if state["grammar"] is None:
            state["grammar"] = default_grammar()
        return state["grammar"]

    def resolve_for_record(locator: str) -> tuple[EntityKey, dict]:
        return _resolve_for_record(identity, locator)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "legis", "version": __version__}

    # --- git/change surface (WP-1.1) ---

    @app.get("/git/branches")
    def git_branches() -> list[dict]:
        try:
            return [asdict(b) for b in git().branches()]
        except GitError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/git/commits/{sha}")
    def git_commit(sha: str) -> dict:
        try:
            return asdict(git().commit(sha))
        except GitError:
            raise HTTPException(status_code=404, detail=f"unknown commit: {sha}")

    @app.get("/git/renames")
    def git_renames(rev_range: str = Query(...)) -> list[dict]:
        try:
            return [asdict(r) for r in git().renames(rev_range)]
        except GitError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/git/rename-feed")
    def git_rename_feed(
        base: str = Query(...),
        head: str = Query("HEAD"),
        include_worktree: bool = Query(False),
    ) -> dict:
        try:
            return build_rename_feed(
                repo_path or os.getcwd(),
                base=base,
                head=head,
                include_worktree=include_worktree,
            )
        except GitError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/git/pull-requests/{number}")
    def get_pull_request(number: int) -> dict:
        if pull_requests is None:
            raise HTTPException(status_code=404, detail="pull-request source not enabled")
        pr = pull_requests.get(number)
        if pr is None:
            raise HTTPException(status_code=404, detail=f"no pull request {number}")
        # PR metadata AND the check outcomes associated with it (roadmap §1.1):
        # join the recorded CI check runs for this PR onto the forge context.
        return {**asdict(pr),
                "checks": [_check_to_dict(r) for r in checks().for_pr(number)]}

    @app.post("/git/pulls", status_code=201)
    def post_recorded_pull_request(
        pr: PullRequestIn, actor: str = Depends(verify_writer)
    ) -> dict:
        recorded = PullRequest(**pr.model_dump(), recorded_by=actor)
        pulls().record(recorded)
        return _pull_to_dict(recorded)

    @app.get("/git/pulls/{number}")
    def get_recorded_pull_request(number: int) -> dict:
        pr = pulls().get(number)
        if pr is None:
            raise HTTPException(status_code=404, detail=f"unknown PR: {number}")
        return {
            **_pull_to_dict(pr),
            "checks": [_check_to_dict(r) for r in checks().for_pr(number)],
        }

    # --- CI/check surface (WP-1.2) ---

    @app.post("/checks", status_code=201)
    def post_check(run: CheckRunIn, actor: str = Depends(verify_writer)) -> dict:
        cr = CheckRun(**run.model_dump(), recorded_by=actor)
        checks().record(cr)
        return _check_to_dict(cr)

    @app.get("/checks/commit/{sha}")
    def checks_for_commit(sha: str) -> list[dict]:
        return [_check_to_dict(r) for r in checks().for_commit(sha)]

    @app.get("/checks/branch/{name}")
    def checks_for_branch(name: str) -> list[dict]:
        return [_check_to_dict(r) for r in checks().for_branch(name)]

    @app.get("/checks/pr/{pr}")
    def checks_for_pr(pr: int) -> list[dict]:
        return [_check_to_dict(r) for r in checks().for_pr(pr)]

    # --- simple-tier enforcement surface (WP-2.1 chill / WP-2.2 coached) ---

    @app.post("/overrides")
    def post_override(body: OverrideIn, response: Response, actor: str = Depends(verify_writer)) -> dict:
        protected_set = (
            trail_verifier.protected_policies if trail_verifier is not None else frozenset()
        )
        if body.policy in protected_set:
            raise HTTPException(
                status_code=403,
                detail=f"Policy {body.policy!r} is protected; use the protected overrides endpoint instead."
            )
        try:
            result = _submit_override(
                engine(),
                identity=identity,
                policy=body.policy,
                entity=body.entity,
                rationale=body.rationale,
                agent_id=_recorded_actor(actor, body.agent_id),
                entity_sei=body.entity_sei,
            )
        except UnresolvedInputError as exc:
            raise _unresolved_input_http(exc) from exc
        # ACCEPTED → 201 (the override took effect); BLOCKED → 409 (it did not,
        # the agent must correct or convince). Full body either way so the agent
        # gets the judge's reasoning to revise.
        response.status_code = 201 if result.accepted else 409
        return {
            "accepted": result.accepted,
            "seq": result.seq,
            "verdict": result.verdict.value if result.verdict else None,
            "judge_model": result.judge_model,
            "judge_rationale": result.judge_rationale,
        }

    def verified_governance_records():
        try:
            return _verified_records(
                protected_gate, trail_verifier, lambda: engine().records()
            )
        except AuditIntegrityError as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app.get("/overrides")
    def get_overrides() -> list[dict]:
        return [r.payload for r in verified_governance_records()]

    # --- complex-tier enforcement surface (WP-3.1 structured / WP-3.2 protected) ---

    @app.post("/protected/overrides")
    def post_protected_override(
        body: ProtectedIn, response: Response, actor: str = Depends(verify_writer)
    ) -> dict:
        try:
            result = _submit_protected_override(
                protected_gate,
                identity=identity,
                policy=body.policy,
                entity=body.entity,
                rationale=body.rationale,
                agent_id=_recorded_actor(actor, body.agent_id),
                file_fingerprint=body.file_fingerprint,
                ast_path=body.ast_path,
                source_root=source_root,
                entity_sei=body.entity_sei,
            )
        except UnresolvedInputError as exc:
            raise _unresolved_input_http(exc) from exc
        except NotEnabledError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except InvalidArgumentError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        response.status_code = 201 if result.accepted else 409
        return {
            "accepted": result.accepted,
            "seq": result.seq,
            "verdict": result.verdict.value,
            "judge_model": result.judge_model,
            "judge_rationale": result.judge_rationale,
            "signature": result.signature,
        }

    @app.post("/protected/operator-override", status_code=201)
    def post_operator_override(body: OperatorOverrideIn, operator: str = Depends(verify_operator)) -> dict:
        try:
            result = _submit_operator_override(
                protected_gate,
                identity=identity,
                policy=body.policy,
                entity=body.entity,
                rationale=body.rationale,
                operator_id=_recorded_actor(operator, body.operator_id),
                file_fingerprint=body.file_fingerprint,
                ast_path=body.ast_path,
                source_root=source_root,
                entity_sei=body.entity_sei,
            )
        except UnresolvedInputError as exc:
            raise _unresolved_input_http(exc) from exc
        except NotEnabledError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except InvalidArgumentError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "accepted": result.accepted,
            "seq": result.seq,
            "verdict": result.verdict.value,
            "signature": result.signature,
        }

    @app.post("/signoff/request", status_code=202)
    def post_signoff_request(body: SignoffRequestIn, actor: str = Depends(verify_writer)) -> dict:
        try:
            result = _request_signoff(
                signoff_gate,
                identity=identity,
                policy=body.policy,
                entity=body.entity,
                rationale=body.rationale,
                agent_id=_recorded_actor(actor, body.agent_id),
                entity_sei=body.entity_sei,
            )
        except UnresolvedInputError as exc:
            raise _unresolved_input_http(exc) from exc
        except NotEnabledError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"seq": result.seq, "cleared": result.cleared}

    @app.post("/signoff/{request_seq}/bind-issue", status_code=201)
    def bind_issue(
        request_seq: int, body: BindIssueIn, actor: str = Depends(verify_writer)
    ) -> dict:
        # The whole bind decision — fail-closed trail verification, cleared
        # request, SEI/content_hash sourced from the record (never the caller),
        # SEI_BACKFILL recovery — is the single service decision shared with the
        # MCP signoff_bind_issue tool (Q-H2). This route only maps errors.
        try:
            return _bind_signoff_issue(
                signoff_gate,
                trail_verifier,
                filigree,
                issue_id=body.issue_id,
                request_seq=request_seq,
                key=binding_key,
                ledger=binding_ledger,
            )
        except NotEnabledError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AuditIntegrityError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except NotClearedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except BindingUnavailableError as exc:
            # A locator-keyed (non-SEI) sign-off can't be rename-stably bound.
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/signoff/{request_seq}/binding")
    def get_binding(request_seq: int) -> dict:
        if binding_ledger is None:
            raise HTTPException(status_code=404, detail="binding ledger not enabled")
        try:
            binding = binding_ledger.get(request_seq)
        except BindingError as exc:
            raise HTTPException(status_code=500, detail=f"binding integrity failure: {exc}")
        if binding is None:
            raise HTTPException(status_code=404, detail="no binding at seq")
        return binding

    @app.get("/filigree/issues/{issue_id}/closure-gate")
    def filigree_closure_gate(issue_id: str) -> Any:
        from legis.governance.filigree_gate import evaluate_issue_closure

        if binding_ledger is None:
            raise HTTPException(status_code=404, detail="binding ledger not enabled")
        try:
            decision = evaluate_issue_closure(binding_ledger, issue_id=issue_id)
        except BindingError as exc:
            raise HTTPException(status_code=500, detail=f"binding integrity failure: {exc}")
        if not decision["allowed"]:
            return JSONResponse(status_code=409, content=decision)
        return decision

    @app.post("/signoff/{request_seq}/sign")
    def post_signoff_sign(request_seq: int, body: SignoffSignIn, operator: str = Depends(verify_operator)) -> dict:
        try:
            result = _sign_off(
                signoff_gate,
                request_seq=request_seq,
                operator_id=_recorded_actor(operator, body.operator_id),
                rationale=body.rationale,
            )
        except NotEnabledError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"seq": result.seq, "cleared": result.cleared}

    @app.get("/governance/override-rate")
    def override_rate() -> dict:
        res = _compute_override_rate(verified_governance_records())
        return {
            "status": res.status.value,
            "rate": res.rate,
            "sample_size": res.sample_size,
        }

    # --- SEI lineage-spine read surfaces (WP-5.2) ---
    # Pull-only, on-demand: each held SEI is re-resolved against Loomweave when the
    # surface is hit. Detection consumes verified_governance_records() — the
    # protected store (HMAC-verified, fail-closed) when a protected gate is wired,
    # the engine store otherwise — so PROTECTED attestations are orphan-detectable.
    # A tampered protected trail raises HTTP 500 before any scan is attempted.
    # When no client is wired there is nothing stable to probe.

    # Both reads (GOV-1/GOV-2 honesty discipline: status "unavailable" vs
    # "checked"/three-way, never a bare [] false-green) are single service
    # decisions shared with the MCP identity_gap_list / lineage_integrity_get
    # tools (Q-H2). verified_governance_records maps a tampered trail to 500.

    @app.get("/governance/identity-gaps")
    def identity_gaps() -> dict:
        return _read_identity_gaps(identity, verified_governance_records)

    @app.get("/governance/lineage-integrity")
    def lineage_integrity() -> dict:
        return _read_lineage_integrity(identity, verified_governance_records)

    # --- agent-programmable policy grammar (WP-4.1) ---

    @app.post("/policy/evaluate")
    def policy_evaluate(body: PolicyEvalIn, actor: str = Depends(verify_writer)) -> dict:
        ev = _evaluate_policy(
            grammar_(),
            engine=engine(),
            policy=body.policy,
            target=body.target,
        )
        return {
            "policy": ev.policy,
            "result": ev.result.value,
            "detail": ev.detail,
            "provenance_gap": ev.provenance_gap,
        }

    # --- wardline suite-combination surface (WP-6.1) ---

    @app.post("/wardline/scan-results", response_model=None)
    def wardline_scan_results(body: ScanResultsIn, actor: str = Depends(verify_writer)) -> dict[str, Any] | JSONResponse:
        try:
            routing = resolve_scan_routing(
                server_cell=os.environ.get("LEGIS_WARDLINE_CELL"),
                server_cell_by_severity=os.environ.get("LEGIS_WARDLINE_CELL_BY_SEVERITY"),
                request_cell=body.cell,
                request_severity_map=body.cell_by_severity,
                request_fail_on=body.fail_on,
                allow_request_routing=(
                    os.environ.get("LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING") == "1"
                ),
            )
        except WardlineRoutingError as exc:
            raise HTTPException(
                status_code=_WARDLINE_ROUTING_STATUS[exc.kind], detail=str(exc)
            ) from exc

        # Only provision the governance store when a surface cell can actually run:
        # engine() lazily creates .weft/legis/legis-governance.db, so a pure block_escalate scan
        # must not touch it. signoff_gate is an injected param (no side effect).
        needs_engine = bool(routing.cells & {WardlineCellPolicy.SURFACE_OVERRIDE,
                                             WardlineCellPolicy.SURFACE_ONLY})
        try:
            result = _route_wardline_scan(
                body.scan,
                agent_id=_recorded_actor(actor, body.agent_id),
                identity=identity,
                engine=engine() if needs_engine else None,
                signoff=signoff_gate,
                policy=routing.policy,
                cell_map=routing.cell_map,
                fail_on=routing.fail_on,
                artifact_key=(
                    os.environ["LEGIS_WARDLINE_ARTIFACT_KEY"].encode("utf-8")
                    if os.environ.get("LEGIS_WARDLINE_ARTIFACT_KEY")
                    else None
                ),
                allow_dirty=os.environ.get("LEGIS_WARDLINE_ALLOW_DIRTY") == "1",
            )
        except WardlineDirtyTreeError as exc:
            # Environment-not-ready, not success: nothing was governed, so the
            # transport must not share the 2xx signal with ROUTED. Keep the
            # typed/actionable payload so callers can branch on the cause.
            return JSONResponse(status_code=409, content=exc.to_payload())
        except WardlinePayloadError as exc:
            raise HTTPException(status_code=422, detail=f"invalid Wardline scan: {exc}")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        # Echo the scan-level posture at the root (opp #6), identical contract to
        # the MCP scan_route surface, so an HTTP caller can likewise distinguish a
        # keyless dev pass from a CI-signed verified pass.
        return {
            "outcome": ScanOutcome.ROUTED,
            "routed": result.routed,
            "artifact_status": result.artifact_status,
            # The honesty surface: distinguishes key-absent (verification
            # DISABLED) from a key that failed to verify, identical contract to
            # the MCP scan_route surface (PDR-0023).
            "artifact_status_reason": result.artifact_status_reason,
        }

    return app
