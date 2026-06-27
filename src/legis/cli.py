import argparse
import json
import logging
import sys
from pathlib import Path

import uvicorn

from legis import __version__
from legis.clock import SystemClock
from legis.governance.sei_backfill import run_pre_sei_backfill
from legis.identity.loomweave_client import HttpLoomweaveIdentity, loomweave_hmac_key_from_env
from legis.policy.boundary_scan import scan_policy_boundaries
from legis.store.audit_store import AuditStore

logger = logging.getLogger(__name__)


def _add_judge_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--judge-provider",
        choices=("openrouter",),
        help="LLM judge provider. Omit to keep protected cells fail-closed.",
    )
    parser.add_argument(
        "--judge-model",
        help="LLM judge model id. Falls back to LEGIS_JUDGE_MODEL.",
    )
    parser.add_argument(
        "--judge-max-tokens",
        type=int,
        help="Maximum judge response tokens. Falls back to LEGIS_JUDGE_MAX_TOKENS.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="legis", description="Legis CLI")
    parser.add_argument(
        "--version",
        action="version",
        version=f"legis {__version__}",
        help="Print the legis version and exit",
    )
    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser("serve", help="Run the Legis API server")
    serve.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    serve.add_argument("--port", default=8000, type=int, help="Bind port (default: 8000)")
    serve.add_argument(
        "--governance-db",
        help="Governance store URL (falls back to LEGIS_GOVERNANCE_DB env var)",
    )
    serve.add_argument(
        "--check-db",
        help="Check store URL (falls back to LEGIS_CHECK_DB env var)",
    )
    serve.add_argument(
        "--protected-policies",
        help="Comma-separated protected policy list (falls back to LEGIS_PROTECTED_POLICIES env var)",
    )
    serve.add_argument(
        "--loomweave-url",
        help="Loomweave identity API URL (falls back to LOOMWEAVE_API_URL env var)",
    )
    serve.add_argument(
        "--filigree-url",
        help="Filigree issue-tracker API URL (falls back to FILIGREE_API_URL env var)",
    )
    serve.add_argument(
        "--binding-db",
        help="Signoff-binding ledger URL (falls back to LEGIS_BINDING_DB env var)",
    )
    _add_judge_flags(serve)

    mcp = subparsers.add_parser("mcp", help="Run the Legis MCP stdio server")
    mcp.add_argument("--agent-id", required=True, help="Launch-bound agent identity")
    mcp.add_argument(
        "--governance-db",
        help="Governance store URL (falls back to LEGIS_GOVERNANCE_DB env var)",
    )
    mcp.add_argument(
        "--check-db",
        help="Check store URL (falls back to LEGIS_CHECK_DB env var)",
    )
    mcp.add_argument(
        "--policy-cells",
        help="Policy cell registry TOML path (falls back to LEGIS_POLICY_CELLS env var)",
    )
    mcp.add_argument(
        "--protected-policies",
        help="Comma-separated protected policy list (falls back to LEGIS_PROTECTED_POLICIES env var)",
    )
    mcp.add_argument(
        "--loomweave-url",
        help="Loomweave identity API URL (falls back to LOOMWEAVE_API_URL env var)",
    )
    _add_judge_flags(mcp)

    from legis.config import governance_db_url
    gov_db_default = governance_db_url()
    rate = subparsers.add_parser(
        "check-override-rate",
        help="Fail (exit 1) if the override-rate gate is FAIL — for CI",
    )
    rate.add_argument(
        "--db", default=gov_db_default,
        help="Governance store URL (defaults to the server's governance store)",
    )
    gate = subparsers.add_parser(
        "governance-gate",
        help="Run governance CI gates; currently the override-rate gate",
    )
    gate.add_argument(
        "--db", default=gov_db_default,
        help="Governance store URL (defaults to the server's governance store)",
    )
    gov_read = subparsers.add_parser(
        "governance-read",
        help="Read per-SEI verified governance clearances (governance_read.v1); output is always JSON",
    )
    gov_read.add_argument("sei", help="Stable Entity Identity (SEI) to query")
    gov_read.add_argument(
        "--db", default=gov_db_default,
        help="Governance store URL (defaults to the server's governance store)",
    )
    backfill = subparsers.add_parser(
        "sei-backfill",
        help="Resolve legacy locator-keyed governance records through Loomweave batch resolve",
    )
    backfill.add_argument(
        "--db",
        default=gov_db_default,
        help="Governance store URL (falls back to LEGIS_GOVERNANCE_DB env var)",
    )
    backfill.add_argument(
        "--loomweave-url",
        required=True,
        help="Loomweave identity API URL",
    )
    backfill.add_argument(
        "--execute",
        action="store_true",
        help="Append backfill events. Omit for a dry-run report.",
    )
    backfill.add_argument(
        "--actor",
        default="legis-sei-backfill",
        help="Actor stamped on appended backfill events",
    )

    boundary = subparsers.add_parser(
        "policy-boundary-check",
        help="Fail when @policy_boundary metadata lacks current behavioural evidence",
    )
    boundary.add_argument("--root", default="src", help="Python source root to scan")
    boundary.add_argument("--repo-root", default=".", help="Repo root for test_ref resolution")
    boundary.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="Output format: human-readable text (default) or machine-readable json",
    )

    install = subparsers.add_parser(
        "install",
        help="Inject legis instructions, install the legis-workflow skill, and register the hook",
    )
    install.add_argument("--claude-md", action="store_true", help="Inject instructions into CLAUDE.md only")
    install.add_argument("--agents-md", action="store_true", help="Inject instructions into AGENTS.md only")
    install.add_argument("--skills", action="store_true", help="Install the Claude Code skill pack only")
    install.add_argument("--codex-skills", action="store_true", help="Install the Codex skill pack only")
    install.add_argument("--hooks", action="store_true", help="Register the Claude Code SessionStart hook only")
    install.add_argument("--gitignore", action="store_true", help="Add legis config rules to .gitignore only")
    install.add_argument("--mcp", action="store_true", help="Register the legis MCP server in .mcp.json only")
    install.add_argument(
        "--posture", action="store_true",
        help="Mint the operator key + write the posture-ledger GENESIS only",
    )
    install.add_argument(
        "--insecure-key-in-env", action="store_true",
        help="Custody the operator key via the plaintext LEGIS_OPERATOR_KEY env "
             "var (CI/headless escape hatch; emits a warning — never use in prod)",
    )
    install.add_argument(
        "--agent-id", default=None,
        help="Agent id stamped in the .mcp.json legis entry "
             "(default: claude-code, or preserve an existing entry's id)",
    )

    subparsers.add_parser(
        "session-context",
        help="SessionStart hook: print a posture banner and refresh drifted legis instructions/skills in the cwd",
    )

    doctor = subparsers.add_parser(
        "doctor",
        help="View and repair legis install/config health",
    )
    doctor.add_argument("--root", default=".", help="Project root to inspect (default: cwd)")
    doctor.add_argument("--fix", "--repair", action="store_true", help="Apply safe repairs, then re-check")
    doctor.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="Output format: human text (default) or machine-readable json",
    )

    posture = subparsers.add_parser(
        "posture",
        help="Read the signed posture floor (show) or move it (set, needs an open operator session)",
    )
    posture_sub = posture.add_subparsers(dest="posture_command")
    posture_sub.add_parser("show", help="Print the current posture floor")
    pset = posture_sub.add_parser(
        "set",
        help="Move the floor to <cell>; requires an open operator session (legis operator enable)",
    )
    pset.add_argument("cell", help="Target floor cell (e.g. chill, coached, structured, protected)")
    pset.add_argument(
        "--rationale", default="operator posture change",
        help="Rationale stamped on the signed TRANSITION record",
    )
    pset.add_argument(
        "--agent-id", default="legis-operator-cli",
        help="Agent id stamped on the TRANSITION record",
    )
    prekey = posture_sub.add_parser(
        "rekey",
        help=(
            "Lost-key recovery: mint a new operator key epoch while preserving "
            "the standing floor, and chain a loud KEY_RESET (doctor stays "
            "non-zero until you acknowledge the reset with a signed "
            "`posture set` under the new key)"
        ),
    )
    prekey.add_argument(
        "--backend", default=None,
        help="Custody backend for the new key (keychain, age-file, env). "
        "Defaults to the auto-selected backend.",
    )
    prekey.add_argument(
        "--agent-id", default="legis-operator-cli",
        help="Agent id stamped on the KEY_RESET record",
    )

    operator = subparsers.add_parser(
        "operator",
        help="Open (enable) or close (disable) the operator elevation session that authorizes posture set",
    )
    operator_sub = operator.add_subparsers(dest="operator_command")
    op_enable = operator_sub.add_parser(
        "enable",
        help=(
            "Open an elevation session (sudo for governance signing). "
            "CI/headless bootstrap: set LEGIS_OPERATOR_KEY, run "
            "`legis operator enable --insecure-key-in-env`, then `legis posture set <cell>`."
        ),
    )
    op_enable.add_argument(
        "--ttl", default="5m",
        help="Session window, e.g. 300, 5m, 1h (default: 5m)",
    )
    op_enable.add_argument(
        "--operator-id", default=None,
        help="Operator identity recorded on the session (default: $USER or 'operator')",
    )
    op_enable.add_argument(
        "--insecure-key-in-env", action="store_true",
        help="Use the plaintext LEGIS_OPERATOR_KEY env backend (CI/headless escape hatch; emits a warning)",
    )
    operator_sub.add_parser("disable", help="End the current operator elevation session")

    return parser


def _missing_sqlite_db(url: str) -> Path | None:
    from sqlalchemy.engine import make_url

    parsed = make_url(url)
    if parsed.get_backend_name() != "sqlite":
        return None
    database = parsed.database
    if not database or database == ":memory:":
        return None
    path = Path(database)
    return path if not path.exists() else None


def _apply_judge_env(args) -> None:
    import os

    if getattr(args, "judge_provider", None):
        os.environ["LEGIS_JUDGE_PROVIDER"] = args.judge_provider
    if getattr(args, "judge_model", None):
        os.environ["LEGIS_JUDGE_MODEL"] = args.judge_model
    if getattr(args, "judge_max_tokens", None) is not None:
        os.environ["LEGIS_JUDGE_MAX_TOKENS"] = str(args.judge_max_tokens)


def _check_override_rate(db_url: str) -> int:
    import os
    from legis.config import protected_policies
    from legis.enforcement.lifecycle import GateStatus
    from legis.service.errors import AuditIntegrityError, ProtectedKeyRequiredError
    from legis.service.governance import evaluate_override_rate_gate
    from legis.store.audit_store import AuditStore

    missing_db = _missing_sqlite_db(db_url)
    if missing_db is not None:
        if (
            os.environ.get("CI", "").lower() == "true"
            and os.environ.get("LEGIS_ALLOW_MISSING_GOVERNANCE_DB") != "1"
        ):
            print(
                "override-rate gate: FAIL "
                f"(governance database is missing: {missing_db})",
                file=sys.stderr,
            )
            return 1
        print(
            "override-rate gate: PASS_WITH_NOTICE "
            f"(governance database is missing: {missing_db})"
        )
        return 0

    store = AuditStore(db_url)
    if not store.verify_integrity():
        print("Error: Database hash chain integrity check failed!", file=sys.stderr)
        return 1

    records = store.read_all()

    # The detect -> require-key -> verify -> score decision lives in the service
    # layer (Q-H2), so the cli, the api, and any future consumer all measure the
    # gate the same way. The cli keeps only its I/O shell and exit-code mapping.
    try:
        res = evaluate_override_rate_gate(
            records,
            hmac_key=os.environ.get("LEGIS_HMAC_KEY"),
            protected_policies=protected_policies(),
        )
    except (ProtectedKeyRequiredError, AuditIntegrityError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"override-rate gate: {res.status.value} "
          f"(rate={res.rate:.3f}, sample={res.sample_size})")
    return 1 if res.status is GateStatus.FAIL else 0


def _governance_read(db_url: str, sei: str) -> int:
    """Per-SEI verified governance clearances (governance_read.v1) for the CLI path.

    Both verification halves are mandatory (Constraint 1 / must-fix #1):
      1. ``store.verify_integrity()`` — the hash-chain / seq-contiguity / delete-reorder
         half; catches a tampered non-protected record that ``TrailVerifier.verify``
         is silent about (it only verifies records it recognises as protected).
      2. ``read_governance_for_sei_gate`` — the signature half, through the service
         gate (Constraint 6), exactly as ``_check_override_rate`` does it.

    Fail-closed paths: no key → unavailable; missing DB → unavailable; chain
    tamper → exit 1; signature tamper → exit 1. No bare ``except``.
    Output is always JSON (no ``--json`` flag needed / warning avoided).
    """
    import os

    from legis.config import protected_policies
    from legis.service.errors import AuditIntegrityError, ProtectedKeyRequiredError
    from legis.service.governance import governance_read_unavailable, read_governance_for_sei_gate
    from legis.store.audit_store import AuditStore

    hmac_key = os.environ.get("LEGIS_HMAC_KEY")
    if not hmac_key:
        # No key → signatures are unverifiable from the CLI → unavailable, never
        # a silent checked/[] that claims clearances were confirmed.
        print(json.dumps(governance_read_unavailable(
            sei, "trail not signature-verifiable (LEGIS_HMAC_KEY unset)"), sort_keys=True))
        return 0

    missing_db = _missing_sqlite_db(db_url)
    if missing_db is not None:
        # Absent store on a READ = unavailable (NOT the override-rate CI
        # PASS_WITH_NOTICE axis, and NOT an auto-created empty DB read as
        # checked/[] — that would be a false-green on the "no governance yet"
        # case, indistinguishable from "verified and found none").
        print(json.dumps(governance_read_unavailable(
            sei, f"governance store not found: {missing_db}"), sort_keys=True))
        return 0

    store = AuditStore(db_url)
    # HALF 1: hash-chain / seq-contiguity / delete-reorder defence.
    # Must run BEFORE read_all + the service gate (which only checks
    # signatures, not the chain). A seq gap in non-protected records
    # passes TrailVerifier.verify silently but fails here.
    if not store.verify_integrity():
        print(
            "Error: audit integrity failure: database hash chain verification failed",
            file=sys.stderr,
        )
        return 1

    records = store.read_all()
    try:
        # HALF 2: signature verification, through the service gate (Constraint 6).
        # TamperError is wrapped into AuditIntegrityError inside the gate.
        envelope = read_governance_for_sei_gate(
            records, sei, hmac_key=hmac_key, protected_policies=protected_policies()
        )
    except (ProtectedKeyRequiredError, AuditIntegrityError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(envelope, sort_keys=True))
    return 0


def _run_doctor(args) -> int:
    from legis.doctor import run_doctor

    return run_doctor(Path(args.root), repair=args.fix, fmt=args.format)


def _parse_ttl(spec: str) -> int:
    """Parse a TTL like ``300``, ``5m``, ``1h`` into seconds.

    A bare integer is seconds; ``s``/``m``/``h`` suffixes scale. Fail-closed:
    an unparseable value raises ``ValueError`` so the caller refuses rather than
    opening a silently-wrong (e.g. zero-length) window.
    """
    s = spec.strip().lower()
    if not s:
        raise ValueError("empty TTL")
    units = {"s": 1, "m": 60, "h": 3600}
    if s[-1] in units:
        value, scale = s[:-1], units[s[-1]]
    else:
        value, scale = s, 1
    n = int(value)
    if n <= 0:
        raise ValueError(f"TTL must be positive, got {spec!r}")
    return n * scale


def _build_operator_signer(backend_id: str):
    """Construct the custody signer for an open session's backend (Phase 7).

    Mirrors the install-time custody routing: ``env`` -> :class:`EnvSigner`
    (plaintext escape hatch, behind its own opt-in), ``age-file`` ->
    :class:`AgeFileSigner` over the at-rest blob with a per-sign passphrase
    re-prompt, ``keychain`` -> not shipped (raises LOUD). Fail-closed: any
    custody gap raises rather than returning a wrong-key signer.
    """
    from legis.posture import AgeFileSigner, EnvSigner

    if backend_id == "env":
        return EnvSigner(insecure_env=True)
    if backend_id == "age-file":
        import os

        from legis.config import operator_age_path

        blob_path = operator_age_path()
        if not blob_path.exists():
            raise RuntimeError(
                f"age-file custody blob {blob_path} is missing; re-run `legis install --posture`"
            )
        blob = blob_path.read_bytes()
        passphrase = os.environ.get("LEGIS_OPERATOR_KEY_AGE_PASSPHRASE")
        if not passphrase:
            raise RuntimeError(
                "age-file custody needs the passphrase in "
                "LEGIS_OPERATOR_KEY_AGE_PASSPHRASE to sign the posture change"
            )
        return AgeFileSigner(blob=blob, passphrase_cb=lambda: passphrase)
    raise RuntimeError(
        f"no shipped custody adapter for backend {backend_id!r}; cannot sign the posture change"
    )


def _run_posture(args) -> int:
    from legis.clock import SystemClock
    from legis.config import posture_db_url
    from legis.posture import PostureLedger, load_session, set_floor
    from legis.posture.ledger import PostureSetResult

    command = getattr(args, "posture_command", None)

    if command == "show":
        # Read path: open the ledger handle without running DDL (initialize=False)
        # so a `show` never mutates local state on launch (Phase-4 reconciliation).
        ledger = PostureLedger(posture_db_url(), initialize=False)
        floor = ledger.read_floor()
        if floor is None:
            print("posture floor: structured (no ledger)")
        else:
            print(f"posture floor: {floor}")
        return 0

    if command == "set":
        # Per D3 a posture change REQUIRES an open elevation session; there is no
        # direct-sign path. Resolve the session's backend, build its signer, and
        # run the change gate, which is fail-closed end to end.
        session = load_session()
        if session is None:
            print(
                "posture set: refused — no open operator session. Run "
                "`legis operator enable` first.",
                file=sys.stderr,
            )
            return 1
        try:
            signer = _build_operator_signer(session.backend_id)
        except Exception as exc:  # noqa: BLE001 — custody gap is a fail-closed refusal
            print(f"posture set: refused — {exc}", file=sys.stderr)
            return 1

        ledger = PostureLedger(posture_db_url(), initialize=False)
        result: PostureSetResult = set_floor(
            args.cell,
            ledger=ledger,
            signer=signer,
            agent_id=args.agent_id,
            rationale=args.rationale,
        )
        if not result.accepted:
            detail = f" ({result.detail})" if result.detail else ""
            print(
                f"posture set: refused — {result.reason}{detail}",
                file=sys.stderr,
            )
            return 1
        print(f"posture floor set to {result.floor} (session {result.session_id})")
        return 0

    if command == "rekey":
        # Lost-key recovery (Phase 11 / design §8): mint a fresh key epoch while
        # preserving the standing floor, and chain a loud KEY_RESET. Needs NO
        # open session and NO old key — a lost key cannot sign, so the indelible,
        # doctor-flagged record IS the accountability. The new key bytes reach
        # ONLY custody via the install key-sink; the ledger stores the fingerprint
        # alone.
        from legis.install import OperatorKeyCustodyError, _default_key_sink, choose_install_backend

        backend = args.backend
        if backend is None:
            backend = choose_install_backend(insecure_env=False)
        if backend == "env":
            print(
                "posture rekey: refused — env custody cannot persist the freshly "
                "minted rekey key from this child process; use age-file or keychain.",
                file=sys.stderr,
            )
            return 1
        ledger = PostureLedger(posture_db_url(), initialize=True)
        try:
            new_fp = ledger.rekey(
                agent_id=args.agent_id,
                recorded_at=SystemClock().now_iso(),
                key_sink=_default_key_sink,
                backend=backend,
            )
        except (OperatorKeyCustodyError, RuntimeError, ValueError) as exc:
            print(f"posture rekey: refused — {exc}", file=sys.stderr)
            return 1
        print(
            f"posture rekey: new key epoch {new_fp[:12]}… minted (backend={backend}); "
            f"floor preserved as {ledger.read_floor() or 'structured'}. Acknowledge "
            f"the reset with a signed `legis posture set` under the new key — "
            f"`legis doctor` stays non-zero until you do."
        )
        return 0

    # `legis posture` with no subcommand.
    print("usage: legis posture {show,set,rekey}", file=sys.stderr)
    return 2


def _run_operator(args) -> int:
    from legis.clock import SystemClock
    from legis.config import posture_db_url
    from legis.posture import (
        PostureLedger,
        end_session,
        open_session,
        persist_session,
    )

    command = getattr(args, "operator_command", None)

    if command == "disable":
        end_session()
        print("operator session ended")
        return 0

    if command == "enable":
        import os

        try:
            ttl = _parse_ttl(args.ttl)
        except ValueError as exc:
            print(f"operator enable: refused — invalid --ttl: {exc}", file=sys.stderr)
            return 1

        insecure_env = getattr(args, "insecure_key_in_env", False)
        operator_id = (
            args.operator_id
            or os.environ.get("USER")
            or "operator"
        )

        # Resolve + verify custody up front so `enable` cannot open a window the
        # operator can never sign through. Building the signer is the unlock:
        # env reads LEGIS_OPERATOR_KEY (and emits the plaintext warning),
        # age-file re-prompts per sign (unlock_ref stays None, D5), keychain is
        # the only backend carrying a non-null unlock_ref (its item id).
        from legis.install import choose_install_backend

        backend_id = choose_install_backend(insecure_env=insecure_env)
        try:
            signer = _build_operator_signer(backend_id)
        except Exception as exc:  # noqa: BLE001 — fail-closed: no session on custody gap
            print(f"operator enable: refused — {exc}", file=sys.stderr)
            return 1

        ledger = PostureLedger(posture_db_url(), initialize=False)
        epoch_fp = ledger.current_epoch_fingerprint()
        if epoch_fp is None:
            print(
                "operator enable: refused — no posture key epoch exists yet; run "
                "`legis install --posture` after configuring key custody.",
                file=sys.stderr,
            )
            return 1
        try:
            signer_fp = signer.fingerprint()
        except Exception as exc:  # noqa: BLE001 — custody gap is a fail-closed refusal
            print(f"operator enable: refused — cannot read signer fingerprint: {exc}", file=sys.stderr)
            return 1
        if signer_fp != epoch_fp:
            print(
                "operator enable: refused — signer fingerprint does not match the "
                "current posture key epoch.",
                file=sys.stderr,
            )
            return 1

        # The keychain item id is the only non-null unlock_ref (D5); env/age-file
        # carry None (re-prompt / resident plaintext is the unlock).
        unlock_ref = getattr(signer, "_item_id", None)

        clock = SystemClock()
        session = open_session(
            ttl=ttl,
            operator_id=operator_id,
            backend_id=backend_id,
            unlock_ref=unlock_ref,
            signer=signer,
            persist=False,
        )
        # The env path STILL opens a session (D3): every TRANSITION it later
        # produces carries this session_id, so there is no auth path that
        # bypasses session accountability. Append the audit event before writing
        # the session file; a ledger failure must not leave a usable unaudited
        # elevation window behind.
        ledger.session_opened(
            operator_id=operator_id,
            enabled_at=clock.now_iso(),
            ttl=ttl,
            keychain_auth_ref=unlock_ref,
            session_id=session.session_id,
        )
        persist_session(session)
        if insecure_env:
            print(
                "WARNING: --insecure-key-in-env uses the plaintext LEGIS_OPERATOR_KEY "
                "backend, readable by this process; use keychain/age-file in production."
            )
        print(
            f"operator session opened for {operator_id} "
            f"(backend={backend_id}, window={ttl}s, session={session.session_id})"
        )
        return 0

    print("usage: legis operator {enable,disable}", file=sys.stderr)
    return 2


def _run_install(args) -> int:
    from legis.install import (
        OperatorKeyCustodyError,
        choose_install_backend,
        ensure_gitignore,
        ensure_legis_dir_gitignore,
        inject_instructions,
        install_claude_code_hooks,
        install_codex_skills,
        install_posture,
        install_skills,
        register_mcp_json,
    )

    project_root = Path.cwd()
    install_all = not any(
        [
            args.claude_md,
            args.agents_md,
            args.skills,
            args.codex_skills,
            args.hooks,
            args.gitignore,
            args.mcp,
            args.posture,
        ]
    )

    def _do_posture() -> tuple[bool, str]:
        insecure_env = getattr(args, "insecure_key_in_env", False)
        backend = choose_install_backend(insecure_env=insecure_env)
        try:
            fp = install_posture(project_root, backend=backend)
        except OperatorKeyCustodyError as exc:
            # NO genesis was written (the sink runs before the append), so the
            # ledger never carries a fingerprint the operator cannot sign
            # against. A broad install may defer posture setup, but an explicit
            # posture install is a readiness check and must fail closed.
            return not args.posture, (
                f"deferred: {exc} "
                f"(re-run `legis install --posture` once custody is configured)"
            )
        if fp is None:
            return False, "posture ledger could not be read back after genesis"
        return True, f"posture ledger ready (backend={backend}, key={fp[:12]}…)"

    steps: list[tuple[bool, str, object]] = [
        (install_all or args.claude_md, "CLAUDE.md", lambda: inject_instructions(project_root / "CLAUDE.md")),
        (install_all or args.agents_md, "AGENTS.md", lambda: inject_instructions(project_root / "AGENTS.md")),
        (install_all or args.skills, "Claude Code skill", lambda: install_skills(project_root)),
        (install_all or args.codex_skills, "Codex skill", lambda: install_codex_skills(project_root)),
        (install_all or args.hooks, "Claude Code hook", lambda: install_claude_code_hooks(project_root)),
        (install_all or args.gitignore, ".gitignore", lambda: ensure_gitignore(project_root)),
        (
            install_all or args.gitignore,
            ".weft/legis/.gitignore",
            lambda: ensure_legis_dir_gitignore(project_root),
        ),
        (install_all or args.mcp, ".mcp.json", lambda: register_mcp_json(project_root, args.agent_id)),
        (install_all or args.posture, "posture ledger", _do_posture),
    ]

    failures = 0
    for selected, name, step in steps:
        if not selected:
            continue
        try:
            ok, message = step()  # type: ignore[operator]
        except Exception as exc:  # noqa: BLE001 — one bad step must not abort the rest
            # Stay consistent with the per-step [OK]/[FAIL] model instead of
            # aborting the whole install with a traceback and leaving it
            # half-applied. Render the failure, count it, keep going.
            logger.warning("install step %r raised", name, exc_info=True)
            print(f"[FAIL] {name}: {exc}")
            failures += 1
            continue
        mark = "OK" if ok else "FAIL"
        print(f"[{mark}] {name}: {message}")
        if not ok:
            failures += 1
    return 1 if failures else 0


def _refresh_instructions_best_effort() -> None:
    """Refresh drifted legis instructions on MCP boot. Never raises."""
    try:
        from legis.hooks import refresh_instructions

        for message in refresh_instructions(Path.cwd()):
            print(message, file=sys.stderr)
    except Exception:  # noqa: BLE001  (boot refresh must never break the server)
        # Best-effort: never break the server, but don't vanish silently either —
        # the sibling SessionStart path (hooks.generate_session_context) logs too.
        logger.warning("Best-effort instruction refresh on MCP boot failed", exc_info=True)


def main(argv: list[str] | None = None, *, run=uvicorn.run) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        import os
        if args.governance_db:
            os.environ["LEGIS_GOVERNANCE_DB"] = args.governance_db
        if args.check_db:
            os.environ["LEGIS_CHECK_DB"] = args.check_db
        if args.protected_policies:
            os.environ["LEGIS_PROTECTED_POLICIES"] = args.protected_policies
        if args.loomweave_url:
            os.environ["LOOMWEAVE_API_URL"] = args.loomweave_url
        if args.filigree_url:
            os.environ["FILIGREE_API_URL"] = args.filigree_url
        if args.binding_db:
            os.environ["LEGIS_BINDING_DB"] = args.binding_db
        _apply_judge_env(args)

        run("legis.api.app:create_app", host=args.host, port=args.port, factory=True)
        return 0

    if args.command == "install":
        return _run_install(args)

    if args.command == "session-context":
        from legis.hooks import generate_session_context

        # Always non-empty (N-1): a posture banner, then any refresh messages.
        print(generate_session_context())
        return 0

    if args.command in {"check-override-rate", "governance-gate"}:
        return _check_override_rate(args.db)

    if args.command == "governance-read":
        return _governance_read(args.db, args.sei)

    if args.command == "sei-backfill":
        report = run_pre_sei_backfill(
            AuditStore(args.db),
            HttpLoomweaveIdentity(args.loomweave_url, hmac_key=loomweave_hmac_key_from_env()),
            SystemClock(),
            dry_run=not args.execute,
            actor=args.actor,
        )
        print(json.dumps(report.to_dict(), sort_keys=True))
        return 0

    if args.command == "mcp":
        import os
        if args.governance_db:
            os.environ["LEGIS_GOVERNANCE_DB"] = args.governance_db
        if args.protected_policies:
            os.environ["LEGIS_PROTECTED_POLICIES"] = args.protected_policies
        if args.loomweave_url:
            os.environ["LOOMWEAVE_API_URL"] = args.loomweave_url
        if args.check_db:
            os.environ["LEGIS_CHECK_DB"] = args.check_db
        if args.policy_cells:
            os.environ["LEGIS_POLICY_CELLS"] = args.policy_cells
        _apply_judge_env(args)

        # Universal refresh trigger: every agent (Claude or Codex) reaches legis
        # by booting this MCP server, so refreshing here keeps the instruction
        # block + skill pack fresh even in Codex-only repos with no SessionStart
        # hook. Best-effort — it must never block or break server startup.
        _refresh_instructions_best_effort()

        from legis.mcp import main as mcp_main

        return mcp_main(args.agent_id)

    if args.command == "policy-boundary-check":
        from pathlib import Path

        from legis.policy.boundary_scan import count_source_files

        # repo_root defaults to "." (the real working directory); a relative
        # --root resolves against it so a misrouted repo_root cannot silently
        # scan the wrong tree.
        repo_root = Path(args.repo_root)
        root = Path(args.root)
        if not root.is_absolute():
            root = repo_root / root
        # Gate honesty (cf. weft-ef2e898642 silent-clean-on-zero-scope): a scan
        # that looked at NOTHING — missing root, or a root with zero analyzable
        # .py files — must NOT report a clean PASS. Surface NO_ROOT and a nonzero
        # exit so CI cannot mistake a vacuous green for a real one.
        if count_source_files(root) == 0:
            if not root.exists():
                detail = (
                    f"scan root {root} does not exist; nothing was scanned. "
                    "Pass --root pointing at the project's Python source."
                )
            else:
                detail = (
                    f"scan root {root} contains no analyzable Python files; "
                    "nothing was scanned. Pass --root pointing at the project's "
                    "Python source — a zero-file scan is never a clean PASS."
                )
            if args.format == "json":
                print(
                    json.dumps(
                        {
                            "outcome": "NO_ROOT",
                            "findings": [],
                            "scanned_root": str(root),
                            "repo_root": str(repo_root),
                            "detail": detail,
                        },
                        sort_keys=True,
                    )
                )
            else:
                print(f"policy-boundary-check: NO_ROOT: {detail}")
            return 2

        findings = scan_policy_boundaries(root, repo_root=args.repo_root)
        if args.format == "json":
            print(json.dumps([f.to_dict() for f in findings], sort_keys=True))
        elif findings:
            for f in findings:
                print(f"{f.file_path}:{f.line}: {f.rule_id}: {f.qualname}: {f.reason}")
        else:
            print("policy-boundary-check: PASS")
        return 1 if findings else 0

    if args.command == "doctor":
        return _run_doctor(args)

    if args.command == "posture":
        return _run_posture(args)

    if args.command == "operator":
        return _run_operator(args)

    parser.print_help(sys.stderr)
    return 2
