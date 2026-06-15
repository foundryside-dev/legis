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


def _run_doctor(args) -> int:
    from legis.doctor import run_doctor

    return run_doctor(Path(args.root), repair=args.fix, fmt=args.format)


def _run_install(args) -> int:
    from legis.install import (
        ensure_gitignore,
        inject_instructions,
        install_claude_code_hooks,
        install_codex_skills,
        install_skills,
        register_mcp_json,
    )

    project_root = Path.cwd()
    install_all = not any(
        [args.claude_md, args.agents_md, args.skills, args.codex_skills, args.hooks, args.gitignore, args.mcp]
    )

    steps: list[tuple[bool, str, object]] = [
        (install_all or args.claude_md, "CLAUDE.md", lambda: inject_instructions(project_root / "CLAUDE.md")),
        (install_all or args.agents_md, "AGENTS.md", lambda: inject_instructions(project_root / "AGENTS.md")),
        (install_all or args.skills, "Claude Code skill", lambda: install_skills(project_root)),
        (install_all or args.codex_skills, "Codex skill", lambda: install_codex_skills(project_root)),
        (install_all or args.hooks, "Claude Code hook", lambda: install_claude_code_hooks(project_root)),
        (install_all or args.gitignore, ".gitignore", lambda: ensure_gitignore(project_root)),
        (install_all or args.mcp, ".mcp.json", lambda: register_mcp_json(project_root, args.agent_id)),
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

    parser.print_help(sys.stderr)
    return 2
