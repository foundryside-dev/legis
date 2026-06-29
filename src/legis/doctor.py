"""`legis doctor` — view and repair legis install/config health.

It inspects and repairs the *host* install and legis's own per-member
artifacts. The REPORT side (``collect_checks(..., repair=False)`` /
``doctor_payload``) is shared with the agent MCP surface's report-only
``doctor_get`` tool; the REPAIR side stays operator/CLI only (``--fix`` is
never reachable over MCP, C-8), and per hub doctrine C-9(b) doctor NEVER
writes weft.toml.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from sqlalchemy.engine import make_url

from legis import config
from legis import install as _install


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    id: str
    status: str  # "ok" | "warn" | "error"
    fixed: bool = False
    message: str | None = None
    repairable: bool = False

    @property
    def ok(self) -> bool:
        return self.status != "error"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "status": self.status,
            "fixed": self.fixed,
            "repairable": self.repairable,
        }
        if self.message:
            data["message"] = self.message
        return data


def _next_actions(checks: list[DoctorCheck]) -> list[str]:
    return [f"{c.id}: {c.message}" for c in checks if c.status != "ok" and c.message]


def doctor_payload(checks: list[DoctorCheck]) -> dict[str, Any]:
    """The machine-readable doctor report — single-sourced for the CLI's
    ``--format json`` and the MCP ``doctor_get`` structuredContent, so the two
    surfaces can never drift."""
    return {
        "ok": all(c.ok for c in checks),
        "checks": [c.to_dict() for c in checks],
        "next_actions": _next_actions(checks),
    }


def render_json(checks: list[DoctorCheck]) -> str:
    return json.dumps(doctor_payload(checks), indent=2, sort_keys=True)


def render_text(checks: list[DoctorCheck]) -> str:
    has_error = any(c.status == "error" for c in checks)
    has_warn = any(c.status == "warn" for c in checks)
    fixed = [c for c in checks if c.fixed]
    # Render anything that is not a clean pass: problems AND repaired items. A
    # repaired check carries status "ok" + fixed=True, so a problems-only filter
    # (status != "ok") would drop it — leaving the operator no record of what
    # `--fix` repaired and the [fixed] tag below unreachable.
    rendered = [c for c in checks if c.status != "ok" or c.fixed]
    if not has_error:
        # warn-only / all-ok / repaired: the project is healthy; surface any warns
        # and repairs below.
        notes = []
        if has_warn:
            notes.append(f"{sum(1 for c in checks if c.status == 'warn')} warning(s)")
        if fixed:
            notes.append(f"fixed {len(fixed)} item(s)")
        header = "legis doctor: ok" + (f" ({', '.join(notes)})" if notes else "")
        if not rendered:
            return header
        lines = [header]
    else:
        lines = ["legis doctor:"]
    has_auto_fixable = False
    has_operator = False
    for c in rendered:
        if c.fixed:
            tag = "[fixed]"
        elif c.repairable:
            tag = "[auto-fixable]"
            has_auto_fixable = True
        else:
            tag = "[operator]"
            has_operator = True
        body = f"{c.status} — {c.message}" if c.message else c.status
        lines.append(f"  {c.id}: {body} {tag}")
    if has_auto_fixable:
        lines.append("  -> Run `legis doctor --fix` to repair auto-fixable items.")
    if has_operator:
        lines.append(
            "  -> [operator] items are not auto-fixable by `legis doctor --fix`; they need "
            "out-of-band config (env var or file) and a relaunch (see each line)."
        )
    return "\n".join(lines)


def check_mcp_json(root: Path, *, repair: bool) -> DoctorCheck:
    """Check that `.mcp.json` has a current legis server entry.

    'Current' means: a legis entry exists, its args invoke `mcp`, and its
    command resolves to an existing executable. Byte-equality with the canonical
    entry is deliberately NOT required — a valid but differently-resolved legis
    binary (uv-tool vs venv path) must not read as drift.
    """
    cid = "install.mcp_json"
    if _install.mcp_entry_is_current(root):
        return DoctorCheck(cid, "ok", repairable=True)
    if repair:
        from legis.install import register_mcp_json

        ok, msg = register_mcp_json(root)
        if ok and _install.mcp_entry_is_current(root):
            return DoctorCheck(cid, "ok", fixed=True, repairable=True)
        return DoctorCheck(cid, "error", message=msg, repairable=True)
    return DoctorCheck(
        cid, "error", message="legis server missing or stale (run: legis install --mcp)", repairable=True
    )


# ---------------------------------------------------------------------------
# Install-wiring checks (Task 6)
# ---------------------------------------------------------------------------


def _block_tokens(root: Path, filename: str) -> list[str | None] | None:
    """Tokens of every legis block in <root>/<filename>, or None if unreadable.

    ``[]`` means the file exists but carries no legis block. More than one entry
    is a split brain (two divergent copies of the guidance)."""
    path = root / filename
    if not path.exists():
        return None
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    return _install._own_open_marker_tokens(content)


def _block_fresh(root: Path, filename: str) -> bool:
    """True iff <root>/<filename> has EXACTLY ONE legis block at the current token.

    A second (stale) block is a split brain the injector tolerates but cannot
    canonicalise across a sibling — reading freshness off the first marker alone
    would report "healthy" while conflicting guidance sits in the file
    (INSTALL-1). Requiring a singleton list at the current token closes that.
    """
    tokens = _block_tokens(root, filename)
    return tokens == [_install._marker_token()]


def check_instruction_block(root: Path, filename: str, *, repair: bool) -> DoctorCheck:
    """Check that <root>/<filename> has the legis instruction block at the current token."""
    cid = "install.claude_md" if filename == "CLAUDE.md" else "install.agents_md"
    if _block_fresh(root, filename):
        return DoctorCheck(cid, "ok", repairable=True)
    # A split brain (>1 legis block) cannot be auto-collapsed: the injector
    # bounds its rewrite at its own first close and will not splice across a
    # sibling's block or delete inter-block user content, so re-running install
    # canonicalises the first block but leaves the stale copy. Surface it for
    # hand-resolution instead of churning or, worse, reporting healthy.
    tokens = _block_tokens(root, filename)
    if tokens is not None and len(tokens) > 1:
        return DoctorCheck(
            cid,
            "error",
            message=(
                f"{filename} has {len(tokens)} legis instruction blocks (split "
                "brain); the stale copy cannot be auto-collapsed across another "
                "tool's block — resolve it by hand"
            ),
            # NOT auto-fixable: --fix returns before the repair branch for this
            # split-brain case (the injector won't splice across a sibling's
            # block), so tag it [operator] to match its own "resolve it by hand"
            # message — tagging [auto-fixable] would re-create the --fix loop the
            # plan eliminates (false signal in a codebase that blocks on those).
            repairable=False,
        )
    if repair:
        ok, msg = _install.inject_instructions(root / filename)
        if ok and _block_fresh(root, filename):
            return DoctorCheck(cid, "ok", fixed=True, repairable=True)
        return DoctorCheck(cid, "error", message=msg, repairable=True)
    missing = "missing" if not (root / filename).exists() else "block missing or drifted"
    return DoctorCheck(cid, "error", message=f"{filename} {missing} (run: legis install)", repairable=True)


def _skill_fresh(root: Path, base: str) -> bool:
    """True iff the skill pack under <root>/<base>/skills/ matches the source fingerprint."""
    source = _install._get_skills_source_dir() / _install.SKILL_NAME
    target = root / base / "skills" / _install.SKILL_NAME
    if not source.is_dir() or not target.is_dir():
        return False
    return _install._skill_tree_fingerprint(target) == _install._skill_tree_fingerprint(source)


def check_skill_pack(root: Path, base: str, *, repair: bool) -> DoctorCheck:
    """Check that the legis skill pack under <root>/<base>/skills/ is present and fresh."""
    cid = "install.claude_skill" if base == ".claude" else "install.agents_skill"
    installer = _install.install_skills if base == ".claude" else _install.install_codex_skills
    if _skill_fresh(root, base):
        return DoctorCheck(cid, "ok", repairable=True)
    if repair:
        ok, msg = installer(root)
        if ok and _skill_fresh(root, base):
            return DoctorCheck(cid, "ok", fixed=True, repairable=True)
        return DoctorCheck(cid, "error", message=msg, repairable=True)
    return DoctorCheck(
        cid,
        "error",
        message=f"{base}/skills/{_install.SKILL_NAME} missing or drifted (run: legis install)",
        repairable=True,
    )


def _hook_present(root: Path) -> bool:
    """True iff the SessionStart hook is registered in .claude/settings.json."""
    settings_path = root / ".claude" / "settings.json"
    if not settings_path.exists():
        return False
    try:
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    return _install._has_unscoped_session_start_hook(
        settings,
        _install.SESSION_CONTEXT_COMMAND,
        project_root=root,
    )


def check_hook(root: Path, *, repair: bool) -> DoctorCheck:
    """Check that the legis SessionStart hook is registered."""
    cid = "install.hook"
    if _hook_present(root):
        return DoctorCheck(cid, "ok", repairable=True)
    if repair:
        ok, msg = _install.install_claude_code_hooks(root)
        if ok and _hook_present(root):
            return DoctorCheck(cid, "ok", fixed=True, repairable=True)
        return DoctorCheck(cid, "error", message=msg, repairable=True)
    return DoctorCheck(
        cid, "error", message="SessionStart hook not registered (run: legis install)", repairable=True
    )


def check_gitignore(root: Path, *, repair: bool) -> DoctorCheck:
    """Check that legis .gitignore rules are present."""
    cid = "install.gitignore"
    if _install.gitignore_rules_present(root):
        return DoctorCheck(cid, "ok", repairable=True)
    if repair:
        ok, msg = _install.ensure_gitignore(root)
        if ok and _install.gitignore_rules_present(root):
            return DoctorCheck(cid, "ok", fixed=True, repairable=True)
        return DoctorCheck(cid, "error", message=msg, repairable=True)
    return DoctorCheck(
        cid, "error", message=".weft/legis/ not in .gitignore (run: legis install)", repairable=True
    )


def _nested_gitignore_shipped(legis_dir: Path) -> bool:
    """True iff ``.weft/legis/.gitignore`` carries the legis-managed marker."""
    nested = legis_dir / ".gitignore"
    try:
        return nested.is_file() and _install.LEGIS_DIR_GITIGNORE_MARKER in nested.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False


def check_dir_gitignore(root: Path, *, repair: bool) -> DoctorCheck:
    """Check that legis's dot-dir ships its nested ``.gitignore`` (suite standard).

    An absent ``.weft/legis/`` is OK — it is created lazily and holds nothing to
    protect yet (mirrors :func:`check_store_dir`). Once the dir exists, the
    nested ignore must be present so legis runtime state never commits even if a
    consuming repo drops the root ``.weft/`` rule (filigree-4ed8152630).
    """
    cid = "install.dir_gitignore"
    legis_dir = _store_dir_for(root)
    if _nested_gitignore_shipped(legis_dir):
        return DoctorCheck(cid, "ok", repairable=True)
    if repair:
        # Ship it (creating .weft/legis/ if needed) so the protection exists
        # before any DB is opened — robust against the dir being created lazily
        # by a later check (e.g. an audit-chain DB open) in the same repair pass.
        ok, msg = _install.ensure_legis_dir_gitignore(root)
        if ok and _nested_gitignore_shipped(legis_dir):
            return DoctorCheck(cid, "ok", fixed=True, repairable=True)
        return DoctorCheck(cid, "error", message=msg, repairable=True)
    if not legis_dir.is_dir():
        # Created lazily; nothing to protect yet (mirrors check_store_dir).
        return DoctorCheck(cid, "ok", repairable=True)
    return DoctorCheck(
        cid, "error", message=".weft/legis/.gitignore missing (run: legis install)", repairable=True
    )


# ---------------------------------------------------------------------------
# Task 7: config & store checks
# ---------------------------------------------------------------------------

# Sourced from config's single store-identity registry so adding a store there
# can't silently drop doctor coverage (review #2).
_DB_OVERRIDE_ENVS = tuple(env for env, _ in config.STORE_DB_SPECS)
_LEGACY_DB_NAMES = tuple(name for _, name in config.STORE_DB_SPECS)


def _store_dir_for(root: Path) -> Path:
    """legis's built-in store dir anchored at *root*.

    Repo-local ``weft.toml`` is report-only for doctor and must not redirect
    governance checks. Operators relocate stores with explicit ``LEGIS_*_DB``
    env vars, which ``_store_url`` handles before calling this helper.
    """
    return root / ".weft" / "legis"


def check_weft_toml(root: Path) -> DoctorCheck:
    """Report-only (C-9(b)): NEVER writes weft.toml. Distinguishes ABSENT (ok —
    defaults intentional) from PRESENT-BUT-BROKEN (error — config silently not
    applying), restoring the operator signal that C-9(c) silences at runtime."""
    cid = "config.weft_toml"
    path = root / "weft.toml"
    if not path.exists():
        return DoctorCheck(cid, "ok", message="absent (built-in defaults)")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as exc:
        return DoctorCheck(
            cid,
            "error",
            message=f"present but unparseable; [legis] silently not applying ({exc})",
        )
    table = data.get("legis")
    if table is not None and not isinstance(table, dict):
        return DoctorCheck(cid, "error", message="[legis] in weft.toml must be a table")
    return DoctorCheck(cid, "ok")


def _nearest_existing(path: Path) -> Path:
    p = path
    while not p.exists() and p != p.parent:
        p = p.parent
    return p


def check_store_dir(root: Path, *, repair: bool = False) -> DoctorCheck:
    """An absent .weft/legis/ is ok (created lazily). A present-but-unwritable
    dir is an error. --fix ensures the dir exists (explicit operator action)."""
    cid = "store.dir"
    store_dir = _store_dir_for(root)
    if store_dir.exists():
        if not os.access(store_dir, os.W_OK):
            return DoctorCheck(cid, "error", message=f"{store_dir} not writable", repairable=True)
        return DoctorCheck(cid, "ok", repairable=True)
    if repair:
        try:
            store_dir.mkdir(parents=True, exist_ok=True)
            return DoctorCheck(cid, "ok", fixed=True, repairable=True)
        except OSError as exc:
            return DoctorCheck(cid, "error", message=f"cannot create {store_dir}: {exc}", repairable=True)
    anchor = _nearest_existing(store_dir)
    if not os.access(anchor, os.W_OK):
        return DoctorCheck(
            cid, "error", message=f"{store_dir} not creatable ({anchor} not writable)", repairable=True
        )
    return DoctorCheck(cid, "ok", message="absent (created on first store open)", repairable=True)


def check_db_overrides(root: Path) -> DoctorCheck:  # noqa: ARG001
    cid = "store.db_overrides"
    bad = []
    for env in _DB_OVERRIDE_ENVS:
        # Match config's precedence: a present-but-empty override is a verbatim
        # (broken) override, not "unset" — so validate membership, not truthiness.
        if env not in os.environ:
            continue
        try:
            make_url(os.environ[env])
        except Exception:  # noqa: BLE001 — any parse failure is a bad override
            bad.append(env)
    if bad:
        return DoctorCheck(cid, "error", message="invalid URL in: " + ", ".join(bad))
    return DoctorCheck(cid, "ok")


def check_legacy_stray_db(root: Path) -> DoctorCheck:
    cid = "store.legacy_stray"
    stray = [n for n in _LEGACY_DB_NAMES if (root / n).is_file()]
    if stray:
        return DoctorCheck(
            cid,
            "warn",
            message="legacy DB at repo root (move to .weft/legis/): " + ", ".join(stray),
        )
    return DoctorCheck(cid, "ok")


# ---------------------------------------------------------------------------
# Task 8: governance integrity + runtime/sibling checks
# ---------------------------------------------------------------------------


def _store_url(root: Path, db_name: str, env: str) -> str:
    """Resolve a store URL anchored at *root* (never cwd).
    The LEGIS_*_DB override wins when set (present-but-empty included, matching
    config's verbatim-override precedence); otherwise a file URL is built under
    the built-in root-anchored store dir."""
    if env in os.environ:
        return os.environ[env]
    return "sqlite:///" + (_store_dir_for(root) / db_name).as_posix()


_AUDIT_LOG_COLUMNS = {"seq", "payload", "content_hash", "prev_hash", "chain_hash"}


def _sqlite_audit_schema_error(db: Path) -> str | None:
    """Return a report-only schema error for an existing SQLite audit DB."""
    try:
        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return f"cannot open audit DB read-only: {exc}"
    try:
        row = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
        ).fetchone()
        if row is None:
            return "audit_log table missing (store may be truncated or erased)"
        columns = {row[1] for row in con.execute("PRAGMA table_info(audit_log)").fetchall()}
    except sqlite3.Error as exc:
        return f"cannot inspect audit_log schema: {exc}"
    finally:
        con.close()
    missing = sorted(_AUDIT_LOG_COLUMNS - columns)
    if missing:
        return "audit_log schema missing columns: " + ", ".join(missing)
    return None


def check_audit_chain(cid: str, url: str) -> DoctorCheck:
    """Report-only. Absent file store => ok (nothing to verify; must NOT create
    the DB). A tampered chain => error (cannot/must not be auto-repaired)."""
    try:
        parsed = make_url(url)
    except Exception:  # noqa: BLE001
        return DoctorCheck(cid, "ok", message="store URL not a file store")
    db = parsed.database
    if parsed.get_backend_name() != "sqlite" or not db or db == ":memory:":
        return DoctorCheck(cid, "ok", message="not a file store")
    db_path = Path(db)
    if not db_path.exists():
        return DoctorCheck(cid, "ok", message="no store yet")
    schema_error = _sqlite_audit_schema_error(db_path)
    if schema_error is not None:
        return DoctorCheck(cid, "error", message=schema_error)
    from legis.store.audit_store import AuditStore

    try:
        intact = AuditStore(url, initialize=False, apply_pragmas=False).verify_integrity()
    except Exception as exc:  # noqa: BLE001 — surface any verify failure, never raise from doctor
        return DoctorCheck(cid, "error", message=f"integrity check failed: {exc}")
    if intact:
        return DoctorCheck(cid, "ok")
    return DoctorCheck(
        cid, "error", message="hash chain verification FAILED (report-only; cannot repair)"
    )


def check_hmac_key(root: Path) -> DoctorCheck:  # noqa: ARG001
    """Presence-only; NEVER renders the key value."""
    cid = "runtime.hmac_key"
    if not config.protected_policies():
        return DoctorCheck(cid, "ok", message="no protected policies configured")
    if os.environ.get("LEGIS_HMAC_KEY"):
        return DoctorCheck(cid, "ok")
    return DoctorCheck(
        cid,
        "warn",
        message="protected policies configured but LEGIS_HMAC_KEY not set; protected submissions will fail",
    )


def check_policy_cells(root: Path) -> DoctorCheck:
    """Report-only (N3 / C-10(c)): is the policy-cell registry discoverable?

    Mirrors ``legis.policy.cells.load_policy_cell_registry``'s precedence (LEGIS_POLICY_CELLS >
    policy/cells.toml > LEGIS_DEV_DEFAULT_CELLS > fail-closed), but resolves the
    root from the doctor target (``root``) where the server falls back to
    ``os.getcwd()`` — these coincide when doctor runs from the server's launch
    CWD. Never writes a file, never auto-opens — when nothing resolves it reports
    the fail-closed ``structured`` default is in effect and NAMES the enablement
    path. Cell DEFINITIONS are non-secret; this check never touches a key (C-8)."""
    cid = "runtime.policy_cells"
    configured = os.environ.get("LEGIS_POLICY_CELLS")
    if configured:
        return DoctorCheck(cid, "ok", message=f"LEGIS_POLICY_CELLS={configured}")
    source_root = Path(os.environ.get("LEGIS_SOURCE_ROOT") or root)
    default_path = source_root / "policy" / "cells.toml"
    if default_path.exists():
        return DoctorCheck(cid, "ok", message=f"{default_path}")
    if os.environ.get("LEGIS_DEV_DEFAULT_CELLS") == "1":
        return DoctorCheck(cid, "ok", message="chill dev default (LEGIS_DEV_DEFAULT_CELLS=1)")
    return DoctorCheck(
        cid,
        "warn",
        message=(
            "no policy cells configured — fail-closed (unlisted policies escalate "
            "to structured). The operator maps policies via policy/cells.toml or "
            "LEGIS_POLICY_CELLS (out-of-band, takes effect on relaunch; chill/coached "
            "are reachable keyless); LEGIS_DEV_DEFAULT_CELLS=1 for the chill dev posture"
        ),
    )


# ---------------------------------------------------------------------------
# Phase 10: posture-ledger reconciliation (report-only; non-zero on rekey)
# ---------------------------------------------------------------------------

_POSTURE_DB_NAME = "legis-posture.db"
_POSTURE_DB_ENV = "LEGIS_POSTURE_DB"
_OPERATOR_KEY_ENV = "LEGIS_OPERATOR_KEY"


def _posture_url(root: Path) -> str:
    return _store_url(root, _POSTURE_DB_NAME, _POSTURE_DB_ENV)


def _posture_db_path(url: str) -> Path | None:
    """The on-disk path for a file-backed posture store URL, else ``None``."""
    try:
        parsed = make_url(url)
    except Exception:  # noqa: BLE001
        return None
    db = parsed.database
    if parsed.get_backend_name() != "sqlite" or not db or db == ":memory:":
        return None
    return Path(db)


def check_posture_chain(root: Path) -> DoctorCheck:
    """Report-only hash-chain integrity for the posture ledger (Task 10.1).

    A missing or zero-byte store is ``ok`` ("no ledger yet") and the runtime
    floor fails closed to ``structured``; doctor must NOT create the DB. A
    schema-present-but-tampered chain is ``error`` (report-only; never
    auto-repaired). Mirrors :func:`check_audit_chain`'s no-leak posture but
    special-cases the missing store before the zero-byte schema check so an
    un-installed project reads as ``ok``, not ``error``."""
    cid = "store.posture_chain"
    url = _posture_url(root)
    db = _posture_db_path(url)
    if db is not None and (not db.exists() or db.stat().st_size == 0):
        return DoctorCheck(cid, "ok", message="no ledger yet (floor fail-closed structured)")
    return check_audit_chain(cid, url)


def check_posture_ledger(root: Path) -> DoctorCheck:
    """Distinguish no-file (ok), GENESIS-present (ok, reports floor), and
    file-but-no-GENESIS (warn) (Task 10.1).

    ``verify_integrity()`` on an empty store returns True (the loop exits at
    once), so ``check_posture_chain`` would misleadingly say "chain ok" while
    ``read_floor()`` is ``None`` and the effective floor is fail-closed
    ``structured``. This check makes the empty-store signal explicit and names
    the operator action."""
    cid = "store.posture_ledger"
    url = _posture_url(root)
    db = _posture_db_path(url)
    if db is not None and (not db.exists() or db.stat().st_size == 0):
        return DoctorCheck(cid, "ok", message="no posture ledger yet")
    from legis.posture.ledger import PostureLedger

    try:
        ledger = PostureLedger(url, initialize=False)
        floor = ledger.read_floor()
    except Exception as exc:  # noqa: BLE001 — never raise from doctor
        return DoctorCheck(cid, "error", message=f"cannot read posture ledger: {exc}")
    if floor is None:
        return DoctorCheck(
            cid,
            "warn",
            message="store initialized but no genesis record — re-run legis install",
        )
    return DoctorCheck(cid, "ok", message=f"floor: {floor}")


def _operator_key_provider(fingerprint: str, *, root: Path | None = None) -> str | None:
    """Default key provider: produce the hex key for *fingerprint* if a backend
    can without revealing it elsewhere. The env escape hatch is probeable when
    explicitly set; the age-file backend is probeable when the operator supplies
    ``LEGIS_OPERATOR_KEY_AGE_PASSPHRASE`` for this doctor run. Returns the key
    hex ONLY for internal verification — never rendered in any message."""
    env_key = os.environ.get(_OPERATOR_KEY_ENV)
    if env_key:
        try:
            from legis.posture.signing import key_fingerprint

            if key_fingerprint(env_key) == fingerprint:
                return env_key
        except Exception:  # noqa: BLE001 — malformed env key is just unreachable
            pass
    age_passphrase = os.environ.get("LEGIS_OPERATOR_KEY_AGE_PASSPHRASE")
    if age_passphrase:
        try:
            from legis.config import operator_age_path
            from legis.posture.signing import key_fingerprint, unwrap_key

            age_path = operator_age_path(root)
            if age_path.exists():
                key_hex = unwrap_key(age_path.read_bytes(), age_passphrase)
                if key_fingerprint(key_hex) == fingerprint:
                    return key_hex
        except Exception:  # noqa: BLE001 — wrong passphrase/blob is unreachable
            pass
    return None


def _latest_key_reset(records: list[Any]) -> Any | None:
    """The most recent KEY_RESET record, or ``None``."""
    from legis.posture.records import KIND_KEY_RESET

    for rec in reversed(records):
        if rec.payload.get("kind") == KIND_KEY_RESET:
            return rec
    return None


def _transition_acknowledges(rec: Any, *, new_fp: str, key_provider: Any) -> bool:
    """True iff TRANSITION *rec*'s ``operator_sig`` verifies under the new-epoch
    key (D6). Record-kind presence is insufficient — the signature must verify
    against a key whose fingerprint equals *new_fp*, proving the transition was
    signed under the reset's new epoch, not merely placed after it."""
    from legis.crypto import signing as _signing
    from legis.posture.signing import key_fingerprint

    sig = rec.payload.get("operator_sig")
    if not sig:
        return False
    key_hex = key_provider(new_fp)
    if not key_hex:
        return False
    try:
        if key_fingerprint(key_hex) != new_fp:
            return False
        key_bytes = bytes.fromhex(key_hex)
    except Exception:  # noqa: BLE001
        return False
    fields = {k: v for k, v in rec.payload.items() if k != "operator_sig"}
    fields["chain_seq"] = rec.seq
    try:
        return _signing.verify(fields, sig, key_bytes)
    except Exception:  # noqa: BLE001 — verify failure is non-acknowledgment
        return False


def check_posture_key_reset(root: Path, *, key_provider: Any = None) -> DoctorCheck:
    """Non-zero exit on an unacknowledged ``KEY_RESET`` (Task 10.2, D6).

    A ``rekey`` preserves the standing floor and chains a ``KEY_RESET`` carrying
    a fresh epoch fingerprint — loud and indelible (design §8). Until an operator
    acknowledges the reset with a ``TRANSITION`` whose ``operator_sig``
    *verifies* against the new epoch key, the reset is unacknowledged and doctor
    fails CI (``error`` / ``run_doctor`` returns non-zero). Per D6, a later
    TRANSITION of the right kind is NOT enough — record-kind presence is
    replayable; the signature must verify under the new epoch. Missing/empty
    ledger → ``ok``. Never renders key material (the fingerprint and the
    verification result are the only signals)."""
    cid = "store.posture_key_reset"
    if key_provider is None:
        def key_provider(fingerprint: str) -> str | None:
            return _operator_key_provider(fingerprint, root=root)

    url = _posture_url(root)
    db = _posture_db_path(url)
    if db is not None and (not db.exists() or db.stat().st_size == 0):
        return DoctorCheck(cid, "ok", message="no posture ledger yet")
    from legis.posture.records import KIND_TRANSITION
    from legis.store.audit_store import AuditStore

    try:
        records = AuditStore(url, initialize=False, apply_pragmas=False).read_all()
    except Exception as exc:  # noqa: BLE001 — never raise from doctor
        return DoctorCheck(cid, "error", message=f"cannot read posture ledger: {exc}")
    reset = _latest_key_reset(records)
    if reset is None:
        return DoctorCheck(cid, "ok", message="no key-epoch reset")
    new_fp = reset.payload.get("key_fingerprint")
    # An acknowledging TRANSITION after the reset whose sig verifies under new_fp.
    acknowledged = False
    for rec in records:
        if rec.seq <= reset.seq:
            continue
        if rec.payload.get("kind") != KIND_TRANSITION:
            continue
        if _transition_acknowledges(rec, new_fp=new_fp, key_provider=key_provider):
            acknowledged = True
            break
    if acknowledged:
        return DoctorCheck(cid, "ok", message="key epoch reset acknowledged by a signed transition")
    agent = reset.payload.get("agent_id") or "unknown"
    when = reset.payload.get("recorded_at") or "unknown"
    floor = reset.payload.get("floor") or "structured"
    return DoctorCheck(
        cid,
        "error",
        message=(
            f"posture key epoch reset on {when} by {agent} — unacknowledged. The floor "
            f"remains {floor}; acknowledge the reset with a signed `legis posture set` "
            "under the new key (doctor stays non-zero until then)."
        ),
        repairable=False,
    )


def check_operator_key_accessible(root: Path, *, key_provider: Any = None) -> DoctorCheck:
    """Report-only operator-key reachability (Task 10.3).

    Reads the current epoch ``key_fingerprint`` (latest GENESIS/KEY_RESET) and
    probes whether any backend can produce it WITHOUT revealing the key. If the
    env escape hatch is set it ``warn``s with the plaintext-in-env honesty note
    (reachable, but residual); if nothing can produce the fingerprint it
    ``warn``s that ``posture set`` will refuse until ``rekey``. Never renders the
    key. Missing/empty ledger → ``ok`` (nothing to reach yet)."""
    cid = "runtime.operator_key"
    if key_provider is None:
        def key_provider(fingerprint: str) -> str | None:
            return _operator_key_provider(fingerprint, root=root)

    url = _posture_url(root)
    db = _posture_db_path(url)
    if db is not None and (not db.exists() or db.stat().st_size == 0):
        return DoctorCheck(cid, "ok", message="no posture ledger yet")
    from legis.posture.ledger import PostureLedger

    try:
        ledger = PostureLedger(url, initialize=False)
        epoch_fp = ledger.current_epoch_fingerprint()
    except Exception as exc:  # noqa: BLE001
        return DoctorCheck(cid, "error", message=f"cannot read posture ledger: {exc}")
    if epoch_fp is None:
        return DoctorCheck(cid, "ok", message="no key epoch yet")
    env_key = os.environ.get(_OPERATOR_KEY_ENV)
    env_matches_epoch = False
    if env_key:
        try:
            from legis.posture.signing import key_fingerprint

            env_matches_epoch = key_fingerprint(env_key) == epoch_fp
        except Exception:  # noqa: BLE001 — malformed env key is a mismatch here
            env_matches_epoch = False
    if env_matches_epoch:
        return DoctorCheck(
            cid,
            "warn",
            message=(
                "operator key present in LEGIS_OPERATOR_KEY (plaintext-in-env) — usable "
                "but a residual: prefer the keychain/age backend."
            ),
        )
    if key_provider(epoch_fp) is not None:
        if env_key:
            return DoctorCheck(
                cid,
                "warn",
                message=(
                    "LEGIS_OPERATOR_KEY is present but does not match the current key epoch; "
                    "another custody backend is reachable."
                ),
            )
        return DoctorCheck(cid, "ok", message="operator key reachable")
    if env_key:
        return DoctorCheck(
            cid,
            "warn",
            message=(
                "LEGIS_OPERATOR_KEY is present but does not match the current key epoch — "
                "`posture set` will refuse until a matching custody backend is available."
            ),
        )
    return DoctorCheck(
        cid,
        "warn",
        message=(
            "operator key not reachable in any backend — `posture set` will refuse; "
            "`legis posture rekey` to recover (mints a new epoch and preserves the "
            "current floor)."
        ),
    )


def check_wardline_routing(root: Path) -> DoctorCheck:  # noqa: ARG001
    """Report-only (N3 / C-10(c)): is scan_route's server-owned cell wired?

    Presence-only; never sets env or renders a value. When unset it reports that
    scan_route is server-owned and inert until configured, and names the key."""
    cid = "runtime.wardline_routing"
    cell = os.environ.get("LEGIS_WARDLINE_CELL")
    by_severity = os.environ.get("LEGIS_WARDLINE_CELL_BY_SEVERITY")
    if cell:
        return DoctorCheck(cid, "ok", message=f"LEGIS_WARDLINE_CELL={cell}")
    if by_severity:
        return DoctorCheck(cid, "ok", message="LEGIS_WARDLINE_CELL_BY_SEVERITY set")
    return DoctorCheck(
        cid,
        "warn",
        message=(
            "scan_route routing is server-owned and unconfigured — inert until set. "
            "Set LEGIS_WARDLINE_CELL (e.g. =surface_only) or "
            "LEGIS_WARDLINE_CELL_BY_SEVERITY"
        ),
    )


def check_wardline_artifact_key(root: Path) -> DoctorCheck:  # noqa: ARG001
    """Report-only (N3 / C-10(c)): is the wardline->legis artifact verification
    key configured? Presence-only; NEVER renders the key value (C-8).

    The honesty defect this closes (PDR-0023): without
    ``LEGIS_WARDLINE_ARTIFACT_KEY`` every wardline scan governs as
    ``artifact_status: "unverified"`` — a confident-degraded posture with no
    operator-facing signal, byte-indistinguishable from a per-scan verification
    that genuinely failed. The operator/agent has no way to tell "unverified
    because nobody configured a key" from "unverified because verification
    failed". So doctor goes AMBER (warn) when the key is absent and NAMES the
    missing key plus the action to fix it — a recruiting advisory, not a silent
    confession.

    This is deliberately a warn, not an error: keyless dev is a legitimate,
    permissive posture (scans still govern). The amber is the recruiting signal
    that CI-grade signed verification is DISABLED and how to enable it."""
    cid = "runtime.wardline_artifact_key"
    if os.environ.get("LEGIS_WARDLINE_ARTIFACT_KEY"):
        return DoctorCheck(cid, "ok")
    return DoctorCheck(
        cid,
        "warn",
        message=(
            "LEGIS_WARDLINE_ARTIFACT_KEY not set — wardline artifact verification "
            "is DISABLED. Every scan governs as artifact_status=unverified "
            "(reason=key_absent), indistinguishable from a real verification "
            "failure. Set LEGIS_WARDLINE_ARTIFACT_KEY (operator-held, out-of-band; "
            "takes effect on relaunch) to require signed scanner/rule-set/commit/"
            "tree provenance and govern as 'verified'"
        ),
    )


def check_sibling_url(cid: str, env: str) -> DoctorCheck:
    url = os.environ.get(env)
    if not url:
        return DoctorCheck(cid, "ok", message="not configured")
    parsed = urlsplit(url)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        return DoctorCheck(cid, "ok")
    return DoctorCheck(cid, "error", message=f"{env} invalid URL: {url!r}")


# The federation-WRITE paths filigree's ProjectMiddleware fail-closes in
# server-mode when unscoped (dashboard.py protected_paths + the 400 "scope to a
# project — use /api/p/{key}/… or ?project={key}"). An unscoped binding to one of
# these silently NON-emits under a multi-project daemon (N1). A path is project-
# scoped iff it is mounted under /api/p/<key>/ OR carries a ?project= query.
_FEDERATION_WRITE_PATHS = frozenset(
    {"/api/scan-results", "/api/observations", "/api/v1/scan-results", "/api/v1/observations"}
)


def _filigree_binding_urls(root: Path) -> list[str]:
    """Every ``--filigree-url`` value across the .mcp.json server entries.

    This widens doctor past its own legis entry into the scanner (wardline) entry
    that actually emits scan-results — deliberately, because that is the binding
    subject to filigree's N1 fail-closed server-mode write."""
    path = root / ".mcp.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return []
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return []
    urls: list[str] = []
    for entry in servers.values():
        args = entry.get("args") if isinstance(entry, dict) else None
        if not isinstance(args, list):
            continue
        for i, arg in enumerate(args):
            if arg == "--filigree-url" and i + 1 < len(args) and isinstance(args[i + 1], str):
                urls.append(args[i + 1])
    return urls


def _is_unscoped_federation_write(url: str) -> bool:
    """True iff *url* targets a federation-write path WITHOUT a project scope."""
    parsed = urlsplit(url)
    path = parsed.path
    if path.startswith("/api/p/") or "project" in parse_qs(parsed.query):
        return False  # scoped (path mount or ?project=)
    norm = path.rstrip("/")
    return path.startswith("/api/weft/") or norm in _FEDERATION_WRITE_PATHS


def check_filigree_binding_scope(root: Path) -> DoctorCheck:
    """Report-only: is the .mcp.json filigree scan-results binding project-scoped?

    Triggered by the PRESENCE of an unscoped filigree scan-results binding URL, not
    by a local filigree install. The harm — a server-mode filigree daemon
    fail-closing an unscoped federation write (``/api/weft/…`` etc.) with a 400 (N1)
    so the scan silently never lands — is driven by the binding URL targeting a
    server-mode daemon, which may be REMOTE. A local-install gate false-greens the
    federation-consumer case (a pure scan-results emitter with no local marker that
    pins an unscoped remote ``--filigree-url``): doctor stays green while the remote
    daemon fail-closes and scans silently non-emit — the false-green the governance
    forbids. So the unscoped binding URL itself is the signal: if one is present,
    warn regardless of whether filigree is installed in *root*.

    The binding is operator-owned: this ``--filigree-url`` is operator-pinned in
    wardline's ``.mcp.json`` entry — legis never writes it — so the check stays
    report-only (``repairable=False``) and names the operator action rather than
    auto-fixing."""
    cid = "install.filigree_scope"
    urls = _filigree_binding_urls(root)
    if not urls:
        return DoctorCheck(cid, "ok", message="no filigree scan-results binding in .mcp.json")
    unscoped = [u for u in urls if _is_unscoped_federation_write(u)]
    if unscoped:
        return DoctorCheck(
            cid,
            "warn",
            message=(
                "filigree binding not project-scoped: "
                + ", ".join(unscoped)
                + " — this --filigree-url is operator-pinned in wardline's .mcp.json entry "
                "(legis never writes it; filigree doctor doesn't manage it). A server-mode "
                "filigree daemon fail-closes unscoped federation writes (HTTP 400), so scans "
                "silently non-emit. Operator action: scope it to "
                "/api/p/<project>/weft/scan-results (or add ?project=<project>)"
            ),
        )
    return DoctorCheck(cid, "ok", message="project-scoped: " + ", ".join(urls))


def collect_checks(root: Path, *, repair: bool) -> list[DoctorCheck]:
    """Run every check against *root*. Repairs run inside individual checks
    when *repair* is True; each returned check reflects post-repair state."""
    checks: list[DoctorCheck] = []
    checks.append(check_instruction_block(root, "CLAUDE.md", repair=repair))
    checks.append(check_instruction_block(root, "AGENTS.md", repair=repair))
    checks.append(check_skill_pack(root, ".claude", repair=repair))
    checks.append(check_skill_pack(root, ".agents", repair=repair))
    checks.append(check_hook(root, repair=repair))
    checks.append(check_gitignore(root, repair=repair))
    checks.append(check_dir_gitignore(root, repair=repair))
    checks.append(check_mcp_json(root, repair=repair))
    checks.append(check_filigree_binding_scope(root))
    checks.append(check_weft_toml(root))
    checks.append(check_store_dir(root, repair=repair))
    checks.append(check_db_overrides(root))
    checks.append(check_legacy_stray_db(root))
    checks.append(check_audit_chain("store.governance_chain", _store_url(root, "legis-governance.db", "LEGIS_GOVERNANCE_DB")))
    checks.append(check_audit_chain("store.binding_chain", _store_url(root, "legis-binding.db", "LEGIS_BINDING_DB")))
    checks.append(check_posture_chain(root))
    checks.append(check_posture_ledger(root))
    checks.append(check_posture_key_reset(root))
    checks.append(check_operator_key_accessible(root))
    checks.append(check_hmac_key(root))
    checks.append(check_policy_cells(root))
    checks.append(check_wardline_routing(root))
    checks.append(check_wardline_artifact_key(root))
    checks.append(check_sibling_url("runtime.loomweave_url", "LOOMWEAVE_API_URL"))
    checks.append(check_sibling_url("runtime.filigree_url", "FILIGREE_API_URL"))
    return checks


def run_doctor(root: Path, *, repair: bool, fmt: str) -> int:
    checks = collect_checks(root, repair=repair)
    print(render_json(checks) if fmt == "json" else render_text(checks))
    return 0 if all(c.ok for c in checks) else 1
