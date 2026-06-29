"""SessionStart / MCP-boot refresh for legis instruction artifacts.

Two callers drive ``refresh_instructions``:

- the ``legis session-context`` CLI subcommand, registered as a Claude Code
  SessionStart hook, and
- ``legis mcp`` startup (best-effort), which is the universal trigger that also
  covers Codex-only repos with no ``.claude/`` hook.

Both refresh *in place* only — they never create a block or skill pack that is
not already present (that is ``legis install``'s job). A non-project cwd
produces no refresh work, because the refresh only ever touches marker-bearing
files — but the CLI subcommand still emits a one-line posture banner, so an
agent can distinguish "nothing to report" from "broken" (dogfood N-1).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from legis.install import (
    INSTRUCTIONS_MARKER,
    SKILL_NAME,
    _get_skills_source_dir,
    _instructions_block_is_current,
    _skill_tree_fingerprint,
    inject_instructions,
    install_codex_skills,
    install_skills,
)
from legis.policy.cells import load_policy_cells

logger = logging.getLogger(__name__)


def refresh_instructions(root: Path) -> list[str]:
    """Refresh drifted legis instruction blocks and skill packs under *root*.

    Compares each owned ``CLAUDE.md`` / ``AGENTS.md`` block byte-for-byte
    against the bundled block (re-injecting on drift), and each installed skill
    pack's tree fingerprint against the bundled source (reinstalling on drift).
    Returns human-readable update messages (empty when everything is current).
    Only marker-bearing files and already-installed skill packs are touched.
    """
    messages: list[str] = []

    for filename in ("CLAUDE.md", "AGENTS.md"):
        md_path = root / filename
        if not md_path.exists():
            continue
        try:
            content = md_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            logger.debug("Could not read %s for freshness check", md_path, exc_info=True)
            continue
        if INSTRUCTIONS_MARKER not in content:
            continue
        if _instructions_block_is_current(content):
            continue
        ok, reason = inject_instructions(md_path)
        if ok:
            messages.append(f"Updated legis instructions in {filename}")
        else:
            # Drift was detected and re-injection was attempted but failed
            # (e.g. a symlinked target → (False, reason), not a raise). Never
            # drop it: agents would keep running on drifted instructions with no
            # signal. Surface it for the operator (peer of the boot-log path).
            logger.warning(
                "legis instruction refresh failed for %s: %s", md_path, reason
            )

    source_root = _get_skills_source_dir() / SKILL_NAME
    if source_root.is_dir():
        source_hash = _skill_tree_fingerprint(source_root)
        skill_targets = (
            (root / ".claude" / "skills" / SKILL_NAME, install_skills, "Updated legis skill pack"),
            (root / ".agents" / "skills" / SKILL_NAME, install_codex_skills, "Updated legis Codex skill pack"),
        )
        for target_root, installer, msg in skill_targets:
            if not target_root.is_dir():
                continue
            if _skill_tree_fingerprint(target_root) != source_hash:
                ok, reason = installer(root)
                if ok:
                    messages.append(msg)
                else:
                    logger.warning(
                        "legis skill refresh failed for %s: %s", target_root, reason
                    )

    return messages


def _instructions_posture(root: Path) -> str:
    """Marker-bearing instruction files under *root*: installed and current?

    Runs after the refresh, so a still-drifted token means the re-injection
    failed (already warned by ``refresh_instructions``) — say so rather than
    claiming currency. Unreadable files mirror the refresh's skip semantics.
    """
    seen = False
    for filename in ("CLAUDE.md", "AGENTS.md"):
        md_path = root / filename
        if not md_path.exists():
            continue
        try:
            content = md_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if INSTRUCTIONS_MARKER not in content:
            continue
        seen = True
        if not _instructions_block_is_current(content):
            return "instructions stale (refresh failed; see logs)"
    if not seen:
        return "instructions not installed (run legis install)"
    return "instructions current"


def _skill_pack_posture(root: Path) -> str:
    """Installed skill packs under *root* vs the bundled source fingerprint."""
    targets = [
        target
        for target in (
            root / ".claude" / "skills" / SKILL_NAME,
            root / ".agents" / "skills" / SKILL_NAME,
        )
        if target.is_dir()
    ]
    if not targets:
        return "skill pack not installed"
    source_root = _get_skills_source_dir() / SKILL_NAME
    if not source_root.is_dir():
        # Without the bundled source there is nothing to compare against —
        # never claim currency that was not verified.
        return "skill pack unverifiable (bundled source missing)"
    source_hash = _skill_tree_fingerprint(source_root)
    if all(_skill_tree_fingerprint(target) == source_hash for target in targets):
        return "skill pack current"
    return "skill pack stale (refresh failed; see logs)"


def _cells_posture(root: Path) -> str:
    """Is a policy-cell registry discoverable from this process, and how big?

    Mirrors ``legis.policy.cells.load_policy_cell_registry``'s file precedence
    (LEGIS_POLICY_CELLS > policy/cells.toml) but only *reports* — this hook
    process does not see the MCP server's env (.mcp.json), so it never claims
    server runtime posture. No malformed-cells fallback is ratified (the server
    propagates the error), so a bad file is reported as unreadable, not guessed.
    """
    configured = os.environ.get("LEGIS_POLICY_CELLS")
    if configured:
        path = Path(configured)
        label = f"LEGIS_POLICY_CELLS={configured}"
    else:
        path = root / "policy" / "cells.toml"
        label = "policy/cells.toml"
        if not path.exists():
            return "cells config: absent (policies default-route)"
    try:
        registry = load_policy_cells(path)
    except (OSError, ValueError):  # tomllib.TOMLDecodeError is a ValueError
        logger.warning("Policy cells config %s is unreadable", path, exc_info=True)
        return f"cells config: unreadable ({label})"
    count = len(registry.rules)
    noun = "policy" if count == 1 else "policies"
    return f"cells config: {label} ({count} {noun} mapped)"


def _posture_floor() -> str:
    """The governing posture floor for this project — read-only, fail-closed.

    Honesty in the session banner (Phase 4 / D0): an agent that reads only
    "cells config: absent" would assume chill, while a signed posture floor may
    be raising every policy to structured/protected. ``initialize=False`` never
    creates a store; a missing or empty ledger reads as the fail-closed
    ``structured`` default (design §4) and is reported distinctly from a
    genuinely-set floor. Never raises into the session banner.
    """
    from sqlalchemy.exc import SQLAlchemyError

    from legis.config import posture_db_url
    from legis.posture.ledger import PostureLedger

    try:
        floor = PostureLedger(posture_db_url(), initialize=False).read_floor()
    except (OSError, ValueError, SQLAlchemyError):
        logger.warning("Posture ledger is unreadable", exc_info=True)
        return "posture floor: unreadable"
    if floor is None:
        return "posture floor: none (fail-closed structured)"
    return f"posture floor: {floor}"


def generate_session_context() -> str:
    """Refresh instruction drift in the cwd and return the session banner.

    Always returns a non-empty string (dogfood N-1 — silence is
    indistinguishable from a broken command): a single posture line derived
    only from what this process can see (instruction/skill freshness, cells
    config discoverability — never the MCP server's runtime posture, which it
    gets from its own env), followed by any refresh messages on their own
    lines. A failed freshness check yields a one-line failure signal.
    """
    root = Path.cwd()
    try:
        messages = refresh_instructions(root)
    except (OSError, UnicodeDecodeError, ValueError):
        logger.warning("Instruction freshness check failed", exc_info=True)
        return "legis: instruction freshness check failed (see logs)"
    banner = "legis: " + "; ".join(
        (
            _instructions_posture(root),
            _skill_pack_posture(root),
            _cells_posture(root),
            _posture_floor(),
        )
    )
    return "\n".join([banner, *messages])
