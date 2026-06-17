"""Project installation helpers for legis.

Legis "stands itself up": ``legis install`` injects a lean agent-orientation
block into ``CLAUDE.md`` / ``AGENTS.md``, installs the ``legis-workflow`` skill
pack, registers a Claude Code SessionStart hook, and extends ``.gitignore``.

The block carries a versioned, content-hashed marker
(``<!-- legis:instructions:v{version}:{hash} -->``) so a drift check can
re-inject it when either the bundled content or the package version changes.
This mirrors filigree's mechanism (``filigree/src/filigree/install.py`` and
``install_support/``), right-sized for legis: no dashboard, no server mode.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.metadata
import importlib.resources
import json
import logging
import os
import re
import shlex
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INSTRUCTIONS_MARKER = "<!-- legis:instructions"
"""Detection prefix for legis instruction blocks in markdown files."""

_END_MARKER = "<!-- /legis:instructions -->"

# Recognises ANY tool's instruction-block fence (open or close) by its vendor
# namespace, so legis can bound its own rewrite at a *foreign* fence and never
# delete a co-resident sibling block (wardline/filigree) in a shared
# CLAUDE.md/AGENTS.md (peer of filigree-bcbd4d66fd). The namespace match is
# case-insensitive: an uppercase-namespaced sibling must still register as a
# boundary. The cross-tool multi-owner block contract lives in weft
# conventions.md (C-4).
_INSTR_FENCE_RE = re.compile(r"<!--\s*(?P<close>/?)(?P<ns>[A-Za-z0-9_-]+):instructions")


def _first_foreign_fence_pos(content: str, search_from: int) -> int:
    """Index of the first non-legis instruction fence at/after *search_from*.

    Own-namespace (``legis``) fences are absorbed — never treated as a
    boundary — so duplicate or unclosed legis blocks still collapse to one
    clean block (the orphan-tail idempotency invariant). When no foreign fence
    follows, returns ``len(content)`` (i.e. bound at EOF).
    """
    for m in _INSTR_FENCE_RE.finditer(content, search_from):
        if m.group("ns").lower() != "legis":
            return m.start()
    return len(content)


def _first_own_open_fence_pos(content: str) -> int:
    """Index of legis's *own* open instruction fence, or -1 if none.

    A legis open fence quoted *inside* a co-resident sibling block (a worked
    example, documentation) is identical in text to a real one, so a bare
    substring/regex anchor would splice there and gut the sibling. This walks
    fences in document order, tracking the foreign block we are currently inside,
    and only returns a legis open fence found at top level (not enclosed by an
    unclosed foreign block). An unclosed foreign block therefore shields any
    legis marker beyond it: we decline to claim content we cannot prove is ours,
    and the caller falls back to an append (which deletes nothing).
    """
    inside_foreign: str | None = None
    for m in _INSTR_FENCE_RE.finditer(content):
        ns = m.group("ns").lower()
        is_close = bool(m.group("close"))
        if inside_foreign is not None:
            if is_close and ns == inside_foreign:
                inside_foreign = None
            continue
        if ns == "legis" and not is_close:
            return m.start()
        if ns != "legis" and not is_close:
            inside_foreign = ns
    return -1

SKILL_NAME = "legis-workflow"
"""Name of the legis skill pack directory."""

SESSION_CONTEXT_COMMAND = "legis session-context"
"""Bare form of the SessionStart hook command."""


# ---------------------------------------------------------------------------
# Symlink-safe project paths
# ---------------------------------------------------------------------------


class UnsafeInstallPathError(ValueError):
    """Raised when an installer target could escape the project root."""


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _check_existing_components_not_symlinks(path: Path, root: Path) -> None:
    """Reject symlinks in existing path components between root and path."""
    current = root
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError as exc:  # pragma: no cover - guarded by callers
        msg = f"Installer target {path} is outside project root {root}"
        raise UnsafeInstallPathError(msg) from exc

    for part in relative_parts:
        current = current / part
        if current.is_symlink():
            msg = f"Refusing to write through symlinked installer target: {current}"
            raise UnsafeInstallPathError(msg)


def project_path(project_root: Path, *parts: str) -> Path:
    """Return a project-contained path, rejecting symlink escape hatches."""
    root = project_root.resolve(strict=True)
    target = root.joinpath(*parts)
    _check_existing_components_not_symlinks(target, root)
    resolved_target = target.resolve(strict=False)
    if not _is_relative_to(resolved_target, root):
        msg = f"Installer target {target} resolves outside project root {root}"
        raise UnsafeInstallPathError(msg)
    return target


def ensure_project_dir(project_root: Path, *parts: str) -> Path:
    """Create and return a project-contained directory without following links."""
    target = project_path(project_root, *parts)
    target.mkdir(parents=True, exist_ok=True)
    _check_existing_components_not_symlinks(target, project_root.resolve(strict=True))
    if not target.is_dir():
        msg = f"Installer target directory is not a directory: {target}"
        raise UnsafeInstallPathError(msg)
    return target


def reject_symlink(path: Path) -> None:
    """Reject a direct installer target that is a symlink, including dangling."""
    if path.is_symlink():
        msg = f"Refusing to write through symlinked installer target: {path}"
        raise UnsafeInstallPathError(msg)


# ---------------------------------------------------------------------------
# Instructions block
# ---------------------------------------------------------------------------


def _instructions_text() -> str:
    """Read the instructions template from the shipped data file."""
    ref = importlib.resources.files("legis.data").joinpath("instructions.md")
    return ref.read_text(encoding="utf-8")


def _instructions_hash() -> str:
    """Return the first 8 hex characters of SHA256 of the instructions content."""
    return hashlib.sha256(_instructions_text().encode()).hexdigest()[:8]


def _instructions_version() -> str:
    """Return a sensible legis version for instructions markers."""
    try:
        return importlib.metadata.version("legis")
    except importlib.metadata.PackageNotFoundError:
        from legis import __version__

        return __version__ or "0.0.0-dev"


def _marker_token() -> str:
    """Return the ``v{version}:{hash}`` identity carried by the open marker.

    Freshness compares this whole token, so a content edit (hash drift) *or* a
    package-version bump both re-inject and keep the marker truthful. This is a
    deliberate divergence from filigree (which compares the hash segment only):
    legis treats ``CLAUDE.md`` / ``AGENTS.md`` as regenerated, git-ignored
    artifacts, so a marker-only rewrite on a version bump produces no committed
    diff — it just keeps the embedded version honest.
    """
    return f"v{_instructions_version()}:{_instructions_hash()}"


def _build_instructions_block() -> str:
    """Build the full instructions block with versioned markers."""
    text = _instructions_text()
    opening = f"{INSTRUCTIONS_MARKER}:{_marker_token()} -->"
    return f"{opening}\n{text}{_END_MARKER}"


# Reader counterpart to the opening marker built in `_build_instructions_block`.
# It lives next to the writer (and is derived from the same `INSTRUCTIONS_MARKER`
# constant) so marker audits cannot silently desync from the marker format:
# the prefix is `re.escape`d from the constant, and the token is captured as an
# opaque `\S+` rather than re-encoding its `v{version}:{hash}` shape — so a future
# change to the token shape needs no edit here. The round-trip is pinned by a test.
_MARKER_TOKEN_RE = re.compile(re.escape(INSTRUCTIONS_MARKER) + r":(\S+) -->")


def _extract_marker_token(content: str) -> str | None:
    """Return the token from the first legis instruction marker, or ``None``."""
    m = _MARKER_TOKEN_RE.search(content)
    return m.group(1) if m else None


def _instructions_block_is_current(content: str) -> bool:
    """Return whether the installed top-level legis block exactly matches source.

    The marker token is a hint, not proof: an attacker can leave the current
    marker in place and edit the body. Freshness therefore compares the whole
    owned block to the bundled block, using the same foreign-fence-aware bounds
    as ``inject_instructions``.
    """
    start = _first_own_open_fence_pos(content)
    if start == -1:
        return False
    own_end = content.find(_END_MARKER, start)
    if own_end == -1:
        return False
    foreign = _first_foreign_fence_pos(content, start + len(INSTRUCTIONS_MARKER))
    if own_end >= foreign:
        return False
    bound = own_end + len(_END_MARKER)
    if content[start:bound] != _build_instructions_block():
        return False
    return _first_own_open_fence_pos(content[bound:]) == -1


def _own_open_marker_tokens(content: str) -> list[str | None]:
    """Tokens of legis's *own* top-level open instruction fences, in order.

    Foreign-aware exactly like ``_first_own_open_fence_pos``: a legis open fence
    quoted *inside* an (unclosed) sibling block is not legis's own and is not
    counted, so this never miscounts a documented example as a real block. A
    canonical open fence yields its ``v{version}:{hash}`` token; a malformed one
    yields ``None`` (present but not extractable → never "fresh").

    The list length is the number of distinct legis blocks. More than one is a
    split brain — two divergent copies of the guidance — which the injector
    tolerates when it cannot canonicalise across a sibling's block (it warns and
    leaves the stale copy). Doctor consumes this so it cannot read "healthy" off
    the first marker alone while a stale second block survives (INSTALL-1).
    """
    tokens: list[str | None] = []
    inside_foreign: str | None = None
    for m in _INSTR_FENCE_RE.finditer(content):
        ns = m.group("ns").lower()
        is_close = bool(m.group("close"))
        if inside_foreign is not None:
            if is_close and ns == inside_foreign:
                inside_foreign = None
            continue
        if ns == "legis" and not is_close:
            tm = _MARKER_TOKEN_RE.match(content, m.start())
            tokens.append(tm.group(1) if tm else None)
        elif ns != "legis" and not is_close:
            inside_foreign = ns
    return tokens


def _atomic_write_text(path: Path, content: str) -> None:
    """Write *content* to *path* atomically (temp + rename), preserving mode."""
    # Refuse-to-empty guard (filigree-04bad2a2bf parity). Every caller of this
    # writer (instruction injection, .gitignore management, settings.json) always
    # has non-empty content; an empty or whitespace-only payload can only be
    # corruption or a logic bug. Refuse loudly rather than rename an empty temp
    # file over a populated CLAUDE.md/AGENTS.md/.gitignore.
    if not content.strip():
        msg = f"refusing to write empty content to {path}"
        raise ValueError(msg)
    reject_symlink(path)
    existing_mode: int | None
    try:
        existing_mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        existing_mode = None

    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp", prefix=path.name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        if existing_mode is not None:
            os.chmod(tmp, existing_mode)
        else:
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(tmp, 0o666 & ~umask)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def inject_instructions(file_path: Path) -> tuple[bool, str]:
    """Inject legis workflow instructions into a markdown file.

    - missing file → create with just the block;
    - has the marker → replace the block in place;
    - exists without the marker → append the block.
    """
    try:
        reject_symlink(file_path)
    except UnsafeInstallPathError as exc:
        return False, str(exc)

    block = _build_instructions_block()

    if not file_path.exists():
        _atomic_write_text(file_path, block + "\n")
        return True, f"Created {file_path}"

    content = file_path.read_text(encoding="utf-8")
    start = _first_own_open_fence_pos(content)
    if start != -1:
        # Bound legis's writable region at the first of:
        #   (a) its own close marker, *if* that close precedes any foreign fence
        #       → normal in-place replace;
        #   (b) the next foreign-namespace fence — bounded recovery for a
        #       malformed/unclosed block, and for the unclosed-first / closed-
        #       later "Shape 2" where a bare ``find`` would otherwise jump over a
        #       foreign block to a later legis close;
        #   (c) EOF.
        # Own-namespace fences are absorbed (see _first_foreign_fence_pos), so
        # duplicate/unclosed legis blocks still collapse to one clean block —
        # preserving the orphan-tail idempotency invariant. Monotonic safety:
        # in every branch ``bound`` ≤ the old code's cut point, so this can only
        # *preserve* bytes the old code deleted, never delete bytes it kept.
        # ``start`` is legis's own top-level open fence (see
        # _first_own_open_fence_pos), never a marker quoted inside a sibling block.
        own_end = content.find(_END_MARKER, start)
        foreign = _first_foreign_fence_pos(content, start + len(INSTRUCTIONS_MARKER))
        if own_end != -1 and own_end < foreign:
            bound = own_end + len(_END_MARKER)
            tail = content[bound:]
            sep = ""
        else:
            # Bounded recovery: stop at the foreign fence (or EOF). Re-insert the
            # separating newline we may have eaten, so our close marker is never
            # glued mid-line against a following foreign fence — keeping us
            # independent of whether a sibling's block detector is line-anchored.
            bound = foreign
            tail = content[bound:]
            sep = "\n" if (bound < len(content) and not tail.startswith("\n")) else ""
        if _first_own_open_fence_pos(tail) != -1:
            # A second legis block survives beyond the boundary because
            # canonicalising it would mean reaching across a block we don't own.
            # It is STALE, conflicting guidance — not a harmless duplicate — so
            # surface it instead of silently shipping a split brain
            # (foreign-safety wins over own-dedup).
            logger.warning(
                "legis instruction block in %s has a duplicate that could not be "
                "canonicalised without crossing another tool's block; the stale copy "
                "was left in place. Resolve it by hand.",
                file_path,
            )
        content = content[:start] + block + sep + tail
        _atomic_write_text(file_path, content)
        return True, f"Updated instructions in {file_path}"

    if not content.strip():
        # An existing empty / whitespace-only file is effectively a create: write
        # just the block rather than leaving leading blank-line artifacts.
        _atomic_write_text(file_path, block + "\n")
        return True, f"Created {file_path}"

    if not content.endswith("\n"):
        content += "\n"
    content += "\n" + block + "\n"
    _atomic_write_text(file_path, content)
    return True, f"Appended instructions to {file_path}"


# ---------------------------------------------------------------------------
# Skill pack
# ---------------------------------------------------------------------------


def _get_skills_source_dir() -> Path:
    """Return the path to the bundled skills directory inside the package."""
    return Path(__file__).parent / "data" / "skills"


def _skill_tree_fingerprint(root: Path) -> str:
    """Return a short hash of every file under *root* (relative path + bytes)."""
    digest = hashlib.sha256()
    files = sorted(p for p in root.rglob("*") if p.is_file())
    for path in files:
        rel = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(rel)
        digest.update(b"\0")
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<unreadable>")
        digest.update(b"\0")
    return digest.hexdigest()[:8]


def _install_skill_to(project_root: Path, target_subpath: Path) -> tuple[bool, str]:
    """Copy the legis skill pack into *target_subpath* under *project_root*.

    Idempotent — overwrites existing skill files to track the installed legis
    version. Safe under concurrent invocation: each call stages into a unique
    directory and tolerates a peer winning the final rename race.
    """
    skill_source = _get_skills_source_dir() / SKILL_NAME
    if not skill_source.is_dir():
        return False, f"Skill source not found at {skill_source}"

    try:
        target_parent = ensure_project_dir(project_root, *target_subpath.parts)
    except UnsafeInstallPathError as exc:
        return False, str(exc)
    target_dir = target_parent / SKILL_NAME
    try:
        reject_symlink(target_dir)
    except UnsafeInstallPathError as exc:
        return False, str(exc)

    staging = Path(tempfile.mkdtemp(dir=target_dir.parent, prefix=f"{SKILL_NAME}.installing."))
    staging.rmdir()
    staging_consumed = False
    swap_done = False
    backup: Path | None = None
    try:
        shutil.copytree(skill_source, staging)
        if target_dir.exists():
            backup_holder = Path(tempfile.mkdtemp(dir=target_dir.parent, prefix=f"{SKILL_NAME}.old."))
            backup_holder.rmdir()
            try:
                os.rename(target_dir, backup_holder)
                backup = backup_holder
            except FileNotFoundError:
                pass
        try:
            os.rename(staging, target_dir)
            staging_consumed = True
            swap_done = True
        except OSError:
            # Distinguish a peer winning the race (target now holds their
            # identical content) from a genuine failure. Only the former is
            # safe to report as success — otherwise we would claim a successful
            # install over a pack we just destroyed.
            if target_dir.exists() and target_dir.is_dir():
                swap_done = True
            else:
                # Genuine failure: restore the original pack we set aside and
                # report failure rather than a false-positive "Installed".
                if backup is not None and backup.exists():
                    try:
                        os.rename(backup, target_dir)
                        backup = None
                    except OSError:
                        # Could not restore — leave the backup in place (it may
                        # be the only surviving copy) rather than delete it.
                        pass
                return False, f"Failed to install skill pack to {target_dir}: swap failed"
    finally:
        if not staging_consumed and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        # Only discard the prior pack once the new one is in place. If the swap
        # failed we must not delete the backup — it may be the only copy left.
        if backup is not None and swap_done and backup.exists():
            shutil.rmtree(backup, ignore_errors=True)

    return True, f"Installed skill pack to {target_dir}"


def install_skills(project_root: Path) -> tuple[bool, str]:
    """Copy the legis skill pack into ``.claude/skills/`` for the project."""
    return _install_skill_to(project_root, Path(".claude") / "skills")


def install_codex_skills(project_root: Path) -> tuple[bool, str]:
    """Copy the legis skill pack into ``.agents/skills/`` for Codex."""
    return _install_skill_to(project_root, Path(".agents") / "skills")


# ---------------------------------------------------------------------------
# Claude Code SessionStart hook
# ---------------------------------------------------------------------------


def _which_nonlocal(name: str, project_root: Path | None) -> str | None:
    """``shutil.which(name)`` that skips a match living under *project_root*.

    PATH's first hit can be a project-local shim (a repo ``.venv/bin`` ahead of
    the global tool dir); when *project_root* is given and that first hit is
    project-local, scan the remaining PATH entries for a stable one rather than
    returning a command the freshness checks will immediately reject as drift."""
    found = shutil.which(name)
    if found is None:
        return None
    if project_root is None or not _path_head_is_project_local(found, project_root):
        return found
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        cand = shutil.which(name, path=entry)
        if cand and not _path_head_is_project_local(cand, project_root):
            return cand
    return None


def _find_legis_command(project_root: Path | None = None) -> list[str]:
    """Resolve how to invoke legis for a hook / .mcp.json command.

    Prefer the legis entrypoint that is *running right now* (``sys.argv[0]``) —
    resolution must be faithful to the binary the operator invoked, not to
    whatever ``which legis`` happens to find first. A dev venv ahead of the
    uv-tool shim on PATH would otherwise poison every consumer config written
    by an explicitly-invoked stable binary (legis-788a85fac1). Falls back to
    PATH lookup, then to the safe-path module form ``<python> -P -m legis`` so
    module resolution does not prepend the project directory.

    When *project_root* is given, a project-local resolution (the running
    binary, the PATH hit, or the interpreter all under the target repo, e.g. a
    ``<repo>/.venv/bin/legis`` install) is skipped in favour of a stable one:
    the freshness checks (``_hook_command_is_stale`` / ``mcp_entry_is_current``)
    reject a project-local command head, so writing one produces an entry
    ``doctor`` flags stale on arrival, churning the same fix every run.
    """
    import sys

    def _local(path: str) -> bool:
        return project_root is not None and _path_head_is_project_local(
            os.path.abspath(path), project_root
        )

    argv0 = sys.argv[0] if sys.argv else ""
    if Path(argv0).name.lower() in ("legis", "legis.exe"):
        running = Path(os.path.abspath(argv0))
        if running.is_file() and not _local(str(running)):
            return [str(running)]
    found = _which_nonlocal("legis", project_root)
    if found:
        return [found]
    python = sys.executable
    if _local(python):
        python = (
            _which_nonlocal("python3", project_root)
            or _which_nonlocal("python", project_root)
            or sys.executable
        )
    return [python, "-P", "-m", "legis"]


def _path_head_is_project_local(head: str, project_root: Path | None) -> bool:
    """True when a command head names a path controlled by the project root."""
    if project_root is None or not head:
        return False
    if "/" not in head and "\\" not in head:
        return False
    root = project_root.resolve(strict=False)
    candidate = Path(head)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError:
        return False
    return True


def _hook_cmd_matches(
    hook_command: str,
    bare_command: str,
    *,
    project_root: Path | None = None,
    allow_project_local: bool = False,
) -> bool:
    """Whether *hook_command* is a safe bare, absolute-path, or module form of *bare_command*."""
    if hook_command == bare_command:
        return True
    try:
        hook_tokens = shlex.split(hook_command)
        bare_tokens = shlex.split(bare_command)
    except ValueError:
        return False
    if not hook_tokens or not bare_tokens:
        return False
    n = len(bare_tokens)
    bare_bin = bare_tokens[0]  # "legis"

    if len(hook_tokens) == n:
        if hook_tokens[1:] != bare_tokens[1:]:
            return False
        hook_bin = hook_tokens[0]
        if hook_bin == bare_bin:
            return True
        if _path_head_is_project_local(hook_bin, project_root) and not allow_project_local:
            return False
        if (
            "/" in hook_bin or "\\" in hook_bin
        ) and not Path(hook_bin).is_absolute() and not allow_project_local:
            return False
        hook_base = hook_bin.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        return hook_base.lower() in {bare_bin.lower(), f"{bare_bin.lower()}.exe"}

    module_prefixes = (["-m", bare_bin], ["-P", "-m", bare_bin])
    for prefix in module_prefixes:
        if len(hook_tokens) == n + len(prefix) and hook_tokens[1 : 1 + len(prefix)] == prefix:
            if _path_head_is_project_local(hook_tokens[0], project_root) and not allow_project_local:
                return False
            if (
                "/" in hook_tokens[0] or "\\" in hook_tokens[0]
            ) and not Path(hook_tokens[0]).is_absolute() and not allow_project_local:
                return False
            return hook_tokens[1 + len(prefix) :] == bare_tokens[1:]

    return False


def _has_unscoped_session_start_hook(
    settings: dict[str, Any],
    command: str,
    *,
    project_root: Path | None = None,
) -> bool:
    """Whether *command* appears in an unscoped/wildcard SessionStart block."""
    if not isinstance(settings, dict):
        return False
    hooks = settings.get("hooks", {})
    if not isinstance(hooks, dict):
        return False
    session_start = hooks.get("SessionStart", [])
    if not isinstance(session_start, list):
        return False
    for matcher in session_start:
        if not isinstance(matcher, dict):
            continue
        if "matcher" in matcher and matcher.get("matcher") not in (None, "*"):
            continue
        hook_list = matcher.get("hooks", [])
        if not isinstance(hook_list, list):
            continue
        for hook in hook_list:
            if isinstance(hook, dict) and _hook_cmd_matches(
                hook.get("command", ""),
                command,
                project_root=project_root,
            ):
                return True
    return False


def _hook_command_is_stale(cmd: str, *, project_root: Path | None = None) -> bool:
    """Whether a legis hook command can no longer run and needs re-pinning.

    Stale means the executable token cannot be exec'd: a bare token (portable
    form — pin it to the resolved binary) or a path that no longer exists. A
    *working* absolute path that merely differs from our current resolution is
    operator state, not drift — rewriting it would repoint a consumer at
    whatever binary shadows PATH today (legis-788a85fac1). Same invariant as
    ``mcp_entry_is_current``.
    """
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return False
    if not tokens:
        return False
    head = tokens[0]
    if _path_head_is_project_local(head, project_root):
        return True
    if "/" not in head and "\\" not in head:
        return True  # bare form — pin to the resolved binary
    return not (Path(head).is_file() or shutil.which(head))


def _upgrade_hook_commands(
    settings: dict[str, Any],
    bare_command: str,
    new_command: str,
    *,
    project_root: Path | None = None,
) -> bool:
    """Re-pin stale hook commands matching *bare_command* to *new_command*."""
    changed = False
    hooks = settings.get("hooks", {})
    if not isinstance(hooks, dict):
        return False
    session_start = hooks.get("SessionStart", [])
    if not isinstance(session_start, list):
        return False
    for matcher in session_start:
        if not isinstance(matcher, dict):
            continue
        # Only upgrade commands in unscoped blocks legis owns. A user's scoped
        # block (e.g. {"matcher": "resume"}) is their config — never rewrite a
        # portable bare command there into a venv-specific absolute path.
        if "matcher" in matcher and matcher.get("matcher") not in (None, "*"):
            continue
        hook_list = matcher.get("hooks", [])
        if not isinstance(hook_list, list):
            continue
        for hook in hook_list:
            if not isinstance(hook, dict):
                continue
            cmd = hook.get("command", "")
            if (
                _hook_cmd_matches(
                    cmd,
                    bare_command,
                    project_root=project_root,
                    allow_project_local=True,
                )
                and cmd != new_command
                and _hook_command_is_stale(cmd, project_root=project_root)
            ):
                hook["command"] = new_command
                changed = True
    return changed


def install_claude_code_hooks(project_root: Path) -> tuple[bool, str]:
    """Register ``legis session-context`` as a Claude Code SessionStart hook.

    Idempotent: re-running upgrades a bare/stale command to the resolved binary
    and never duplicates the entry. Reuses only an unscoped block already
    carrying the legis hook; otherwise appends a dedicated matcher-less block so
    the hook fires on every SessionStart source.
    """
    try:
        claude_dir = ensure_project_dir(project_root, ".claude")
    except UnsafeInstallPathError as exc:
        return False, str(exc)
    settings_path = claude_dir / "settings.json"
    try:
        reject_symlink(settings_path)
    except UnsafeInstallPathError as exc:
        return False, str(exc)

    recovered_backup: str | None = None  # set when a corrupt file was backed up

    settings: dict[str, Any] = {}
    if settings_path.exists():
        try:
            parsed = json.loads(settings_path.read_text(encoding="utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("settings.json is not a JSON object")
            settings = parsed
        except (json.JSONDecodeError, ValueError):
            backup = settings_path.with_suffix(".json.bak")
            try:
                reject_symlink(backup)
            except UnsafeInstallPathError as exc:
                return False, str(exc)
            shutil.copy2(settings_path, backup)
            recovered_backup = backup.name
            logger.warning(
                "malformed .claude/settings.json backed up to %s and replaced with "
                "a fresh file; reconcile any lost settings by hand",
                backup.name,
            )

    prefix = shlex.join(_find_legis_command(project_root))
    session_context_cmd = f"{prefix} session-context"

    upgraded = _upgrade_hook_commands(
        settings,
        SESSION_CONTEXT_COMMAND,
        session_context_cmd,
        project_root=project_root,
    )
    needs_add = not _has_unscoped_session_start_hook(
        settings,
        SESSION_CONTEXT_COMMAND,
        project_root=project_root,
    )

    if not needs_add:
        _atomic_write_text(settings_path, json.dumps(settings, indent=2) + "\n")
        if upgraded:
            return True, f"Upgraded hook command in .claude/settings.json to use {prefix}"
        return True, "Hook already registered in .claude/settings.json"

    # A valid top-level object whose "hooks"/"SessionStart" is the wrong type
    # parses cleanly (so the malformed-JSON backup above did not fire), but the
    # resets below would silently drop that user data — preserve a recoverable
    # copy first.
    existing_hooks = settings.get("hooks")
    existing_ss = existing_hooks.get("SessionStart") if isinstance(existing_hooks, dict) else None
    nested_corrupt = (existing_hooks is not None and not isinstance(existing_hooks, dict)) or (
        isinstance(existing_hooks, dict) and "SessionStart" in existing_hooks and not isinstance(existing_ss, list)
    )
    if nested_corrupt and settings_path.exists():
        backup = settings_path.with_suffix(".json.bak")
        try:
            reject_symlink(backup)
        except UnsafeInstallPathError as exc:
            return False, str(exc)
        shutil.copy2(settings_path, backup)
        recovered_backup = backup.name
        logger.warning(
            "corrupt hooks structure in .claude/settings.json backed up to %s "
            "before resetting it; reconcile any lost hooks by hand",
            backup.name,
        )

    if not isinstance(settings.get("hooks"), dict):
        settings["hooks"] = {}
    hooks = settings["hooks"]
    if not isinstance(hooks.get("SessionStart"), list):
        hooks["SessionStart"] = []
    session_start = hooks["SessionStart"]

    # needs_add is True only when no unscoped block already carries the legis
    # hook (see _has_unscoped_session_start_hook), so there is never a reusable
    # block to find — append a dedicated matcher-less block that fires on every
    # SessionStart source regardless of how neighbouring blocks are scoped.
    session_start.append(
        {"hooks": [{"type": "command", "command": session_context_cmd, "timeout": 5000}]}
    )

    _atomic_write_text(settings_path, json.dumps(settings, indent=2) + "\n")
    msg = f"Registered hook in .claude/settings.json: {session_context_cmd}"
    if recovered_backup is not None:
        msg += f" (backed up malformed settings.json to {recovered_backup})"
    return True, msg


# ---------------------------------------------------------------------------
# .gitignore
# ---------------------------------------------------------------------------

# Only legis's OWN rules — never another member's. ``.weft/legis/`` is legis's
# machine-written runtime-state subtree (DBs &c.); ``.weft/`` as a whole is the
# shared federation namespace and must NOT be claimed wholesale here. The legacy
# ``.legis/`` / ``legis.yaml`` surfaces were retired with the weft store
# consolidation — no legis code reads them (``legis.yaml`` was the per-member
# config that ``weft.toml`` ``[legis]`` now replaces).
#
# The operator-elevation surfaces (``operator_session.json`` ephemeral session
# metadata, ``operator.age`` wrapped operator key) live UNDER ``.weft/legis/`` and
# are already covered by the subtree rule, but are also pinned explicitly and
# root-anchored (``/.weft/...``) per the posture-ratchet plan (Phase 6) so the
# operator-secret-shaped paths are individually visible in ``.gitignore`` — a
# reviewer reading the file sees, by name, that they are never committed.
_LEGIS_IGNORE_RULES = (
    ".weft/legis/",
    "/.weft/legis/operator_session.json",
    "/.weft/legis/operator.age",
)
_LEGIS_IGNORE_BLOCK = (
    "\n# Legis — machine-written runtime state (regenerated/local; never commit)\n"
    ".weft/legis/\n"
    "/.weft/legis/operator_session.json\n"
    "/.weft/legis/operator.age\n"
)


def gitignore_rules_present(project_root: Path) -> bool:
    """True iff every legis ignore rule is already a non-comment line in .gitignore."""
    try:
        gitignore = project_path(project_root, ".gitignore")
    except (OSError, UnsafeInstallPathError):
        return False
    if not gitignore.exists():
        return False
    try:
        content = gitignore.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    present = {ln.strip() for ln in content.splitlines() if ln.strip() and not ln.lstrip().startswith("#")}
    return all(rule in present for rule in _LEGIS_IGNORE_RULES)


def mcp_entry_is_current(project_root: Path) -> bool:
    """True iff .mcp.json has a usable legis stdio server entry: a dict whose
    args invoke `mcp` and whose command resolves to an existing executable.
    Deliberately NOT byte-equality with the canonical entry — a valid but
    differently-resolved legis binary (uv-tool vs venv path) must not read as
    drift. Only a missing entry, malformed args, or a dead command path is stale.
    """
    try:
        path = project_path(project_root, ".mcp.json")
    except UnsafeInstallPathError:
        return False
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    if not isinstance(data, dict):
        return False
    servers = data.get("mcpServers")
    entry = servers.get("legis") if isinstance(servers, dict) else None
    if not isinstance(entry, dict):
        return False
    if entry.get("type") != "stdio":
        return False
    if not _mcp_args_are_current(entry.get("args")):
        return False
    if not _mcp_command_resolves_safely(entry.get("command"), project_root):
        return False
    env = _safe_mcp_env(entry.get("env"))
    return env is not None and env == entry.get("env", {})


def ensure_gitignore(project_root: Path) -> tuple[bool, str]:
    """Ensure legis's runtime-state subtree (``.weft/legis/``) is ignored."""
    try:
        gitignore = project_path(project_root, ".gitignore")
    except (OSError, UnsafeInstallPathError) as exc:
        return False, str(exc)

    if gitignore.exists():
        if gitignore_rules_present(project_root):
            return True, "legis config already in .gitignore"
        content = gitignore.read_text(encoding="utf-8")
        present = {
            line.strip() for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")
        }
        missing = [rule for rule in _LEGIS_IGNORE_RULES if rule not in present]
        if not content.endswith("\n"):
            content += "\n"
        # Append only the rules that are actually absent — writing the whole
        # block when one rule is already present would duplicate the other.
        content += "\n# Legis — local working dir / config (regenerated/local; never commit)\n"
        content += "".join(f"{rule}\n" for rule in missing)
        _atomic_write_text(gitignore, content)
        return True, f"Added {', '.join(missing)} to .gitignore"

    _atomic_write_text(gitignore, _LEGIS_IGNORE_BLOCK.lstrip("\n"))
    return True, "Created .gitignore with legis config rules"


# ---------------------------------------------------------------------------
# .mcp.json (agent MCP server registration)
# ---------------------------------------------------------------------------

_DEFAULT_AGENT_ID = "claude-code"

_UNSAFE_MCP_ENV_KEYS = frozenset({
    "LEGIS_UNSAFE_DEV_AUTH",
    "LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING",
    "LEGIS_ALLOW_INSECURE_REMOTE_HTTP",
    "LEGIS_ALLOW_UNSCOPED_API_TOKENS",
    "LEGIS_ALLOW_MISSING_GOVERNANCE_DB",
    "LEGIS_WARDLINE_ALLOW_DIRTY",
})

_SECRET_MCP_ENV_KEYS = frozenset({
    "LEGIS_API_SECRET",
    "LEGIS_API_TOKEN_ACTORS",
    "LEGIS_HMAC_KEY",
    "LEGIS_WARDLINE_ARTIFACT_KEY",
    "LEGIS_LOOMWEAVE_HMAC_KEY",
    # Retired by G11 (legis->Filigree transport-HMAC dropped) and now inert, but
    # still secret-shaped: keep scrubbing it so a stale operator-set value is
    # never copied verbatim into .mcp.json as "safe operator-owned env".
    "LEGIS_FILIGREE_HMAC_KEY",
    "OPENROUTER_API_KEY",
    # The operator-authority key (posture-ratchet, Phase 6). It is minted at
    # install and handed to a custody backend; it must NEVER be copied into
    # .mcp.json where the agent process can read it back as plaintext. The
    # ``LEGIS_OPERATOR_KEY_*`` family (e.g. the age passphrase var) is scrubbed
    # by prefix in ``_safe_mcp_env``.
    "LEGIS_OPERATOR_KEY",
})

# Operator-key family scrubbed by PREFIX in ``_safe_mcp_env`` — any
# ``LEGIS_OPERATOR_KEY*`` var (the key itself and its passphrase/unlock kin) is
# secret-shaped and never belongs in agent-readable .mcp.json.
_REJECTED_MCP_ENV_PREFIXES = ("LEGIS_OPERATOR_KEY",)

_REJECTED_MCP_ENV_KEYS = _UNSAFE_MCP_ENV_KEYS | _SECRET_MCP_ENV_KEYS


def _mcp_args_are_current(args: Any) -> bool:
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        return False
    if args[:1] == ["mcp"]:
        tail = args
    elif args[:2] == ["-m", "legis"]:
        tail = args[2:]
    elif args[:3] == ["-P", "-m", "legis"]:
        tail = args[3:]
    else:
        return False
    if tail[:1] != ["mcp"]:
        return False
    try:
        agent_idx = tail.index("--agent-id")
    except ValueError:
        return False
    return agent_idx + 1 < len(tail) and bool(tail[agent_idx + 1])


def _mcp_command_resolves_safely(command: Any, project_root: Path) -> bool:
    if not isinstance(command, str) or not command:
        return False
    if _path_head_is_project_local(command, project_root):
        return False
    resolved = shutil.which(command)
    if resolved is not None:
        return not _path_head_is_project_local(resolved, project_root)
    path = Path(command)
    return path.is_absolute() and path.is_file()


def _safe_mcp_env(env: Any) -> dict[str, str] | None:
    if env is None:
        return {}
    if not isinstance(env, dict):
        return None
    safe: dict[str, str] = {}
    for key, value in env.items():
        if not isinstance(key, str) or not isinstance(value, str):
            return None
        if key in _REJECTED_MCP_ENV_KEYS:
            continue
        if any(key.startswith(prefix) for prefix in _REJECTED_MCP_ENV_PREFIXES):
            continue
        safe[key] = value
    return safe


def _legis_mcp_entry(
    agent_id: str = _DEFAULT_AGENT_ID, *, project_root: Path | None = None
) -> dict[str, Any]:
    """The canonical legis stdio server entry for .mcp.json.

    Splits the resolved invocation into a bare ``command`` (the executable an
    MCP client execs directly) plus ``args`` so the module-fallback form
    (``<python> -P -m legis ...``) launches correctly — a single joined string
    in ``command`` would not be exec'd as separate argv tokens. *project_root*
    is threaded to ``_find_legis_command`` so a repo-venv install never pins a
    project-local command the freshness check rejects on arrival.
    """
    cmd = _find_legis_command(project_root)
    return {
        "args": cmd[1:] + ["mcp", "--agent-id", agent_id],
        "command": cmd[0],
        "env": {},
        "type": "stdio",
    }


def register_mcp_json(
    project_root: Path, agent_id: str | None = None
) -> tuple[bool, str]:
    """Register (or refresh) the legis server in <root>/.mcp.json.

    Creates the file if absent; merges into mcpServers without disturbing
    sibling entries. An explicit *agent_id* always wins; when it is ``None``
    (the default), an existing legis entry's agent-id is preserved (operator
    choice), falling back to ``_DEFAULT_AGENT_ID`` for a fresh entry.

    A *usable* existing entry (args invoke ``mcp``, command resolves to a real
    executable — the ``mcp_entry_is_current`` invariant) is never regenerated:
    a working binary that differs from our current resolution is operator
    state, not drift, and at most the agent-id is retargeted in place. Only an
    unusable entry (missing, malformed args, dead command) is rebuilt — and
    even then the operator-owned ``env`` dict is carried over, never wiped
    (legis-788a85fac1).
    """
    try:
        path = project_path(project_root, ".mcp.json")
    except UnsafeInstallPathError as exc:
        return False, str(exc)

    data: dict[str, Any] = {}
    if path.exists():
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return False, ".mcp.json present but unreadable; fix or remove it by hand"
        if not isinstance(parsed, dict):
            return False, ".mcp.json present but not a JSON object; fix or remove it by hand"
        data = parsed

    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
        data["mcpServers"] = servers

    existing = servers.get("legis")
    if agent_id is not None:
        keep_agent = agent_id  # explicit caller wins
    else:
        keep_agent = _DEFAULT_AGENT_ID  # default...
        if isinstance(existing, dict):  # ...but preserve an existing entry's id
            args = existing.get("args", [])
            if isinstance(args, list) and "--agent-id" in args:
                i = args.index("--agent-id")
                if i + 1 < len(args) and isinstance(args[i + 1], str):
                    keep_agent = args[i + 1]

    usable = False
    if isinstance(existing, dict):
        usable = (
            existing.get("type") == "stdio"
            and _mcp_args_are_current(existing.get("args"))
            and _mcp_command_resolves_safely(existing.get("command"), project_root)
            and _safe_mcp_env(existing.get("env")) == existing.get("env", {})
        )

    if usable:
        assert isinstance(existing, dict)  # narrowed by the usable check
        args = list(existing.get("args", []))
        if "--agent-id" in args and args.index("--agent-id") + 1 < len(args):
            current_agent = args[args.index("--agent-id") + 1]
        else:
            current_agent = None
        if agent_id is None or current_agent == keep_agent:
            return True, "legis already registered in .mcp.json"
        # Explicit agent-id retarget — in place, preserving command/env.
        if current_agent is not None:
            args[args.index("--agent-id") + 1] = keep_agent
        else:
            args += ["--agent-id", keep_agent]
        existing["args"] = args
        _atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")
        return True, f"Updated legis agent-id to {keep_agent} in .mcp.json"

    desired = _legis_mcp_entry(keep_agent, project_root=project_root)
    if isinstance(existing, dict):
        safe_env = _safe_mcp_env(existing.get("env"))
        if safe_env is not None:
            desired["env"] = safe_env  # preserve safe operator-owned env
    if existing == desired:
        return True, "legis already registered in .mcp.json"
    servers["legis"] = desired
    _atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")
    return True, "Registered legis server in .mcp.json"


# ---------------------------------------------------------------------------
# Posture ledger genesis + operator-key mint (posture-ratchet, Phase 6)
# ---------------------------------------------------------------------------
#
# Install "stands up" the signed posture floor: it mints the operator-authority
# key ONCE, hands it to a custody backend (never the ledger, never .mcp.json),
# and writes a single keyless ``GENESIS`` record at ``floor="chill"`` carrying
# only the key's *fingerprint*. From then on the agent process never sees the
# key bytes; ``posture set`` signs through the backend.
#
# Fail-closed / idempotent (spec §5): a second install over an existing ledger
# — whether its tail is the GENESIS or a Phase-11 ``KEY_RESET`` — re-mints
# nothing and appends nothing. The ledger's own ``read_all`` non-empty guard
# (``PostureLedger.genesis``) is the source of truth; install mirrors it so it
# does not even mint a throwaway key on the idempotent path.


class OperatorKeyCustodyError(RuntimeError):
    """The minted operator key could not be placed in custody.

    Raised by the default key sink when a backend cannot persist the key (no age
    passphrase, no shipped keychain adapter). Install treats this as fail-closed:
    NO ``GENESIS`` is written (the sink runs before the genesis append), so the
    ledger never carries a fingerprint the operator cannot later sign against. A
    bare ``legis install`` reports this as a *deferred* posture step (re-run with
    custody configured), not a hard failure of the whole install.
    """


# A sink that persists the minted key into the chosen custody backend. The key
# crosses this boundary exactly once, at install; the default sink below routes
# by backend id. Injectable so tests can observe the hand-off without a live
# keychain / writing an age blob.
KeySink = Callable[[str, str], None]


def posture_db_url_for_install() -> str:
    """The posture-ledger store URL, resolved against the install cwd.

    A thin indirection over :func:`legis.config.posture_db_url` so install (and
    its tests) name one symbol; the resolver is cwd-relative by design (the CLI
    runs install with ``cwd == project_root``).
    """
    from legis.config import posture_db_url

    return posture_db_url()


def _keychain_available() -> bool:
    """Probe whether an OS secure store is reachable for key custody.

    Conservative + injectable: the real probe (Secret Service / Keychain /
    Credential Manager reachability) is environment-specific and is mocked in
    tests via ``monkeypatch``. Until a live adapter ships it returns ``False``
    so install deterministically falls back to the age-file backend rather than
    claiming a keychain it cannot actually write — fail-closed on custody.
    """
    return False


def choose_install_backend(*, insecure_env: bool = False) -> str:
    """Pick the custody backend id at install time (keychain > age-file; env opt-in).

    Mirrors :func:`legis.posture.select_backend` but feeds it the live keychain
    probe (:func:`_keychain_available`) so the CLI does not re-implement the
    availability check. ``insecure_env=True`` (the ``--insecure-key-in-env``
    opt-in) forces the env escape hatch; it is never auto-selected.
    """
    from legis.posture import select_backend

    return select_backend(
        keychain_available=_keychain_available(), insecure_env=insecure_env
    )


def install_posture(
    project_root: Path,
    *,
    backend: str,
    key_sink: KeySink | None = None,
    agent_id: str = _DEFAULT_AGENT_ID,
    recorded_at: str | None = None,
) -> str | None:
    """Mint the operator key + write the posture-ledger ``GENESIS``, once.

    Returns the current-epoch ``key_fingerprint`` (the freshly-minted one on a
    first install, the EXISTING one on the idempotent path), or ``None`` if the
    ledger could not be read back.

    Steps:
      1. ``ensure_project_dir(project_root, ".weft", "legis")`` — the
         project-contained store subtree (symlink-checked).
      2. open ``PostureLedger(posture_db_url(), initialize=True)`` (the ONE DDL
         run; subsequent reads/writes open fresh connections).
      3. **Idempotency guard:** if the store already holds ANY record (a GENESIS
         or a ``KEY_RESET`` tail) -> no mint, no append; return the existing
         epoch fingerprint. This mirrors ``PostureLedger.genesis``'s own guard so
         install never mints a throwaway key on a second pass.
      4. else: ``mint_key()`` -> hand to the backend via ``key_sink`` -> compute
         the fingerprint -> ``ledger.genesis(key_fingerprint=fp, ...)``. The key
         bytes reach ONLY the sink; the ledger stores the fingerprint alone.
    """
    from legis.clock import SystemClock
    from legis.posture import (
        PostureLedger,
        key_fingerprint,
        mint_key,
    )

    ensure_project_dir(project_root, ".weft", "legis")
    url = posture_db_url_for_install()
    ledger = PostureLedger(url, initialize=True)

    # Idempotency guard (spec §5): an existing GENESIS or KEY_RESET tail means
    # the epoch is already established — re-mint nothing, append nothing.
    if ledger.store.get_latest_sequence_and_hash()[0] != 0:
        return ledger.current_epoch_fingerprint()

    key_hex = mint_key()
    sink = key_sink if key_sink is not None else _default_key_sink
    # Hand the key to custody BEFORE writing GENESIS: if custody fails we have
    # written no fingerprint we cannot later sign against (fail-closed).
    sink(key_hex, backend)
    fp = key_fingerprint(key_hex)

    when = recorded_at if recorded_at is not None else SystemClock().now_iso()
    ledger.genesis(key_fingerprint=fp, agent_id=agent_id, recorded_at=when)
    return fp


def _default_key_sink(key_hex: str, backend: str) -> None:
    """Default custody hand-off for the minted operator key.

    Routes by backend id. ``env`` is a no-op (the operator already placed the
    key in ``LEGIS_OPERATOR_KEY``). ``age-file`` wraps the key under a passphrase
    from ``LEGIS_OPERATOR_KEY_AGE_PASSPHRASE`` and writes ``operator.age`` (the
    blob never contains plaintext — :func:`legis.posture.wrap_key`). ``keychain``
    requires a live adapter that has not shipped; until then it raises so install
    fails LOUD rather than silently dropping the key (a dropped key means
    ``posture set`` would later refuse with no recoverable custody).
    """
    if backend == "env":
        return
    if backend == "age-file":
        from legis.config import operator_age_path
        from legis.posture import wrap_key

        passphrase = os.environ.get("LEGIS_OPERATOR_KEY_AGE_PASSPHRASE")
        if not passphrase:
            raise OperatorKeyCustodyError(
                "age-file operator-key custody needs a passphrase in "
                "LEGIS_OPERATOR_KEY_AGE_PASSPHRASE; refusing to write an "
                "unprotected operator key"
            )
        blob = wrap_key(key_hex, passphrase)
        path = operator_age_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        # The wrapped blob is binary; write atomically via a temp + replace.
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".operator.age.")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
        return
    raise OperatorKeyCustodyError(
        f"no shipped custody adapter for backend {backend!r}; cannot persist the "
        "operator key (the live keychain adapter has not shipped)"
    )
