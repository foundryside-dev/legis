"""Store-location resolver — the single source for legis's database URLs.

These previously lived on ``legis.api.app``, which forced ``mcp`` (and any
other composition root) to import from the HTTP layer just to learn where the
governance store lives (Q-H2). They are transport-agnostic configuration, so
they belong here; ``api`` and ``mcp`` both import them from this module.

**Federated store layout.** legis's machine-written runtime state lives under
``.weft/legis/`` at the project root — the federation convention shared with
the other weft members. legis is the *sole writer* of this subtree. Resolution
is anchored at the current working directory: the same notion the installer
uses (``cli.py`` sets ``project_root = Path.cwd()``), and every member resolves
``.weft/`` against that same cwd, so running each tool from the project root
keeps them in agreement. The default URLs are therefore cwd-relative
(``sqlite:///.weft/legis/...``), preserving the historical resolution semantics.

**weft.toml is enrich-only, never load-bearing.** The operator-authored
``weft.toml`` may carry a ``[legis]`` table, but repo-local data must not decide
where governance stores live. Per-DB relocation is deliberately limited to
operator environment overrides (``LEGIS_*_DB``). An absent file, an absent
``[legis]`` section, or even a malformed weft.toml must still boot on the
built-in defaults — legis never *depends* on weft.toml (Doctrine §5 deletion
test).

**Clean break.** There is no fallback to the old cwd-root locations
(``legis-governance.db`` &c.). Existing deployments move their files into
``.weft/legis/`` or pin the ``LEGIS_*_DB`` env vars.

**Keys are out of scope — with one deliberate carve-out.** Operator-held
signing keys are the authority-key carve-out: capability-confined and
deliberately not agent-reachable. Config still touches no key *plaintext*.

The posture-ratchet feature (spec §5/§6) amends this doctrine narrowly: an
operator-authority key is *minted at install* and held by a custody backend
(OS keychain / age-encrypted file / env escape hatch). Two new in-scope paths
appear under this subtree as a result — ``operator_session.json`` (ephemeral
elevation-session metadata + an unlock *reference* + session HMAC, never the key) and
``operator.age`` (the age-file backend's *encrypted* blob). Both are
gitignored at install. The key plaintext itself is still never written to disk
by legis except via the explicit ``--insecure-key-in-env`` escape hatch.
"""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy.engine import make_url

WEFT_MEMBER = "legis"

# Built-in DB filenames under the member's runtime-state subtree. The legacy
# names are preserved so a clean-break move is a relocation, not a rename.
_CHECK_DB_NAME = "legis-checks.db"
_GOVERNANCE_DB_NAME = "legis-governance.db"
_BINDING_DB_NAME = "legis-binding.db"
_PULL_DB_NAME = "legis-pulls.db"
_POSTURE_DB_NAME = "legis-posture.db"

# Per-DB override env vars. Highest precedence (see ``_resolve_db_url``).
_CHECK_DB_ENV = "LEGIS_CHECK_DB"
_GOVERNANCE_DB_ENV = "LEGIS_GOVERNANCE_DB"
_BINDING_DB_ENV = "LEGIS_BINDING_DB"
_PULL_DB_ENV = "LEGIS_PULL_DB"
_POSTURE_DB_ENV = "LEGIS_POSTURE_DB"

# Public, stably-ordered (override env var, default filename) for every store.
# THE single source of store identity so consumers (e.g. ``legis doctor``) never
# re-list the env vars / filenames: adding a 5th store here automatically extends
# their coverage instead of silently dropping it.
STORE_DB_SPECS: tuple[tuple[str, str], ...] = (
    (_CHECK_DB_ENV, _CHECK_DB_NAME),
    (_GOVERNANCE_DB_ENV, _GOVERNANCE_DB_NAME),
    (_BINDING_DB_ENV, _BINDING_DB_NAME),
    (_PULL_DB_ENV, _PULL_DB_NAME),
    (_POSTURE_DB_ENV, _POSTURE_DB_NAME),
)

# Protected-policy set: the policy names whose judge-ACCEPTED verdicts are
# downgraded to operator sign-off (Q-H3). Composition-root config like the DB
# URLs above, so resolved here.
_PROTECTED_POLICIES_ENV = "LEGIS_PROTECTED_POLICIES"


def project_root() -> Path:
    """The directory the federation treats as project root (the cwd)."""
    return Path.cwd()


def _store_dir() -> Path:
    """The built-in runtime-state subtree.

    Repo-local ``weft.toml`` is intentionally ignored here. Load-bearing store
    relocation must come from explicit ``LEGIS_*_DB`` operator env vars.
    """
    return Path(".weft") / WEFT_MEMBER


def _sqlite_url(path: Path) -> str:
    """Render a filesystem path as a SQLite URL, preserving relative-ness.

    A relative path stays relative (``sqlite:///.weft/legis/x.db``, resolved by
    SQLite against cwd); an absolute path renders with the leading slash intact
    (``sqlite:////abs/x.db``).
    """
    return f"sqlite:///{path.as_posix()}"


def _resolve_db_url(env_var: str, db_name: str) -> str:
    """Resolve a store URL with the documented precedence (module docstring):
    the per-DB ``LEGIS_*_DB`` override wins; otherwise the URL is composed from
    the built-in ``.weft/legis`` default under the canonical filename.

    This is THE single resolution point — callers invoke the ``*_db_url()``
    function directly and never re-implement the env layering, so changing
    precedence or adding an alias is a one-line edit here, not ~11 call sites.
    ``env_var in os.environ`` (not ``.get(...) or``) so a present-but-empty
    override is returned verbatim rather than silently falling through.
    """
    if env_var in os.environ:
        return os.environ[env_var]
    return _sqlite_url(_store_dir() / db_name)


def check_db_url() -> str:
    return _resolve_db_url(_CHECK_DB_ENV, _CHECK_DB_NAME)


def governance_db_url() -> str:
    return _resolve_db_url(_GOVERNANCE_DB_ENV, _GOVERNANCE_DB_NAME)


def binding_db_url() -> str:
    return _resolve_db_url(_BINDING_DB_ENV, _BINDING_DB_NAME)


def pull_db_url() -> str:
    return _resolve_db_url(_PULL_DB_ENV, _PULL_DB_NAME)


def posture_db_url() -> str:
    """The signed posture-floor ledger store (design §4).

    Same resolution contract as the other four stores: ``LEGIS_POSTURE_DB``
    override wins, else the built-in ``.weft/legis/legis-posture.db`` default.
    """
    return _resolve_db_url(_POSTURE_DB_ENV, _POSTURE_DB_NAME)


def operator_session_path() -> Path:
    """The ephemeral elevation-session metadata file (design §6).

    Holds only session/window metadata + a backend-specific unlock reference —
    never key plaintext, never a passphrase. Created by ``legis operator
    enable``, deleted on TTL lapse or ``disable``. Gitignored at install.
    """
    return _store_dir() / "operator_session.json"


def operator_age_path() -> Path:
    """The age-encrypted operator-key blob for the age-file custody backend.

    Project-rooted under ``.weft/legis/`` (the federation convention), NOT a
    home-config path. Encrypted at rest (scrypt + AES-GCM); gitignored at
    install. Only the age-file backend uses it.
    """
    return _store_dir() / "operator.age"


def protected_policies() -> frozenset[str]:
    """Resolve the protected-policy set from ``LEGIS_PROTECTED_POLICIES``.

    THE single parse point for the env var: the API factory, the MCP runtime,
    and the CLI override-rate gate all call this rather than re-implementing the
    ``frozenset(split(","))`` idiom, so the delimiter/trim rule cannot diverge
    between composition roots (it decides whether a judge ACCEPTED is downgraded
    to sign-off, so a divergence would be a real authority split). Read at call
    time — like the ``*_db_url()`` resolvers — because ``cli.py`` writes the env
    var from ``--protected-policies`` before the downstream root reads it. Empty,
    whitespace-only, and absent all yield the empty set.
    """
    raw = os.environ.get(_PROTECTED_POLICIES_ENV, "")
    return frozenset(p.strip() for p in raw.split(",") if p.strip())


def ensure_sqlite_parent(url: str) -> None:
    """Create the parent directory for a SQLite *file* URL, if needed.

    Called at store-open time (not at URL-compute time) so that merely importing
    config or computing a default URL never litters ``.weft/`` directories — the
    subtree appears only when a DB is actually opened. No-op for in-memory or
    non-SQLite URLs. SQLite creates the ``.db`` file but never its parent, so
    without this an open against a fresh ``.weft/legis/`` raises "unable to open
    database file".
    """
    parsed = make_url(url)
    if not parsed.drivername.startswith("sqlite"):
        return
    database = parsed.database
    if not database or database == ":memory:":
        return
    Path(database).expanduser().parent.mkdir(parents=True, exist_ok=True)
