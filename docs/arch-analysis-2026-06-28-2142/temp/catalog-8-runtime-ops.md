## install.py — Project Installer

**Location:** `src/legis/install.py`

**Responsibility:** Stands up legis in a project by injecting a versioned instruction block into CLAUDE.md/AGENTS.md, installing the legis-workflow skill pack, registering a Claude Code SessionStart hook in .claude/settings.json, writing .gitignore rules, minting the posture-ledger GENESIS and operator key, and registering the MCP server entry in .mcp.json — all idempotent, all symlink-escape-guarded.

**Key Components:**
- `project_path` / `ensure_project_dir` / `reject_symlink` (lines 132–160) — symlink-escape guards applied to every installer write; raise `UnsafeInstallPathError` on traversal outside project root
- `inject_instructions` (lines 311–387) — foreign-fence-aware instruction-block injector; uses `_first_own_open_fence_pos` + `_first_foreign_fence_pos` to never delete a co-resident sibling block (wardline/filigree); writes via `_atomic_write_text` (temp + `os.replace`)
- `_atomic_write_text` (lines 278–308) — empty-content guard + mode-preserving atomic write (refuses empty payload, rejects symlink direct target); used for all text writes in install
- `_install_skill_to` (lines 416–483) — concurrent-safe skill-pack copytree with rename race: stages to a temp dir, renames target aside, atomically swaps in new tree; on failure restores the prior pack rather than silently dropping it
- `install_claude_code_hooks` (lines 733–837) — registers `legis session-context` as a SessionStart hook; upgrades stale/bare commands to the resolved binary path; backs up malformed `settings.json` before resetting rather than silently clobbering; only rewrites unscoped blocks (never touches user-scoped blocks)
- `register_mcp_json` (lines 1199–1289) — idempotent MCP entry manager; a usable existing entry (command resolves + args valid + env clean) is NEVER regenerated; on rebuild preserves the operator-owned `env` dict minus blocked keys (`_safe_mcp_env`); `_REJECTED_MCP_ENV_KEYS` + `_REJECTED_MCP_ENV_PREFIXES` scrub secrets and unsafe escape-hatch vars
- `install_posture` (lines 1367–1431) — posture-ledger genesis; key minted once, handed to custody sink BEFORE `GENESIS` is written (fail-closed: no fingerprint written if custody fails); idempotency guard at `current_epoch_fingerprint()` prevents second-mint; env-backend adopts `LEGIS_OPERATOR_KEY` rather than minting a throwaway (legis-1844bf8ac9)
- `_default_key_sink` (lines 1462–1502) — custody router: `env`=no-op, `age-file`=atomic blob write, `keychain`=loud failure (adapter not shipped); raises `OperatorKeyCustodyError` rather than dropping the key
- `_find_legis_command` (lines 522–562) — binary resolution; prefers `sys.argv[0]` (faithful to the running binary, legis-788a85fac1) over PATH; skips project-local hits to avoid pinning a venv shim that doctor would immediately flag as stale

**Dependencies:**
- Inbound: `hooks.py` (imports `inject_instructions`, `install_skills`, `install_codex_skills`, `_get_skills_source_dir`, `_skill_tree_fingerprint`, `_instructions_block_is_current`, `_marker_token`, `INSTRUCTIONS_MARKER`, `SKILL_NAME`); `doctor.py` (imports `_install` module, calls `mcp_entry_is_current`, `inject_instructions`, `install_claude_code_hooks`, `install_skills`, `install_codex_skills`, `gitignore_rules_present`, `ensure_gitignore`, `ensure_legis_dir_gitignore`, `_has_unscoped_session_start_hook`, `_own_open_marker_tokens`, `_marker_token`, `SESSION_CONTEXT_COMMAND`, `SKILL_NAME`, `LEGIS_DIR_GITIGNORE_MARKER`); `posture/` (imports `install_posture` for genesis)
- Outbound: `legis.config` (posture DB URL); `legis.posture` (`PostureLedger`, `mint_key`, `key_fingerprint`, `wrap_key`, `select_backend`); `legis.clock`; `importlib.resources` / `importlib.metadata` (bundled instructions, version); stdlib (`hashlib`, `shutil`, `tempfile`, `os`, `json`, `re`, `stat`)

**Patterns Observed:**
- Fail-closed on every operation: custody failure before GENESIS write, empty-content guard before any text write, `UnsafeInstallPathError` on symlink escape — the codebase never auto-accepts partial success
- Strict idempotency contract: every installer function checks current state before acting; a second `install` over a healthy project modifies nothing material (returns early with "already registered" / "already present")
- Operator-env preservation on `.mcp.json` updates: the existing `env` dict is carried forward (minus scrubbed secret keys) rather than wiped — named fix for legis-788a85fac1; `_safe_mcp_env` is the scrub gate
- Foreign-fence awareness in instruction injection: `_INSTR_FENCE_RE` detects any tool's namespace fence (case-insensitive); the injector never deletes inter-block content owned by wardline/filigree (C-4 multi-owner block contract)
- `_find_legis_command` avoids project-local path poisoning: prefers the running binary, skips `.venv/bin/legis` hits so the registered hook/MCP command doesn't bounce on freshness checks

**Concerns:**
- `_keychain_available()` (line 1348–1349) always returns `False` — the live OS-keychain backend is not yet implemented. This means `choose_install_backend` never selects `keychain` automatically. The comment documents it as deferred, but a caller providing `backend="keychain"` directly would route to the `_default_key_sink` `raise` path. The honesty posture is correct (fail-closed, not silent), but the gap means the most-secure custody path is unattainable without a custom `key_sink` injection.
- `install.py` is 1503 lines and owns six distinct responsibilities (instruction injection, skill pack, hook, gitignore, MCP registration, posture genesis). The functions are well-decomposed but the file is a god module by size; a future author adding a seventh install artifact has no forcing function to split it.
- The `settings.json` backup-on-corrupt path (lines 761–768, 804–817) writes `settings.json.bak` by copying via `shutil.copy2` then overwrites without `reject_symlink` on the backup path itself — a symlink at `.claude/settings.json.bak` could cause the backup to land outside the project tree. The backup path does call `reject_symlink` (lines 763, 807) before the copy, so this is mitigated, but only for the direct symlink case, not for symlinked parent directories. Evidence: line 763 `reject_symlink(backup)` is present, so direct symlink is blocked.

**Confidence:** High — Read 100% of install.py (1503 lines). Every claim cites specific line ranges. Cross-verified the `hooks.py` import list against actual `from legis.install import (...)` at hooks.py:23–32. Verified `register_mcp_json` env-preservation logic at lines 1282–1284. Verified `install_posture` idempotency guard at lines 1411–1413. Verified `_keychain_available` stub at lines 1347–1349.


## doctor.py — Operator Health and Repair

**Location:** `src/legis/doctor.py`

**Responsibility:** Inspects and (with `--fix`) repairs legis's install and runtime artifacts, reporting each problem as `[auto-fixable]` or `[operator]`, sharing the machine-readable report surface (`doctor_payload`) with the MCP `doctor_get` tool so CLI and agent surfaces cannot drift.

**Key Components:**
- `DoctorCheck` (lines 28–49) — frozen dataclass with `id`, `status` (`ok`/`warn`/`error`), `fixed`, `message`, `repairable`; the `repairable` field is the source of truth for the `[auto-fixable]` vs `[operator]` tag rendered in `render_text`
- `render_text` (lines 71–114) — renders `[fixed]`/`[auto-fixable]`/`[operator]` tags; a `repairable=False` check that is not fixed renders `[operator]`; a `repairable=True` check that is not fixed renders `[auto-fixable]`; confirmed honest: split-brain blocks set `repairable=False` (line 197) matching their "resolve it by hand" message
- `doctor_payload` (lines 56–64) — single source of the machine-readable schema shared by CLI `--format json` and MCP `doctor_get`; both render from this function (docstring confirmed; cross-validated against `mcp.py` usage by import path)
- `collect_checks` (lines 967–996) — runs 25 checks in order; repair branches live inside individual check functions (not here), so the orchestrator is pure composition
- `check_instruction_block` (lines 172–205) — distinguishes missing / drifted / split-brain; split-brain (`len(tokens) > 1`) returns `repairable=False` (line 197) because the injector cannot canonicalise across a sibling's block — honesty-correct; `--fix` re-runs `inject_instructions` and re-checks state before reporting success
- `check_mcp_json` (lines 117–137) — repair calls `register_mcp_json` and re-checks `mcp_entry_is_current` before returning `fixed=True`; never writes env secrets (delegates to `_safe_mcp_env` inside `register_mcp_json`)
- `check_audit_chain` (lines 461–487) — absent store → `ok` (never creates DB); tampered chain → `error`, `repairable=False`; never auto-repairs a hash-chain failure
- `check_posture_chain` / `check_posture_ledger` / `check_posture_key_reset` / `check_operator_key_accessible` (lines 561–810) — posture-ledger integrity checks; all report-only; `check_operator_key_accessible` probes key reachability without rendering the key value (lines 763–791); env escape hatch presence yields `warn`, not `ok` (honesty note at line 773)
- `check_weft_toml` (lines 339–358) — distinguishes absent (ok / defaults apply) from present-but-broken (error / config silently not applying), per C-9(b); NEVER writes `weft.toml` (confirmed — no write call anywhere in this function)
- `check_filigree_binding_scope` (lines 927–964) — triggered by unscoped filigree URL presence, NOT local install; `repairable=False` (operator-pinned URL); closes the false-green where doctor said "ok" while scans silently non-emitted
- `_store_dir_for` (lines 329–336) — anchored at `root`, not `cwd`, and explicitly ignores `weft.toml` (comment at line 332); custody rule correctly enforced in doctor's own store-path logic

**Dependencies:**
- Inbound: CLI (`legis.cli` `doctor` subcommand); MCP tool surface (`legis.mcp` `doctor_get` tool uses `doctor_payload` / `collect_checks`); integration tests
- Outbound: `legis.install` (all repair operations delegate back to install functions); `legis.config` (`STORE_DB_SPECS`, `protected_policies`, `posture_db_url`, `operator_age_path`); `legis.store.audit_store` (`AuditStore`); `legis.posture.ledger` (`PostureLedger`); `legis.posture.signing` (`key_fingerprint`, `unwrap_key`); `legis.posture.records` (kind constants); `legis.enforcement.signing` (`verify`)

**Patterns Observed:**
- Report-then-repair contract: every check function verifies current state first; repair branches are conditional on the `repair` flag; post-repair state is re-verified before claiming `fixed=True` (e.g. `check_hook` lines 259–261)
- `repairable` flag drives honest tagging: split-brain blocks, operator-key items, and audit-chain failures all set `repairable=False`; auto-fixable items all set `repairable=True`; the tag in `render_text` derives directly from this flag, not from ad-hoc conditions
- Doctor never writes `weft.toml` (C-9(b)): confirmed — no `weft.toml` write in any check function; `check_weft_toml` is read-only
- `_store_dir_for` ignores `weft.toml` and uses `root`-anchored path (line 332 comment); doctor's store resolution is independent of the runtime config's `LEGIS_*_DB` overrides for the store-path check itself (overrides are respected only by `_store_url` when building actual DB URLs for integrity checks)
- `STORE_DB_SPECS` imported from `config` (line 325) ensures doctor's override-env list can never silently drop a store when a 6th store is added — single-source enumeration closes that coverage gap

**Concerns:**
- `check_wardline_artifact_key` (line 836) reports a `warn` when `LEGIS_WARDLINE_ARTIFACT_KEY` is absent, saying all scans govern as `artifact_status=unverified`. The honesty diagnosis (PDR-0023) is correct and the signal is present. However the message does not name a path for a "warn" exit in CI: operators who see a `warn` may not know whether CI fails on `warn` or only on `error`. `run_doctor` (line 999–1002) returns non-zero only when any check is not `.ok` — and `warn` is not "ok" (`.ok` is `status != "error"`, not `status == "ok"` — confirmed: `DoctorCheck.ok` at line 38 returns `self.status != "error"`). This means `warn`s do NOT cause a non-zero exit. An unset `LEGIS_WARDLINE_ARTIFACT_KEY` therefore yields a `warn` that does NOT fail CI — which is documented as intentional ("deliberately a warn, not an error") but could mislead operators who expect CI-blocking behavior for unsigned verification.
- At 1002 lines `doctor.py` carries both the check domain logic and the rendering/orchestration logic. It is coherent but large; adding a new sibling or posture check requires editing a single growing file with no structural boundary.

**Confidence:** High — Read 100% of doctor.py (1003 lines). Every claim cites specific line ranges. Verified `DoctorCheck.ok` property logic at line 38. Confirmed `repairable=False` for split-brain at line 197. Confirmed `check_weft_toml` has no write call. Confirmed `run_doctor` exit-code logic at lines 999–1002.


## hooks.py — SessionStart Hook and Refresh

**Location:** `src/legis/hooks.py`

**Responsibility:** Implements the `legis session-context` SessionStart hook, which refreshes drifted instruction blocks and skill packs in place and emits a one-line posture banner (instructions, skill, cells, posture floor) that is always non-empty to distinguish "nothing to report" from "broken."

**Key Components:**
- `refresh_instructions` (lines 38–93) — refreshes drifted instruction blocks (byte-exact check via `_instructions_block_is_current`) and stale skill packs (fingerprint check via `_skill_tree_fingerprint`); only touches marker-bearing files and already-installed skill dirs; never creates a block or dir that doesn't already exist (that is install's job)
- `generate_session_context` (lines 198–222) — the top-level entry point; always returns a non-empty string (dogfood N-1); composes four posture sub-strings: `_instructions_posture`, `_skill_pack_posture`, `_cells_posture`, `_posture_floor`; exceptions from `refresh_instructions` are caught and reported as a failure line, not raised
- `_posture_floor` (lines 173–195) — reads the posture ledger with `initialize=False` (never creates the DB); absent/empty ledger returns `"posture floor: none (fail-closed structured)"` not a false-green claim; unreadable ledger returns `"posture floor: unreadable"` (warn, not silent); imported lazily inside the function to avoid circular import at module load
- `_cells_posture` (lines 145–170) — mirrors `mcp._load_policy_cell_registry` file precedence (`LEGIS_POLICY_CELLS` > `policy/cells.toml`) but is explicitly documented as report-only at hook process scope, never claiming server runtime posture; unreadable cells → `"cells config: unreadable"`, not a false-green
- `_skill_pack_posture` (lines 122–142) — when bundled source is missing, returns `"skill pack unverifiable (bundled source missing)"` (line 138) rather than claiming currency — honesty-correct; only claims "current" when fingerprints compare equal

**Dependencies:**
- Inbound: `legis.cli` (the `session-context` subcommand calls `generate_session_context`); `legis.mcp` (MCP startup calls `refresh_instructions` best-effort)
- Outbound: `legis.install` (substantial: `inject_instructions`, `install_skills`, `install_codex_skills`, `_get_skills_source_dir`, `_skill_tree_fingerprint`, `_instructions_block_is_current`, `_marker_token`, `INSTRUCTIONS_MARKER`, `SKILL_NAME`); `legis.policy.cells` (`load_policy_cells`); `legis.config` (`posture_db_url`); `legis.posture.ledger` (`PostureLedger`)

**Patterns Observed:**
- Refresh-only-in-place invariant: `refresh_instructions` checks `if not md_path.exists(): continue` (line 50) and `if not target_root.is_dir(): continue` (line 83) — never creates absent install artifacts; install vs hooks boundary is structurally enforced
- All four posture sub-functions are fail-closed: each returns a distinct "unreadable" or "not installed" string rather than silently eliding the field or returning an empty string
- Lazy import of `legis.config` / `legis.posture.ledger` inside `_posture_floor` (lines 183–184) avoids circular import; consistent with the pattern used across enforcement modules

**Concerns:**
- `refresh_instructions` warns via `logger.warning` (lines 69–71, 88–90) when drift re-injection fails, but the warning goes to the log, not to the session banner. An operator reading the banner without checking logs would see no signal about the failure. The comment at line 69 notes this is intentional ("Surface it for the operator (peer of the boot-log path)"), but in practice an agent running headlessly may have no log reader. The `_instructions_posture` post-refresh check (line 116) does catch still-drifted state and returns `"instructions stale (refresh failed; see logs)"` in the banner — so this is only a partial gap.
- `hooks.py` imports eight private symbols from `install.py` (prefixed `_`). This is a documented dependency (the module comment explains the two callers), but changes to private install helpers require cross-checking hooks.py. The coupling is inward-only (hooks does not re-export these) and exists because hooks is explicitly a "lighter-weight" refresh surface reusing install's logic.

**Confidence:** High — Read 100% of hooks.py (223 lines). Verified `refresh_instructions` never creates absent paths (lines 50, 83). Verified `_posture_floor` uses `initialize=False` (line 189). Verified `_skill_pack_posture` unverifiable path (line 138). Confirmed private symbol imports from install at lines 23–32.


## config.py — Store Resolution and Env Configuration

**Location:** `src/legis/config.py`

**Responsibility:** Resolves all SQLite store URLs and composition-root configuration (protected policies, operator paths) from environment variables, with `LEGIS_*_DB` overrides as the sole relocation mechanism — `weft.toml` is explicitly and deliberately ignored for store paths.

**Key Components:**
- `STORE_DB_SPECS` (lines 71–77) — stably-ordered tuple of `(env_var, db_filename)` for all five stores; the single source of store identity so doctor and any future consumer never re-list the env vars / filenames independently
- `_resolve_db_url` (lines 110–123) — the single resolution point for all stores: `env_var in os.environ` (membership check, not `.get()`) so a present-but-empty override returns verbatim rather than silently falling through to the default; a present-but-empty override is therefore a broken override, never a "use default" fallback
- `_store_dir` (lines 90–97) — ignores `weft.toml` by design (comment at line 92); builds `.weft/legis/` under the provided root or `Path(".")` (relative, resolved against cwd at call time)
- `protected_policies` (lines 171–184) — single parse point for `LEGIS_PROTECTED_POLICIES`: `frozenset` of comma-split, stripped, non-empty names; read at call time so the CLI can write the env var from `--protected-policies` before composition roots read it
- `ensure_sqlite_parent` (lines 187–203) — creates the parent directory lazily at store-open time, never at URL-compute time; importing `config` or computing a default URL never litters `.weft/` directories
- `operator_session_path` / `operator_age_path` (lines 151–168) — operator-elevation file paths, both under `.weft/legis/`; documented as holding references/encrypted blobs only, never key plaintext

**Dependencies:**
- Inbound: every module that opens a store (`api/app.py`, `mcp.py`, `cli.py`, `store/`, `posture/`, `install.py`, `doctor.py`, `hooks.py`)
- Outbound: `sqlalchemy.engine.make_url` (URL parsing in `ensure_sqlite_parent`); `os`, `pathlib`

**Patterns Observed:**
- `weft.toml`-is-enrich-only documented at module level (lines 18–23) and structurally enforced: `_store_dir` does not read `weft.toml` at all; no `tomllib` import in `config.py`
- Present-but-empty env var treated as verbatim override (line 121), not silent fallback — consistent with CLAUDE.md doctrine
- Call-time resolution (not module-load-time) for both DB URLs and `protected_policies`: env vars written late by the CLI (e.g. `--protected-policies` flag sets `os.environ` before the composition root reads it) always produce the correct value

**Concerns:**
- None observed. Verified: no `weft.toml` read in any path; present-but-empty override is handled correctly (line 121); `ensure_sqlite_parent` defers directory creation to store-open time (not import time); `STORE_DB_SPECS` is the single enumeration consumed by doctor. The module is 204 lines with a single, well-bounded responsibility.

**Confidence:** High — Read 100% of config.py (204 lines). Verified `env_var in os.environ` membership-check at line 121. Verified absence of `tomllib` import. Verified `_store_dir` comment at lines 91–93. Verified `STORE_DB_SPECS` structure at lines 71–77. Confirmed lazy `ensure_sqlite_parent` design at lines 193–203.
