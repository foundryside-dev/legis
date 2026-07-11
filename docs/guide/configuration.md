# Configuring Legis (operator guide)

This is the **operator's** reference: the dials a human turns to govern from
outside the agent's operating loop. It is the companion to two existing docs —
read them first if you have not:

- **[`README.md`](../../README.md)** — *why* the governance 2×2 exists and what
  each cell is for (the concept). This guide does not re-derive that model.
- **The `legis-workflow` skill** (`src/legis/data/skills/legis-workflow/SKILL.md`)
  — the *agent-call mechanics* (tool arguments, MCP error codes). This guide does
  not duplicate the agent surface.

This guide owns one thing: **what an operator sets, what enabling it costs, and
what it buys.**

## "Zero human config" — reconciled

The README leads with *"zero human config."* That is the **agent's** experience:
the agent operates with no setup because the instruction layer is preloaded. It
is not a claim that the *operator* has nothing to do. The operating invariant is
**agent-first: humans on the loop, not in the loop** — and the loop's edge is
exactly where configuration lives. The operator governs by two acts, both done
out-of-band (never through an agent-reachable tool):

1. **Choosing which cell governs which policy** — how much structure and whether
   a judge sits inline.
2. **Holding the signing key** — the authority secret that the complex tier
   binds records to. Keys are env-provided secrets, deliberately not files in
   legis's state subtree and not reachable from any MCP tool.

A solo project that turns nothing on pays nothing: legis is invisible until an
operator enables a cell.

## The default posture is fail-closed

With no routing configured, an unmatched policy routes to **`structured`** (block
+ escalate to a human), not to self-clear. This is deliberate — an incomplete
deployment must not silently downgrade governance. You move *off* fail-closed by
configuring routing (below), not by accident.

Routing is resolved in this order (first match wins):

1. `LEGIS_POLICY_CELLS` — explicit path to a cell-registry TOML.
2. `policy/cells.toml` under `LEGIS_SOURCE_ROOT` (or cwd) if present.
3. `LEGIS_DEV_DEFAULT_CELLS=1` → everything defaults to **`chill`** (the relaxed
   dev posture — see [escape hatches](#dev-only-flags-and-escape-hatches)).
4. Otherwise → **fail-closed**, everything defaults to `structured`.

## Turning on each cell

A "cell" is the (structure × judge) pairing that governs a policy. You assign
policies to cells in a **cell registry** (`policy/cells.toml`, or a file pointed
at by `LEGIS_POLICY_CELLS`):

```toml
# policy/cells.toml — exact policy names beat globs; unlisted policies use default_cell.
default_cell = "structured"

[[policy]]
pattern = "import-allowlist"
cell = "coached"

[[policy]]
pattern = "protected.*"      # glob
cell = "protected"
```

| Cell | What it costs to enable | What it buys |
|---|---|---|
| **chill** (simple, judge off) | Map the policy to `chill`. **Keyless, no judge, no other config.** | A policy violation lets the agent self-clear with a *recordable* override; you review the trail asynchronously. |
| **coached** (simple, judge on) | Map to `coached`, **plus configure the judge** (`LEGIS_JUDGE_PROVIDER=openrouter` + `OPENROUTER_API_KEY` + a model). Still keyless. | An LLM wall the agent must satisfy *before* the override records. Raises the cost of lazy overrides; no key management. |
| **structured** (complex, judge off) | Map to `structured`, **plus `LEGIS_HMAC_KEY`** (records are signed), plus the binding ledger (`LEGIS_BINDING_DB`) if you gate Filigree closures. | A hard gate: a designated human signs off before it clears. No model in the critical path. |
| **protected** (complex, judge on) | `structured`'s requirements **plus the judge** (as in `coached`). Optionally declare the policy in `LEGIS_PROTECTED_POLICIES` for a config-hygiene warning. | The full machinery: HMAC-signed verdicts, decay sweep, override-rate gate. A judge `ACCEPTED` here is advisory only and downgrades to operator sign-off unless a deterministic validator confirms it. |

**Why `LEGIS_HMAC_KEY` is the complex-tier gate.** The simple tier (chill/coached)
is keyless. The complex tier (structured/protected) signs every verdict, so a
governance store with raw-file write access stays tamper-*evident*. Without a key,
a complex cell reports `CELL_NOT_ENABLED` rather than silently signing nothing.
Keep this key on storage only the operator controls.

## Environment variable reference

Flags on `legis serve` / `legis mcp` override the matching env var; the env var is
the fallback. (Run `legis <command> --help` for the authoritative flag list.)

### Stores — where legis's databases live

legis writes its runtime state under `.weft/legis/` at the project root (the
federation convention; legis is the sole writer of that subtree). You normally do
not touch these — they default sensibly and the directory is created on first use.

| Variable | Default | Role |
|---|---|---|
| `LEGIS_GOVERNANCE_DB` | `.weft/legis/legis-governance.db` | The append-only, SEI-keyed audit trail (overrides, verdicts, sign-offs). |
| `LEGIS_CHECK_DB` | `.weft/legis/legis-checks.db` | Recorded CI/check outcomes. |
| `LEGIS_BINDING_DB` | `.weft/legis/legis-binding.db` | Sign-off binding ledger (required to gate Filigree closures). |
| `LEGIS_PULL_DB` | `.weft/legis/legis-pulls.db` | Recorded pull-request metadata. |

To relocate stores, set the relevant `LEGIS_*_DB` variable in the operator
environment. Repo `weft.toml` is read-only/report-only for legis and is not used
for database placement, so committed project config cannot redirect governance
stores. A missing or malformed `weft.toml` boots on defaults — it is never
load-bearing.

### Cell routing

| Variable | Role |
|---|---|
| `LEGIS_POLICY_CELLS` | Path to the cell-registry TOML (highest-precedence routing source). |
| `LEGIS_PROTECTED_POLICIES` | Comma-separated policy names that *declare* themselves protected. Drives a config-hygiene warning + the read-side signature requirement; it does **not** by itself route a policy to the protected cell (the registry does). |
| `LEGIS_WARDLINE_CELL` | The single cell `scan_route` routes Wardline findings into (server-owned routing). |
| `LEGIS_WARDLINE_CELL_BY_SEVERITY` | A `SEVERITY=cell` map for `scan_route`, comma-separated — e.g. `CRITICAL=block_escalate,WARN=surface_override`. Severities are the uppercase Wardline names (`CRITICAL`/`ERROR`/`WARN`/`INFO`/`NONE`); cells are the Wardline routing values (`block_escalate`/`surface_override`/`surface_only`), not the governance policy-cell names. |

### Signing keys (complex tier)

All HMAC keys are operator-held secrets supplied via the environment. A
channel-specific key wins; absent it, the shared `LEGIS_HMAC_KEY` is the fallback
where the channel supports transport signing.

| Variable | Role |
|---|---|
| `LEGIS_HMAC_KEY` | Shared signing key — signs governance verdicts and is the fallback for the channel keys below. Enabling the complex tier requires it. |
| `LEGIS_WARDLINE_ARTIFACT_KEY` | Verifies the signed Wardline scan artifact (`scan_route` CI posture). |
| `LEGIS_LOOMWEAVE_HMAC_KEY` | Signs legis's requests to Loomweave. |
| `LEGIS_FILIGREE_HMAC_KEY` | Deprecated and inert for the classic Filigree bind route. It no longer enables request signing. |

Filigree entity-association binds are intentionally transport-open: Legis sends
the app-level `binding_signature` in the JSON body, but no `X-Weft-*` transport
HMAC headers.

### LLM judge (coached / protected cells)

Configuring a judge is what turns the judge axis *on*. Omit it and protected cells
stay fail-closed.

| Variable | Default | Role |
|---|---|---|
| `LEGIS_JUDGE_PROVIDER` | unset | Judge provider; `openrouter` is the supported value. Omit to keep the judge off. |
| `LEGIS_JUDGE_MODEL` | (provider default) | Judge model id. |
| `LEGIS_JUDGE_MAX_TOKENS` | (provider default) | Cap on judge response tokens. |
| `LEGIS_JUDGE_BASE_URL` | `https://openrouter.ai/api/v1` | Override the judge API base URL. |
| `OPENROUTER_API_KEY` | unset | Credential for the OpenRouter provider (required when `LEGIS_JUDGE_PROVIDER=openrouter`). |

### Federation (sibling tools)

| Variable | Role |
|---|---|
| `LOOMWEAVE_API_URL` | Loomweave identity API — SEI resolution and lineage. Without it, legis degrades honestly (identity status `unavailable`) rather than guessing. |
| `FILIGREE_API_URL` | Filigree issue-tracker API — closure-gate and issue context. |
| `PLAINWEAVE_MCP_CMD` | Retired 1.5.0 legacy migration key. Do not set it as active configuration; `legis doctor --fix` removes it from safe Legis environment tables. |

### Plainweave MCP runtime autodiscovery and legacy migration

Legis MCP uses runtime autodiscovery once at startup from the active project
cwd. It calls the hardened local Plainweave discovery boundary with the
existing project signals; it does not create or read a new binding manifest.
It accepts either a valid root-pinned local Plainweave MCP entry by itself, or
`.plainweave/plainweave.db` plus a trusted non-project-local `plainweave-mcp` on
`PATH`.

The local entry must resolve to an executable and contain exactly one `--root`
that resolves to the active project root. It establishes applicability and
supplies the executable without requiring the database signal. The `PATH`
executable is only a fallback when the direct database file establishes an
initialized project; it does not initialize or wire a project by itself.

This integration has a POSIX-only safety boundary. Runtime discovery, binding
inspection/removal, and the shared configuration-writer lock require
directory-relative file descriptors, `O_DIRECTORY`, `O_NOFOLLOW`, `fchmod`,
anchored replacement, and advisory `flock`. On hosts without those primitives,
doctor reports a non-repairable platform error and leaves configuration
unchanged; `legis install --mcp` cannot safely update `.mcp.json`. Windows is
not currently supported.

An initialized project without a valid local Plainweave entry needs the trusted
fallback on `PATH`. Check it before running doctor:

```bash
command -v plainweave-mcp
# Expected: an absolute path, such as /home/alice/.local/bin/plainweave-mcp
```

A valid local project entry can supply its own executable instead. If doctor
reports that no trusted Plainweave executable is available, repair the
Plainweave installation or local entry using that product's operator procedure,
then rerun `command -v plainweave-mcp` when using the fallback path and rerun
`legis doctor`. Do not use `legis doctor --fix` to initialize Plainweave; doctor
only diagnoses runtime discovery and removes retired Legis keys.

Global Codex Legis configuration must remain tool-only and project-agnostic. It
must not carry a Plainweave command or root, and it must not pin a fixed `cwd`.
The legacy `PLAINWEAVE_MCP_CMD` key is retired runtime configuration retained
only as a migration name that doctor can find and remove.

Plainweave discovery treats `.mcp.json` as untrusted input. It reads at most
1 MiB and accepts no more than 100 nested JSON objects/arrays. Invalid input is
never used; when no independently resolved safe fallback applies, doctor
reports a generic configuration error without echoing hostile values.

Legis install and doctor readers apply the same 1 MiB accepted-size limit to
the project `.mcp.json` before currentness, repair-blocker, or cross-server
binding checks. They may read one additional sentinel byte to detect overflow;
special files and oversized input are rejected with the target `.mcp.json`
unchanged. Ordinary install may create the persistent `.mcp.json.legis.lock`
sidecar described below before it refuses the target.

| Check ID | Target | Scope |
|---|---|---|
| `install.plainweave_project_binding` | Active project discovery plus `.mcp.json` → `mcpServers.legis.env` | Verifies runtime discovery and absence of the retired legacy `PLAINWEAVE_MCP_CMD` key. If the Legis registration is missing or stale, `install.mcp_json` owns its repair. |
| `install.plainweave_codex_binding` | Existing `$CODEX_HOME/config.toml` (or `~/.codex/config.toml`) Legis entry | Independently verifies that an existing global registration has no retired legacy key and no fixed `cwd`. No registration is healthy and not applicable; doctor never creates one. |

Binding inspection and its final pre-write snapshot recheck accept at most
1 MiB from either `.mcp.json` or the existing Codex `config.toml`. To distinguish
an exact-limit file from an oversized one, Legis reads at most one additional
sentinel byte. An oversized file is reported as operator-owned invalid input and
is left unchanged; doctor does not truncate or partially parse it.

The checks are independent. A project binding can need repair while the global
Codex binding is current, absent, or operator-owned, and vice versa.

Run the health check before changing configuration:

```bash
legis doctor
```

Doctor prints `[auto-fixable]` for a safely removable retired key. A missing or
stale project Legis registration is also `[auto-fixable]`, but
`install.mcp_json` owns that repair. Apply and post-verify safe repairs with:

```bash
legis doctor --fix
```

Within that run, `install.mcp_json` runs before the Plainweave binding checks. It
may create or rebuild a missing or stale project Legis registration, including
its `command`, `args`, `type`, and safe `env`, before the project binding check
runs. The project binding-specific repair semantically changes only the retired
legacy `PLAINWEAVE_MCP_CMD` key, but it reserializes the whole
`.mcp.json` document with two-space indentation. Unrelated JSON values, the
detected newline sequence, final-newline presence, and file mode are preserved;
arbitrary indentation and other whitespace formatting are normalized. The
global Codex TOML removal is text-surgical and preserves its surrounding
comments and formatting. Project repair refuses unsafe or secret-bearing
`.mcp.json` environment tables and leaves the file unchanged. Global
remove-only repair accepts string-valued environment entries and preserves
every unrelated entry, including secret-shaped names. It refuses malformed,
unsupported, or mixed-transport shapes and leaves them `[operator]`.

Legis serializes its own `.mcp.json` writers through the persistent
`/.mcp.json.legis.lock` sidecar (created with mode `0600` and ignored by the
managed project `.gitignore`). The same lock covers ordinary MCP registration
and the Plainweave binding replacement, so a waiting Legis writer rechecks the
validated file snapshot after the preceding writer completes. Before reporting
a replacement successful, Legis synchronizes the staged file, performs the
atomic rename, and synchronizes the containing directory entry. A synchronization
failure is reported rather than treated as durable success. The lock is advisory:
editors and other processes that do not participate in it can still write during
the final atomic-replace syscall window. Stop those writers while running an
automatic repair when that distinction matters.

An existing global Codex repair uses the same protocol with a persistent
`config.toml.legis.lock` beside `$CODEX_HOME/config.toml`.

Each successful removal prints its own `[fixed]` line. When project registration
and legacy cleanup both needed repair, inspect `[fixed]` on both
`install.mcp_json` and `install.plainweave_project_binding`; also inspect
`install.plainweave_codex_binding` for an existing global registration. A fixed
global `cwd` is always operator-owned: doctor reports it but never removes it.
If a global entry contains both the retired key and fixed `cwd`, `--fix` removes
the safe legacy key but leaves the check in a partial `[fixed] [operator]` state.

Use this migration sequence:

1. Run `legis doctor` and read both Plainweave check lines.
2. Run `legis doctor --fix` to remove safe retired keys.
3. If doctor reports a fixed global `cwd`, remove that field manually from the
   global Codex Legis registration.
4. Reconnect or restart the affected MCP clients so each new Legis process
   inherits its active project cwd.
5. Rerun `legis doctor` and confirm both checks are healthy.

Legis MCP then performs runtime autodiscovery once during startup. Doctor does
not restart clients, initialize Plainweave, remove fixed `cwd`, or repair
malformed/unsafe project configuration or malformed/unsupported global shapes.

For machine-readable inspection, run `legis doctor --format json`. The MCP
`doctor_get` tool returns the same report shape, but it is report-only and never
fixes configuration. See the [`doctor` CLI reference](cli-reference.md#doctor)
for the command workflow and success criteria.

### API server authentication (`legis serve` only)

These apply only when running the HTTP server. The MCP/stdio surface is
launch-bound (`--agent-id`) and takes no actor argument.

| Variable | Role |
|---|---|
| `LEGIS_API_SECRET` | Bearer token required on write routes. |
| `LEGIS_API_SECRET_SCOPE` | Pipe-separated scope for `LEGIS_API_SECRET` (default `writer`). |
| `LEGIS_API_TOKEN_ACTORS` | Maps bearer tokens to actor identities (per-token attribution). |
| `LEGIS_API_ACTOR` | Default actor recorded for an authenticated write. |

### Tuning

| Variable | Default | Role |
|---|---|---|
| `LEGIS_SOURCE_ROOT` | cwd | The repository root legis reads git/source state and `policy/cells.toml` from. |
| `LEGIS_MCP_MAX_REQUEST_BYTES` | built-in cap | Per-line stdin byte cap for the MCP server (bounds a pathological client). |

## Dev-only flags and escape hatches

> **These are not ordinary knobs.** Each one relaxes a fail-closed default or a
> custody guarantee. In production they are footguns; legis is a governance-
> *honesty* tool, so it names them plainly rather than burying them. Several
> mirror a residual documented in the README's *Known security limitations*.

| Variable | What it relaxes | Use only when |
|---|---|---|
| `LEGIS_DEV_DEFAULT_CELLS=1` | Flips the no-config default from fail-closed `structured` to relaxed `chill` (unmatched policies self-clear). | Local dev on a project with no `cells.toml` yet. |
| `LEGIS_UNSAFE_DEV_AUTH=1` | Disables required authentication on the `serve` write surface. | Local development only — never a shared/remote server. |
| `LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING=1` | Lets a `scan_route` *call* specify its own cell/severity_map/fail_on instead of the server owning routing. | A trusted single-caller dev setup; server-owned routing is the safe default. |
| `LEGIS_ALLOW_INSECURE_REMOTE_HTTP=1` | Permits plaintext HTTP to a remote Loomweave/Filigree, **voiding the SEI/binding TLS custody seal** (responses are unsigned; an on-path attacker could forge a binding). Logs a warning. | Loopback / dev only. |
| `LEGIS_ALLOW_UNSCOPED_API_TOKENS=1` | Permits API tokens without a project scope. | Dev only; grants unscoped tokens operator-level authority. |
| `LEGIS_ALLOW_MISSING_GOVERNANCE_DB=1` | Lets the override-rate CI gate pass when the governance DB is absent under `CI=true` (otherwise a hard fail). | A first run before any trail exists. |
| `LEGIS_WARDLINE_ALLOW_DIRTY=1` | Governs an *unsigned* dirty-tree Wardline artifact instead of skipping it; recorded as `dirty`, never `verified`. | Dev iteration before committing; signing is clean-tree-only by design. |

## Checking your configuration

`legis doctor` reports the install + config layer and tags each problem
`[auto-fixable]` (doctor can repair with `--fix`) or `[operator]` (needs
out-of-band config + a relaunch — e.g. an unwired governance cell or routing).
It reports; it never auto-enables a cell or touches a signing key.

```bash
legis doctor                 # health view
legis doctor --fix           # apply safe repairs to the install layer
legis doctor --format json   # machine-readable (each check carries a `repairable` bit)
```

See **[reading-legis-output.md](reading-legis-output.md)** for what the verdicts,
outcomes, and statuses you then see actually mean.
