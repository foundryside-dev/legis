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
| `PLAINWEAVE_MCP_CMD` | Project-scoped Plainweave MCP command. A Legis MCP process reads it when it builds its runtime; without it, Plainweave advisory context is unavailable. |

### Plainweave MCP launch binding

This integration has a POSIX-only safety boundary. Discovery, binding
inspection/repair, and the shared configuration-writer lock require
directory-relative file descriptors, `O_DIRECTORY`, `O_NOFOLLOW`, `fchmod`,
anchored replacement, and advisory `flock`. On hosts without those primitives,
doctor reports a non-repairable platform error and leaves configuration
unchanged; `legis install --mcp` cannot safely update `.mcp.json`. Windows is
not currently supported.

Plainweave integration applies to the current project when either of these is
true:

- `.plainweave` is a direct directory, not a symlink, and
  `.plainweave/plainweave.db` is a direct regular file, not a symlink; or
- the project `.mcp.json` contains a valid, root-pinned
  `mcpServers.plainweave` stdio entry. Its command must resolve to an executable,
  and its arguments must contain exactly one `--root` that resolves to the
  current project root.

A globally installed `plainweave-mcp` executable alone does not wire an
uninitialized project. In that state, doctor reports both binding checks as
healthy and not applicable. It also treats a project with no Plainweave
configuration as a healthy, non-applicable state.

An applicable database-only project needs `plainweave-mcp` on `PATH`. Check it
before running doctor:

```bash
command -v plainweave-mcp
# Expected: an absolute path, such as /home/alice/.local/bin/plainweave-mcp
```

A valid root-pinned project entry can supply its own executable instead. If
doctor reports `Plainweave project has no executable available`, either install
or reinstall the Plainweave MCP entry point with the package method used on your
host so `plainweave-mcp` resolves, or repair the project registration:

```bash
plainweave install --root . --target project
```

Then rerun `command -v plainweave-mcp` when using the database-only path and
rerun `legis doctor`. Do not use `legis doctor --fix` to initialize Plainweave;
doctor only diagnoses and repairs Legis launch wiring.

When Plainweave applies, Legis needs the resolved project command in the Legis
MCP registration's `PLAINWEAVE_MCP_CMD` value:

Plainweave discovery treats `.mcp.json` as untrusted input. It reads at most
1 MiB and accepts no more than 100 nested JSON objects/arrays. Invalid input is
never used; when no independently resolved safe fallback applies, doctor
reports a generic configuration error without echoing hostile values.

| Check ID | Target | Scope |
|---|---|---|
| `install.plainweave_project_binding` | `.mcp.json` → `mcpServers.legis.env.PLAINWEAVE_MCP_CMD` | Checks the current project's Legis registration. If that registration is missing or stale, `install.mcp_json` owns its repair. |
| `install.plainweave_codex_binding` | `$CODEX_HOME/config.toml` (or `~/.codex/config.toml`) → `mcp_servers.legis.env.PLAINWEAVE_MCP_CMD` | Checks only an existing global Codex Legis registration. Doctor never creates one. |

The checks are independent. A project binding can need repair while the global
Codex binding is current, absent, or operator-owned, and vice versa.

Run the health check before changing configuration:

```bash
legis doctor
```

Doctor prints `[auto-fixable]` for a safe missing or stale target. A missing or
stale project Legis registration is also `[auto-fixable]`, but
`install.mcp_json` owns that repair. Apply and post-verify safe repairs with:

```bash
legis doctor --fix
```

Within that run, `install.mcp_json` runs before the Plainweave binding checks. It
may create or rebuild a missing or stale project Legis registration, including
its `command`, `args`, `type`, and safe `env`, before the project binding check
adds the target. The binding-specific repair then changes only the nested
`PLAINWEAVE_MCP_CMD` value and preserves the surrounding safe configuration.

Legis serializes its own `.mcp.json` writers through the persistent
`/.mcp.json.legis.lock` sidecar (created with mode `0600` and ignored by the
managed project `.gitignore`). The same lock covers ordinary MCP registration
and the Plainweave binding replacement, so a waiting Legis writer rechecks the
validated file snapshot after the preceding writer completes. The lock is
advisory: editors and other processes that do not participate in it can still
write during the final atomic-replace syscall window. Stop those writers while
running an automatic repair when that distinction matters.

An existing global Codex repair uses the same protocol with a persistent
`config.toml.legis.lock` beside `$CODEX_HOME/config.toml`.

Each successful repair prints its own `[fixed]` line. When project registration
and binding both needed repair, inspect `[fixed]` on both `install.mcp_json` and
`install.plainweave_project_binding`; also inspect
`install.plainweave_codex_binding` when an existing global Codex registration
needed repair. Doctor leaves secret-bearing, unsafe, or malformed project
configuration unchanged and tags it `[operator]`; it does the same for malformed
or unsupported Codex TOML.

Legis MCP processes build their runtime once and read `PLAINWEAVE_MCP_CMD` at
startup. Reconnect or restart the affected MCP client after a repair so it
launches a new Legis process with the corrected binding. Doctor does not restart
clients or initialize Plainweave.

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
