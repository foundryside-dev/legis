# `legis` CLI reference

The complete `legis` command-line surface, one section per subcommand:
purpose, key flags, and exit codes. Verified against `src/legis/cli.py` and
`legis --help` at `1.0.0`.

This is the *invocation* reference. For what each flag *buys you* as an
operator — what enabling a cell costs, what the signing key is for — read
[`configuration.md`](configuration.md); for the agent-call surface (MCP tools,
error codes), read the `legis-workflow` skill. This guide does not re-derive
either.

## Conventions

- `legis --version` prints `legis 1.0.0` and exits `0`.
- `legis --help` (or `-h`) prints usage and exits `0`.
- Running `legis` with **no subcommand** prints help to stderr and exits `2`.
- Most flags that name a store URL or a URL endpoint fall back to an
  environment variable when omitted — the per-flag notes below name it. Env-var
  semantics are documented in [`configuration.md`](configuration.md).

The nine subcommands:

| subcommand | one-line purpose |
|---|---|
| [`serve`](#serve) | run the HTTP API server |
| [`mcp`](#mcp) | run the MCP-over-stdio server (launch-bound agent identity) |
| [`check-override-rate`](#check-override-rate) | CI gate: fail if the override-rate gate is `FAIL` |
| [`governance-gate`](#governance-gate) | CI gate runner (currently the override-rate gate) |
| [`sei-backfill`](#sei-backfill) | resolve legacy locator-keyed records to SEIs via Loomweave |
| [`policy-boundary-check`](#policy-boundary-check) | CI gate: fail when `@policy_boundary` metadata lacks current evidence |
| [`install`](#install) | inject instructions, install the skill, register the hook/MCP entry |
| [`session-context`](#session-context) | SessionStart hook: print a posture banner + refresh drift |
| [`doctor`](#doctor) | view and repair install/config health |

---

## `serve`

Run the Legis HTTP API server (uvicorn, the `legis.api.app:create_app`
factory).

**Key flags**

| flag | default | purpose |
|---|---|---|
| `--host` | `127.0.0.1` | bind host |
| `--port` | `8000` | bind port |
| `--governance-db` | env `LEGIS_GOVERNANCE_DB` | governance store URL |
| `--check-db` | env `LEGIS_CHECK_DB` | check store URL |
| `--protected-policies` | env `LEGIS_PROTECTED_POLICIES` | comma-separated protected-policy list |
| `--loomweave-url` | env `LOOMWEAVE_API_URL` | Loomweave identity API URL |
| `--filigree-url` | env `FILIGREE_API_URL` | Filigree issue-tracker API URL |
| `--binding-db` | env `LEGIS_BINDING_DB` | sign-off-binding ledger URL |
| `--judge-provider` | — | LLM judge provider (`openrouter`). Omit to keep protected cells fail-closed. |
| `--judge-model` | env `LEGIS_JUDGE_MODEL` | LLM judge model id |
| `--judge-max-tokens` | env `LEGIS_JUDGE_MAX_TOKENS` | max judge response tokens |

Each flag, when given, is exported into the corresponding env var before the
server boots, so a flag wins over a pre-set env var.

**Exit codes** — returns `0` after `uvicorn.run` returns (i.e. on normal
shutdown). A long-running server, so in practice it runs until interrupted.

---

## `mcp`

Run the Legis MCP stdio server: one JSON-RPC object per line on stdin, one
response per line on stdout. On boot it also makes a best-effort refresh of any
drifted legis instruction block / skill pack in the cwd (never blocks or breaks
startup).

**Key flags**

| flag | default | purpose |
|---|---|---|
| `--agent-id` | **required** | the launch-bound agent identity stamped on every write. No tool argument can supply or override the actor — it is fixed here, at launch. |
| `--governance-db` | env `LEGIS_GOVERNANCE_DB` | governance store URL |
| `--check-db` | env `LEGIS_CHECK_DB` | check store URL |
| `--policy-cells` | env `LEGIS_POLICY_CELLS` | policy-cell registry TOML path |
| `--protected-policies` | env `LEGIS_PROTECTED_POLICIES` | comma-separated protected-policy list |
| `--loomweave-url` | env `LOOMWEAVE_API_URL` | Loomweave identity API URL |
| `--judge-provider` / `--judge-model` / `--judge-max-tokens` | see [`serve`](#serve) | LLM judge configuration |

**Exit codes** — returns whatever the MCP server loop returns (`mcp_main`);
`0` on clean shutdown.

---

## `check-override-rate`

CI gate. Read the governance trail and fail (exit `1`) if the operator
force-past override-rate gate is `FAIL`. The detect → require-key → verify →
score decision lives in the service layer, so the CLI, the API, and any future
consumer all measure the gate identically; the CLI keeps only its I/O shell and
exit-code mapping.

**Key flags**

| flag | default | purpose |
|---|---|---|
| `--db` | the server's governance store (`governance_db_url()`) | governance store URL to read |

**Exit codes**

| code | meaning |
|---|---|
| `0` | gate is `PASS`, `PASS_WITH_NOTICE`, or (non-CI) the governance DB is simply missing |
| `1` | gate is `FAIL`; or hash-chain integrity check failed; or a protected key was required and absent / an audit-integrity error; or, under `CI=true` (without `LEGIS_ALLOW_MISSING_GOVERNANCE_DB=1`), the governance DB is missing |

A missing SQLite governance DB is treated as `PASS_WITH_NOTICE` (exit `0`)
outside CI, but as `FAIL` (exit `1`) under `CI=true` unless
`LEGIS_ALLOW_MISSING_GOVERNANCE_DB=1` is set — a missing audit store must not
silently pass a real CI run.

---

## `governance-gate`

Run the governance CI gates. **Currently identical to**
[`check-override-rate`](#check-override-rate): it runs the same override-rate
gate with the same `--db` flag and the same exit-code mapping. The separate
name is the stable entry point for the gate suite as more gates are added.

**Key flags** — `--db` (same default and meaning as `check-override-rate`).

**Exit codes** — same as [`check-override-rate`](#check-override-rate).

---

## `sei-backfill`

Resolve legacy locator-keyed governance records to stable SEIs by batch-
resolving them through Loomweave. Prints a JSON report. Defaults to a **dry
run** — pass `--execute` to actually append the backfill events.

**Key flags**

| flag | default | purpose |
|---|---|---|
| `--db` | env `LEGIS_GOVERNANCE_DB` (`governance_db_url()`) | governance store URL |
| `--loomweave-url` | **required** | Loomweave identity API URL used for batch resolve |
| `--execute` | off (dry run) | append the backfill events; omit for a report-only dry run |
| `--actor` | `legis-sei-backfill` | actor stamped on the appended backfill events |

**Exit codes** — returns `0` after printing the JSON report (both for the dry
run and after an `--execute` append).

---

## `policy-boundary-check`

CI gate for the policy-authoring loop. Scan a Python source root and fail
(exit `1`) when any `@policy_boundary` declaration lacks current behavioural
evidence (its `test_ref`).

**Key flags**

| flag | default | purpose |
|---|---|---|
| `--root` | `src` | Python source root to scan |
| `--repo-root` | `.` | repo root used to resolve a finding's `test_ref` |
| `--format` | `text` | `text` (human-readable) or `json` (machine-readable) |

**Exit codes**

| code | meaning |
|---|---|
| `0` | no findings — prints `policy-boundary-check: PASS` (text) or `[]` (json) |
| `1` | one or more findings — prints each `file:line: rule_id: qualname: reason` (text) or a JSON array |

---

## `install`

Inject the legis instruction block, install the `legis-workflow` skill pack,
and register the SessionStart hook + MCP entry in the **current working
directory's** project. With no selector flag, installs **all** steps; any
selector flag installs only the named steps. Each step prints `[OK]` or
`[FAIL]`; a failing step does not abort the rest.

**Key flags**

| flag | purpose |
|---|---|
| `--claude-md` | inject instructions into `CLAUDE.md` only |
| `--agents-md` | inject instructions into `AGENTS.md` only |
| `--skills` | install the Claude Code skill pack only |
| `--codex-skills` | install the Codex skill pack only |
| `--hooks` | register the Claude Code SessionStart hook only |
| `--gitignore` | add legis config rules to `.gitignore` only |
| `--mcp` | register the legis MCP server in `.mcp.json` only |
| `--agent-id` | agent id stamped in the `.mcp.json` legis entry (default: `claude-code`, or preserve an existing entry's id) |

**Exit codes**

| code | meaning |
|---|---|
| `0` | every selected step succeeded |
| `1` | one or more steps reported `[FAIL]` (or raised) |

---

## `session-context`

The SessionStart hook entry point. Print a posture banner, then refresh any
drifted legis instructions / skills in the cwd. Output is always non-empty (a
banner at minimum). Takes no flags.

**Exit codes** — returns `0`.

---

## `doctor`

View and repair legis install / config health. Read-only by default; with
`--fix` it applies safe repairs and re-checks. (The MCP `doctor_get` tool is
the read-only counterpart — it never repairs; fixes stay on this CLI.)

**Key flags**

| flag | default | purpose |
|---|---|---|
| `--root` | `.` | project root to inspect |
| `--fix` / `--repair` | off | apply safe repairs, then re-check |
| `--format` | `text` | `text` (human) or `json` (machine-readable) |

**Exit codes**

| code | meaning |
|---|---|
| `0` | every check is `ok` or `warn` after any repairs (a `warn` does not fail) |
| `1` | at least one check remains `error`-status |

The `text` / `json` payload carries an `ok` boolean and a per-check `status`
(`ok` / `warn` / `error`); the exit code is `0` only when no check is left at
`error`.
