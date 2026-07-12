# Plainweave binding repair in `legis doctor`

> **Superseded:** The project-rooted environment-binding design in this document was replaced by the [2026-07-12 Plainweave runtime autodiscovery design](2026-07-12-plainweave-runtime-autodiscovery-design.md). It remains as the historical 1.5.0 implementation record.

Date: 2026-07-11

Status: superseded

## Problem

Legis exposes `plainweave_preflight_get`, but its MCP runtime constructs the
Plainweave client only when `PLAINWEAVE_MCP_CMD` is present at process startup.
The current project and Codex Legis registrations can be otherwise healthy while
omitting that environment value. In that state Legis honestly returns
`plainweave client not configured`, even when Plainweave is installed and the
project's Plainweave store is healthy.

`legis doctor` currently validates the project Legis MCP entry but does not
validate this nested sibling binding, and it does not inspect an existing global
Codex Legis registration. The missing binding is safe to repair automatically
when the target project is initialized for Plainweave and a trustworthy
Plainweave MCP invocation can be resolved.

## Scope and invariants

The change adds two independent doctor checks:

- `install.plainweave_project_binding` checks the Legis entry in
  `<root>/.mcp.json`.
- `install.plainweave_codex_binding` checks an existing Legis entry in the
  active Codex configuration.

Both checks are report-only through `doctor_get`. Only the operator CLI path,
`legis doctor --fix`, may repair them.

The following invariants are load-bearing:

1. An uninitialized project is not wired merely because Plainweave is installed
   globally.
2. Project repair semantically changes only `PLAINWEAVE_MCP_CMD` in the target
   Legis entry, while reserializing the whole JSON document with two-space
   indentation.
3. Project repair preserves all other commands, arguments, agent IDs,
   environment values, sibling servers, the detected newline sequence,
   final-newline presence, and file mode, but not arbitrary JSON whitespace.
   Global Codex TOML repair additionally preserves comments and formatting.
4. A missing global Codex Legis registration is not created by this feature.
5. Ambiguous, malformed, symlinked, or unsupported configuration fails closed
   without being rewritten.
6. The stored command is root-pinned so nested Plainweave does not depend on an
   MCP host's inherited working directory.
7. A repaired binding takes effect only after the Legis MCP process reconnects;
   doctor must say so.

## Applicability and discovery

Plainweave is applicable to the target project when either:

- `<root>/.plainweave/plainweave.db` is a regular file; or
- `<root>/.mcp.json` contains a valid `mcpServers.plainweave` stdio entry rooted
  at the target project.

An installed `plainweave-mcp` executable without either project signal is
reported as "installed, project not initialized" and does not recruit either
binding.

The desired Plainweave invocation is resolved in this order:

1. A valid project `mcpServers.plainweave` entry. Its `command` and `args` are
   preserved after validating that the command is executable and any `--root`
   value identifies the doctor target.
2. An executable `plainweave-mcp` found on `PATH`, with
   `--root <resolved-doctor-root>` appended explicitly.

The argv vector is serialized with `shlex.join` into the single string expected
by `PLAINWEAVE_MCP_CMD`. Arbitrary files under `.weft/` are not consulted;
Plainweave 1.2.1's project state is `.plainweave/plainweave.db`, and no current
`.weft/plainweave` configuration contract exists.

If project evidence exists but no safe executable can be resolved, both
applicable checks report an operator error and make no changes.

## Project registration check and repair

The project check reads `<root>/.mcp.json` and examines
`mcpServers.legis.env.PLAINWEAVE_MCP_CMD`.

- Correct value: `ok`, not fixed.
- Missing or stale value with a resolved desired invocation: `error`,
  `repairable=true`.
- Missing or malformed Legis entry: the existing `install.mcp_json` check owns
  registration repair. During `--fix`, it runs first; the Plainweave binding
  check then updates the repaired entry in the same pass.
- Malformed JSON, unsafe environment shape, symlink, or unsafe path: error,
  unchanged.

Repair performs a nested JSON update and an atomic, mode-preserving write. It
semantically changes only the target value and retains every unrelated field
and sibling entry. The whole document is reserialized with two-space
indentation while preserving the detected newline sequence, final-newline
presence, and file mode; arbitrary JSON whitespace is intentionally normalized.

## Global Codex registration check and repair

The active configuration path is `$CODEX_HOME/config.toml` when `CODEX_HOME` is
set, otherwise `~/.codex/config.toml`.

The global check examines
`mcp_servers.legis.env.PLAINWEAVE_MCP_CMD` only when an existing
`mcp_servers.legis` table identifies a Legis MCP invocation.

- No global Legis registration: `ok` with a not-configured message; no repair.
- Correct value: `ok`, not fixed.
- Missing or stale value with a resolved desired invocation: `error`,
  `repairable=true`.
- Malformed TOML, symlink, non-table Legis entry, or a representation the
  surgical editor cannot prove safe: operator error, unchanged.

The implementation uses a stdlib-only, assignment-level TOML editor rather than
`codex mcp add`. An isolated probe demonstrated that re-adding a server replaces
the whole registration and drops unrelated environment values. The editor
recognizes explicit parent and child table forms, parses the full document with
`tomllib` before and after mutation, and refuses inline or dotted shapes it
cannot update without ambiguity. Writes are atomic and preserve file mode,
comments, sibling tables, and newline style.

## Doctor output and ordering

The new checks run after `install.mcp_json`, allowing a single `--fix` pass to
repair the project Legis entry and then add its Plainweave binding. They use
separate IDs so a healthy project binding cannot hide a broken global binding,
or vice versa.

Pending repairs are tagged `[auto-fixable]`. Successful repairs return
`status="ok"`, `fixed=true`, and a message stating that MCP clients must restart
or reconnect. Operator-owned failures remain `[operator]`. As with all doctor
checks, warnings remain nonfatal and errors make the CLI exit nonzero.

## Test strategy

Implementation follows red-green TDD. Tests cover:

- initialized project plus missing project binding;
- initialized project plus missing global binding;
- one `--fix` pass repairs both existing registrations;
- a missing global Legis registration is not created;
- installed Plainweave without project initialization remains unwired and
  healthy;
- project MCP invocation takes precedence and retains an explicit matching
  `--root`;
- PATH fallback adds an explicit resolved `--root`;
- existing correct bindings are idempotent and byte-identical on a second fix;
- stale values are replaced without changing unrelated fields, environment
  values, sibling servers, the detected newline sequence, final-newline
  presence, or file mode; project JSON uses two-space indentation while Codex
  TOML preserves comments and formatting;
- malformed JSON/TOML, symlinks, unsafe environment values, inline unsupported
  TOML, dead executables, and mismatched roots remain unchanged and fail closed;
- `collect_checks`, text/JSON rendering, exit status, and `doctor_get` expose the
  new checks while MCP remains report-only.

Focused tests are followed by the repository's formatting, lint, type, complete
test, coverage-floor, SEI-oracle, and policy-boundary gates required by current
project conventions.

## Documentation

Update the README doctor summary, configuration guide, CLI reference, output
interpretation guide, and changelog. Documentation must distinguish:

- Plainweave installed globally;
- Plainweave initialized for the current project;
- Legis bound to Plainweave on each launch surface; and
- a repaired registration awaiting MCP reconnection.

## Out of scope

- Initializing a Plainweave project or creating its database.
- Creating a missing global Codex Legis registration.
- Repairing Plainweave's own MCP registrations.
- Editing `weft.toml` or inventing a `.weft/plainweave` schema.
- Starting or restarting MCP processes automatically.
- Changing the advisory-only governance boundary of Plainweave preflight facts.
