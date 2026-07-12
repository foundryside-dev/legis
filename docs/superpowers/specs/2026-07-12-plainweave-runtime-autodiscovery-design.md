# Plainweave runtime autodiscovery for Legis

**Issue:** `legis-3622e80f2e`

**Status:** approved design

## Context

Legis 1.5.0 writes a project-specific Plainweave command into two Legis launch
registrations:

- project `.mcp.json` at
  `mcpServers.legis.env.PLAINWEAVE_MCP_CMD`; and
- global Codex `config.toml` at
  `mcp_servers.legis.env.PLAINWEAVE_MCP_CMD`.

The command is deliberately root-pinned, for example:

```text
/home/john/.local/bin/plainweave-mcp --root /home/john/esper-lite
```

The project registration is local and can represent that value. The Codex
registration cannot: `~/.codex/config.toml` has one shared `mcp_servers.legis`
entry for every project. Running `legis doctor --fix` in two initialized
Plainweave projects therefore rewrites the singleton value back and forth.
Whichever project ran doctor last is healthy; the other reports
`install.plainweave_codex_binding: error [auto-fixable]`.

Filigree already solves the same global-registration problem. Its Codex entry
contains only the globally installed tool and no project argument. At process
startup the tool discovers the active project from the inherited working
directory. Filigree doctor rejects a globally pinned `--project` argument, and
install rewrites old pinned registrations to the project-agnostic form.

Legis will adopt that model for its Plainweave advisory client.

## Decision

Plainweave binding is project-local and runtime-discovered. A global Legis MCP
registration may identify the Legis executable, but it must not carry a
Plainweave command, root, URL, fixed project working directory, or other
project identity.

Legis will not create a new binding manifest. The existing project-local
Plainweave signals form two alternative discovery paths. Discovery accepts
either a valid root-pinned local Plainweave MCP entry by itself, or
`.plainweave/plainweave.db` plus a trusted non-project-local `plainweave-mcp` on
`PATH`. The local entry establishes applicability and selects the executable in
one signal. When there is no local Plainweave entry and no local configuration
issue, the direct database file establishes initialized state and permits the
trusted `PATH` fallback. For an initialized project, a present malformed
`.mcp.json` or invalid local Plainweave entry fails closed and disables the
trusted `PATH` fallback. The database-plus-`PATH` fallback is considered only
when local config presents no Plainweave configuration issue.

The existing `discover_plainweave(root)` boundary already resolves those
signals into a canonical root-pinned command while enforcing bounded,
no-symlink reads, executable trust, exact-root matching, and fail-closed error
states. Legis MCP startup will call that boundary for its active project.

`PLAINWEAVE_MCP_CMD` is retired as runtime configuration. It remains a named
legacy key only so doctor can identify and remove 1.5.0-era bindings.

## Architecture

### Runtime composition

`build_runtime(agent_id)` will obtain the active Legis project using the
existing `legis.config.project_root()` contract, which is the process current
working directory. It will call `discover_plainweave(project_root())` once at
startup.

The result drives runtime wiring as follows:

| Discovery result | Runtime behavior |
| --- | --- |
| Not applicable | Leave `runtime.plainweave` unset without a warning. |
| Applicable with a command | Split the canonical command and construct `PlainweaveMcpClient` for the active project. |
| Applicable with an error | Log one actionable warning and leave the advisory client unset. |
| Invalid command after splitting | Log one actionable warning and leave the advisory client unset. |

The runtime will not read or fall back to `PLAINWEAVE_MCP_CMD`. A stale process
environment must not reintroduce global project binding after doctor repairs
the config files.

This changes only advisory enrichment. Plainweave remains unable to affect a
Legis governance verdict, and unavailable or malformed Plainweave state keeps
the existing honest-degrade behavior.

### Project doctor check

`install.plainweave_project_binding` will mean “the active project has a
runtime-discoverable Plainweave binding and the Legis project registration is
project-agnostic.”

For an applicable project it will:

1. run `discover_plainweave(root)`;
2. verify that the project Legis MCP registration is otherwise current;
3. inspect the Legis entry for the legacy `PLAINWEAVE_MCP_CMD` key; and
4. report healthy when discovery succeeds and the legacy key is absent.

Read-only doctor reports a present legacy key as an auto-fixable error. During
`--fix`, the check removes only that key, preserving all other safe environment
entries and project MCP registrations. It then repeats discovery and inspection
before returning `[fixed]`.

An uninitialized project remains not applicable. An initialized project with
no trusted Plainweave executable remains an operator error. Malformed or unsafe
project MCP configuration remains fail-closed, outranks any executable found on
`PATH`, and is never rewritten by this check.

### Global Codex doctor check

`install.plainweave_codex_binding` will mean “an existing global Codex Legis
registration is project-agnostic and therefore permits runtime discovery.”

The check will not compare global configuration with the active project's
discovered command. It will inspect only the global Legis entry:

- no global Legis registration: healthy and not applicable, preserving the
  current behavior;
- legacy `PLAINWEAVE_MCP_CMD` present: auto-fixable error;
- legacy key absent and no fixed `cwd`: healthy;
- fixed `cwd`: operator-owned error because it prevents the process from
  inheriting the active project's working directory; and
- malformed, mixed-transport, or unsupported configuration:
  operator-owned error, unchanged.

During `--fix`, Legis removes only `PLAINWEAVE_MCP_CMD`. It does not delete a
fixed `cwd` or rewrite the operator's global Legis invocation. Removing an
operator-authored `cwd` changes unrelated launch semantics and therefore
requires explicit operator action.

Project repair refuses unsafe or secret-bearing `.mcp.json` environment tables
and leaves the file unchanged. Global remove-only repair accepts string-valued
environment entries and preserves every unrelated entry, including
secret-shaped names. It refuses malformed, unsupported, or mixed-transport
global shapes.

The check is independent of whether the current project has initialized
Plainweave state. A stale global project binding is globally invalid and must
be reported even when doctor is run from an uninitialized project.

### Migration and compatibility

The 1.5.0 migration path is:

1. start with project and/or global Legis entries containing
   `PLAINWEAVE_MCP_CMD`;
2. read-only doctor reports each legacy location independently;
3. `legis doctor --fix` removes the project key and then the global key;
4. post-verification proves both registrations are project-agnostic; and
5. restarted MCP processes discover Plainweave from their active project.

The repair remains surgical, mode-preserving, race-aware, and idempotent. It
must preserve comments and unrelated TOML semantics in global Codex config,
and preserve unrelated JSON values and safe Legis environment variables in
project config.

The old inspection and repair machinery for setting a desired binding will be
reduced or replaced with remove-only legacy-key operations. Security hardening
for bounded reads, no-follow opens, snapshot rechecks, anchored replacement,
and unrelated-mutation comparison remains in force.

## Security and failure behavior

- Global configuration never supplies project identity to Plainweave.
- Runtime discovery reads only the active project's existing local signals.
- Discovery accepts only recognized `plainweave-mcp` executables or the
  supported Python module launcher, outside the project tree.
- The discovered command must contain exactly one root option matching the
  active project.
- Missing or malformed local state disables advisory enrichment rather than
  changing governance behavior or crashing MCP startup.
- Doctor never executes a discovered Plainweave command.
- Doctor never repairs malformed/unsafe project configuration or
  malformed/unsupported global shapes. Secret-shaped string values in unrelated
  global environment entries are preserved rather than classified as unsafe.
- A fixed global Codex `cwd` is surfaced, not silently removed.
- The existing Plainweave advisory-boundary byte-identity invariant remains a
  blocking regression gate.

## Project-root scope

This fix uses Legis's existing project-root definition: the MCP process current
working directory. It does not add Filigree-style ancestor walking or change
where Legis stores resolve. Codex and project MCP launchers are expected to
start Legis in the active project root, matching current Legis behavior.

Adding nested-directory project discovery would affect every Legis store and
composition root and is outside this bug.

## Testing

Tests will prove:

1. two initialized projects sharing one global Codex config both remain healthy
   after repair, regardless of doctor order;
2. no project-specific Plainweave root is written to global configuration;
3. project and global legacy keys are removed independently and idempotently;
4. unrelated project JSON, global TOML, comments, newlines, modes, and safe
   environment values survive repair;
5. fixed global `cwd` is an operator error and is never auto-removed;
6. runtime startup discovers each project's distinct Plainweave command from
   that process's cwd;
7. runtime ignores a stale `PLAINWEAVE_MCP_CMD` environment value;
8. absent, uninitialized, malformed, unavailable, and unsafe Plainweave states
   degrade honestly without affecting governance;
9. project-local executable and mismatched-root defenses remain enforced; and
10. the Plainweave advisory boundary and full repository suite remain green.

## Documentation

README, changelog, configuration guidance, CLI reference, and output guidance
will describe runtime autodiscovery and the 1.5.0 legacy-key migration. They
will no longer instruct users to place a project-rooted Plainweave command in a
Legis environment table.

## Non-goals

- Creating `.weft/legis/plainweave-binding.json` or any other new manifest.
- Changing Plainweave's own MCP installation format.
- Changing Legis project-root or store-resolution semantics.
- Adding ancestor walk-up from nested directories.
- Repairing or creating a missing global Codex Legis registration.
- Making Plainweave advisory facts authoritative for governance.
- Refactoring unrelated project or Codex configuration writers.
