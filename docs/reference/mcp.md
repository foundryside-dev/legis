# Legis MCP tool reference

The complete Legis MCP tool surface: every tool the `legis mcp` server
advertises, with its purpose and key arguments. Verified against
`tool_definitions()` in `src/legis/mcp.py` at `1.0.0` — **21 tools**.

All tools are reached over MCP-over-stdio (`legis mcp --agent-id <id>`). Two
properties hold across the whole surface and are not repeated per tool:

- **The actor is launch-bound.** No tool argument supplies or overrides the
  acting identity. Every write is attributed to the `--agent-id` fixed at
  server launch; a read filter named `submitted_by` (on `override_list`) filters
  by a *recorded* actor and is not the caller's own identity.
- **Errors share one envelope.** A failed call returns `isError:true` with a
  `structuredContent` of `{error_code, message, recoverable, next_action}`, and
  a text mirror `"{code}: {message}\nnext_action: …"`. Codes seen on this
  surface include `INVALID_ARGUMENT`, `CELL_NOT_ENABLED`, `NO_SUCH_REQUEST`,
  `NOT_FOUND`, `SIGNOFF_NOT_CLEARED`, `BINDING_UNAVAILABLE`,
  `FILIGREE_UNAVAILABLE`, `INVALID_CELL_SPEC`, `WARDLINE_DIRTY_TREE`,
  `GIT_ERROR`, `AUDIT_INTEGRITY_FAILURE`, `SERVICE_ERROR`, `UNKNOWN_TOOL`, and
  `INTERNAL_ERROR`. Switch on `error_code`, not message text. (Full recovery
  guidance: the `legis-workflow` skill.)

This is the *tool catalogue*. For the cell model behind these calls (chill /
coached / structured / protected, what self-clears vs escalates) read the
[`README.md`](../../README.md) and [`guide/configuration.md`](../guide/configuration.md);
for the CLI that hosts this server, [`guide/cli-reference.md`](../guide/cli-reference.md).

## Policy & override (governance writes and reads)

| tool | purpose | key args |
|---|---|---|
| `policy_explain` | explain which governance cell controls a policy/entity pair, whether that cell is enabled here, and which move the agent may make next. `policy_known:false` means no routing rule matched the name (possibly hallucinated; routed to `default_cell`). | `policy`, `entity` (both required) |
| `policy_list` | list the policy-to-cell routing table (`default_cell` + pattern rules) and each cell's real enabled state on this server. The complex tier reports `enabled:false` without `LEGIS_HMAC_KEY`. | none |
| `policy_evaluate` | evaluate a policy against a target **without** recording an override. | `policy`, `target` (object) — both required |
| `override_submit` | submit an override as the launch-bound agent. The server routes to the governing cell and returns a discriminated outcome envelope (`ACCEPTED_SELF` / `ACCEPTED_BY_JUDGE` / `BLOCKED` / `ESCALATED_PENDING` / `NEED_INPUTS`). | `policy`, `entity`, `rationale` (required); `file_fingerprint`, `ast_path`, `idempotency_key` (optional) |
| `override_list` | read the verified governance trail (overrides, sign-off requests, governance events), each with its `seq` handle. A tampered trail is `AUDIT_INTEGRITY_FAILURE`, never silently read. | optional exact-match filters: `policy`, `entity`, `submitted_by` (the recorded `agent_id`) |
| `override_rate_get` | read the fixed operator force-past override-rate gate (status / rate / sample size). | none |

## Sign-off & Filigree closure

| tool | purpose | key args |
|---|---|---|
| `signoff_status_get` | poll whether a structured sign-off request has been cleared. When cleared and the binding ledger is enabled, also returns the recorded Filigree binding. | `seq` (required) |
| `signoff_bind_issue` | bind a **cleared** structured sign-off to a Filigree issue. The bound SEI and content hash come from the recorded sign-off, never from the caller. Records the evidence `filigree_closure_gate_get` reads. | `seq`, `issue_id` (required) |
| `filigree_closure_gate_get` | read whether legis holds verified binding evidence for closing a Filigree issue. | `issue_id` (required) |

## Wardline routing

| tool | purpose | key args |
|---|---|---|
| `scan_route` | route Wardline scan findings through one cell, a `severity_map` policy, or a cell + `fail_on` threshold. Returns a discriminated success outcome (`ROUTED`); a dirty unsigned artifact where signed provenance is required returns `WARDLINE_DIRTY_TREE`. | `scan` (object, required); `cell`, `severity_map`, `fail_on` (optional, gated behind `LEGIS_UNSAFE_WARDLINE_REQUEST_ROUTING` — server-owned routing rejects them with `INVALID_CELL_SPEC`) |

## Git & pull-request context

| tool | purpose | key args |
|---|---|---|
| `git_branch_list` | list local git branches and upstream divergence facts. | none |
| `git_commit_get` | read one git commit by SHA or safe ref. | `sha` (required) |
| `git_rename_list` | list git rename evidence for a revision range. | `rev_range` (required) |
| `git_rename_feed_get` | Loomweave-ready rename feed: committed renames over `base..head` plus optional uncommitted working-tree renames. | `base` (required); `head`, `include_worktree` (optional) |
| `pull_request_get` | read recorded pull-request metadata with joined check outcomes. | `number` (required) |

## CI / check outcomes

| tool | purpose | key args |
|---|---|---|
| `check_list` | read recorded CI/check outcomes for a commit, branch, or PR target. | `target_type` (`commit` / `branch` / `pr`), `target` — both required |
| `check_report` | record a CI/check outcome as the launch-bound agent. The recorded fact is a writer-supplied claim with provenance `unauthenticated` — readers must not treat it as forge-attested. | `check_name`, `run_id`, `commit_sha`, `outcome` (required); `branch`, `pr`, `ran_against`, `rule_set`, `policy_version`, `started_at`, `finished_at` (optional) |

## Identity & lineage integrity

| tool | purpose | key args |
|---|---|---|
| `identity_gap_list` | list governance attestations whose SEI Loomweave now reports dead (orphaned). Two-state payload: `checked` (possibly zero gaps) vs `unavailable` — never read an empty list as all-clear without status `checked`. | none |
| `lineage_integrity_get` | verify each recorded lineage snapshot is still a prefix of the entity's current Loomweave lineage. Three-way status (`diverged` > `unverified` > `verified`, with `unavailable`); appends (rename/move) are legitimate, a removed/mutated prior event is divergence. | none |

## Health & policy-boundary

| tool | purpose | key args |
|---|---|---|
| `doctor_get` | report-only install/config health read — the same JSON `legis doctor --format json` emits, run against the server's source root. **Never repairs** (fixes stay on the `legis doctor --fix` CLI). | none |
| `policy_boundary_check` | read-only scan validating `@policy_boundary` declarations against current behavioural evidence (the CLI's `legis policy-boundary-check`). Discriminated outcome: `PASS` or `FINDINGS`. | optional `root` (defaults to `<repo_root>/src`), `repo_root` (defaults to the server's source root) |
