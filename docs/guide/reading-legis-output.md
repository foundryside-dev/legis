# Reading Legis output — what am I seeing when an agent does X (operator guide)

You are **on the loop, not in it.** Most of what legis emits is for *asynchronous
review*: an attributable record of what an agent did, so you can audit it later —
not a prompt demanding you act right now. A few signals *do* require a human, and
they say so explicitly. This guide tells you, for each signal: **where it
surfaces, what it means, and whether you need to act.**

For *why* the cells behave this way see [`README.md`](../../README.md); for the
agent-side call mechanics see the `legis-workflow` skill. This guide is the human
reading layer.

## Two vocabularies, deliberately distinct

These look similar and are easy to conflate. They are different layers:

- **The call outcome envelope** — what an agent's `override_submit` *call returns*
  in the moment. Values: `ACCEPTED_SELF`, `ACCEPTED_BY_JUDGE`, `BLOCKED`,
  `ESCALATED_PENDING`, `NEED_INPUTS`. This is transient: it tells the agent what
  to do next.
- **The recorded Verdict** — what is *written to the audit trail*. Values:
  `ACCEPTED`, `BLOCKED`, `OVERRIDDEN_BY_OPERATOR`. This is durable: it is what you
  read when you review.

They overlap on `BLOCKED` but mean different things in different places. When in
doubt: an **envelope** is what a tool call returned; a **Verdict** is what the
trail says happened.

## A worked example: an agent hits a coached policy

Concrete, end to end — the mental model the tables below fill in:

1. An agent edits code that trips the `import-allowlist` policy, which your
   `cells.toml` routes to the **coached** cell.
2. The agent submits an override with a rationale. Because the cell has a judge,
   the LLM evaluates it *before anything records*. The judge is unconvinced and
   the call returns **`BLOCKED`** with `blocked_reason_code: RATIONALE_INSUFFICIENT`
   and `next_actions: [REVISE_CODE, REVISE_RATIONALE]`. **Nothing is written to the
   trail; this attempt does not count toward the override-rate.** You see nothing
   that needs you.
3. The agent sharpens its rationale (or fixes the import) and resubmits. This time
   the judge accepts: the call returns **`ACCEPTED_BY_JUDGE`**, and a **`ACCEPTED`**
   Verdict is written to the SEI-keyed audit trail with the judge's rationale
   recorded verbatim.
4. **Later, on your schedule,** you review the trail and see the `ACCEPTED` record:
   which policy, which entity, the rationale the judge accepted. If it looks wrong,
   you act then — out of band. You were never blocked, and the agent never silently
   passed.

Had the same policy been routed to **structured** instead, step 2 would have
returned **`ESCALATED_PENDING`** and stopped — waiting for *you* to sign off before
the agent could proceed. That is the one common case where you are in the loop by
design. The rest of this guide is the reference for every signal in that flow.

## When an agent overrides a policy

This is the core event. An agent hit a policy at the CI/git boundary and chose to
override rather than refactor. What you see depends on the cell governing that
policy.

| Outcome envelope | Cell | What it means | Do you act? |
|---|---|---|---|
| `ACCEPTED_SELF` | chill | The agent self-cleared with a recordable override. | **No** — review the trail when convenient. The record is attributable; nothing was silently passed. |
| `ACCEPTED_BY_JUDGE` | coached / protected | The LLM judge accepted the override before it recorded. (In protected, may be re-judged later by the decay sweep.) | **No** in coached. In protected, watch the override-rate gate over time. |
| `BLOCKED` | coached / protected | The judge refused. The agent **cannot self-clear past it** — it must revise the code or its rationale and resubmit. The blocked attempt does **not** count toward the override-rate. | **No** — this is the wall working. The agent is expected to fix and retry. |
| `ESCALATED_PENDING` | structured | A hard gate. A human operator must sign off before it clears. The agent is told to wait. | **Yes** — *you* are the gate. Review and sign off (or refuse). |
| `NEED_INPUTS` | protected | The submission is missing required evidence (e.g. `file_fingerprint`, `ast_path`). The agent must supply them and resubmit. | **No** — the agent self-corrects. |

A `BLOCKED` envelope also carries a `blocked_reason_code` so you (or the agent) can
see *why*:

| `blocked_reason_code` | Roughly means |
|---|---|
| `RATIONALE_INSUFFICIENT` | The justification was too thin — sharpen it. |
| `CODE_VIOLATION` | The change itself trips the policy — fix the code, not the words. |
| `POLICY_HARD_BLOCK` | A policy that is not meant to be talked past at all. |
| `UNCLASSIFIED` | The judge refused without a recognised category. |

**The only outcome that needs you in real time is `ESCALATED_PENDING`** — a
structured sign-off. Everything else is async-review or agent-self-correct.

## What the audit trail records

When you review (rather than watch live), you read recorded **Verdicts** keyed on
SEI (so they survive renames/moves):

| Recorded Verdict | What happened |
|---|---|
| `ACCEPTED` | The override was accepted — by the agent itself (chill) or by the judge (coached/protected). |
| `BLOCKED` | The judge refused; this attempt was not a kept suppression. |
| `OVERRIDDEN_BY_OPERATOR` | A human operator forced the decision past the gate. **This is the line item to watch** — see the override-rate gate below. |

A structured request you have not yet actioned shows sign-off state
`PENDING_SIGNOFF`; once you sign, `SIGNED_OFF`.

In the protected cell, each recorded verdict is HMAC-signed and bound to the exact
source bytes and AST node the judge inspected (`file_fingerprint` + `ast_path`), so
an after-the-fact edit by someone who cannot recompute the signature is detectable.

## When an agent routes a Wardline scan

`scan_route` feeds Wardline findings into governance. You will see an **outcome**
and, on the artifact, a **status**:

| `scan_route` outcome | Meaning | Do you act? |
|---|---|---|
| `ROUTED` | Findings were governed into the configured cell. Normal path. | No. |
| `SKIPPED_DIRTY_TREE` | A typed recoverable failure: an unsigned dirty-tree dev artifact arrived where signed provenance is required. **Nothing was governed.** HTTP returns 409 with this outcome; MCP returns `isError: true` with `error_code: WARDLINE_DIRTY_TREE` and message/reason `SKIPPED_DIRTY_TREE`. | No — the agent commits for a signed artifact (or a dev sets `LEGIS_WARDLINE_ALLOW_DIRTY=1`). |

The artifact's provenance `status` tells you how far it verified:

| `artifact_status` | Meaning |
|---|---|
| `verified` | Signed, clean-tree artifact — full provenance. |
| `dirty` | Governed an unsigned dirty-tree artifact (only under the dev opt-in). Honest about what it is. |
| `unverified` | Provenance could not be confirmed. |

## Identity and lineage status

Because legis keys on SEI from Loomweave, you will see how identity resolution
went. An `unavailable` is **honest degradation, not an error** — it means legis
could not reach a Loomweave decision and refused to guess.

| `identity_resolution_status` | Meaning |
|---|---|
| `resolved` | SEI resolved; the record keys on stable identity. |
| `not_alive` | The entity is no longer live per Loomweave. |
| `unavailable` | No Loomweave capability/decision (e.g. `LOOMWEAVE_API_URL` unwired). Degraded honestly. |
| `invalid` | (Backfill path only) the legacy record could not be keyed. |

| `lineage_snapshot_status` | Meaning |
|---|---|
| `verified` | Lineage snapshot confirmed. |
| `unavailable` | Could not confirm (sibling unwired or no decision). |
| `not_applicable` | No lineage applies to this record. |

> If a governance posture endpoint reports `diverged` (lineage integrity) or a
> status of `unavailable` where you expected `checked`, that is the honesty
> machinery doing its job — it refuses to report a false "all clear." Investigate
> the sibling wiring; do not read the bare absence of a finding as success.

## The override-rate gate

This is the **single most important signal to watch over time.** It measures the
share of kept suppressions that were *forced past the judge by an operator*
(`OVERRIDDEN_BY_OPERATOR ÷ (ACCEPTED + OVERRIDDEN_BY_OPERATOR)`) over a rolling
window. Agent retries and blocked attempts do **not** move it — only operator
force-pasts do.

| Gate status | Meaning | Do you act? |
|---|---|---|
| `PASS` | Operator override rate is under threshold. | No. |
| `FAIL` | Too many operator force-pasts. **Either the policy is miscalibrated, or an operator is breaking their own rules to ship.** Either way it is now observable, not silent. | **Yes** — investigate which, and recalibrate or stop. |
| `PASS_WITH_NOTICE` | Sample below the minimum — too few records to judge mechanically. | No (yet). |

Where you see it:
- In-session: `override_rate_get` → `{status, rate, sample_size}`.
- In CI: `legis check-override-rate` (or `legis governance-gate`) prints
  `override-rate gate: <STATUS> (rate=…, sample=…)` and **exits 1 on `FAIL`**.

## CI gate exit codes

| Command | Exit 0 | Exit 1 |
|---|---|---|
| `legis check-override-rate` / `legis governance-gate` | `PASS` / `PASS_WITH_NOTICE` | `FAIL`, or a failed hash-chain integrity check, or a missing DB under `CI=true` (without the dev allow-flag). |
| `legis policy-boundary-check` | `policy-boundary-check: PASS` | One `path:line: rule_id: qualname: reason` per finding — a `@policy_boundary` lacks current behavioural evidence. |

## `legis doctor` tags

Each problem line is tagged so you know who fixes it:

- `[auto-fixable]` — `legis doctor --fix` can repair it (install-layer wiring).
- `[operator]` — **not** auto-fixable; needs out-of-band config (an env var or
  file) and a relaunch. The line names the action.
- `[fixed]` — a `--fix` run just repaired it.

doctor reports the governance surface; it never auto-enables a cell or touches a
signing key.

## MCP tool errors (one to never ignore)

The agent surface returns typed `error_code`s with `recoverable` and `next_action`
hints (the full table is in the `legis-workflow` skill). Almost all are
agent-recoverable by fixing input or asking you to enable a cell. **One is not:**

> **`AUDIT_INTEGRITY_FAILURE`** — a hash-chain or binding-ledger verification
> failed. This is not recoverable and must not be retried. It means the audit
> trail's tamper-evidence tripped. **Stop and inspect the governance store.**

`INTERNAL_ERROR` is likewise not auto-recoverable — surface it to a human.

---

**In one sentence:** if you see `ESCALATED_PENDING` (sign-off), an override-rate
`FAIL`, or `AUDIT_INTEGRITY_FAILURE`, a human is needed; almost everything else is
the system working as designed and waiting for your *asynchronous* review.
