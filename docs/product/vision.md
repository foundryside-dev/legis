# Vision — Legis

## Purpose
Legis is the **governance surface of the Weft suite**: it turns "did a human authorize this change, and is that authorization still valid for the code as it stands now?" into a cited, durable, machine-readable fact. It records SEI-keyed governance verdicts, overrides, sign-offs, and audit lineage over the 2×2 enforcement cells (chill / coached / structured / protected), and exposes the git/CI provenance surface (branch / commit / PR / CI state) that those verdicts attach to. Its defining property is **governance _honesty_** — it never reports a green it cannot prove, and an unauthorized or unverifiable change is always _detectable_. It serves agents first: humans supervise, approve, and govern from **outside** the operating loop, not inside it.

## Who it serves
- **Primary:** coding agents operating under governance — the agent-customers of the Legis MCP/HTTP surface that submit overrides, request sign-offs, read attestations, and route Wardline findings.
- **Secondary:** human operators who supervise and authorize from outside the loop (sign-offs, posture floor, key custody, release gates) — served, but never pulled _into_ the operating cycle.
- **Sibling tools** (Loomweave, Wardline, Filigree, Warpline) consuming Legis's git-rename feed and governance attestations across the federation contracts.
- **Explicitly not:** humans who want a config-driven CI dashboard; anyone wanting Legis to be a general-purpose CI runner, a trust/taint analyzer, or an identity authority.

## Anti-goals (what it refuses to be)
- **A second judge of trust.** "Wardline analyses, Legis governs." Trust vocabulary passes through verbatim; Legis never re-adjudicates a taint/trust verdict.
- **An identity owner.** The SEI is opaque to Legis. It consumes Loomweave's `resolve_sei` / `lineage`; it never parses or mints identity.
- **Tamper-_proof_.** Legis is a governance-_honesty_ tool. The honest claim is "an unauthorized change is detectable," never "impossible."
- **A config-driven security boundary.** Config is not a security boundary; signing keys stay out of agent reach. Governance is promoted into signed records, not editable TOML.
- **Human-in-the-loop by default.** Zero _human_ config; the instruction layer is the configuration mechanism. Humans gate by exception, not by operating the tool.

## Authority grant
Granted by: john (john@pgpl.net)     Last reviewed: 2026-06-24
Review cadence: monthly, or on any vision change

Autonomous within strategy — the agent MAY, without asking:
  prioritize the backlog, write PRDs, dispatch delivery, accept against
  criteria, reprioritize, kill a failing bet per metrics.md.

Escalate BEFORE acting — the agent MUST get owner sign-off for:
  - changing this vision / strategy / authority grant
  - a PyPI publish or a GitHub release (outward-facing)
  - deprecating a feature siblings or users depend on
  - changing a **federation contract that binds a sibling tool** (the
    contracts-index seams: SEI consumption, git-rename provider, Filigree
    sign-off binding, Wardline routing, Warpline preflight) — these bind
    external parties (sibling maintainers), so a contract change escalates
  - a pricing / commercial / licensing change
  - deleting data or any irreversible data operation
  - anything touching an external party (sibling maintainers, users, registries)
  (Taxonomy + rationale: product-ownership-operating-model.md.)

> Grant **confirmed live** by the owner on 2026-06-24 during bootstrap
> (`/own-product`). Status: confirmed, not draft.
