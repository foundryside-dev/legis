# 01 — Discovery Findings (Holistic Assessment)

> Evidence base: directory/LOC scan, `pyproject.toml`, cross-subsystem import matrix, and `CLAUDE.md`/`README` framing, all verified against `src/legis/` on the analyzed checkout. Subsystem-level depth is produced by the parallel reviewers (`02-subsystem-catalog.md`).

## 1. What Legis is
The git/CI + **governance** layer of the Weft four-tool suite (Loomweave, Wardline, Legis, Filigree). It answers *"what changed, in which branch/commit/PR/check context, and what governance/attestation state exists for that change?"* and enforces agent-defined policy at the git/CI boundary via a graded **2×2 enforcement model**. Defining stance: a **governance-honesty** tool — the cardinal sin is a **false-green** (reporting clearance when nothing was governed); code paths fail **closed**.

## 2. Technology stack
- **Language/runtime:** Python ≥3.12, `uv`-managed.
- **Persistence:** SQLite (5 stores under `.weft/legis/`), append-only HMAC-signed audit chain (v3 chain-position binding).
- **Crypto:** HMAC signing (`weft_signing.py`, `canonical.py` byte-for-byte JSON contract with Wardline), OS-keychain operator key (posture).
- **Transports:** HTTP (FastAPI-style `api/app.py`), MCP stdio (`mcp.py`), CLI (`cli.py`).
- **Quality gates:** ruff (scoped `E4,E7,E9,F`), mypy, pytest+coverage (global 88 floor + stricter per-package floors), SEI conformance oracle, a self-hosted governance-honesty policy-boundary scanner, override-rate governance-gate.

## 3. Organization model
**Hybrid layered + domain.** A central `service/` layer holds governance truth; three thin transport adapters sit above it; domain subsystems (enforcement, policy, identity, store, posture, federation seams, git/CI surfaces) sit beside/below it; a foundation of leaf utilities (`canonical.py`, `clock.py`, `weft_signing.py`, `provenance.py`, `config.py`, `records/`) underpins everything.

## 4. Entry points
- **CLI / all transports:** `legis = legis.cli:main` (`pyproject.toml [project.scripts]`). The CLI also launches the MCP server (`legis mcp`) and the HTTP app.
- **HTTP:** `api/app.py` (imports nearly every surface + `mcp`).
- **MCP:** `mcp.py` (`build_runtime`, `call_tool`, `tool_definitions`) — ~21+ tools.
- **Install/runtime bootstrap:** `install.py` (`legis install`), `doctor.py` (`legis doctor [--fix]`), `hooks.py` (SessionStart).

## 5. Subsystem inventory (by LOC)
| Subsystem | LOC | Role (one line) |
|-----------|-----|-----------------|
| `mcp.py` | 2748 | MCP stdio adapter; ~21 tools; ServiceError→error-envelope mapping |
| `install.py` | 1503 | Stand-up: instruction block, skill pack, hooks, `.mcp.json`, posture genesis |
| `service/` | 1497 | **Single source of governance truth**; adapters call into it |
| `enforcement/` | 1367 | The 2×2 engine: engine, judge, protected, signing, signoff, verdict, lifecycle |
| `posture/` | 1331 | Posture floor, OS-keychain operator key, sudo-style elevation sessions, ledger |
| `policy/` | 1186 | Policy grammar, cells (2×2 routing), boundary scanner, `@policy_boundary` decorator |
| `doctor.py` | 1002 | Operator health/repair; tags problems `[auto-fixable]`/`[operator]` |
| `api/` | 955 | HTTP adapter (ServiceError→status codes) |
| `cli.py` | 844 | CLI adapter (ServiceError→exit codes) + subcommands |
| `wardline/` | 728 | Ingest Wardline findings; route into enforcement cells |
| `store/` | 667 | SQLite stores, head anchor, audit protocol |
| `governance/` | 607 | SEI-keyed sign-off binding, filigree gate |
| `identity/` | 542 | Loomweave SEI seam (client, resolver, entity_key) — consumer only |
| `git/` | 328 | Branch/commit/PR/check context + rename-feed provider |
| `hooks.py` | 222 | SessionStart hook |
| `config.py` | 203 | Env/`LEGIS_*_DB` store resolution |
| `filigree/` | 185 | Filigree consumer (bind/closure) |
| `checks/` | 175 | CI check surface |
| `warpline_preflight/` | 143 | Advisory preflight consumer |
| `pulls/` | 112 | PR surface |
| leaf utils | ~240 | `weft_signing.py`, `canonical.py`, `clock.py`, `provenance.py`, `records/` |

## 6. Dependency overview (from the import matrix)
- **Hub:** `service/` → enforcement, identity, governance, wardline, policy, warpline_preflight, canonical. All three transports import `service/` (HTTP 15, MCP 6, CLI 2) — the "adapters over a truth layer" architecture is real, not aspirational.
- **Foundation (imported, imports little):** `canonical.py`, `clock.py`, `weft_signing.py`, `provenance.py`, `config.py`, `records/`.
- **`git/` is self-contained** (imports no other legis subsystem) — clean.
- **Coupling signals to probe in the quality pass (candidate concerns):**
  1. **`store/ ↔ enforcement/` bidirectional** — `store` imports `enforcement` and `enforcement` imports `store`. Possible layering tangle.
  2. **`policy/ → service/`** — policy (a lower-level grammar/scanner) imports the service hub; inversion risk (the boundary-scan containment fix used a *deferred* `service.errors` import precisely to avoid a load-time cycle — corroborates that this edge is delicate).
  3. **`posture/ → install/`** — posture imports the 1503-LOC ops module; heavy/odd dependency direction.
  4. **`api/ → mcp`** — the HTTP adapter imports the MCP module (transport-on-transport).
  5. **`mcp.py` (2748) and `install.py` (1503) are very large single files** — god-module risk; candidates for the quality pass.

## 7. Orchestration decision
**PARALLEL**, eight reviewer clusters (see `00-coordination.md`). Rationale: ≥5 independent subsystems, ~16.5K LOC, a clean hub-and-adapters shape with only a handful of coupling edges to watch — well suited to independent per-cluster review followed by central synthesis and a validation gate.

## 8. Confidence
**High** on structure, entry points, and dependency direction (directly measured). **Medium** pending the reviewers on internal patterns, invariants, and concerns per subsystem. Two release-only areas (`governance_read.v1`, `plainweave_preflight/` contents) are out of scope on this checkout (§ limitations in `00-coordination.md`).
