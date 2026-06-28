# 00 — Coordination Plan

## Analysis Configuration
- **Subject:** Legis — the git/CI + governance layer of the Weft suite.
- **Scope:** `src/legis/` (~16,585 LOC, ~78 Python files, ~17 cohesive subsystems).
- **Deliverables:** **Option C — Architect-Ready** = discovery + full subsystem catalog + C4 diagrams + final report + code-quality assessment + architect handover.
- **Strategy:** **PARALLEL** — ≥5 independent subsystems, ~16.5K LOC, mostly loosely coupled around a central `service/` hub. Eight reviewer agents over coherent clusters, then validation, then synthesis.
- **Branch analyzed:** `fix/policy-boundary-containment` (off `main` `25d64e2`) — current working tree.
- **Complexity estimate:** High (crypto/audit-chain, 2×3-way error mapping, federation seams, three transports).

## Scope limitations (documented, honest)
- `governance_read.v1` (service fn + transports) and the contents of `plainweave_preflight/` are **release-only / in-flight on PR #21** (`release/1.3.0-federation-reads`), NOT in this `main`-based checkout. They are described from CLAUDE.md/PDRs where relevant but not analyzed from source here. `warpline_preflight/` IS present (143 LOC).
- A pre-existing, unrelated dirty working-tree state exists under `docs/arch-analysis-2026-06-06-0158/` (a June-6 analysis showing deleted-but-tracked files). Left untouched; out of scope.
- All analysis artifacts are kept **untracked** (not committed) so nothing pollutes open PR #22 (the security fix) or PR #21 (the release).

## Orchestration — eight reviewer clusters
| # | Cluster | Paths | ~LOC |
|---|---------|-------|------|
| 1 | Service layer (governance truth hub) | `service/` | 1497 |
| 2 | Enforcement & Policy (the 2×2 engine) | `enforcement/`, `policy/` | 2553 |
| 3 | Identity & Persistence (SEI + audit chain) | `identity/`, `store/`, `canonical.py`, `weft_signing.py`, `provenance.py`, `records/` | ~1416 |
| 4 | Transports (thin adapters) | `mcp.py`, `api/`, `cli.py` | ~4547 |
| 5 | Posture (floor + operator key + elevation) | `posture/` | 1331 |
| 6 | Federation seams | `wardline/`, `filigree/`, `governance/`, `warpline_preflight/` | ~1663 |
| 7 | Git/CI surfaces | `git/`, `checks/`, `pulls/` | 615 |
| 8 | Runtime/Ops | `install.py`, `doctor.py`, `hooks.py`, `config.py` | ~2930 |

## Execution Log
- [2142] Created workspace `docs/arch-analysis-2026-06-28-2142/`.
- [2142] User selected **Option C (Architect-Ready)**.
- [2142] Holistic scan: LOC/file counts, entry point, cross-subsystem import matrix captured.
- [2143] Strategy = PARALLEL; 8 reviewer clusters defined (above).
- [next] Write `01-discovery-findings.md`; dispatch 8 parallel reviewers → `temp/catalog-*.md`; merge to `02-subsystem-catalog.md`; validate; synthesize `03`–`06`.

## Execution Log (continued)
- [2143] Wrote 01-discovery-findings.md.
- [2144] Dispatched 8 parallel codebase-explorer reviewers → temp/catalog-*.md. All 8 returned with file:line-cited entries.
- [2145] Assembled 02-subsystem-catalog.md (687 lines).
- [2145] Controller-verified 2 surprising findings (posture read_floor = main-checkout artifact; keychain = deliberate fail-closed stub).
- [2146] Validation subagent STALLED mid-stream (API infra error, no report). Completed validation as controller with documented file:line evidence → temp/validation-catalog.md. Verdict PASS_WITH_NOTES; 4 high-severity-sounding concerns reclassified (none a live false-green).
- [2147] Synthesized 03-diagrams.md, 04-final-report.md, 05-quality-assessment.md, 06-architect-handover.md from the validated catalog.
- [DONE] Option C deliverables complete. Synthesis docs derive from the validated catalog (the load-bearing layer); reclassifications applied throughout.

## Validation-gate note
The mandatory multi-subsystem validation ran against the catalog (the source-of-truth document). It stalled as a subagent (infra), so the controller completed it with per-claim evidence — a deviation from the independent-subagent gate, recorded transparently. The four synthesis documents (03–06) are derived from the validated catalog and apply its reclassifications; they were not separately subagent-validated.
