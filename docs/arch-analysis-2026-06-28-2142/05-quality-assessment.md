# 05 — Code Quality Assessment

> Findings from the 8 reviewers, **after validation** (`temp/validation-catalog.md`). Severity is by Legis's own yardstick: a real high-severity issue is a **false-green / fail-open** risk; documented fail-closed residuals are not defects. Each item cites evidence and, where relevant, an existing tracker ID.

## Governance-honesty posture — strong
No live false-green or fail-open path surfaced across 16.5K LOC / 8 independent reviews. The composition root fails closed (mcp.py:194-200), sign-off binding fails closed on non-SEI keys and on split-state (signoff_binding.py:46-50, 71-81), the audit chain is HMAC-signed with v3 chain binding, and the self-hosted policy-boundary gate prevents vacuous PASS. **This is the product's core promise and the code keeps it.**

## A. Reclassified — NOT defects (validation corrected the reviewers)
| Item | Original framing | Corrected classification |
|------|------------------|--------------------------|
| Posture `read_floor` not gating `verify_integrity` (ledger.py:92) | fail-open floor read | **Scope artifact** — gate (`eb28e4b`, legis-476ab6f125) is unmerged on release/PR #21, not on `main`. Fixed on the release line. |
| `_keychain_available()` returns False (install.py:1349) | unimplemented custody | **Deliberate fail-closed stub** — falls back to age-file rather than claiming a keychain it can't write. Honest future-work. |
| `default_policy_cells()` defaults to chill (cells.py:64) | silent self-clear default | **Fail-closed in production** — composition root needs explicit `LEGIS_DEV_DEFAULT_CELLS=1` for chill; otherwise `structured`. Discipline note only. |
| Sign-off partial-write window (signoff_binding.py:71-81) | uncompensated split state | **Documented fail-closed trade-off** — detectable via `ledger.verify()`; a repair tool is future-work (§D). |

## B. Real — Structural / maintainability (Important)
| # | Finding | Evidence | Why it matters |
|---|---------|----------|----------------|
| B1 | **`mcp.py` god-module (2748 LOC)** — 23 tool handlers + JSON-schema catalog + stdio loop + runtime + idempotency + helpers in one file | mcp.py whole | Every new tool edits 4 sites in one file; high change-coupling, no structural enforcer. Highest-churn surface in the repo. |
| B2 | **`install.py` god-module (1503 LOC)** — instruction block, skill pack, hooks, `.mcp.json`, posture genesis, key custody | install.py whole | Mixed responsibilities; `posture/` even reaches back into it (B5). |
| B3 | **`store ↔ enforcement` bidirectional coupling** | `store.head_anchor`→`enforcement.signing`; `enforcement.{engine,protected,signoff}`→`store.*` | Not a runtime cycle today (no decision logic crosses), but `enforcement.signing` is a shared crypto primitive mis-located in `enforcement/`; one upward import would break the non-circular property silently. |
| B4 | **`policy → service` layering inversion** | policy imports service; `boundary_scan.py` uses a *deferred* `service.errors` import to dodge a load-time cycle | A lower-level grammar/scanner depending on the hub; the deferred import is a smell marker that this edge is fragile. |
| B5 | **`posture → install` inverted dependency** | `posture/ledger.py:344` imports `OperatorKeyCustodyError` from `install.py` | Setup module imported by a runtime module; the error type belongs in a shared/posture errors module. |
| B6 | **`api → mcp` transport-on-transport** | `api/app.py:398` imports private `mcp._load_policy_cell_registry` (comment cites Q-H2) | Fragile change-coupling between two adapters; helper belongs in `config.py`/`policy/`. |

## C. Real — Public surface / contract hygiene (Minor)
| # | Finding | Evidence |
|---|---------|----------|
| C1 | `service/__init__.py` `__all__` omits `UnresolvedInputError`, `WardlineRoutingError`, `ProtectedKeyRequiredError`, and `sign_off` — adapters must reach into submodules to catch/call them | service/__init__.py:37; governance.py:724-746 |
| C2 | Two structurally-unrelated PR types (`git/pull_request.PullRequestContext` vs `pulls/models.PullRequest`) with identical fields — intentional ("forge is source of truth") but no type-level guard against confusion | git/pull_request.py, pulls/models.py |

## D. Real — Robustness / ops future-work (Minor, fail-closed today)
| # | Finding | Evidence | Note |
|---|---------|----------|------|
| D1 | No reconciliation/repair tool for a sign-off split-state | signoff_binding.py:71-81 | Detectable via `verify()`; healing is manual. A `doctor` repair path would close it. |
| D2 | Keychain custody adapter unimplemented | install.py:1344-1349 | Deliberate stub; age-file/env tiers work. Ship a live keychain adapter when ready. |
| D3 | `checks.check_report` accepts `commit_sha` with no proof-of-commit; `pulls.record()` does delete-then-insert with no staleness check | checks surface; pulls/surface.py | No false-green (records labeled `UNAUTHENTICATED`), but phantom/stale rows can mislead a downstream SHA join. |
| D4 | Advisory boundary enforced by discipline/comments, not a type wall (Warpline/Filigree clients return untyped dicts) | warpline_preflight/client.py | A newtype/sealed return would make accidental verdict-path use impossible rather than merely discouraged. |

## E. Tracked / known (link, do not re-file)
- **F1** — `TrailVerifier._requires_verification` derives verification need from attacker-controllable in-record fields (modify-to-unsigned). = tracker **legis-e5e5b0b57f** + README conceded raw-DB residual.
- **Non-ASCII golden vector** — `canonical.py ensure_ascii=False` is correct (intentional HMAC contract); the missing non-ASCII pinned cross-tool golden is a Wardline-side follow-up.
- **Q-H2** — the `api→mcp` helper placement (B6) is the named decision.

## Overall
**Correctness/honesty: A.** **Structure/maintainability: B–.** The debt is concentrated in two god-modules and a handful of coupling inversions — all incrementally fixable. Prioritized plan in `06-architect-handover.md`.
