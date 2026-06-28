# 06 — Architect Handover

> Transition document: from "what is" (`02`/`04`/`05`) to "what to change." For improvement-planning. Scope is **structure/maintainability** — the validation pass confirmed governance correctness is sound, so nothing here touches the fail-closed seams except to make them easier to keep correct. Items map to `05-quality-assessment.md` IDs.

## Guardrails for any change here
1. **Preserve fail-closed.** Never let a refactor introduce a path where absent/empty input reads as a pass. Re-run the honesty gates after every change: `uv run legis policy-boundary-check --root src --repo-root .`, `uv run legis governance-gate`, `uv run pytest tests/conformance/test_sei_oracle.py`, full suite + coverage floors.
2. **Don't touch the byte-contracts.** `canonical.py ensure_ascii=False` and the HMAC field sets are cross-tool contracts — out of bounds for cleanup.
3. **SEI stays opaque.** No refactor may start parsing/deriving SEI.
4. **These are `main`-line refactors** — schedule them after PR #21 (release) and PR #22 (security fix) land, to avoid colliding with in-flight work.

## Prioritized backlog

### P1 — Decouple the layering inversions (low effort, high leverage)
These are small moves that remove the most fragile edges and unlock safer evolution.

- **H-1 (B3): Extract a `crypto/` (or `signing/`) leaf.** Move `enforcement.signing` to a dependency-free leaf package that `store/` and `enforcement/` both import downward. Kills the `store↔enforcement` bidirectional edge and the "one upward import breaks it silently" risk. *Effort: S. Impact: H.*
- **H-2 (B5): Relocate `OperatorKeyCustodyError`.** Move it from `install.py` to a shared `posture/errors.py` (or a common errors module); `posture` stops importing the 1503-LOC setup module. *Effort: XS. Impact: M.*
- **H-3 (B6 / Q-H2): Move `_load_policy_cell_registry`** out of `mcp.py` into `policy/` or `config.py`; have both `api/` and `mcp.py` import it from there. Removes the transport-on-transport edge. *Effort: S. Impact: M.*
- **H-4 (B4): Document/contain the `policy→service` edge.** Confirm the only `policy→service` use is the deferred `service.errors` import; if so, consider moving the small error types `policy` needs into a leaf so the deferred import can become a normal one (or leave the deferred import with a clear comment as the sanctioned pattern). *Effort: S. Impact: M (clarity).*

### P2 — God-module decomposition (medium effort, high long-term leverage)
- **H-5 (B1): Split `mcp.py` (2748 LOC).** Separate concerns: (a) tool **schemas/catalog**, (b) tool **handlers** (grouped by domain: governance, git/CI, federation, posture), (c) the **stdio loop + dispatch + error mapping**, (d) **runtime construction**. Keep `call_tool`/`tool_definitions`/`build_runtime` as the stable public surface. Target: no single file > ~600 LOC; adding a tool touches one handler module + one schema entry. *Effort: M–L. Impact: H. Risk: mechanical but broad — do behind the existing MCP conformance tests.*
- **H-6 (B2): Split `install.py` (1503 LOC).** Separate instruction-block injection, skill-pack install, hook registration, `.mcp.json` wiring, and posture/key custody into focused modules under an `install/` package. Lets H-2 land cleanly. *Effort: M. Impact: M–H.*

### P3 — Robustness & contract hygiene (close the honest loose ends)
- **H-7 (D1): Sign-off reconciliation/repair.** Add a `doctor` check + repair that detects a Filigree-attached binding with no ledger entry (the documented split-state) and offers an `[operator]`-tagged heal. Turns a detectable-but-manual residual into a guided fix. *Effort: M. Impact: M.*
- **H-8 (C1): Complete `service/__init__.py` `__all__`.** Re-export `UnresolvedInputError`, `WardlineRoutingError`, `ProtectedKeyRequiredError`, and `sign_off` so the service layer's public surface is whole. *Effort: XS. Impact: M (contract clarity).*
- **H-9 (D3): Tighten the git/CI write surfaces.** Add an optional proof-of-commit gate to `check_report` (or document why `UNAUTHENTICATED`-labeled phantom rows are acceptable) and a staleness/conflict guard to `pulls.record()`. No false-green today, but removes downstream-join foot-guns. *Effort: M. Impact: M.*
- **H-10 (D4): Type-wall the advisory boundary.** Give the Warpline/Filigree advisory clients a sealed/newtype return so a future edit physically cannot route advisory data into a verdict path — upgrade the invariant from discipline to compiler-enforced. *Effort: M. Impact: M (defense-in-depth on the load-bearing advisory boundary).*

### P4 — Future-work (already fenced, ship when ready)
- **H-11 (D2): Keychain custody adapter.** Implement `_keychain_available()` + a live keychain `key_sink`; the fail-closed fallback already protects users until then.

## Tracked items — link, don't duplicate
- **F1 / legis-e5e5b0b57f** (derive protected-record verification from config/identity, not in-record fields) — already on the tracker; the modify-to-unsigned residual. Not re-filed here.
- **Posture `read_floor` gate** — already fixed on the release line (`eb28e4b`, legis-476ab6f125); will land on `main` with PR #21. No action.
- **Non-ASCII cross-tool golden vector** — Wardline-side follow-up.

## Sequencing suggestion
P1 (H-1..H-4) first — they're cheap and make P2 safer. Then H-5/H-6 (god-modules) behind the conformance + full test suite. P3 as capacity allows; P4 when the keychain adapter is prioritized. Hand the sequenced/effort-scored version to `/axiom-program-management` if this becomes a funded refactor track; per-module implementation plans to `/axiom-planning`.

## Suggested next packs
- **Quality deep-dive:** `axiom-system-architect` (architecture critique / debt cataloging) on the god-module split.
- **Security/threat modeling:** `ordis-security-architect` for an adversarial pass on the federation seams + audit chain (complements the governance-honesty lens here).
