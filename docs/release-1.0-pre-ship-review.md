# legis 1.0 — second-pass adversarial pre-ship review

> Independent verification pass over `docs/release-1.0-risk-audit.md`, run **2026-06-08 on `rc4` @ `7a054a6`**. Six adversarial reviewers over the high-risk surface, with the orchestrator personally re-verifying every blocker-class finding against source (code read + PoC run + wiring trace). Baseline: **792 passed, 2 skipped, ruff clean**.
>
> **Premise (why this pass exists):** the prior 9-lane audit *found* the bugs adversarially, but every *fix* (`0dabc8b`…`5076170`) landed after the audit baseline (`4a254f2`) and was **self-verified by the fixer with the fixer's own tests**. The newest, least-reviewed, highest-risk code was exactly the code under the microscope. Each reviewer was told to treat every "CLOSED ✓" as a hypothesis to falsify, not a fact to confirm.

---

## ✅ RESOLUTION (2026-06-09) — all findings closed and independently re-verified

The review verdict below was **NO-GO until the must-fix set closed**. All of it is now closed, on top of `7a054a6`, suite **801 passed / 2 skipped**, ruff + mypy clean.

| Finding | Status | What landed |
|---|---|---|
| **JUDGE-3** | ✅ CLOSED + re-attacked (no bypass) | Protected cell fail-closed **unconditionally**: the gate clears only on a validator-confirmed `ACCEPTED`; every other judge verdict downgrades to `BLOCKED`. The first completion missed a variant — a fooled model emitting the operator-only `OVERRIDDEN_BY_OPERATOR` (which `_record_signed` also counts as accepted) — caught by independent verification and closed at **two layers**: the judge JSON parser now restricts to `{ACCEPTED, BLOCKED}`, and `submit()` downgrades the whole accepted-set. `protected.py`, `judge.py`, `mcp.py` comment. |
| **GOV-2** | ✅ CLOSED | `/governance/identity-gaps` returns a `{status, gaps}` envelope (`unavailable` vs `checked`). `api/app.py`. |
| **F1** | ✅ CLOSED (docstring) | `TrailVerifier` docstring honestly scopes the guarantee; modify-to-unsigned / truncation documented as conceded-tier residuals (code hardening tracked post-1.0). |
| **POLICY-1** | ✅ CLOSED (documented) | Aliased-marker + fixture-skip vectors documented as residuals in `_disabling_marker` (zero live `@policy_boundary` sites; name-heuristic hardening tracked post-1.0). |
| **README overclaim** | ✅ CLOSED | "Known security limitations" section added; coached model-robustness limit named. |
| **ID-SEI-1** | ✅ CLOSED | `LEGIS_ALLOW_INSECURE_REMOTE_HTTP` warns on remote-plaintext bypass (both clients) + federation/README docs. |
| **ID-SEI-2** | ✅ CLOSED | `alive` is strict-bool; non-bool truthy degrades fail-closed. `resolver.py`. |

**Verification method (anti-circularity).** Fixes were implemented directly, then **independently adversarially re-attacked** by separate agents told to falsify each fix. That pass caught the JUDGE-3 `OVERRIDDEN_BY_OPERATOR` bypass that the fix's own (green-but-blind) tests missed — the exact self-verification failure mode this review exists to prevent. Regression tests added at both the parser and gate levels.

**Behavior change shipped (operator-approved, option A).** In the default production config (no deterministic validator wired), **all protected-cell overrides now require operator sign-off** — a judge `ACCEPTED` is advisory only.

**Deliberately deferred post-1.0:** JUDGE-4 (audit-record-on-transport-error), hooks.py freshness symmetry, F1 *code* hardening. **Not done (operator's call):** version bump / tag / publish (gated on live e2e).

---

## Verdict: **NO-GO for a clean 1.0 as-is → GO after the must-fix honesty set (all small, localized)**

The single most important confirmation is good news: **the crypto-threshold assumption HOLDS** (verified across the Wardline / Filigree / weft seams). That assumption gates the entire deferral strategy (ensure_ascii, v1-canonical, unsigned-channel) — if it had broken, several deferrals would have become blockers. It did not.

But this pass found **a genuine code fail-open the self-verified audit missed** (JUDGE-3), **a sibling honesty bug of the exact GOV-1 blocker shape left unfixed** (GOV-2), and **a shipping docstring that makes a guarantee the code does not provide** (F1). For a governance-*honesty* tool these are the headline class of defect — a gate that does not do what it claims, on the condition it exists to catch.

---

## MUST-FIX before 1.0 (new honesty breaks, all reachable without exotic capability)

### JUDGE-3 — protected-cell Q-H3 silent fail-open: a fooled-model ACCEPTED is signed authoritative when cell-routing diverges from `protected_policies()`  **[HIGH — top must-fix]**
> Substance, not paperwork: this is a *real* fail-open of the protected cell's defining protection, reachable through the normal agent override path under plausible operator config. It is **not** a GOV-1-style documented lie — the gate's own docstring (`protected.py:210-217`) is honest that "Empty set / no validator preserves prior behaviour," and `policy_explain` carries no structured Q-H3 claim. The overclaim is confined to an **internal** construction comment (`mcp.py:186-188`: "a judge ACCEPTED is downgraded" stated unconditionally). What makes it must-fix is the silent absence of protection + no detection + glob-impossibility, not a user-facing false statement.
- **Where:** `enforcement/protected.py:306-310` (downgrade condition) · `:199-200` (defaults `protected_policies=frozenset()`, `validator=None`) · `mcp.py:189-192` & `api/app.py` gate construction (**no `validator=` passed at any site**) · `policy/cells.py:33-40` (glob-capable routing) vs `config.py:168-181` (`protected_policies()`, exact-match only).
- **What's wrong:** Two independent, differently-syntaxed config sources decide (a) *whether a policy reaches the protected gate* — the **cell registry** (`cells.toml`/`LEGIS_POLICY_CELLS`, supports `fnmatch` globs) — and (b) *whether a model ACCEPTED is downgraded inside the gate (Q-H3)* — `protected_policies()` (`LEGIS_PROTECTED_POLICIES`, exact-string, no globs). The downgrade fires only when `policy in self._protected_policies`. A policy routed to `cell="protected"` but **absent** from `protected_policies()` → the judge's ACCEPTED is **not** downgraded, is recorded `accepted=True`, and is **HMAC-signed v3 as authoritative evidence**. Because no call site wires a `validator`, the "non-LLM deterministic validator confirms the ACCEPTED" backstop the audit cites **does not exist at runtime** — Q-H3 reduces entirely to exact set membership.
- **Reachability (verified, normal agent path):** `override_submit` → `cell_for(policy) == "protected"` → `submit_protected_override(...)` (mcp.py:863-888), independent of `protected_policies()`. Two shapes nothing prevents:
  1. **Empty-set default:** `LEGIS_PROTECTED_POLICIES` unset (default `frozenset()`) + any `cell="protected"` route → **every** protected-cell override is fail-open.
  2. **Glob routing:** `pattern="secrets-*", cell="protected"` is expressible in the registry but **cannot** be mirrored in exact-match `protected_policies()`, so Q-H3 can *never* fire for the matched policies — an operator using glob protected-routing has no way to make the protection apply.
- **No detection:** `doctor.py` cross-checks `protected_policies()` against the HMAC key, but never checks protected-cell *routes* against `protected_policies()`.
- **Why it's a fail-open, not model-robustness:** advisory-downgrade-of-the-model's-word is the protected cell's entire reason to exist. Reproduced: a fooled judge returning ACCEPTED yields `accepted=True, verdict=ACCEPTED, signed=True`.
- **Fix direction:** make the protected gate **fail-closed**: if a policy reaches `ProtectedGate.submit()` and there is no effective downgrade path (`validator is None AND policy not in _protected_policies`), do **not** honor a model ACCEPTED — downgrade to BLOCKED/escalate. That makes "routed to protected" *sufficient* for the protection and eliminates the two-config divergence. Minimum: a doctor/startup consistency check that every `cell="protected"` route is covered by `protected_policies()`.

### GOV-2 — `/governance/identity-gaps` reports the all-clear on the one condition it cannot check  **[HIGH/MEDIUM — same class as the GOV-1 blocker]**
- **Where:** `api/app.py:734-739`.
- **What's wrong:** returns bare `[]` when `identity is None or identity.client is None`. An empty list is byte-for-byte indistinguishable from "checked the whole trail, found zero orphan gaps." The endpoint exists to surface orphaned attestations (SEI now `alive:false`); on the exact condition where it cannot do its job (Loomweave unwired) it returns the all-clear. The author already knows the distinction matters — the **sibling endpoint directly below** (`lineage_integrity`, app.py:741-748) returns `status:"unavailable"` for the identical condition (the GOV-1 fix). identity-gaps was simply not given the same treatment.
- **Reachable:** Loomweave unwired (`LOOMWEAVE_API_URL` absent) against a governance DB that already holds SEI-stable attestations from when it *was* wired — normal operation, no special capability.
- **Fix:** return a typed envelope distinguishing "unavailable" from "checked, empty," mirroring lineage-integrity; pin it with a test asserting `status` is not a green reading on the unwired condition.

### F1 — `protected.py` docstring guarantees a protection the code does not provide (modify-to-unsigned)  **[docstring = must-fix honesty; code = post-1.0, conceded tier]**
- **Where:** false claim at `enforcement/protected.py:96-99`; mechanism at `_requires_verification` `:118-127`; same in-record keying in `service/governance.py:152-158`.
- **What's wrong:** the docstring states *"stripping a signature and flipping an in-record flag cannot downgrade a protected record to 'unsigned, skip'."* That is **exactly** what a file-write attacker can do: `_requires_verification` decides whether a record must be signature-checked by reading **attacker-controlled in-record fields** (`payload["policy"]`, `ext["protected_cell"]`, the four `*_signature`/`file_fingerprint`/`ast_path` triggers). Rewrite `payload["policy"]` to a non-protected value, strip the ext triggers, recompute `content_hash`, re-chain → every predicate clause is False → the signature is **never examined**. Both `verify_integrity()` and `TrailVerifier.verify()` pass. The damning record is neutered to a benign unsigned row. **No HMAC key required.** Verified by PoC (`/tmp/attack_predicate.py`): `TrailVerifier.verify: PASSED` after neutering a protected `OVERRIDDEN_BY_OPERATOR` to `policy='benign-note'`. The head anchor does **not** save it: composed with the already-conceded snapshot/replay residual, anchor-ON also falls (`/tmp/attack_anchor_compose.py`).
- **Severity calculus:** the *exploit* requires raw file-write to `gov.db` — the same conceded C3 out-of-band capability that made **AUD-1 a post-1.0 non-blocker**. By the project's own yardstick the *code hardening* is legitimately post-1.0. But the *false docstring* is an honesty break (the same over-claim class POLICY-1/GOV-1 were): a shipping artifact (the docstring ships in the installed package) asserts a guarantee that does not hold. *Scope check (verified):* the **CHANGELOG makes no AUD-1 closure claim at all**, so it does not need correcting; the only other place the modify-to-unsigned variant is omitted is the `acdbff0` commit message (git history, not a shipped artifact). The fix is therefore confined to one docstring. **Fix the docstring now** to scope the guarantee honestly (in-place edit / reorder / renumber are caught by v3 seq-binding; modify-to-unsigned and tail-truncation are residuals of the conceded file-write tier, mitigated only by the opt-in head anchor and even then with the documented replay caveat). **Track the code hardening post-1.0:** derive the verification requirement from config/entity identity rather than the record being verified, or sign **all** appends so "unsigned" is itself tamper for the whole trail.

---

## SHOULD-FIX before 1.0 (cheap honesty hygiene)

- **README coached-cell — name the model-robustness limit explicitly.**  `README.md:83`; code at `enforcement/engine.py:92`. *Downgraded from must-fix after reading the source directly:* the README is largely honest — it states the agent clears the gate by "explain[ing] itself convincingly" and that the wall is against *lazy* overrides ("raises the cost of lazy overrides without raising the cost of honest ones"), which discloses semantic persuasion. The gap is narrower than the subagent framed: it does not name the **prompt-injection / model-robustness** limit (a *malicious* injection, not honest persuasion, can fool the judge). That residual is honest in the `judge.py` docstring but absent from user-facing docs. Add one sentence to the known-limitations note (below). Not a blocker.
- **POLICY-1 — harden against aliased disabling markers.**  `policy/evidence.py:29-59` (`_disabling_marker`). The gate matches only the **terminal name** against `{skip, skipif, xfail}`; a marker bound to a local/module alias — `skipper = pytest.mark.skip; @skipper` → `ast.Name("skipper")` — is not flagged, so a genuinely-skipped evidence test (`1 skipped`) keeps the boundary GREEN. This is an **under-match**, the precise failure the docstring claims to fail-closed against, and unlike the two *documented* residuals (module-level `pytestmark`, class-level `@skip` — genuinely parity-unfixable, they live outside the function source) this alias **is** in the function's `decorator_list` and is catchable on both gate paths. *Why should-fix not must-fix:* there are **zero shipped `@policy_boundary` decoration sites** in the tree today, so the 1.0 product has no live false-green from this — but it should be hardened before anyone adds a boundary. **Fix:** fail-closed on an evidence-test decorator whose terminal name is not a recognized non-disabling marker (the docstring already asserts the only legitimate decorators on evidence tests are pytest markers, so fail-closed-on-unknown is consistent with the stated design). Pin with a test.

- **User-facing "Known security limitations" home.** AUD-1 HeadAnchor replay, ID-3 (unsigned probe when keyless), and the AUD-3 durability tier (synchronous=FULL / power-cut tail-loss) are honestly described **only** in source docstrings and the internal `release-1.0-risk-audit.md` — not in any artifact the user reads (README/CHANGELOG). A residual the user cannot see is itself an honesty gap. Add a short README/CHANGELOG section. (This also matters because of the disclosure decision below: if the internal audit doc is pulled, these residuals lose their *sole* home.)
- **ID-SEI-1 — undocumented `LEGIS_ALLOW_INSECURE_REMOTE_HTTP`** (`identity/loomweave_client.py:137-139`). TLS is the *only* response-integrity control on the SEI path (the request HMAC signs requests, nothing verifies responses — the ratified, documented model). This flag lets a **keyed, non-loopback** deployment talk to Loomweave over plaintext, so an on-path attacker can forge a `resolve` response into a **wrong-but-stable identity binding (identity_stable=True)** with no TLS break. Off-by-default and INSECURE-named, so **not a blocker**, but its binding-integrity blast radius is documented nowhere. Add a one-line warning log when it bypasses HTTPS on a keyed/non-loopback host + a sentence in the federation trust-model doc.
- **POLICY-1 fixture-auto-skip residual.** A test whose conftest fixture is edited to `pytest.skip()` never runs but its fingerprint is unchanged (fixture body lives elsewhere). Genuinely in the parity-unfixable class (out-of-band signal), so non-blocking — but currently **undocumented**; add it to the disclosed-residual list to keep the honesty claim complete.

---

## POST-1.0 / tracked (non-blocking)

- **F1 code hardening** — config/identity-derived verification requirement, or sign-all-appends (see F1 above).
- **JUDGE-4** — a coached transport error (`LLMTransportError`) propagates and writes **no** record (`engine.py:80`). Fail-closed at outcome (no accept), but contradicts the module's "exactly one append-only record, no silent path" guarantee — a failed override attempt leaves no trace. LOW.
- **hooks.py:59** — the SessionStart/MCP-boot freshness probe (`refresh_instructions`) is still **first-marker-only** (`_extract_marker_token`), the pattern INSTALL-1's commit fixed in `doctor`. On a split brain it silently no-ops (no warning); only operator-invoked `legis doctor` surfaces it. Functional impact low (re-injection can't collapse a split brain anyway), but INSTALL-1 patched the *gate* not the *trigger*. LOW.
- **ID-SEI-2** — `resolver.py:192` `alive` truthiness not type-checked (a hostile/buggy Loomweave returning `"false"` reads as alive). Gated by TLS trust; LOW.

---

## DECISION FOR THE HUMAN (not the reviewer's to make)

`docs/release-1.0-risk-audit.md` is **git-tracked and ships publicly**, and contains **end-to-end-reproduced attack recipes** — the POLICY-1 disable-after-pin sequence, the GOV-1 lineage-tamper-reads-green path, the AUD-1 delete-and-rechain method, and now (if this doc ships too) the JUDGE-3 / F1 mechanisms. For a public 1.0 this is a disclosure decision: intentional transparency, or move the working recipes to a private security record and ship a sanitized "Known limitations" summary? **Flagged, not decided.**

---

## Confirmed HOLDS under adversarial attack (the audit's closures that survived)

> **Attribution.** This pass exists because self-verified closures aren't trustworthy — so the table marks what the orchestrator personally re-verified (code read / PoC) vs what rests on a subagent's report. The one *load-bearing* HOLDS (crypto-threshold, which gates the whole deferral verdict) was orchestrator-verified.

| Closure / claim | Verdict | Verified by | Note |
|---|---|---|---|
| **Crypto-threshold NOT crossed** (no external/non-Python verifier of a legis-*produced* HMAC) | **HOLDS** | **orchestrator** (read `weft_signing.py:30-34`, the one cross-process legis-produced HMAC) + subagent | Weft transport HMAC uses `json.dumps(ensure_ascii=True)`, **not** `canonical_json` — so the deferred canonicalization issues don't ride it; and it is request-auth, not a governance attestation. Filigree stores `binding_signature` verbatim & never verifies; Wardline seam is legis verifying *inbound*. The deferral-gating assumption survives. |
| **GOV-1** lineage-integrity precedence | **HOLDS** | **orchestrator** (read `app.py:751-755`) | `diverged > unverified > verified`; no input combo yields a green top-line on a real divergence. |
| **AUD-1** in-place edit / reorder / prefix-delete-renumber | **HOLDS** | **orchestrator** (read `protected.py:118-182` v3 path) + subagent PoCs | v3 `chain_seq`-binding (seq taken from the column, not payload) + contiguity reject all three. *(Modify-to-unsigned & tail-truncation are NOT in this set — see F1.)* |
| **AUD-3** `synchronous=FULL` | **HOLDS** | subagent | Applied on every connection open (event listener + NullPool), not just create. |
| **AUTH-1** + API authz | **HOLDS** | subagent | Default fail-closed; all 11 write/operator endpoints scope-gated; no unprotected mutation route. |
| **Override-rate gate** | **HOLDS** | subagent | Padding-via-chill defeated; window/sub-sample residuals are *visible* (distinct status + `sample_size`), not silent. |
| **Judge prime fail-open** (error/timeout/unparseable → BLOCKED, never ACCEPTED) | **HOLDS** (coached) | subagent | Every transport/parse failure is BLOCKED or a non-accepting error. (Protected cell: see JUDGE-3.) |
| **Structural prompt injection** (forged sibling `verdict` key) | **HOLDS** | subagent | Rationale is `json.dumps`-escaped into a string value; verdict parsed from a structured field, not scraped. |
| **JUDGE-1 cap** | **HOLDS** | subagent | Reject-not-truncate, before `build_prompt`, measured on serialized request (binds rationale + entity together, post-`ensure_ascii`). |
| **POLICY-2** exemption-rescue deletion | **HOLDS** | subagent (grep) | Orphan-free across src/tests/config; `test_grammar_has_no_exemption_rescue_mechanism` pins both prongs. |
| **INSTALL-1** doctor split-brain detection | **HOLDS** | subagent | Counts own open markers, foreign-fence-aware, surfaces `error` (non-auto-repairable). |
| **C-8 key confinement / no signing oracle** | **HOLDS** | subagent | No MCP tool returns key material; agent-supplied `file_fingerprint` is recomputed from source bytes before signing; non-path entities honestly recorded `unverified`. |
| **Install secret invariant** | **HOLDS** | subagent | No key/token written to any tracked file; `.mcp.json` env is `{}`; `--repair` non-destructive on governance. |
| **scan_route** server-owned + fail-closed | **HOLDS** | subagent | Unconfigured/request-routing → `SERVER_OWNED` deny; unknown cell/severity → `MALFORMED`. |
| **SEI degrade paths** | **HOLDS** | subagent | All 11 enumerated degrade modes fail-closed to a locator key with `identity_stable=False`. |
| **ID-3** signed capability probe | **HOLDS** | subagent | Probe signed when keyed; `signed=False` knob removed; forged probe alone = denial, not wrong binding. |

---

## Recommendation

Close the **3 must-fix items — JUDGE-3, GOV-2, and the F1 docstring** (all small, localized, each with one pinning test), do the **should-fix honesty hygiene** (POLICY-1 aliased-marker hardening, the user-facing "Known security limitations" section incl. the coached model-robustness limit, ID-SEI-1 doc+warning, the fixture-skip residual), make the disclosure call on the public attack-recipe doc, then re-run the strict suite and cut 1.0. File the F1 code hardening, JUDGE-4, hooks.py symmetry, and ID-SEI-2 as tracked post-1.0 issues. The crypto threshold remains uncrossed and the deferrals stay validly deferred.
