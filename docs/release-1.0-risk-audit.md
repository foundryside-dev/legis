# legis 1.0 — pre-release risk audit

> Multi-agent deep-dive: 9 specialist finder lanes over the high-risk surface, adversarial verification of decision-critical findings, synthesized go/no-go. Suite green (767 passed, strict filterwarnings), 92% coverage. Generated 2026-06-08 on branch rc4 (commit 4a254f2).

## Verdict: GO-WITH-FIXES → effectively GO

> **Resolution update (2026-06-08, commits `0dabc8b`…`b36939d` + working tree; suite now 804 passed, 2 skipped).**
> **All 2 blockers and all 8 tracked follow-ups are now resolved** — 7 in committed source, the final 3 `low` items in the working tree (uncommitted). The crypto threshold remains uncrossed and judge-injection remains fail-closed (now additionally hardened). Filigree: the 3 `low` items were filed (`legis-cbedf16dd9` AUTH-1, `legis-e512e97bfc` POLICY-2, `legis-dfc5632033` CRYPTO-THRESHOLD-001) and closed on fix; the 7 earlier findings were resolved directly via commits and were never ticketed.

| Finding | Tier | Status | Commit | Verification |
|---|---|---|---|---|
| **GOV-1** | blocker | ✅ closed | `41e0b20` | `api/app.py` status now `"diverged" if divergences else "unverified" if unavailable else "verified"` |
| **POLICY-1** | blocker | ✅ closed | `0dabc8b` | additive `_DISABLING_MARKERS` + `POLICY_BOUNDARY_TEST_DISABLED`; Q-L5 decorator-strip contract preserved |
| **AUD-1** | post-1.0 (high) | ✅ closed | `acdbff0`, `cf42727` | v3 `chain_seq`-binding + `store/head_anchor.py`; replay honestly documented as a known unclosed limit |
| **AUD-3** | post-1.0 (med) | ✅ closed | `691e838` | `PRAGMA synchronous=FULL` |
| **INSTALL-1** | post-1.0 (med) | ✅ closed | `0a9cfe9` | doctor split-brain detection (no longer first-marker-only) |
| **ID-3** | post-1.0 (low) | ✅ closed | `98c9f5c` | SEI capability probe signed via `weft_signing` when keyed |
| **JUDGE-1** | post-1.0 (med) | ✅ closed | `b36939d` | `MAX_JUDGE_REQUEST_CHARS` cap, reject-not-truncate |
| **AUTH-1** | post-1.0 (low) | ✅ closed (uncommitted) | working tree | `api/app.py:103` comment now states the flag grants unscoped tokens operator authority; `legis-cbedf16dd9` |
| **POLICY-2** | post-1.0 (low) | ✅ closed (uncommitted) | working tree | exemption-rescue mechanism **removed entirely** — `policy/exemptions.py` + `tests/policy/test_exemptions.py` deleted, `PolicyGrammar` exemptions param/branch dropped; regression guard `test_grammar_has_no_exemption_rescue_mechanism` pins it stays gone; `legis-e512e97bfc` |
| **CRYPTO-THRESHOLD-001** | post-1.0 (low, doc) | ✅ closed (uncommitted) | working tree | README note scopes "cryptographic layer" to intra-suite HMAC tamper-evidence / self-asserted actor, not third-party proof; `legis-dfc5632033` |

> Note: POLICY-2's exemption-rescue path was tested-but-unwired (a `VIOLATION→CLEAR` bypass surface reachable only by future wiring), not active dead code. Closed by **removing the mechanism outright** — the cleanest fix, since it eliminates the bypass surface rather than documenting around it; a regression test pins that it cannot be re-introduced by accident.

---

_Original audit (as generated on `4a254f2`) follows._

legis 1.0 is GO-WITH-FIXES: 2 fail-closed honesty breaks must close first; crypto threshold is NOT crossed and judge-injection is fail-closed, so neither forces a NO-GO.

## legis 1.0 release verdict: GO-WITH-FIXES — 2 blockers

Ship after closing **POLICY-1** and **GOV-1**. Both are confirmed fail-closed *honesty breaks* — a governance gate reports green on exactly the condition it exists to catch. Neither is a systemic flaw; the rest of the suite (9 lanes, 767 tests green, 92% coverage) is sound and fail-closed where it counts. No NO-GO.

### The two decision-driving questions

**Does 1.0 cross the cryptographic-guarantees threshold? NO.** The crypto lane enumerated every verifier of a legis-produced `canonical_json` HMAC — all are same-process Python (TrailVerifier, binding_ledger, the protected-cell verify). The only cross-process verify (`verify_wardline_artifact`) checks Wardline's *inbound* signature against a deliberate byte-for-byte Python replica, not a legis attestation, and not cross-language. The legis→Filigree `attach(signature=...)` is an app-level string Filigree merely records; the Filigree transport is deliberately open on the classic route. So no non-Python consumer cryptographically verifies a legis attestation. The protected-cell HMAC is exactly what the docstring claims: intra-suite tamper-evidence against a DB-file-holder, not a third-party cryptographic guarantee. Therefore the settled deferrals (ensure_ascii, v1-canonical, unsigned-channel fallback, dirty-tree) stay post-1.0 and fail *visibly*. The tripwire is named and one-file-sized: the day a non-Python verifier of a legis attestation lands, the v1-canonical deferral becomes a blocker.

**Judge-injection result: fail-closed.** The prime fail-open hypothesis — LLM error/timeout/unparseable response → ACCEPTED — is DISPROVEN: every transport/shape failure raises `LLMTransportError`, propagates with no record written, and surfaces as INTERNAL_ERROR, never ACCEPTED. Structural prompt injection (forging a sibling `{"verdict":"ACCEPTED"}` key) is closed because the agent rationale is JSON-escaped into a string value. The only residual is the coached cell, where a *semantic* injection that fools the judge model clears the gate with no defense-in-depth — that is a model-robustness property, not a code fail-open, and is post-1.0 (JUDGE-1).

### The 2 blockers

1. **POLICY-1 (policy-engine, high)** — `decorator.py:121` blanket-strips `decorator_list` before fingerprinting a `@policy_boundary`'s evidence test. Adding `@pytest.mark.skip`/`@xfail` after a human pins the test yields a byte-identical fingerprint, so the CI `policy-boundary-check` stays green while the proof test no longer runs. Reproduced end-to-end. The decorator strip is the load-bearing Q-L5 parity contract and must NOT be reverted; the fix is additive — emit a `POLICY_BOUNDARY_TEST_DISABLED` finding when the evidence test carries a skip/xfail marker. This is the canonical agent-first disable-after-pin path.

2. **GOV-1 (governance-honesty, high)** — `app.py:742` computes the `/governance/lineage-integrity` headline as `"unverified" if integrity.unavailable else "verified"`, ignoring `integrity.divergences`. A confirmed external-Loomweave lineage tamper (empty `unavailable`, populated `divergences`) is reported `status="verified"`. Self-incriminating: the *lesser* can't-fetch failure already maps to "unverified", so reporting the *greater* confirmed-tamper as "verified" is internally incoherent. One-line fix: treat any divergence as not-"verified" (emit "diverged").

Both fixes are small (one additive rule; one boolean), localized, and each needs one test that pins the headline/finding on the tamper case (the existing tests assert the *data* is present but pointedly skip the *status*/marker assertion).

### Top tracked follow-ups (non-blocking)
- **AUD-1 (high, post-1.0):** out-of-band DB-file delete-and-rechain is undetectable because `signing_fields` binds content but not position; real, but outside the stated forgery guarantee and needs the conceded file-write capability. Bind `seq` into the signature (v3) + persist an out-of-band head anchor.
- **AUD-3 / JUDGE-1 / INSTALL-1** as listed; the rest are doc/naming/coverage nits.

Recommendation: close POLICY-1 and GOV-1 with their tests, re-run the strict suite, then ship 1.0. File AUD-1, AUD-3, JUDGE-1, and the doc caveats as tracked post-1.0 issues.

## Per-lane summary

- **crypto** — GO — threshold NOT crossed: no non-Python consumer verifies a legis-produced attestation, all same-process verifiers; canonical/unsigned deferrals stay post-1.0 and fail visibly. 0 blockers, 1 low doc caveat.
- **audit-trail** — GO-WITH-FOLLOWUP — in-place tamper is genuinely sound; AUD-1 deletion/truncation re-chain gap is real+high but verifier ruled NON-blocker (out-of-band file-write, documented gap not a lie). AUD-2 refuted (seq reuse breaks the signed content_hash, not silent). 0 blockers.
- **policy-engine** — NO-GO until POLICY-1 fixed — @policy_boundary fingerprint is blind to @skip/@xfail, a confirmed agent-first false-green honesty break on the CI-enforced gate. 1 blocker.
- **mcp-surface** — GO — C-8 key-confinement holds; MCP-1 (protected-cell vs protected_policies config split) verifier-downgraded to a non-blocker operator-misconfig footgun (no agent reach, honest escalation in the human-gate cell). 0 blockers.
- **api-authz** — GO — unconfigured server fail-closed 401 on all writes; AUTH-1 unscoped-token flag is by-design/default-closed/not-agent-reachable. 0 blockers.
- **judge-injection** — GO — prime fail-open (error/timeout/unparseable -> ACCEPTED) DISPROVEN, fail-closed to BLOCKED; structural injection closed by JSON-escaping. Coached-cell semantic injection is a post-1.0 model-robustness note. 0 blockers.
- **governance-honesty** — NO-GO until GOV-1 fixed — /governance/lineage-integrity reports status=verified on a confirmed lineage divergence (keys only on unavailable). 1 blocker.
- **identity-sei** — GO — every SEI degrade path fail-closed to a locator key with identity_stable=False; uncovered lines benign. 0 blockers, 1 low unsigned-probe note.
- **install-doctor** — GO — secret invariant holds (no key/token ever written to a committed file), --repair non-destructive on governance; split-brain/backup-clobber/env-overwrite are post-1.0. 0 blockers.

## Blockers (must close before 1.0)

### POLICY-1 — high
- **Location:** src/legis/policy/decorator.py:120-121 (get_normalized_ast_str strips decorator_list); gate teeth in evaluate_test_evidence, reached via decorator.py:206 runtime + boundary_scan.py:159 static
- **Claim:** The @policy_boundary honesty gate blanket-strips ALL decorators before fingerprinting a boundary's evidence test, so adding @pytest.mark.skip / @pytest.mark.xfail to a previously-pinned test produces a byte-identical fingerprint and the CI drift check (legis policy-boundary-check) stays green while the behavioural-evidence test no longer runs.
- **Impact:** Agent-first disable-after-pin: (1) a human approves a real running test for a self-exempting @policy_boundary and the agent pins meta.test_fingerprint; (2) the boundary suppresses named policies ONLY on the strength of that live test; (3) the agent later edits the test to @pytest.mark.skip(...) — it never executes; (4) fingerprint_source is blind to decorator_list so the hash is unchanged, the runtime drift check (decorator.py:206) and static mismatch check (boundary_scan.py:159) both pass; (5) CI reports PASS. The boundary now carries a self-exemption from named policies with zero executing proof and no human re-review, because nothing flagged drift. pyproject has no xfail_strict/strict-markers, so the suite itself does not fail the skip — the policy-boundary-check green is the sole authoritative signal and it is false-green. Reproduced end-to-end: skip-identical and xfail-identical fingerprints both True; evaluate_test_evidence never inspects decorator_list; no skip/xfail rule exists in boundary_scan._EVIDENCE_RULE_IDS.
- **Fix:** Do NOT revert the decorator strip — it is the load-bearing Q-L5 fingerprint-parity contract (inspect.getsource includes decorators, ast.get_source_segment excludes them). Instead, in evaluate_test_evidence (or boundary_scan), scan the evidence test's decorator_list for pytest skip/xfail/skipif markers and emit a new POLICY_BOUNDARY_TEST_DISABLED finding so a disabled evidence test can never satisfy the gate. Add a tests/policy/ case asserting a @pytest.mark.skip-decorated evidence test fails the boundary check.
- **Verifier:** is_real=true, is_blocker=true, severity=high
- **Resolution (2026-06-08, CLOSED):** Fixed additively in the shared evaluator `evidence.evaluate_test_evidence` — the single point both gates route through, so the runtime gate and the static scanner pick up `POLICY_BOUNDARY_TEST_DISABLED` identically and parity holds by construction. Decorator strip untouched (Q-L5 intact). Detection (`_disabling_marker`) is deliberately broad/fail-closed: terminal-name match on `{skip, skipif, xfail}` for any attribute or bare name, with/without a call, so import-aliased forms (`from pytest import mark` → `@mark.skip`) — whose only tell lives outside the fingerprinted function source — are still caught. Tests: `tests/policy/test_evidence.py` (5 evaluator cases incl. skipif + alias + a no-false-positive parametrize guard), `tests/policy/test_boundary_scan.py` (2 end-to-end killer cases pinning the clean fingerprint then disabling on disk — the `len == 1` + `TEST_DISABLED` rule_id simultaneously proves the fingerprint still matched and the new rule fired), `tests/policy/test_honesty_gate.py` (runtime gate, with an explicit assertion that the disabled fingerprint == the clean one). Strict suite green (775 passed, 2 pre-existing conformance skips); `legis policy-boundary-check` PASS over the real tree (zero shipped decoration sites today, so no live boundary regressed). **Residuals (named, NOT fixed — same false-green class, but unfixable here without breaking Q-L5 parity since the runtime gate only sees `getsource` of the test function/method):** module-level `pytestmark = pytest.mark.skip` and a class-level `@pytest.mark.skip` on the test's enclosing class. Both are documented in the `_disabling_marker` docstring. A future hardening that wants them must add an out-of-band whole-file/class scan on the static side and accept the runtime/static asymmetry, or move evidence-liveness to an execution-time signal.

### GOV-1 — high
- **Location:** src/legis/api/app.py:742
- **Claim:** The /governance/lineage-integrity endpoint computes top-level status as `"unverified" if integrity.unavailable else "verified"`, so a confirmed lineage-prefix divergence (external Loomweave tamper) with an empty `unavailable` list is reported as status="verified".
- **Impact:** An external Loomweave prior event for a protected/SEI-keyed governance record is removed or mutated -> the recorded prefix no longer hashes -> find_lineage_integrity yields divergences=[...], unavailable=[] -> the endpoint returns status="verified". A human-on-the-loop or dashboard alerting on the summary status field sees green while a confirmed lineage tamper sits unread in the divergences array. Internally inconsistent and self-incriminating: the LESSER failure (can't-fetch -> unavailable) maps to "unverified" (test_sei_api.py:170), while the GREATER failure (confirmed tamper) maps to "verified" — no coherent definition of verified makes can't-check not-green but tamper-confirmed green. This is independent of the HTTP-500 audit-store tamper guard (app.py:722), which only covers legis's own HMAC store, not the external entity lineage. Reproduced three ways including direct in-process repro of a length-2 snapshot read back truncated to length-1.
- **Fix:** Make status fail-closed on divergence: status = "verified" only when not integrity.unavailable AND not integrity.divergences; emit "diverged" when integrity.divergences (else "unverified"). Add a status assertion to test_complex_api.py:296, which currently asserts the populated divergences but pointedly omits any status check.
- **Verifier:** is_real=true, is_blocker=true, severity=high

## Tracked follow-ups (post-1.0, non-blocking)

### AUD-1 — high (post-1.0)
- **Location:** src/legis/enforcement/protected.py:50-65 (signing_fields) + src/legis/store/audit_store.py:95-96 (_chain)
- **Claim:** The keyed HMAC and the keyless hash chain both bind a record's content but NEVER its chain position or predecessor, so a holder of write access to .weft/legis/gov.db can drop the SQL triggers, DELETE a damning governance record, and re-chain the survivors with verify_integrity()==True and TrailVerifier.verify() passing.
- **Impact:** A file-write actor can silently prune OVERRIDDEN_BY_OPERATOR / BLOCKED records; the override-rate gate (service/governance.py:119) then reads a truncated trail and computes a lower rate. Reproduced empirically. Verifier downgraded to NON-blocker: deletion forges nothing (it removes a validly-signed true record), so it is outside the signing.py docstring's stated forgery guarantee (lines 4-6) and the audit_store hash-chain scope (edit/reorder, not truncation) — a documented gap-in-coverage, not a lie; and it requires the out-of-band raw-SQLite capability already conceded by the C3 file-write threat tier, with no agent-reachable DELETE surface.
- **Follow-up:** Post-1.0: bind seq (and ideally prev chain_hash) into signing_fields and bump the signature tag to v3; persist the head (seq, chain_hash) as an out-of-band anchor and assert monotonic non-rewind on open; add a deletion/truncation test to tests/enforcement/test_trail_verify.py.

### CRYPTO-THRESHOLD-001 — low (post-1.0)
- **Location:** README.md:7-9,54 vs src/legis/provenance.py:26-27 + CHANGELOG C3
- **Claim:** README advertises SEI-keyed/governance attestations as Live at an altitude a consumer can read as authenticated cross-party cryptographic proof, while the actor is self-asserted (Provenance.UNAUTHENTICATED) and the signing is intra-suite Python-only HMAC tamper-evidence over v1 canonical JSON.
- **Impact:** No exploit (gates fail closed, unsigned path downgrades visibly); the advertised altitude merely exceeds the enforced guarantee. Documentation-only.
- **Follow-up:** Post-1.0 doc edit: one sentence in README §Status / matrix clarifying attestations are HMAC tamper-evidence binding governance to SEI-stable code identity with a self-asserted actor, not third-party-verifiable authenticated proof — the scope the C3 charter note already records.

### AUTH-1 — low (post-1.0)
- **Location:** src/legis/api/app.py:105,110
- **Claim:** LEGIS_ALLOW_UNSCOPED_API_TOKENS=1 makes any colon-less (unscoped) token satisfy both writer and operator scopes.
- **Impact:** Verifier ruled by-design + default-closed (default rejects unscoped tokens with 403, tested at test_auth.py:138) + not agent-reachable (human-set env, C-8) + the flag faithfully restores the documented pre-H7 operator semantics. Residual is a naming/doc nit only.
- **Follow-up:** Post-1.0: rename or document the flag so it telegraphs 'grants operator authority'; consider downgrading unscoped to writer-only.

### JUDGE-1 — medium (post-1.0)
- **Location:** src/legis/enforcement/engine.py:92; src/legis/enforcement/judge.py:79-86
- **Claim:** In the COACHED cell a model ACCEPTED maps directly to accepted=True with no defense-in-depth and no length cap/sanitization on the agent-controlled rationale, so a semantic prompt injection that persuades the judge model clears the gate.
- **Impact:** Model-robustness property, not a code fail-open — structural injection is closed by JSON-escaping (judge.py:85) and transport/parse failures are fail-closed to BLOCKED. The coached accept is at least attributable (judge_verdict/model/rationale recorded).
- **Follow-up:** Post-1.0: cap rationale length before build_prompt and reject over-cap as BLOCKED; add a build_prompt round-trip test (JUDGE-2) pinning the structural-escape defense; document the coached-cell model-robustness limitation.

### POLICY-2 — low (post-1.0)
- **Location:** src/legis/policy/grammar.py:86-97,121
- **Claim:** The VIOLATION->CLEAR exemption-rescue branch and ExemptionAllowlist.from_file are dead code in the shipped product (default_grammar builds PolicyGrammar() with no exemptions); a latent trap if a future wiring loads an agent-writable exemptions YAML.
- **Impact:** No live exploit today. Latent: a future wiring from an agent-writable file could convert a real VIOLATION to CLEAR with no human approver tie.
- **Follow-up:** Post-1.0: delete the unused exemption-rescue path until there is a real wiring, or gate it behind an explicit dev opt-in and record exemptions as 'exempted (unverified)' with provenance_gap=True.

### AUD-3 — medium (post-1.0)
- **Location:** src/legis/store/audit_store.py:64
- **Claim:** The audit store runs synchronous=NORMAL under WAL with no checkpoint discipline, so the tail of governance appends can be lost on OS crash/power loss while leaving a structurally valid, internally-consistent (verify_integrity()==True) shortened trail.
- **Impact:** Silent loss of the newest overrides/sign-offs/blocks with no integrity error — weaker than the durable-trail framing implies. Deliberate trade-off, should be a recorded decision not an implicit default.
- **Follow-up:** Post-1.0: set synchronous=FULL for the audit store (cheap given append-only low write rate) or document the durability tier + add wal_checkpoint(FULL) after governance-critical appends; record in an ADR.

### INSTALL-1 — medium (post-1.0)
- **Location:** src/legis/doctor.py:112; install.py:217,305-319
- **Claim:** A fresh-first + stale-duplicate split-brain legis instruction block reads as healthy/'fixed' through doctor because the freshness probe only inspects the FIRST marker; the only signal is a transient install-time log line.
- **Impact:** An agent can run on two conflicting copies of the legis governance instructions while the operator sees 'install.claude_md: ok'. Not a security bypass.
- **Follow-up:** Post-1.0: make doctor detect >1 legis open fence and return non-ok 'duplicate legis block — resolve by hand' so the split-brain is durable doctor state. (INSTALL-2/3 backup-clobber and env-overwrite are lower-priority companions.)

### ID-3 — low (post-1.0)
- **Location:** src/legis/identity/loomweave_client.py:173-179
- **Claim:** The SEI capability probe is sent unsigned even when an HMAC key is provisioned, so an on-path attacker can spoof capability=supported to flip the resolver out of standalone mode.
- **Impact:** Bounded: the follow-on resolve_locator IS signed and fails closed against a forged SEI, so the net effect of the unsigned probe alone is a spurious capability flip / denial, not a wrong-SEI binding. Loopback-trusted default is the documented model.
- **Follow-up:** Post-1.0 (sibling-gated alongside live-Loomweave oracle): sign the capability probe when an HMAC key is provisioned.
