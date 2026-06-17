# Stable Entity Identity (SEI) Conformance Notes

> The authoritative SEI standard lives in the Weft hub at `~/weft/sei-standard.md` (promoted there from the Wardline specs tree, 2026-06-05). All "SEI spec §N" references below are to that document. This file is Legis's own **consumer-side** conformance notes — its obligations, REQ-L-01/02, and resolutions — not a restatement of the standard.

Legis is a **consumer** of Stable Entity Identity (SEI), not the authority.

## Core posture

- Loomweave mints, persists, re-binds, and resolves SEI.
- Legis treats SEI as opaque.
- Legis must never derive, parse, or reinterpret SEI structure.

## Conformance obligations (SEI spec §5)

These are legis's formal §5 obligations — confirmed, not aspirational.

> **IMPLEMENTED (Sprint 5, 2026-06-02; HTTP surface unified Phase 9, 2026-06-17).**
> All six obligations are discharged and proven by the SEI §8 conformance oracle
> (`tests/conformance/test_sei_oracle.py`, six scenarios green). Map: keyed-on-SEI
> → `identity/resolver.py` + `api/app.py:resolve_for_record`, wired into **every**
> governance write path. Since Phase 9 the writer-side submit paths are reached
> through a single policy-routed `POST /overrides` (the floored governance cell —
> chill / coached / structured / protected — selects the gate); the
> operator-clear paths stay distinct (`/protected/operator-override`,
> `/signoff/{seq}/sign`). The SEI keying is identical on every dispatch: each
> service function (`submit_override` / `request_signoff` /
> `submit_protected_override` / `submit_operator_override`) calls
> `resolve_for_entry` internally, so a protected-floor dispatch carrying an
> `entity_sei` still keys the record on the live SEI (`identity_stable=True`).
> Opaque treatment → `EntityKey.from_sei` (value stored verbatim, never parsed);
> lineage spine + two-axis + governance-gap → `governance/gaps.py` and
> `GET /governance/identity-gaps`; honest degrade → `IdentityResolver.resolve`
> (`identity_stable: false` on absent capability / no client / not-alive /
> transport error). See Sprint 5 plan for the scope lines on the lineage-snapshot
> extension and cross-store gap detection.

- **Attestations keyed on SEI.** Governance verdicts, sign-offs, and policy
  decisions that concern a code entity are keyed on SEI — never on a locator.
  A locator-keyed binding is legacy to migrate.
- **Opaque treatment.** SEI is consumed as an opaque token. Legis never
  inspects its internal structure.
- **Lineage as audit spine.** `lineage(sei)` (born / locator_changed / moved /
  orphaned / superseded) maps directly to legis governance lifecycle states.
  Loomweave's append-only lineage log is the authoritative source for identity
  history that legis surfaces to human reviewers.
- **Honest degrade.** When Loomweave does not advertise the `sei` capability,
  every verdict row receives an explicit `identity_stable: false` flag. Legis
  does not silently fall back to locators as stable keys.
- **Governance gap on orphan.** When `resolve_sei(sei)` returns `alive: false`,
  legis surfaces a governance gap: the entity had an attestation; its identity
  is now orphaned; the attestation is in limbo. This relies on the §4
  `{ alive: false, lineage: [...] }` contract — recorded as legis's *reliance*
  on existing behavior, not a new requirement.
- **Two-axis status.** Legis preserves the identity axis (SEI alive / orphaned)
  and content axis (content_hash fresh / stale) as distinct, never collapsed.

## Planned provider contribution to Loomweave

SEI spec §6 names a seam: "if/when `legis` ships a git interface, that signal
can move behind it with no change to the SEI model." Legis **claims this seam**:
once the git interface is built, legis will supply the git-rename and history
events the §3 matcher consumes. This does not move identity authority out of
Loomweave.

The provider interface design should be shaped with legis as the planned first
implementer, so the seam does not calcify as Loomweave-internal before legis ships.
This is a sequencing request, not a wire-contract change.

## Pre-lock requirements (SEI spec §0.5 intake)

Legis's concrete emerging requirements, for the ratification window before SEI
locks. See also `docs/superpowers/specs/2026-06-01-legis-roadmap-to-first-class.md`
Appendix A for the full context.

**REQ-L-01 — Lineage tamper-evidence approach (lock-blocking).**
SEI §2.2 describes Loomweave's lineage as tamper-evidence-**able** but does not
specify *how*. Legis's protected cell is built on the custody axiom:
integrity is re-established at the governance boundary, not assumed from the
store. Before lock, Loomweave must commit to one of:
1. The `lineage(sei)` response carries a hash chain or signature the consumer
   can verify.
2. The lineage endpoint is served from an append-only store with no backfill
   path; transport (TLS) is the custody seal.
3. Out of scope for SEI v1; each consumer establishes its own integrity layer
   over polled snapshots.

Option 3 is acceptable to legis for v1 — legis will store a snapshot hash of
the lineage at each governance decision and detect divergence on re-read. The
ask is that the approach be *explicit*, not left ambiguous.

> **RESOLVED (2026-06-02) — Loomweave committed to Option 3.** Loomweave ships **no**
> lineage hash-chain or signature in v1 (`contracts.md` §legis governance
> consumption: "Integrity is legis's boundary, not Loomweave's"). legis establishes
> prefix-hash custody at the governance boundary: it stores
> `{length, hash(lineage[:length])}` at each decision and, on re-read, verifies
> the snapshot is still a **prefix** of the current lineage — appends (rename/move)
> are legitimate, a truncated or mutated prior event is divergence. Implemented in
> `governance/gaps.py:find_lineage_divergence`; demonstrated by Sprint 5 Task 5.

> **Custody seal depends on TLS (ID-SEI-1).** Because Option 3 makes transport the
> custody seal for SEI responses (the Weft request HMAC authenticates legis's
> *requests*, not Loomweave's *responses*), TLS is the only response-integrity
> control on the SEI path. `LEGIS_ALLOW_INSECURE_REMOTE_HTTP=1` permits plaintext to
> a remote Loomweave/Filigree and therefore **voids that seal** — an on-path attacker
> could forge a resolve response into a wrong-but-stable identity binding with no TLS
> break. The flag now logs a warning when it bypasses HTTPS on a non-loopback host and
> is for **dev/loopback use only**, never a keyed production deployment.

**REQ-L-02 — §6 provider seam design (non-blocking; sequencing).**
The SEI §3 matcher's git-rename detection should be designed as a typed
provider interface (not Loomweave-internal) before it ships, so legis can supply
the event when its git interface is ready. No wire-contract change; sequencing
only.

> **RESOLVED (2026-06-02) — Loomweave built the seam.** Loomweave ships the typed
> `GitRenameSource` trait + a `LegisGitRenameSource` consumer that pulls
> `GET /git/renames` and owns the path→locator translation (legis stays
> path-level). legis's provider half is contract-locked by
> `tests/contract/test_git_renames_contract.py`. Operative enablement is jointly
> gated on Loomweave driving a committed rev-range (window-mismatch gap, surfaced
> in loomweave/docs/federation/contracts.md) — not a legis build item.

**Informational — lineage push surface.**
A push/event surface on lineage would let legis react to SEI lifecycle events
without polling. Legis v1 will use pull-only polling and accept the latency.
Flagged as a possible future SEI-vN consideration, not a lock-blocking demand.
