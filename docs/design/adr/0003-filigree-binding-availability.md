# ADR-0003 — Filigree binding availability when identity is unstable

**Date:** 2026-06-06
**Status:** Accepted
**Finding:** Q-M6 (architecture analysis 2026-06-06) / baseline audit M4

## Context

`bind_signoff_to_issue` (`governance/signoff_binding.py`) attaches a cleared,
governed sign-off to a Filigree issue as an *entity association* keyed on the
entity's SEI (`entity_id` = the SEI, opaque to Filigree). Keying on the SEI is
what makes the code↔governance binding survive a rename or move — the whole
point of the binding.

A binding therefore **requires a stable identity (an SEI)**. The function
rejects an `identity_stable=False` (locator) key: an unstable binding would
orphan the moment the entity is renamed, which is exactly the failure the
binding exists to prevent.

The consequence flagged by Q-M6: a stable SEI is produced by Loomweave. When
Loomweave is **degraded or unavailable**, a sign-off can still be *recorded*
(the governance decision is local and never depends on Loomweave), but it
**cannot be bound** to Filigree, because the entity is still locator-keyed.
Binding availability is thus coupled to Loomweave's SEI capability — and the
question is whether that coupling should be silent, deferred, or explicit.

Three options were on the table:

- **(a) fail closed** — reject the binding when no stable identity is available.
- **(b) resolve through backfill events** — at bind time, look up whether the
  locator has since been backfilled to an SEI and bind on that.
- **(c) surface a "binding-deferred" state** — accept a placeholder binding and
  reconcile it later when identity stabilises.

## Decision

**The binding-availability contract is (b)-then-(a): resolve through backfill at
bind time, and fail closed otherwise. (c) is explicitly rejected.**

1. **Recovery first — backfill resolution at bind time.** The `bind-issue`
   handler already consults the governance trail: when the sign-off's entity is
   locator-keyed, `_binding_entity_from_backfill` walks the trail for a
   `SEI_BACKFILL` event that maps this `original_seq`'s locator to a now-stable
   SEI and binds on that. So a sign-off recorded while Loomweave was degraded
   becomes bindable as soon as `sei-backfill` has resolved its identity — no
   re-issuing of the sign-off, no operator ceremony beyond running the backfill.
   (Tested: `tests/api/test_combinations_api.py` binds a locator-keyed sign-off
   via its backfill event.)

2. **Fail closed when no stable identity exists.** If the entity is neither an
   SEI nor backfill-resolvable, `bind_signoff_to_issue` raises and the HTTP
   surface returns **409 Conflict** with an explicit message ("cannot bind a
   sign-off on an … (locator) key — the binding would orphan on rename; resolve
   to an SEI first"). This is deliberate and visible, not a silent skip. The
   governance record stands; only the *Filigree pointer* — a convenience that
   lets an issue reference the attestation — is withheld until identity is
   stable. (Tested: `tests/governance/test_signoff_binding.py::`
   `test_locator_keyed_signoff_is_rejected_as_unstable`.)

3. **No deferred-binding state (rejected (c)).** A placeholder binding keyed on
   an unstable locator is precisely the orphan-on-rename hazard the SEI keying
   exists to avoid, and a reconciliation subsystem is unjustified machinery for
   a pointer that backfill already repairs. A consumer that needs the binding
   and finds none must treat its absence as "not yet bindable," not "bound."

## Consequences

- **Binding availability is honestly coupled to identity stability, and the
  coupling is surfaced (409), never silent.** An operator who sees the 409 knows
  the remedy: resolve the entity's identity (run `sei-backfill`) and re-bind.
- **The sign-off is never lost.** Governance is recorded independently of
  Loomweave; only the issue pointer waits for a stable SEI.
- **A policy that *requires* a binding to be present** (e.g. a closure gate that
  refuses to clear an issue without a bound attestation) inherits the fail-closed
  posture for free: no binding ⇒ the gate does not clear. This is the desired
  behaviour — an issue is not certified closed on an unbindable attestation.
- The ledger's `verify()` remains the integrity surface: a Filigree pointer with
  no verifiable local ledger entry is exactly what it surfaces, so the
  attach-then-record ordering (no compensating delete) stays an accepted
  trade-off rather than a gap.

## Related: Filigree transport posture (G11)

The HTTP channel that carries the binding (`filigree/client.py`) is
transport-open because Filigree's classic entity-association route deliberately
does not verify `X-Weft-*` headers. Legis therefore sends no transport HMAC on
Filigree binds. The binding `signature` remains an *app-level* attestation about
WHAT is bound and is stored in the JSON body; Legis's local `BindingLedger`
remains the verifier.

The wire body still uses `_json_body_bytes` — JSON with **sorted keys** and
**compact `(",", ":")` separators** — so body-level fixtures and app-level
binding signatures stay stable across Python dict insertion order and spacing
changes.
