# PDR-0004 — Ratify + implement the forge-proof attestation classifier (Task 8); correct spec §4

Date: 2026-06-25   Status: accepted (owner ratified the discriminator 2026-06-25; merge still owner-gated)   Author: claude (opus, product-owner)
Unblocks the Task-8 deferral in [[0002-accept-warpline-bet-defer-classifier]]   Related: [[0003-federation-read-doctrine]]; tracker legis-1734128d34; commits da85e16, 1e21418

## Context
PDR-0002 shipped `attestation_get` fail-closed and **deferred** its positive-admission classifier, because the obvious operator-override discriminator is forgeable. The owner **ratified** the four classifier resolutions (2026-06-25, "Done"): (a) operator-override = a *verifying* signature, never the bare field; (b) only *signed* sign-offs attest; (c) no-key deployments → `unavailable`; (d) absent `content_hash` → omit.

## Options considered
1. Key off the (signed) verdict value, trusting that the record is in the verified set.
2. Key off the **signature MARKER presence** (`judge_metadata_signature` / `signoff_signature`) — a strict subset of `_requires_verification`, so "admitted ⟹ verified" holds — integrity-bind the sign-off `content_hash` join via the signed `request_payload_hash`, and read only the signed `entity_key` dict.
3. Keep it blocked (ship no classifier).

## The call
Option 2. Grounding confirmed the load-bearing facts against the real code: `judge_verdict`, `protected_cell`, and the inline `content_hash` are inside `signing_fields` (**FORGE-A closed**); the signed `SIGNED_OFF` carries a signed `request_payload_hash` (**FORGE-B closed**). Both kinds (`operator_override`, `signoff_cleared`) shipped forge-proof. The *necessary-but-not-sufficient* trap (membership in the verified set ≠ the field is signed) is closed by gating admission on the signature marker (a subset of the verification predicate) and keying only on signed fields; the sign-off join recomputes the PENDING hash and compares it to the signed `request_payload_hash` rather than trusting the `request_seq` pointer.

Verified by an **adversarial forge phase** (4 lenses, live-run probes): **zero forges admitted**, both genuine positives admit; full CI gate green (pytest 1237, mypy clean, coverage 92.13%, ruff). Spec §4.1/§4.2/§7 corrected (the false *unconditional* fail-closed claim → conditional on a signature-verifiable trail; lowercase `signed_off` → `SIGNED_OFF`; hand-wave → the confirmed discriminator).

## Rationale
The forge-proof property is **structural**: admission requires the signature marker → the record was cryptographically verified → the keyed fields are authentic. A mutated unsigned field either breaks the signature (→ `AUDIT_INTEGRITY_FAILURE`) or isn't a field the classifier keys off. The sign-off join is integrity-checked, not pointer-trusted. This is the strongest "governed-good" signal warpline can safely skip reverification on, and it keeps the asymmetric rule (any ambiguity → omit).

## Reversal trigger
- If any adversarial review or production incident finds a forged / non-human-cleared record **admitted** → reopen immediately (Critical; the asymmetric rule is breached).
- If the protected / sign-off **signing surface** changes (a keyed field moves out of `signing_fields` / `signoff_signing_fields`) → re-audit the discriminator against the new signed-field set.
- Broadening the admitted set beyond the two human-cleared kinds is additive and requires the same signing-coverage proof per new kind.
