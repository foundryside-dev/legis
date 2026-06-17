# Design Notes

This directory holds Legis-specific design material.

## Current documents

- `legis-charter.md` - product role, authority boundary, and status

## Architecture decision records

The `adr/` directory holds the accepted decisions, in order:

- [`adr/0001-stack-and-architecture.md`](adr/0001-stack-and-architecture.md) — picks the Python stack and the foundation architecture (persistence model, API shape), and records *why* (the protected-cell machinery already exists in Python in the elspeth ancestor, making this a port rather than a rewrite).
- [`adr/0002-complex-tier-governance-parameters.md`](adr/0002-complex-tier-governance-parameters.md) — fixes where the complex tier's three governance parameters live and who may change them (the HMAC signing key, the protected-policy set, the override-rate gate's threshold/window/floor) — on the rule that the governed party must not be able to tune the gate to pass.
- [`adr/0003-filigree-binding-availability.md`](adr/0003-filigree-binding-availability.md) — resolves what happens when a sign-off→Filigree binding has no stable SEI to key on: it fails closed (`BINDING_UNAVAILABLE`) rather than minting a binding that would orphan on the next rename.

## Related planning docs

- Spec: `../superpowers/specs/2026-06-01-legis-federation-repo-design.md`
- Plan: `../superpowers/plans/2026-06-01-legis-bootstrap.md`
