# Weft shared conformance vectors

These JSON files are the **canonical, cross-member wire-contract vectors** for the
Weft federation. They exist because the Weft incident of 2026-06-10 traced its most
dangerous failure (G1 — Wardline renames a wire key, re-signs HMAC-clean, and legis
routes **zero findings under a green `verified` status**) to root cause #2:

> Most wire contracts — the findings payload, the kind vocabulary, the suppression
> vocabulary — are hand-copied on both sides with no shared test. A rename on one
> side passes its own tests, re-signs cleanly, and breaks the other side invisibly.

The fix is a single executable vector loaded by the **producer's CI and every
consumer's CI**. A contract fix without its vector just re-creates the drift.

## Files

| File | Contract | Producer | Consumers |
|---|---|---|---|
| `wardline_scan_artifact.v1.json` | `weft/wardline-scan-artifact` | Wardline (`core/legis.py`) | legis (`wardline/ingest.py`) |
| `wardline_dirty_scan_artifact.v1.json` | `weft/wardline-dirty-scan-artifact` | Wardline (`core/legis.py`) | legis (`wardline/ingest.py`) |

## How each side loads it

- **legis (consumer)** — `tests/contract/weft/test_wardline_scan_artifact_contract.py`
  drives every `valid`/`invalid` case through `active_defects` and the real signer,
  and asserts the vector's declared anchors (`findings_key`, `defect_kind`,
  `known_kinds`) equal the constants legis ships. The dirty vector drives the
  unsigned dev-artifact path through `verify_wardline_artifact` for keyless dev,
  CI skip, and explicit dev-mode governance.
- **Wardline (producer)** — loads the **same bytes** and asserts that emitting each
  `valid` artifact reproduces `expected_signature`, and that its `Kind` /
  `SuppressionState` enums equal `known_kinds` / the suppression vocabulary. It
  also loads the dirty vector and asserts a live dirty `allow_dirty` emit carries
  the same top-level key set, `dirty: true`, and no `artifact_signature`.

This file is the source of truth. It is **vendored byte-for-byte** into each repo
(no submodule); the `expected_signature` field is the drift detector — if either
side's canonical-JSON + HMAC formula diverges, the signature stops reproducing and
CI fails on that side. When the contract changes, bump the `version`, regenerate
`expected_signature`, and update **both** repos in the same logical change.

## Dirty vector schema (`wardline_dirty_scan_artifact.v1.json`)

- `contract`, `version` — identity; consumers pin these.
- `dirty_key` — the top-level boolean key Legis consumes to classify an unsigned
  dirty dev artifact.
- `signature_key` — the key that must be absent on dirty dev artifacts.
- `signing.key_utf8` / `signing.policy` — the consumer key used to prove CI
  posture rejects unsigned dirty artifacts unless explicit dev-mode is enabled.
- `valid[]` — `{name, description, artifact, expected_keyless_artifact_status,
  expected_ci_allow_dirty_artifact_status, expected_ci_reject_reason}`.

## Vector schema (`wardline_scan_artifact.v1.json`)

- `contract`, `version` — identity; consumers pin these.
- `findings_key` — the batch key carrying the findings list (G1 anchor).
- `known_kinds`, `defect_kind` — the finding-`kind` vocabulary, carried verbatim
  from Wardline `core/finding.py::Kind` (G1-twin anchor).
- `signing.key_utf8` / `signing.scheme` / `signing.covers` — how
  `expected_signature` is computed.
- `valid[]` — `{name, description, artifact, expected_active_fingerprints,
  expected_signature?}`. A clean scan still carries `findings: []`.
- `invalid[]` — `{name, description, artifact, reject_match}`. Each must raise a
  `WardlinePayloadError` whose message matches `reject_match` — never read as zero
  defects under a green status.
