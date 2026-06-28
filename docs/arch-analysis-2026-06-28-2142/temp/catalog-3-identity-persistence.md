## Identity

**Location:** `src/legis/identity/`

**Responsibility:** Resolves git locators to Loomweave-minted Stable Entity Identities (SEIs), producing opaque `EntityKey` values that key governance attestations so they survive rename/move events.

**Key Components:**
- `entity_key.py` (41 lines) — Frozen dataclass holding `value: str` and `identity_stable: bool`; two factory classmethods (`from_locator`, `from_sei`) are the only construction paths; `value` is never parsed downstream — the docstring explicitly states the opacity discipline at line 4.
- `resolver.py` (263 lines) — `IdentityResolver` drives the WP-5.1 upgrade path: returns a locator-keyed (`identity_stable=False`) `EntityKey` on any failure path and an SEI-keyed (`identity_stable=True`) key only on a confirmed-alive Loomweave response; `IdentityResolution` frozen dataclass has a `__post_init__` guard (lines 61–100) that makes it impossible to construct a self-contradictory record (e.g. `alive=True` + status `NOT_ALIVE`).
- `loomweave_client.py` (240 lines) — `HttpLoomweaveIdentity` thin transport wrapper over `urllib`; injectable `fetch` callable for offline tests; HMAC signed via `weft_signing.sign_weft_request` when a key is provisioned; `_validate_base_url` enforces HTTPS for non-loopback hosts (lines 139–159); `_decode_json_response` enforces a 1 MB response cap; SEI strings are URL-quoted but never parsed (lines 224, 232).
- `__init__.py` (1 line) — Module docstring only; no re-exports.

**Dependencies:**
- Inbound: `enforcement/` (uses `IdentityResolver` and `EntityKey`), `governance/signoff_binding.py` (SEI-keyed sign-off), `records/override_record.py` (embeds `EntityKey`)
- Outbound: `canonical.content_hash` (lineage snapshot hashing, resolver.py line 168), `weft_signing` (HMAC transport signing, loomweave_client.py lines 33–38), external Loomweave HTTP service

**Patterns Observed:**
- Fail-closed on every transport and parse error: capability probe failure clears the capability latch (`_capable = None`, resolver.py lines 148–151) so the next resolve retries rather than trusting a stale positive; locator resolve failures and malformed responses all return the `degraded` value (locator-keyed, `UNAVAILABLE`).
- Capability TTL re-probe (5 min window, resolver.py lines 27, 127–153) prevents the positive-latch-forever bug (Q-L6): a Loomweave that loses SEI capability mid-life is noticed within one TTL window.
- `alive is not True` strict identity check (resolver.py lines 194, 232, comment "ID-SEI-2") rejects non-bool truthy values from a buggy or hostile Loomweave — a string `"false"` or integer `1` cannot promote a dead entity to a stable identity.
- `resolve_supplied_sei` returns `None` (not a degraded locator key) when an agent-supplied SEI cannot be confirmed alive (resolver.py lines 171–209): silently demoting an L1 SEI bind to a locator-keyed record is explicitly refused.
- TLS custody warning is emitted but not enforced when `LEGIS_ALLOW_INSECURE_REMOTE_HTTP=1` is set for non-loopback hosts (loomweave_client.py lines 147–158, comment "ID-SEI-1") — the flag is the documented dev-only escape hatch.

**Concerns:**
- The capability TTL and latch-clearing pattern is correct, but a capability probe failure at the START of `_capability()` (before a latch is ever set, `_capable is None`) logs a warning and returns `False` — which is the right degraded behavior. However, if the Loomweave host is reachable but systematically returns a non-`{"sei": {"supported": true}}` body, `_capable` is set to `False` (not `None`) and latched for the full TTL, suppressing re-probes even when the upstream recovers. This is acceptable but is not documented as a known limitation alongside the Q-L6 fix.
- The `content_hash` field on `IdentityResolution` comes verbatim from the Loomweave response (resolver.py lines 200–201, 252–254) and is not independently verified — Legis trusts Loomweave's assertion. This is architecturally correct (Loomweave is the authority), but an on-path attacker who can forge a response (e.g. via the `LEGIS_ALLOW_INSECURE_REMOTE_HTTP` escape) controls the content axis of governance records, which is not called out in the security model.

**Confidence:** High — Read 100% of all four files; cross-verified imports (`resolver.py` line 19 imports `content_hash`, line 20 imports `LoomweaveIdentity`; `loomweave_client.py` lines 33–38 import `weft_signing`). Fail-closed and SEI-opacity behaviors verified line-by-line.


## Store

**Location:** `src/legis/store/`

**Responsibility:** Provides a record-agnostic, append-only, hash-chained SQLite audit store with DB-level UPDATE/DELETE triggers, contiguous-seq verification, and an optional out-of-band head anchor for tail-truncation detection.

**Key Components:**
- `audit_store.py` (457 lines) — `AuditStore` is the implementation; SQLAlchemy with `NullPool` (no lingering locks); `synchronous=FULL` enforced unconditionally (lines 69–77, not configurable); `journal_mode=WAL`; `BEGIN IMMEDIATE` write locks on every append path; `append_signed` (lines 297–312) hands the signer its `(seq, prev_hash)` under the held lock so the v3 HMAC binds the exact position the row receives (AUD-1); `transaction()` (lines 179–212) provides batched appends with thread-local ambient connection; `_assert_no_batch_in_progress` (lines 222–240) turns mid-batch reads into explicit `RuntimeError`s.
- `head_anchor.py` (143 lines) — `HeadAnchor` sidecar file holding `(head_seq, head_chain_hash)` HMAC-signed with `enforcement.signing`; `update` uses temp-file + `os.replace` for atomic writes (line 93); `check` fails closed on missing file (`AnchorError`, lines 107–113) and on signature mismatch (lines 120–121); the REPLAY LIMITATION (a snapshotting attacker can restore a genuine older anchor) is explicitly documented in the module docstring (lines 34–47).
- `protocol.py` (68 lines) — `AppendOnlyStore` Protocol and `AuditRecordLike` Protocol; `transaction()` docstring (lines 57–68) prohibits reads inside batches and documents that `AuditStore` enforces this; `append_signed` contract (lines 27–37) documents the reserve-sign-insert atomicity guarantee.
- `__init__.py` (1 line) — Module docstring only; no re-exports.

**Dependencies:**
- Inbound: `enforcement/engine.py` (imports `AppendOnlyStore` protocol), `enforcement/protected.py` (imports `AnchorError`, `HeadAnchor`, `AppendOnlyStore`), `enforcement/signoff.py` (imports `HeadAnchor`, `AppendOnlyStore`)
- Outbound: `canonical` (`canonical_json`, `content_hash`; audit_store.py line 40), `enforcement/signing` (`sign`, `verify`; head_anchor.py lines 56–57), `legis.config.ensure_sqlite_parent` (lazy import, audit_store.py line 127)

**Patterns Observed:**
- Bidirectional coupling between `store/` and `enforcement/`: `enforcement/` imports `store.protocol` and `store.head_anchor`; `store/head_anchor.py` imports `enforcement.signing`. The dependency graph is: `store.head_anchor` → `enforcement.signing` → `canonical`; `enforcement.{engine,protected,signoff}` → `store.{protocol,head_anchor}`. This forms a cycle at the package level (`store ↔ enforcement`) but NOT at the module level (no circular imports in practice because `audit_store.py` does NOT import enforcement and `enforcement.signing` does not import store).
- `verify_integrity` (lines 362–442) is O(N) by design: checks seq contiguity, recomputes `content_hash` for every payload, walks the `prev_hash` chain, and recomputes `chain_hash`. The `allow_nan=False` in `canonical_json` catches a Nan/Infinity-injected payload that `json.loads` would silently accept (lines 403–415).
- DB-level triggers (lines 161–177) reject UPDATE/DELETE at the SQLite engine before any application logic runs; the application layer has no mutation methods — two independent enforcement layers.
- `append` on an uninitialized (`initialize=False`) path is never called safely against a no-table DB: `_has_log_table` guards reads (lines 314–323) but `_insert` / `_write` would raise `OperationalError` on missing table. This is by design — `initialize=False` is for read-only inspection handles.

**Concerns:**
- The store↔enforcement bidirectional coupling is real but is NOT a circular import at runtime: `store.head_anchor` → `enforcement.signing` → `canonical` is a clean downward dependency; `enforcement.{engine,protected,signoff}` → `store.protocol` / `store.head_anchor` is also clean downward. The cycle is only at the package-name level. The governance-honesty risk is low: neither direction pulls in logic that could silently change a governance decision. However, if `enforcement.signing` ever gains upward imports back into `store`, the current non-circular property breaks silently — a refactor to extract signing into a shared `crypto/` leaf would close this cleanly.
- The head anchor's REPLAY LIMITATION (a snapshotting attacker can restore a genuine earlier anchor and paired truncated DB, and the check passes) is honestly documented in `head_anchor.py` lines 34–47 and in the project README. No mitigating control exists for local-filesystem deployments; the documentation correctly names WORM/remote storage or an external monotonicity monitor as the only closure. This is a conceded residual threat, not a gap.
- `transaction()` nested re-entrance silently reuses the outer batch (lines 201–204), which is the correct behavior for avoid double-commit, but it means a caller who believes it opened a fresh transaction boundary has not — if the outer batch rolls back, so does work the inner caller expected to commit. No warning is emitted on re-entrance. This is low-severity for an append-only store but could surprise future callers.

**Confidence:** High — Read 100% of all four files; cross-verified the bidirectional coupling by grepping all import statements across both packages (head_anchor.py:56–57, enforcement/engine.py:25, enforcement/protected.py:25–26, enforcement/signoff.py:21–22); read enforcement/signing.py in full to confirm it imports only `canonical` (no back-reference to store).


## Crypto/Leaf Primitives

**Location:** `src/legis/canonical.py`, `src/legis/weft_signing.py`, `src/legis/provenance.py`, `src/legis/records/`

**Responsibility:** Provide the canonical JSON serialization, content hashing, transport-HMAC signing, provenance vocabulary, and governance record schemas that all upper layers share without creating inter-layer dependencies.

**Key Components:**
- `canonical.py` (51 lines) — `canonical_json`: `json.dumps` with `sort_keys=True`, `separators=(",",":")`, `ensure_ascii=False`, `allow_nan=False`; `content_hash`: SHA-256 of the UTF-8-encoded canonical form. The `ensure_ascii=False` is the byte-for-byte HMAC contract with Wardline's Python signer; both sides use identical `json.dumps` params, so non-ASCII payloads round-trip without escape divergence. The module docstring (lines 1–34) documents the Q-L4 RFC-8785 deferral, the cross-repo golden vector status, and the condition that triggers the upgrade (a non-Python verifier).
- `weft_signing.py` (91 lines) — `sign_weft_request`: produces `X-Weft-Component`, `X-Weft-Timestamp`, `X-Weft-Nonce` headers; signs `METHOD\npath?query\nsha256(body)\ntimestamp\nnonce`; body canonicalization uses `ensure_ascii=True` (NOT `canonical_json`) to match the transport contract — deliberately different from the audit HMAC contract (lines 38–42, module docstring lines 9–15). `weft_hmac_key_from_env`: channel-specific env var falls back to `LEGIS_HMAC_KEY`.
- `enforcement/signing.py` (61 lines) — `sign`/`verify` for per-record HMACs; version-tagged prefixes (`v2` binds content, `v3` additionally binds `chain_seq`); `verify` accepts both v2 and v3 without ambiguity (lines 57–61); uses `canonical_json` (the `ensure_ascii=False` variant) for HMAC body. This file lives in `enforcement/` but functions as a shared crypto primitive used also by `store/head_anchor.py`.
- `provenance.py` (28 lines) — `Provenance` str-Enum; currently one member (`UNAUTHENTICATED`); shared by `checks/` and `pulls/` without either importing the other.
- `records/override_record.py` (40 lines) — `OverrideRecord` frozen dataclass; `extensions: dict` open field for coached- and protected-cell additions without schema migration; `to_payload()` flattens to dict for `AuditStore.append`.
- `records/__init__.py` (1 line) — Module docstring only.

**Dependencies:**
- Inbound: `canonical` ← `store/audit_store.py`, `enforcement/signing.py`, `identity/resolver.py`, `governance/`, `wardline/` (cross-repo: Wardline's `core/legis.py` replicates the same `json.dumps` call); `weft_signing` ← `identity/loomweave_client.py`, `filigree/`; `enforcement/signing` ← `store/head_anchor.py`, `enforcement/protected.py`, `enforcement/verdict.py`; `records/` ← `enforcement/engine.py`, `governance/`
- Outbound: `canonical.py` — stdlib only (`hashlib`, `json`); `weft_signing.py` — stdlib only (`hashlib`, `hmac`, `json`, `os`, `urllib.parse`); `enforcement/signing.py` — `canonical` only; `provenance.py` — stdlib only; `records/override_record.py` — `identity.entity_key` only

**Patterns Observed:**
- Two distinct canonicalization contracts coexist intentionally: `canonical_json` (`ensure_ascii=False`) for audit HMACs and content hashes; `weft_body_bytes` (`ensure_ascii=True`) for transport HMACs. Both are documented; the module docstrings explicitly cross-reference each other to prevent accidental unification (canonical.py lines 1–34, weft_signing.py lines 1–27).
- `allow_nan=False` in `canonical_json` is a tamper-detection aid: a payload injected with `Infinity` or `NaN` survives `json.loads` but raises on re-canonicalization, which `verify_integrity` catches as tamper rather than a crash (audit_store.py lines 403–415).
- The v2/v3 signature version tag allows the signing primitive to evolve the field set without ambiguity in stored records; `verify` accepts both prefixes, so a store with mixed v2/v3 records verifies correctly.
- `Provenance` as a str-Enum means `json.dumps` / `canonical_json` emit the bare string value without any enum wrapper, keeping wire payloads stable across Python versions and avoiding coercion on read-back (provenance.py lines 14–16).
- `OverrideRecord.extensions` (records/override_record.py line 24) is the deliberate extension point for coached- and protected-cell fields; no schema migration is required to add judge output or HMAC binding to an override record.

**Concerns:**
- `enforcement/signing.py` is located inside `enforcement/` but is consumed as a shared primitive by `store/head_anchor.py` — it is not co-located with the other leaf primitives (`canonical.py`, `weft_signing.py`) it logically belongs with. This is a naming/location inconsistency rather than a governance-honesty risk, but it means a reader of `store/` must know to look in `enforcement/` for the signing primitive, which the `head_anchor.py` import makes visible but surprising.
- `Provenance` has exactly one member (`UNAUTHENTICATED`) and the docstring states an authenticated path "would add a stronger value here." The enum is not yet used in any decision path — it is recorded into check/pull payloads but nothing currently gates on its value. If policy logic is added that trusts a higher-provenance value, the gap between the recorded `unauthenticated` claim and any actual authentication verification must be explicitly re-examined.
- The cross-repo non-ASCII golden vector is not yet pinned (canonical.py lines 22–27): both Python signers use identical `json.dumps` params, so they agree by construction, but a Wardline-side drift (e.g. switching to `ensure_ascii=True` in a refactor) would break cross-repo HMAC verification without a failing test on either side until a non-ASCII payload hits production. The fix (a shared golden HMAC vector with a non-ASCII payload in Wardline's repo) is documented as a Wardline-side follow-up.

**Confidence:** High — Read 100% of `canonical.py` (51 lines), `weft_signing.py` (91 lines), `enforcement/signing.py` (61 lines), `provenance.py` (28 lines), `records/override_record.py` (40 lines), `records/__init__.py` (1 line). Cross-verified that `canonical.py` has no legis imports (stdlib only); verified `weft_signing.py` has no legis imports (stdlib only); verified `enforcement/signing.py` imports only `canonical` (line 30); verified `records/override_record.py` imports only `identity.entity_key` (line 13).
