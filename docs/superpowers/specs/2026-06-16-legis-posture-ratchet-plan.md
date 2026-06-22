# Legis Posture Ratchet + Operator Elevation Sessions — v1 Implementation Plan (Final)

This is a test-driven, dependency-ordered plan. Every task names the test(s) to write FIRST, what they assert, then the implementation against real symbols, then a verification command. Fail-closed behaviors are called out inline. Do not deviate from the canonicalization contract (`canonical_json`, `sort_keys=True`, `ensure_ascii=False`, `allow_nan=False`) — cross-tool signature verification depends on it.

This revision folds in four parallel reviews. The headline structural changes from the draft:

1. **The floor must be applied at every agent-visible cell-resolution site, not just `mcp.py:1693`.** `_tool_policy_explain` (`mcp.py:1636`), `_tool_policy_list` (`mcp.py:1648`), `service/explain.py:88`, and the `hooks.py` session banner all surface unflooored cells today. Leaving them unflooored is an active honesty defect (the agent plans against `chill`, submit routes to `structured`). This is now a first-class decision (Decision D0 below) and is wired in Phase 4, not Phase 8.
2. **`FlooredRegistry` is a *subclass* of `PolicyCellRegistry`, not a composition wrapper.** This is the chosen resolution to the explain/list/hooks honesty gap — existing call sites that accept a `PolicyCellRegistry` transparently accept a `FlooredRegistry`, and `explain_policy`'s internal `rule.cell`/`default_cell` derivation is floored without changing its signature. Decided here, before Phase 4, so Phase 8 cannot fork it.
3. **Phase 9 (API unification) is reordered and phased**: rewrite/extend `tests/api/*` against a unified route added *alongside* the old routes first, prove green, then delete the old routes and old test paths. The unified route's protected-cell `NEED_INPUTS` discriminant and the removal of the legacy env-var `protected_set` 403 guard are now explicit.
4. **`read_floor()` uses a tail read (`get_latest_sequence_and_hash()` + `read_by_seq`), not `read_all()`**, because it is on the per-request hot path.
5. **A coverage floor for `src/legis/posture/` is added to `scripts/check_coverage_floors.py` in Phase 0**, so the CI security gate is fail-closed from the first posture commit.
6. **A session file is REQUIRED for any `posture set`** — there is no direct-sign path. `EnvSigner` (CI path) still opens a session so every `TRANSITION` carries a `session_id`.

---

## Locked decisions (resolve before coding begins)

- **D0 — Floor is applied at EVERY agent-visible cell-resolution site.** Not only the routing branch. Enumerated sites: `mcp.py:1693` (override routing), `mcp.py:1636` (`_tool_policy_explain`), `mcp.py:1648`/`:1675` (`_tool_policy_list` default + per-rule cells), `service/explain.py:87-88` (cell derivation inside `explain_policy`), `hooks.py:164-168`/`:173-192` (session-context banner), and the unified HTTP route (Phase 9). Any one missed is a floor-bypass or honesty gap.
- **D1 — `FlooredRegistry` subclasses `PolicyCellRegistry`.** It overrides `cell_for` (floored via `CELL_TIER_ORDER` index-`max`) and floors `default_cell`. `rule_for` is inherited unchanged so `matched_rule.pattern` still reports the raw rule the agent matched — the floor silently raises the *effective* cell above the matched rule's cell. Because it is a subclass, `explain_policy(registry, ...)` floors automatically when handed a `FlooredRegistry`. (If a subclass proves infeasible against `PolicyCellRegistry`'s `__init__`, fall back to a wrapper that re-implements `cell_for`/`default_cell`/`rule_for` delegating to the inner registry — but the subclass is the default and the test surface is identical either way.)
- **D2 — Floor value is read per request/invocation; the ledger *handle* is held on the runtime.** `PostureLedger(posture_db_url(), initialize=True)` is constructed once (in `build_runtime` for MCP, in `create_app` for HTTP). `read_floor()` is called fresh at each cell-resolution site. **No `posture_floor` field is cached on `McpRuntime`.** Never construct `PostureLedger(initialize=True)` inside a request handler (it runs DDL and serializes requests under a SQLite DDL lock).
- **D3 — A session file is required for every `posture set`.** The session file is the accountability record (carries `session_id` into the `TRANSITION`), not an optimization. `EnvSigner` also requires an open session (`backend_id="env"`); the key value is never stored in the session file.
- **D4 — Idempotency-key replays in MCP `override_submit` return the original record but carry a `floor_warning` discriminant** when the current floor is higher than the floor in force when the record was first written. The *action* is floor-exempt (the record cannot be unwritten) but the replay is **not silent**: the response flags "this replay predates the current floor (was `<floor_then>`, now `<floor_now>`)", honoring the no-silent-path rule. A test pins both the original-outcome return and the warning discriminant. *(Resolved 2026-06-16: warning variant chosen over silent exempt.)*
- **D5 — The age-file backend's `unlock_ref` is `None`.** Re-prompt IS the unlock mechanism; the session file holds only window metadata. Only the keychain backend stores a non-null `unlock_ref` (the keychain item id).
- **D6 — Doctor "acknowledged KEY_RESET" requires a `TRANSITION` whose `operator_sig` verifies against the NEW epoch `key_fingerprint`**, not merely a later `TRANSITION` record. Record-kind inspection alone is replayable.

---

## New module layout

Create a `src/legis/posture/` package, mirroring the existing `src/legis/enforcement/` package convention. Consolidated from the draft's 7 modules to 6 (custody crypto merged into `signing.py`, per the architecture review — all three backends are in-scope for v1 and the crypto helpers live alongside the backends that use them):

```
src/legis/posture/
  __init__.py        # public re-exports: PostureLedger, FlooredRegistry, PostureSigner, ...
  records.py         # PostureRecord dataclass + kind constants (GENESIS/TRANSITION/KEY_RESET/OPERATOR_SESSION_OPENED)
  ledger.py          # PostureLedger: wraps AuditStore(posture_db_url()); read_floor(), genesis(), transition(), rekey(), session_opened()
  floor.py           # FlooredRegistry(PolicyCellRegistry subclass) + tier max() helper + floored_registry(inner, ledger) factory
  signing.py         # PostureSigner protocol + KeychainSigner/AgeFileSigner/EnvSigner; mint_key(), key_fingerprint(); age wrap/unwrap (scrypt+AES-GCM); select_backend()
  session.py         # ElevationSession persisted-file model: open_session(), load_session(), end_session(), is_active(); _atomic_write_json()
```

Tests live under `tests/posture/` (new), plus extensions to `tests/api/*`, `tests/install/*`, `tests/doctor/*`, `tests/cli/*`, and `tests/conformance/*`.

Convention anchors: package style follows `src/legis/enforcement/`; store reuse follows `src/legis/store/audit_store.py:116`; config resolver follows `src/legis/config.py:61-126`; signing primitives follow `src/legis/enforcement/signing.py:46-61`; gate construction follows `src/legis/enforcement/protected.py:207-240`.

---

## PHASE 0 — Dependencies, config plumbing, coverage gate

### Task 0.1 — Add `cryptography` as a hard dependency

- **Modify:** `pyproject.toml:12-18` dependencies list (currently `fastapi, pydantic, pyyaml, uvicorn, sqlalchemy`).
- **Test first:** `tests/posture/test_deps.py::test_cryptography_importable` — asserts `from cryptography.hazmat.primitives.kdf.scrypt import Scrypt; from cryptography.hazmat.primitives.ciphers.aead import AESGCM` succeed.
- **Implementation:** add `cryptography>=42` to the `dependencies` array.
- **Verify:** `python -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM"` and `pip show cryptography`.

### Task 0.2 — Add `posture_db_url()` + session path resolvers

- **Modify:** `src/legis/config.py:61-126`.
- **Test first:** `tests/posture/test_config.py`:
  - `test_posture_db_url_default` — with no env, `posture_db_url()` resolves to the `.weft/legis/legis-posture.db` sqlite URL form, matching `governance_db_url()` shape.
  - `test_posture_db_url_env_override` — with `LEGIS_POSTURE_DB=/tmp/x.db`, returns that.
  - `test_posture_in_store_specs` — `("LEGIS_POSTURE_DB", "legis-posture.db")` is present in `STORE_DB_SPECS`.
  - `test_operator_session_path` — `operator_session_path()` returns `_store_dir() / "operator_session.json"`.
  - `test_posture_db_url_creates_parent_dir` — monkeypatch `_store_dir()` (or `os.getcwd()`) to a tmp path; `AuditStore(posture_db_url(), initialize=True)` creates `.weft/legis/` correctly. **(addresses Quality medium: cwd-relative `_store_dir` trap)**
- **Implementation:** add `(_POSTURE_DB_ENV="LEGIS_POSTURE_DB", _POSTURE_DB_NAME="legis-posture.db")` to `STORE_DB_SPECS` (`config.py:61`); add `def posture_db_url() -> str: return _resolve_db_url(_POSTURE_DB_ENV, _POSTURE_DB_NAME)` next to `governance_db_url()` (`config.py:118`); add `operator_session_path() -> Path` returning `_store_dir() / "operator_session.json"`. **Note: all `PostureLedger` unit tests must construct the store with an explicit absolute URL (`f"sqlite:///{tmp_path}/posture.db"`), not via `posture_db_url()`, matching `tests/store/test_audit_store.py:18-19`.**
- **Doctrine amendment:** update the comment block at `config.py:29-32` to record the deliberate carve-out: the operator-authority key is minted at install and held by a custody backend; config still touches no key *plaintext*, but the path `operator_session.json` and the custody reference are now in scope. Quote spec §5/§6.
- **Verify:** `pytest tests/posture/test_config.py -q`.

### Task 0.3 — Add a coverage floor for the posture package **(NEW — addresses Quality high)**

- **Modify:** `scripts/check_coverage_floors.py:27-34` (the `FLOORS` map).
- **Test first:** N/A (this is the CI gate itself). Instead, the verification command is the gate run.
- **Implementation:** add `'src/legis/posture/': 93.0` to `FLOORS` (matching `enforcement/` at 93%, the highest existing tier — this is the most security-sensitive new code). This must land in the first posture commit so coverage is fail-closed from the start. Confirm the prefix-matching logic at `check_coverage_floors.py:76-82` treats an empty package (no statements yet) gracefully — if it reports "no statements measured" as failure, the floor is added in the same commit as `records.py` so statements exist.
- **Verify:** `python scripts/check_coverage_floors.py` after Phase 1 lands (expect pass once posture has measured statements ≥ 93%).

---

## PHASE 1 — Posture ledger (reuse AuditStore)

Fail-closed rule for this phase: **absent ledger → `read_floor()` reports "no ledger" and callers fall back to `structured`, never `chill`** (spec §4, §5).

### Task 1.1 — `PostureRecord` dataclass + kind constants

- **Create:** `src/legis/posture/records.py`. Model on `src/legis/records/override_record.py:18-30`.
- **Test first:** `tests/posture/test_records.py`:
  - `test_to_payload_keys` — `to_payload()` returns exactly `kind, floor, key_fingerprint, operator_sig, session_id, agent_id, recorded_at, rationale`.
  - `test_to_payload_excludes_chain_fields` — **negative assertion: `seq`, `prev_hash`, and `chain_hash`/`this_hash` are NOT keys in `to_payload()`** (the store adds them; including them would shift the content hash and fail `verify_integrity`). **(addresses Architecture low)**
  - `test_kind_constants` — `KIND_GENESIS="GENESIS"`, `KIND_TRANSITION="TRANSITION"`, `KIND_KEY_RESET="KEY_RESET"`, `KIND_SESSION_OPENED="OPERATOR_SESSION_OPENED"`.
  - `test_canonical_roundtrip` — `canonical_json(record.to_payload())` is stable/sorted; `content_hash()` is deterministic across key-insertion order.
- **Implementation:** frozen dataclass with `to_payload() -> dict[str, Any]`. `operator_sig` and `session_id` default to `None` for keyless records. Reuse `src/legis/canonical.py:41 canonical_json` and `:47 content_hash` directly.
- **Verify:** `pytest tests/posture/test_records.py -q`.

### Task 1.2 — `PostureLedger` wrapping `AuditStore`

- **Create:** `src/legis/posture/ledger.py`.
- **Protocol note:** if `PostureLedger` is declared to implement `AppendOnlyStore`, that protocol has **8 members** (`append`, `append_signed`, `read_all`, `read_by_seq`, `verify_integrity`, `get_latest_sequence_and_hash`, `in_batch`, `transaction` — `store/protocol.py:24-68`), not 6. `PostureLedger` is a *domain* wrapper, not a drop-in store, so it need NOT implement the protocol — it *holds* an `AuditStore` and exposes domain methods. Do not assert "6 methods" anywhere. **(addresses reality-grounding high)**
- **Test first:** `tests/posture/test_ledger.py`:
  - `test_genesis_writes_chill_floor` — fresh DB; `ledger.genesis(...)` appends one `kind=GENESIS, floor="chill"`; `read_floor()` returns `"chill"`.
  - `test_read_floor_missing_ledger_returns_none` — no DB file; `read_floor()` returns `None`; assert it does NOT return `"chill"`.
  - `test_read_floor_is_last_record` — after genesis then a transition to `structured`, `read_floor()` returns `"structured"`.
  - `test_read_floor_uses_tail_read` — instrument/spy that `read_floor()` does **not** call `read_all()`; it uses a tail-oriented query for the latest authoritative floor record. **(addresses Architecture medium: per-request hot path)**
  - `test_read_floor_does_not_point_read_each_metadata_tail` — metadata records after the floor do not force a repeated `read_by_seq()` loop over the tail.
  - `test_chain_integrity` — `store.verify_integrity()` True after genesis + transition.
  - `test_idempotent_open` — opening the ledger twice over an existing DB does NOT append a second GENESIS.
  - `test_genesis_blocked_after_key_reset` — `genesis()` on a ledger whose tail is a `KEY_RESET` (non-empty, no `GENESIS` re-needed) returns without appending. **(addresses Quality high)**
  - `test_transition_record_signed_binds_seq` — `transition()` calls `append_signed(build)` where `build(seq, prev_hash)` includes `chain_seq=seq` in the signed fields; resulting `operator_sig` verifies via `signing.verify`.
  - `test_no_read_inside_transition_batch` — `transition()` resolves the current-epoch `key_fingerprint` (a tail read) BEFORE entering `append_signed`; assert `_assert_no_batch_in_progress` (`audit_store.py:221-239`) is never triggered during a `transition()` call (no `read_floor`/`read_all` inside the `build_payload` callback). **(addresses Quality high — Q-M5 invariant)**
- **Implementation:**
  - `PostureLedger.__init__(self, url, *, initialize=True)` constructs `AuditStore(url, initialize=initialize)` like `audit_store.py:116`.
  - `genesis(key_fingerprint, agent_id, recorded_at)` → keyless `PostureRecord(kind=GENESIS, floor="chill", ...)`, `store.append(record.to_payload())` (`audit_store.py:285`). **Guard:** return early if `store.read_all()` is non-empty (covers both an existing GENESIS and a KEY_RESET tail).
  - `read_floor() -> str | None`: if DB/file absent → `None`; otherwise issue one descending SQLite query over `audit_log.payload`, skip metadata records, and return the newest authoritative `floor` from `GENESIS`, `TRANSITION`, or `KEY_RESET`. `read_all()` is reserved for `verify_integrity()` in doctor, and metadata tails must not create a repeated `read_by_seq()` loop.
  - `transition(new_cell, *, signer, session_id, key_fingerprint, agent_id, rationale, recorded_at)`: **resolve current-epoch `key_fingerprint` via a tail read BEFORE `append_signed`** (never inside the build callback). Then `append_signed(build_payload)` (`audit_store.py:296`); inside `build(seq, prev_hash)`: assemble signing fields including `chain_seq=seq`, verify `signer.fingerprint() == key_fingerprint` first, then `signer.sign(fields)`; embed `operator_sig`/`session_id`. **Fail-closed:** signer raise or fingerprint mismatch → raise before persist (no half-write).
  - `rekey(...)` and `session_opened(...)` are signatures here, implemented in Phase 11 / Phase 3.2.
- **Verify:** `pytest tests/posture/test_ledger.py -q`.

---

## PHASE 2 — PostureSigner seam + custody backends (cryptography mandatory)

Fail-closed rule: **signer error → refuse; key bytes are never returned to the caller** (spec §6, §7, §9).

### Task 2.1 — `PostureSigner` protocol + key primitives

- **Create:** `src/legis/posture/signing.py`. Mirror the `sign/verify` API of `src/legis/enforcement/signing.py:46-61` but the key is held by the backend, never passed by the caller.
- **Test first:** `tests/posture/test_signer.py`:
  - `test_sign_returns_prefixed_signature` — `signer.sign(fields)` returns a string prefixed `hmac-sha256:v3:` (matches `SIG_PREFIX_V3`, `signing.py:32-36`).
  - `test_sign_never_returns_key` — `not hasattr(signer, "key")` AND a **behavioral** check: the returned signature string does not contain the raw key hex; iterating `vars(signer)` values and calling each public method returns no value equal to the key bytes/hex. **(addresses Quality medium: attribute-name check is too weak)**
  - `test_signature_verifies_against_fingerprint_key` — for an in-memory test signer, `signing.verify(fields_with_chain_seq, sig, key_bytes)` is True; `fingerprint == sha256(key_bytes).hexdigest()`.
  - `test_mint_key_is_32_bytes_hex` — `mint_key()` returns `secrets.token_hex(32)` (64 hex chars).
- **Implementation:**
  - `mint_key() -> str` = `secrets.token_hex(32)`.
  - `key_fingerprint(key) -> str` = `sha256(key_bytes).hexdigest()`.
  - `PostureSigner` Protocol: `sign(fields: dict) -> str`, `fingerprint() -> str`. Implementations call `src/legis/enforcement/signing.py:53 sign(fields, key, version="v3")` internally. **Caller hands canonical record fields including `chain_seq`; backend supplies the key.** Document the `chain_seq` requirement loudly (missing `chain_seq` → silent wrong-base verify).
- **Verify:** `pytest tests/posture/test_signer.py -q`.

### Task 2.2 — Custody backends: keychain, age-file, env escape hatch

- **Create:** the three backends and the age crypto helpers in `signing.py` (consolidated; no separate `custody.py`).
- **Test first:** `tests/posture/test_custody.py`:
  - `test_env_signer_emits_warning` — `EnvSigner` from `LEGIS_OPERATOR_KEY` emits an honest plaintext-in-env warning (capture via `caplog`/`warnings`); requires explicit opt-in flag at construction.
  - `test_age_file_roundtrip` — `wrap_key(key, passphrase)` then `unwrap_key(blob, passphrase)` returns the original; wrong passphrase raises (real scrypt+AES-GCM).
  - `test_age_file_never_persists_plaintext` — the produced blob bytes do NOT contain the raw key.
  - `test_keychain_signer_mocked` — with a mocked secure store, `KeychainSigner.sign(fields)` returns a valid signature without the key crossing the caller boundary.
  - `test_custody_default_selection` — `select_backend(keychain_available=True)` → keychain; `select_backend(keychain_available=False)` → age-file; env only when `insecure_env=True`. **The keychain availability probe is injected/mocked via `monkeypatch` (no live D-Bus dependency on CI ubuntu-latest); the real-keychain round-trip test is marked `@pytest.mark.integration` and excluded from CI.** **(addresses Quality low: headless CI keychain probe)**
- **Implementation:**
  - `wrap_key(key, passphrase)` / `unwrap_key(blob, passphrase)`: scrypt KDF (salt in blob header) → AES-GCM (nonce + ciphertext + tag). No `age` CLI shell-out.
  - `KeychainSigner`: probes OS keychain via an injectable seam; stores/loads key by item id; `sign()` loads key into a local var, signs, discards.
  - `AgeFileSigner`: holds the wrapped blob + passphrase callback; sign = unwrap → sign → discard. **Age-file path: `operator_age_path() -> Path` returns `_store_dir() / "operator.age"` (project-rooted `.weft/legis/operator.age`, consistent with the federation convention) — NOT `~/.config/legis/operator.age`. Add `operator_age_path()` to `config.py` and gitignore it (Phase 6).** **(addresses reality-grounding medium: invented home path)**
  - `EnvSigner`: reads `LEGIS_OPERATOR_KEY`; constructed only behind `--insecure-key-in-env`; emits warning.
  - `select_backend(...)`: keychain if available, else age-file; env only on explicit opt-in.
- **Verify:** `pytest tests/posture/test_custody.py -q`.

---

## PHASE 3 — Elevation session (persisted session-file model)

Fail-closed rule: **no open session, or expired session → `posture set` / `transition` refused** (spec §7). Per D3, the session file is required for ALL `posture set` — there is no direct-sign path.

### Task 3.1 — Persisted `operator_session.json` model

- **Create:** `src/legis/posture/session.py`. Includes a local `_atomic_write_json(path, obj)` helper (temp file + `os.replace`) — **`_atomic_write_text` does NOT exist in `install.py`; do not import it.** **(addresses reality-grounding critical)**
- **Test first:** `tests/posture/test_session.py`:
  - `test_enable_writes_session_file` — `open_session(ttl=300, operator_id=..., backend_id=..., unlock_ref=..., signer=...)` writes `.weft/legis/operator_session.json` containing only `session_id, operator_id, opened_at, ttl, expires_at, backend_id, unlock_ref, session_sig` — assert NO `key`, NO passphrase, NO raw blob plaintext.
  - `test_age_backend_unlock_ref_is_none` — for an age-file session, `unlock_ref is None` (per D5: re-prompt is the unlock; only keychain stores an item id). **(addresses Architecture medium)**
  - `test_session_active_within_ttl` / `test_session_expired_after_ttl` — `is_active` honors TTL; `load_session()` past TTL returns `None` AND deletes the file.
  - `test_load_session_double_expire_is_safe` — calling `load_session()` twice past TTL returns `None` both times without raising; the self-delete catches `FileNotFoundError`. **(addresses Quality medium)**
  - `test_disable_ends_early` — `end_session()` deletes the file (idempotent).
  - `test_unique_session_id` — two `open_session` calls produce distinct `session_id`.
  - `test_second_enable_replaces_first` — a second `operator enable` **replaces** the session file atomically (only one active session at a time). This resolves the concurrent-session ambiguity: there is exactly one authoritative `operator_session.json`. **(addresses Quality critical: concurrent-session race)**
- **Implementation:**
  - `open_session(...)` writes the JSON atomically via the local `_atomic_write_json`. Generates `session_id = secrets.token_hex(...)`, signs the session metadata with the operator signer, and stores that HMAC as `session_sig`. A second `open_session` overwrites the prior file (single active session).
  - `load_session() -> Session | None`: reads file; if `now > expires_at` → delete (catching `FileNotFoundError`), return `None`.
  - `end_session()` deletes file (idempotent).
  - `unlock_ref` per D5: keychain → item id; age-file → `None`; env → `None`.
- **Verify:** `pytest tests/posture/test_session.py -q`.

### Task 3.2 — `OPERATOR_SESSION_OPENED` ledger record

- **Modify:** `src/legis/posture/ledger.py` + `records.py`.
- **Test first:** `tests/posture/test_session.py::test_enable_writes_opened_record` — `open_session` (via the operator-enable flow) appends `OPERATOR_SESSION_OPENED { operator_id, enabled_at, ttl, keychain_auth_ref, session_id }` to the posture ledger; keyless record (the enable IS the operator's countersignature on the window, spec §6).
- **Implementation:** `ledger.session_opened(...)` via `store.append(...)`.
- **Verify:** `pytest tests/posture/test_session.py::test_enable_writes_opened_record -q`.

---

## PHASE 4 — FlooredRegistry chokepoint, wired at EVERY agent-visible site

Fail-closed rule: **`read_floor()` returns `None` (missing ledger) → effective floor is `structured`, never `chill`** (spec §4). Per D0/D1, this phase wires the floor at all enumerated sites, not just the routing branch.

### Task 4.1 — `FlooredRegistry` subclass + tier `max()`

- **Create:** `src/legis/posture/floor.py`.
- **Test first:** `tests/posture/test_floor.py`:
  - `test_max_respects_tier_order` — for all 16 (floor × registry-cell) combos over `CELL_TIER_ORDER` (`cells.py:22`), `FlooredRegistry(...).cell_for(policy) == max_by_tier(floor, inner.cell_for(policy))` via **index lookup in `CELL_TIER_ORDER`, not string compare**.
  - `test_floor_only_raises` — registry `chill` + floor `structured` → `structured`; registry `protected` + floor `chill` → `protected`.
  - `test_missing_floor_uses_structured` — floor `None`/missing-ledger → effective floor `structured`, not `chill`.
  - `test_default_cell_floored` — `FlooredRegistry.default_cell` is floored.
  - `test_rule_for_reports_raw_pattern` — `rule_for(policy)` returns the raw matched rule (pattern preserved) so the agent still learns which rule matched; only the *effective cell* is raised. **(addresses Architecture low: matched_rule honesty)**
  - `test_is_policy_cell_registry_subclass` — `isinstance(FlooredRegistry(...), PolicyCellRegistry)` is True, so `explain_policy` accepts it transparently (D1).
- **Implementation:**
  - `class FlooredRegistry(PolicyCellRegistry)`: constructed from an inner registry's rules + a `floor: str`. `cell_for(policy)` = `_max_tier(self.floor, super().cell_for(policy))` where `_max_tier(a, b)` = `CELL_TIER_ORDER[max(CELL_TIER_ORDER.index(a), CELL_TIER_ORDER.index(b))]`. `default_cell` returns the floored default. `rule_for` inherited unchanged.
  - Factory `floored_registry(inner, ledger) -> FlooredRegistry` reads `ledger.read_floor()` **at call time**, maps `None → "structured"`, and returns a `FlooredRegistry` carrying that floor and the inner registry's rules. Constructed per request/invocation; the floor value is never cached (D2).
- **Verify:** `pytest tests/posture/test_floor.py -q`.

### Task 4.2 — Wire FlooredRegistry into ALL MCP cell-resolution sites

- **Modify:** `src/legis/mcp.py:1693` (override routing), `mcp.py:1636-1637` (`_tool_policy_explain`), `mcp.py:1648`/`:1675` (`_tool_policy_list` default + per-rule cells), and `service/explain.py:87-88` (cell derivation). Add a `posture_ledger` accessor on the runtime built in `build_runtime` (`mcp.py:192-271`). **Do NOT add a `posture_floor` field to `McpRuntime` (D2);** hold the `PostureLedger` *handle* only.
- **Test first:** `tests/posture/test_mcp_floor.py`:
  - `test_mcp_override_submit_floored` — floor `structured`, policy whose registry cell is `chill` → `override_submit` routes to the sign-off path, NOT self-clear.
  - `test_policy_explain_reflects_floor` — floor `structured`, chill-registry policy → `policy_explain` returns `cell="structured"` and `self_clearable=False`. **(addresses Architecture/Quality/systems critical: explain honesty gap)**
  - `test_policy_list_reflects_floor` — `policy_list` shows the floored cell for every policy (default + each rule). **(addresses Architecture/systems critical)**
  - `test_mcp_floor_read_per_invocation` — change the floor between two tool calls on the same runtime instance (no restart); the second call reflects the new floor. **(addresses systems medium: no cached floor on McpRuntime)**
  - `test_idempotent_replay_is_floor_exempt` — submit override with `idempotency_key`, raise the floor, resubmit with the same key; assert the replayed response is the original outcome (floor-exempt, per D4) — pinned as a conscious decision, not a silent bypass. **(addresses systems high: idempotency short-circuit)**
- **Implementation:** at each site, build the `FlooredRegistry` via `floored_registry(_registry(runtime), runtime.posture_ledger)` (floor read fresh) and use it instead of the raw `_registry(runtime)`:
  - `mcp.py:1693`: routing branch sees the floored cell.
  - `mcp.py:1696` `explain_policy(...)` is passed the `FlooredRegistry` (subclass → flooring is automatic). Additionally, derive `dispatch_cell = floored_registry.cell_for(policy)` and use `dispatch_cell` for the `in ("chill","coached")` branch at `mcp.py:1747`, so dispatch never depends on an unflooored `explanation.cell`. **(addresses reality-grounding critical: explain dispatch path bypass)**
  - `mcp.py:1636` `_tool_policy_explain`: pass the `FlooredRegistry` into `explain_policy`.
  - `mcp.py:1648`/`:1675` `_tool_policy_list`: floor `default_cell` and each rule's cell before building the cells block.
  - The idempotency short-circuit (`mcp.py:1739-1746`) returns the historical record unchanged (D4); no re-route.
- **Verify:** `pytest tests/posture/test_mcp_floor.py -q`.

### Task 4.3 — Floor the hooks session-context banner

- **Modify:** `src/legis/hooks.py:145-170 _cells_posture` and `:173-192 generate_session_context`.
- **Test first:** `tests/cli/test_hooks_floor.py`:
  - `test_banner_reports_floor_present` — with a posture ledger at `Path.cwd()` and `floor != "chill"`, the session banner emits `floor: <cell>` alongside the cells-config line.
  - `test_banner_reports_floor_absent` — no ledger → banner emits `floor: none (fail-closed structured)`.
- **Implementation:** in `generate_session_context`, attempt `PostureLedger(posture_db_url(), initialize=False).read_floor()` at `Path.cwd()`; emit a `floor:` line. This makes the agent's session-start context honest about the governing floor (today the banner says only "cells config: absent (policies default-route)", which the agent reads as chill). **(addresses systems high: hooks banner honesty gap)**
- **Verify:** `pytest tests/cli/test_hooks_floor.py -q`.

---

## PHASE 5 — The change gate (`posture set` transition)

Fail-closed: **no open session → refuse; fingerprint mismatch → refuse; signer error → refuse; floor unchanged; exactly one outcome** (spec §7). Per D3, a session is required.

### Task 5.1 — Posture-set change gate service

- **Create:** the `transition()` (Task 1.2) plus a thin `set_floor(...)` entry in `ledger.py`.
- **Test first:** `tests/posture/test_change_gate.py`:
  - `test_set_refused_without_session` — no `operator_session.json` → refusal outcome, ledger unchanged.
  - `test_set_refused_fingerprint_mismatch` — open session but `signer.fingerprint()` != **the ledger's current-epoch `key_fingerprint`** (last GENESIS/KEY_RESET) → refused, no record. The fingerprint is checked against the LEDGER epoch, not the session's own recorded field. **(addresses Quality critical: concurrent-session/epoch race)**
  - `test_set_refused_on_signer_error` — signer raises → refused, no half-written record (`append_signed` not committed).
  - `test_set_refused_on_wrong_passphrase` — age-file backend, wrong passphrase → refusal, `ledger.read_all()` count unchanged (unwrap raises mid-callback must not leave partial state). **(addresses Quality medium)**
  - `test_set_accepted_with_valid_session` — open session + matching fingerprint → one `TRANSITION` appended; `read_floor()` reflects new cell; `operator_sig` verifies; `session_id` matches the open session.
  - `test_every_signature_carries_session_id` — the `TRANSITION` record's `session_id` is non-null and equals the open session's id; a transition produced with no session is refused.
  - `test_exactly_one_record_per_outcome` — refusals add 0 records, success adds exactly 1.
- **Implementation:** `set_floor(new_cell, *, ledger, signer, agent_id, rationale)`:
  1. `session = load_session()`; if `None`/expired → refuse.
  2. Resolve current-epoch `key_fingerprint` from the last GENESIS/KEY_RESET record (tail read); if `signer.fingerprint() != key_fingerprint` → refuse.
  3. `ledger.transition(new_cell, signer=signer, session_id=session.session_id, key_fingerprint=key_fingerprint, ...)`. Signer failure inside `append_signed`'s `build` → propagate as refusal (no record).
- **Verify:** `pytest tests/posture/test_change_gate.py -q`.

---

## PHASE 6 — Install (genesis + key mint)

Fail-closed/idempotent: **second install over an existing ledger leaves floor + key epoch untouched** (spec §5). **Never write `LEGIS_OPERATOR_KEY` to `.mcp.json`.**

### Task 6.1 — Install mints key + writes GENESIS

- **Modify:** `src/legis/install.py` (add `install_posture(project_root, *, backend)`); wire into `src/legis/cli.py:270-320 _run_install()`.
- **Test first:** `tests/install/test_install_posture.py`:
  - `test_install_creates_posture_db_with_genesis` — fresh project; after install, `.weft/legis/legis-posture.db` has one `GENESIS`, `floor="chill"`, `key_fingerprint` present, `operator_sig` absent.
  - `test_install_mints_key_to_backend` — the minted 32-byte hex key is handed to the selected backend; the ledger stores only fingerprint + backend id, never the key.
  - `test_install_idempotent` — second install does NOT append a second GENESIS, does NOT re-mint; floor + `key_fingerprint` unchanged.
  - `test_install_idempotent_after_rekey` — ledger exists with a `KEY_RESET` tail; a second install does NOT re-genesis. **(addresses Quality high)**
  - `test_operator_key_not_in_mcp_json` — `register_mcp_json` env never contains `LEGIS_OPERATOR_KEY` or any `LEGIS_OPERATOR_KEY_*` variant.
  - `test_install_default_backend_selection` — keychain if available else age-file (probe mocked via `monkeypatch`); env backend only with `--insecure-key-in-env`.
  - `test_install_gitignores_session_and_age` — `.gitignore` gains `/.weft/legis/operator_session.json` and `/.weft/legis/operator.age` (root-anchored, federation convention). **(addresses systems low: exact gitignore pattern)**
- **Implementation:**
  - `install_posture`: `ensure_project_dir(project_root, ".weft", "legis")` (`install.py:143`); open `PostureLedger(posture_db_url(), initialize=True)`; **guard:** if `read_all()` empty → `mint_key()`, hand to backend (`select_backend`), compute fingerprint, `ledger.genesis(key_fingerprint=fp, ...)`. Else no-op.
  - Extend `_REJECTED_MCP_ENV_KEYS` (`install.py:948-961`) to include `LEGIS_OPERATOR_KEY` and the `LEGIS_OPERATOR_KEY_*` family so `register_mcp_json` (`install.py:1032-1119`) / `_safe_mcp_env` (`install.py:996`) filter them.
  - Add `/.weft/legis/operator_session.json` and `/.weft/legis/operator.age` to `.gitignore` via `ensure_gitignore` (`install.py:905-931`) / `gitignore_rules_present` (`install.py:856`). Use the local `_atomic_write_json` in `session.py` for session writes — install itself never writes a session file (session is ephemeral, created only by `operator enable`).
- **Verify:** `pytest tests/install/test_install_posture.py -q`.

---

## PHASE 7 — CLI (`posture` and `operator` command groups)

### Task 7.1 — `posture` subcommand group

- **Modify:** `src/legis/cli.py:36-186 build_parser()` (register subparser at `cli.py:44`) and `cli.py:329-462 main()` (dispatch branch).
- **Test first:** `tests/cli/test_posture_cli.py`:
  - `test_posture_show_keyless` — `legis posture show` prints the current floor (keyless / no session).
  - `test_posture_set_requires_session` — `legis posture set structured` with no open session exits non-zero with a refusal.
  - `test_posture_set_with_session` — with an open session + matching key, `legis posture set structured` succeeds; floor reads back `structured`.
- **Implementation:** add `posture` subparser with `show`, `set <cell>`, `rekey` (Phase 11). `show` → `read_floor()` (map `None → "structured (no ledger)"`). `set` → Phase 5 `set_floor`.
- **Verify:** `pytest tests/cli/test_posture_cli.py -q`.

### Task 7.2 — `operator` subcommand group + CI/headless bootstrap

- **Modify:** `src/legis/cli.py` (subparser + dispatch).
- **Test first:** `tests/cli/test_operator_cli.py`:
  - `test_operator_enable_opens_session` — `legis operator enable --ttl 5m` writes `operator_session.json` and appends `OPERATOR_SESSION_OPENED`; printed output names operator + window.
  - `test_operator_disable_ends_session` — deletes the session file.
  - `test_enable_default_ttl_5m` — no `--ttl` → 300s.
  - `test_ci_env_backend_opens_session_with_id` — with `LEGIS_OPERATOR_KEY` set, no keychain, `legis operator enable --insecure-key-in-env`: emits the plaintext warning, writes a session file with `backend_id="env"`, and a subsequent `posture set` produces a `TRANSITION` carrying a **non-null `session_id`** (env path still goes through a session, per D3). **(addresses systems high: CI bootstrap + session accountability)**
- **Implementation:** `operator` subparser with `enable [--ttl] [--insecure-key-in-env]`, `disable`. `_run_operator`: `enable` → keychain/age unlock (or env opt-in) → `open_session(..., signer=signer)` + `ledger.session_opened(...)`. `disable` → `end_session()`. **CI bootstrap sequence (documented in the CLI help and `docs/`):** set `LEGIS_OPERATOR_KEY`, run `legis operator enable --insecure-key-in-env`, then `legis posture set <cell>`. The env path NEVER signs without an open session — there is no second auth path that bypasses session accountability.
- **Verify:** `pytest tests/cli/test_operator_cli.py -q`.

---

## PHASE 8 — MCP `posture_get` (per-policy floored effective cell)

Note: the explain/list flooring landed in Phase 4 (D0). Phase 8 adds only the dedicated read-only `posture_get` tool.

### Task 8.1 — `posture_get` read-only tool

- **Modify:** `src/legis/mcp.py` (register the tool).
- **Test first:** `tests/posture/test_posture_get.py`:
  - `test_posture_get_returns_global_floor` — `posture_get()` (no policy) returns the current global floor.
  - `test_posture_get_returns_floored_effective_cell` — `posture_get(policy="X")` returns `max(floor, registry.cell_for("X"))` (per-policy floored effective cell, spec §10).
  - `test_posture_get_missing_ledger_structured` — no ledger → floor reported as `structured`.
  - `test_posture_get_indicates_unacknowledged_key_reset` — after a rekey with no follow-on signed transition, `posture_get()` includes `epoch_reset_unacknowledged: true` so the agent surfaces the same signal doctor does. **(addresses Quality medium: agent visibility of pending operator action)**
  - `test_no_posture_set_over_mcp` — assert there is NO `posture_set`/`posture set` MCP tool.
- **Implementation:** `posture_get` reads floor per-invocation via `read_floor()`, builds `FlooredRegistry`, returns `{floor, effective_cell?, epoch_reset_unacknowledged}`. The unacknowledged-reset flag reuses the same logic as the doctor check (Phase 10.2).
- **Verify:** `pytest tests/posture/test_posture_get.py -q`.

---

## PHASE 9 — HTTP API unification (option b) — phased to keep a green suite

This is the breaking contract change. Collapse the three cell-addressed submit routes into one policy-routed `POST /overrides` via `FlooredRegistry`; keep operator-clear routes; rewrite/extend `tests/api/*`; update the conformance doc + oracle. **Reordered per all reviews: add the unified route alongside the old routes and write the new tests first (green), then delete the old routes + old test paths (still green). This avoids an "all tests fail simultaneously" debugging hole and makes the breaking step bisectable.**

Routes (from reality map):
- COLLAPSE → unified: `post_override` (`app.py:528`), `post_protected_override` (`app.py:576`), `post_signoff_request` (`app.py:637`).
- KEEP DISTINCT: `post_operator_override` (`app.py:609`, `verify_operator`), `post_signoff_sign` (`app.py:719`, operator authority).

### Task 9.0 — Composition-root wiring (do this first)

- **Modify:** `src/legis/api/app.py:319 create_app`; `tests/api/conftest.py`.
- **Implementation:** open `PostureLedger(posture_db_url(), initialize=True)` **once at app startup**, store it in app state alongside `engine`/`protected_gate`/`signoff_gate`. Inject as a FastAPI dependency. **Per-request floor reads call `ledger.read_floor()` on the shared instance** (AuditStore NullPool opens a fresh connection per read → concurrent-safe). **NEVER construct `PostureLedger(initialize=True)` inside a request handler** (DDL serializes requests). Update `conftest.py`'s `create_app` call first so downstream fixtures pick up the new structure cleanly. **(addresses systems critical: per-request DDL lock)**
- **Verify:** `pytest tests/api -q` (still green; no behavior change yet).

### Task 9.1 — Unified request/response model + route (added alongside old routes)

- **Modify:** `src/legis/api/app.py` — add one unified `OverrideIn` (`{policy, entity, rationale, agent_id, entity_sei, file_fingerprint?, ast_path?}`) and one `post_override` handler. **At this step, keep the old three routes in place.**
- **Test first:** `tests/api/test_unified_override.py`:
  - `test_unified_route_exists` — `POST /overrides` accepts the unified body and routes by policy.
  - `test_discriminated_outcome_shape` — response is `{outcome, cell, seq?, request_seq?, ...}` with `outcome ∈ {accepted, blocked, escalation_requested, need_inputs, signed}` mirroring MCP `override_submit_out` (`app.py:399`, including the `NEED_INPUTS` const at `mcp.py:460-467`).
  - `test_operator_routes_unchanged` — `POST /signoff/{seq}/sign` and `POST /protected/operator-override` still exist with `verify_operator` auth.
  - `test_protected_need_inputs` — floored cell `protected` with `file_fingerprint`/`ast_path` absent → returns the `NEED_INPUTS` discriminant listing required inputs (HTTP 422 with discriminant body), **not** a generic `InvalidArgumentError`. **(addresses systems/Architecture critical: protected NEED_INPUTS guard)**
  - `test_no_legacy_protected_set_403_guard` — a policy in `LEGIS_PROTECTED_POLICIES` whose floored cell is `protected` routes to the protected gate via `FlooredRegistry`, NOT via the old env-var `protected_set` 403 guard (which is removed). **(addresses systems critical: legacy 403 guard contradicts floor routing)**
- **Implementation:** new `post_override(body, ...)` builds `FlooredRegistry` per-request (floor read via the injected ledger dependency, NOT app-startup), calls `cell_for(body.policy)`, then dispatches:
  - **`protected` NEED_INPUTS pre-check:** if floored cell is `protected` and (`file_fingerprint` or `ast_path` is `None`) → return `NEED_INPUTS` discriminant before calling the service. Aligns the HTTP discriminant name with MCP's `NEED_INPUTS`.
  - `chill`/`coached` → `service/governance.py:submit_override` (`:261`).
  - `structured` → `service/governance.py:request_signoff` (`:377`) → 202 `escalation_requested{request_seq}`.
  - `protected` → `service/governance.py:submit_protected_override` (`:293`), wiring `source_root` (`app.py:335`), `file_fingerprint`, `ast_path`, `entity_sei`.
  - **Remove the legacy env-var `protected_set` 403 guard (`app.py:530-537`)** — `FlooredRegistry.cell_for` now owns protected routing; the old guard reads a config-era set, not the floored cell, and contradicts floor routing.
  - Preserve `verify_writer` (`app.py:206`). **SEI/identity wiring:** the route does NOT call `resolve_for_entry` directly — the service functions call it internally (existing implicit coupling at `service/governance.py`). Do not import `resolve_for_entry` into `app.py`. Thread `entity_sei` through to each service function via its existing `identity=`/`entity_sei=` parameter so SEI-on-entry binding is preserved. **(addresses reality-grounding/systems medium: resolve_for_entry naming + which layer calls it)**
- **Verify:** `pytest tests/api/test_unified_override.py -q` (old routes still present → existing tests still green).

### Task 9.2 — Discriminated-outcome mapping + HTTP status contract

- **Test first:** `tests/api/test_outcome_status.py`:
  - `test_self_clear_201` / `test_judge_block_409` / `test_escalation_202` / `test_protected_gate_201` / `test_need_inputs_422` — HTTP statuses: 201 self-clear/judge-accept, 202 escalation (structured), 409 judge-block, 422 schema/unresolved/NEED_INPUTS. Ensure structured escalation returns **202, not 201**, so old "201 == accepted" assumptions cannot misread escalation as acceptance.
- **Implementation:** map each service outcome to the discriminated response + status, including the `NEED_INPUTS` → 422 case from 9.1.
- **Verify:** `pytest tests/api/test_outcome_status.py -q`.

### Task 9.3 — Floor admission behavior

- **Test first:** `tests/api/test_floor_admission.py`:
  - `test_structured_floor_refuses_chill_self_clear` — floor `structured`, chill-registry policy → `POST /overrides` escalates (202), no self-clear.
  - `test_floor_read_per_request` — write a new `TRANSITION` directly to `posture.db` between two `TestClient` calls; the second reflects the new floor without restart.
  - `test_missing_ledger_floor_structured` — no ledger → effective floor `structured`.
  - `test_unregistered_policy_respects_floor` — with `default_cell=chill` (dev default, `cells.py:64-71`) and floor `structured`, POST a policy NOT in the registry → 202 escalation, not 201 self-clear. Closes the dev-registry-plus-elevated-floor self-clear hole. **(addresses Quality high)**
- **Implementation:** confirmed by 9.1's per-request `FlooredRegistry` (floor read each request via the injected ledger).
- **Verify:** `pytest tests/api/test_floor_admission.py -q`.

### Task 9.4 — Rewrite each `tests/api/*` against the unified route, THEN delete the old routes

- **Rewrite/extend:** `tests/api/test_override_api.py` (~93 lines), `tests/api/test_complex_api.py` (352 lines), `tests/api/test_sei_api.py` (227 lines), `tests/api/test_combinations_api.py` (**752 lines — full file, not "67-666"**). **(addresses reality-grounding medium: line-count correction)**
- **For each:** replace `POST /protected/overrides` and `POST /signoff/request` submit calls with `POST /overrides` + discriminated-response parsing. Add named assertions that the protected-cell wiring survives the collapse:
  - `tests/api/test_complex_api.py::test_protected_cell_source_binding_preserved` — POST `/overrides` with `{policy: <protected>, file_fingerprint, ast_path, ...}`; assert the resulting governance record has a populated `source_binding` extension. **(addresses Quality critical)**
  - `tests/api/test_complex_api.py::test_protected_cell_sei_binding_preserved` and `test_sei_api.py` equivalents — assert `entity_sei` flows to `entity_key.sei` / `identity_stable=True` for a protected dispatch. **(addresses Quality critical + systems high)**
- **Sequencing (mandatory):** (a) all new/rewritten test files pass with the unified route AND old routes both present; (b) **then** delete `post_protected_override`, `post_signoff_request`, and the legacy `OverrideIn`/`ProtectedIn`/`SignoffRequestIn` submit-path usage (`app.py:214-250`) plus the old test paths; (c) confirm `POST /protected/overrides` and `POST /signoff/request` now 404. The route deletion and final test state land together but only after the new tests are green against the unified route. **(addresses Architecture/Quality/systems high: phasing)**
- **Verify:** `pytest tests/api -q`.

### Task 9.5 — Update SEI conformance doc + oracle + vector

- **Modify:** `docs/federation/sei-conformance.md` (route list ~lines 18-26) and `tests/conformance/test_sei_oracle.py` (+ its fixture `tests/conformance/fixtures/sei-conformance-oracle.json` if it encodes route paths). **(addresses reality-grounding/Quality high: oracle test was omitted)**
- **Test first / audit:** read `tests/conformance/test_sei_oracle.py` and its fixture to find any scenario that POSTs to `/protected/overrides` or `/signoff/request`; update each to `POST /overrides`. Assert SEI keying semantics are preserved (the unified route keys on SEI identically; a protected-floor dispatch with `entity_sei` produces `identity_stable=True`).
- **Implementation:** update the doc's route list to the unified `POST /overrides` + retained operator-clear routes; re-pin the conformance vector to the new surface; name in the doc which floored-cell dispatch path preserves the `identity=` injection.
- **Verify:** the CI step "Run SEI conformance oracle" (`.github/workflows/ci.yml:25`) passes: `pytest tests/conformance -q`.

---

## PHASE 10 — Doctor reconciliation (non-zero exit on KEY_RESET)

Fail-closed: **`doctor` exits non-zero on an unacknowledged `KEY_RESET`** (spec §7/§10). Missing/zero-byte store → report-only `ok`.

### Task 10.1 — Posture ledger chain check + genesis presence check

- **Modify:** `src/legis/doctor.py:653-677 collect_checks()` using `_store_url` (`doctor.py:388`) and the `check_audit_chain` pattern (`doctor.py:424-450`).
- **Test first:** `tests/doctor/test_posture_checks.py`:
  - `test_posture_chain_ok` — healthy ledger → `store.posture_chain` `ok`.
  - `test_posture_chain_missing_is_ok` — no ledger / zero-byte → `ok` with "no ledger yet" (special-case before schema check).
  - `test_posture_chain_tampered_errors` — out-of-band tampered DB → `error` (via `verify_integrity()`).
  - `test_posture_store_exists_no_genesis_warns` — file exists, schema present, **zero rows** → a distinct `store.posture_ledger` check returns `warn` ("store initialized but no genesis record — re-run legis install"), because `verify_integrity()` on an empty store returns True (the loop exits immediately) and would otherwise misleadingly report "chain ok" while `read_floor()` is `None`/structured. **(addresses systems medium: empty-store confusing signal)**
- **Implementation:** `check_posture_chain(root)` (report-only, `repairable=False`) special-cases missing/zero-byte → ok, else `AuditStore(url).verify_integrity()`. `check_posture_ledger(root)` distinguishes no-file (ok), GENESIS-present (ok, reports floor), file-but-no-GENESIS (warn).
- **Verify:** `pytest tests/doctor/test_posture_checks.py -q`.

### Task 10.2 — Unacknowledged KEY_RESET → non-zero exit (with signature verification)

- **Modify:** `src/legis/doctor.py` (add `check_posture_key_reset(root)` to `collect_checks`); `run_doctor` (`doctor.py:680-683`) already returns non-zero if any `.ok` is False.
- **Test first:** `tests/doctor/test_posture_checks.py`:
  - `test_key_reset_unacknowledged_errors` — ledger with a `KEY_RESET` not followed by a signed transition raising the floor → `error`, `ok is False`, `run_doctor` non-zero.
  - `test_key_reset_acknowledged_ok` — `KEY_RESET` (new fp=FP2) followed by a `TRANSITION` whose `operator_sig` **verifies against FP2** → `ok`, `run_doctor` returns 0.
  - `test_key_reset_acknowledged_requires_new_epoch_fingerprint` — `KEY_RESET` (FP2) followed by a `TRANSITION` whose `key_fingerprint`/`operator_sig` is for the OLD epoch FP1 (or mismatched) → still `error`, `run_doctor` non-zero. **(addresses Quality/systems high: acknowledgment must verify the new-epoch signature, not just record-kind)**
  - `test_key_reset_message_attributed` — message names epoch reset date + `agent_id` (spec §8).
- **Implementation:** `check_posture_key_reset(root)`: `read_all()`; find the latest `KEY_RESET`; "acknowledged" = a later `TRANSITION` exists whose `operator_sig` **verifies via `signing.verify` against the new epoch's `key_fingerprint`** (introduced by the `KEY_RESET`). Per D6, record-kind presence is insufficient. If unacknowledged → `error`/`repairable=False`/`[operator]`. Never render key material (presence-only, `doctor.py:453-464`). The doctor uses the stored fingerprint for verification, never the key itself.
- **Verify:** `pytest tests/doctor/test_posture_checks.py -q && legis doctor --format json` (non-zero exit on an unacknowledged-KEY_RESET fixture).

### Task 10.3 — Operator-key accessibility check **(NEW — addresses Architecture/systems medium)**

- **Modify:** `src/legis/doctor.py` (add `check_operator_key_accessible(root)` to `collect_checks`).
- **Test first:** `tests/doctor/test_posture_checks.py`:
  - `test_operator_key_reachable_ok` — backend can produce the expected `key_fingerprint` (mocked) → `ok`.
  - `test_operator_key_lost_warns` — GENESIS present (fingerprint stored) but no backend can produce it → `warn` ("operator key not reachable in any backend — posture set will refuse; rekey to recover").
  - `test_operator_key_env_present_warns` — `LEGIS_OPERATOR_KEY` set → `warn` with the plaintext-in-env honesty note.
- **Implementation:** report-only, no key rendering. Read the latest GENESIS/KEY_RESET `key_fingerprint`; probe whether any backend can produce that fingerprint without revealing the key (keychain item exists; age-file exists at `operator_age_path()`; env `LEGIS_OPERATOR_KEY` set → warn). This closes the "ledger exists but key is lost" silent failure before the operator hits `posture set`.
- **Verify:** `pytest tests/doctor/test_posture_checks.py -q`.

---

## PHASE 11 — Rekey / lost-key path

Fail-closed/loud: **rekey preserves the standing floor, needs no old key, preserves history, writes `KEY_RESET`, doctor flags it** (spec §8).

### Task 11.1 — `posture rekey`

- **Modify:** `src/legis/posture/ledger.py` (`rekey()`), `src/legis/cli.py` (`posture rekey`).
- **Test first:** `tests/posture/test_rekey.py`:
  - `test_rekey_preserves_existing_floor` — `read_floor()` remains at the standing floor after rekey.
  - `test_rekey_mints_new_epoch` — new `key_fingerprint` != prior; new key handed to backend.
  - `test_rekey_preserves_history` — all prior records present; `verify_integrity()` True; `KEY_RESET` chained onto existing history (not a fresh DB).
  - `test_rekey_needs_no_old_key` — succeeds with no open session / no prior key available.
  - `test_rekey_writes_key_reset_record` — exactly one `KEY_RESET` with `kind=KEY_RESET, floor=<standing-floor>, key_fingerprint=<new>, agent_id, recorded_at`.
  - `test_doctor_flags_rekey` — after rekey, `legis doctor` exits non-zero until an acknowledging signed transition verifying against the new epoch (ties to 10.2).
- **Implementation:** `rekey(*, agent_id, recorded_at)`: read the standing floor (missing/empty ledger -> `structured`), `mint_key()` → backend; compute new fingerprint; `store.append(PostureRecord(kind=KEY_RESET, floor=<standing-floor>, key_fingerprint=new_fp, ...).to_payload())` (keyless, chained onto existing chain — `append`, not `append_signed`). CLI `_run_posture` dispatches `rekey`.
- **Verify:** `pytest tests/posture/test_rekey.py -q`.

---

## PHASE 12 — Security / honesty test suite (cross-cutting)

Create `tests/posture/test_security_honesty.py` asserting the spec's honesty guarantees (spec §6, §8, §9, §10).

- **`test_tty_session_expiry`** — past TTL, `load_session()` returns `None` and deletes the file; a `posture set` after expiry is refused.
- **`test_key_never_returned_to_caller`** — no backend exposes raw key bytes; `sign()` returns only a prefixed signature; `fingerprint()` returns a hash. Behavioral (per Quality medium): assert the returned signature does not contain the key hex, and no public method/attr value equals the key.
- **`test_rekey_preserves_existing_floor`** — (cross-ref Phase 11) rekey cannot downgrade an elevated floor.
- **`test_every_signature_carries_session_id`** — every `TRANSITION` in a window has `session_id` == the open session's id; a no-session transition is refused. Includes the **env-backend path** (D3): an `EnvSigner` transition still carries `session_id`.
- **`test_env_escape_hatch_warns`** — `EnvSigner` requires explicit `--insecure-key-in-env` and emits an honest warning.
- **`test_age_file_passphrase_required`** — age-file unlock with wrong/absent passphrase fails closed (no signature).
- **`test_operator_key_never_in_logs`** — **concrete, not aspirational** (per Quality high): instrument each backend's `sign()` with the `caplog` fixture at DEBUG (`propagate=True`), call sign on a known key, assert `key.hex()` does not appear in `caplog.text` at any level. Deterministic; catches regressions when log statements are added.

- **Verify:** `pytest tests/posture/test_security_honesty.py -q`.

### Task 12.1 — Published honesty-statement update **(NEW — addresses systems low)**

- **Modify:** `README.md` "Known security limitations" (and align spec §9).
- **Implementation:** add the operator-session-file residual to the published honesty statement: *"A process with read access to `.weft/legis/operator_session.json` can read the keychain item id and session HMAC; if it also has keychain access, it can produce arbitrary signatures during the window. This is the same tier as raw-DB-write access. The mitigation is OS keychain access control (item accessible only to the legis process user), not file encryption of the session file."* Consistent with the existing tamper-evident-not-tamper-proof stance.
- **Verify:** manual doc read; no test (documentation honesty item).

---

## Final full-suite verification

- **Run:** `pytest -q` (entire suite, including rewritten `tests/api/*` and `tests/conformance/*`).
- **Run:** `python scripts/check_coverage_floors.py` (posture package ≥ 93%).
- **Run:** `legis doctor --format json` on (a) a fresh-installed project → exit 0 with `store.posture_chain ok` + `store.posture_ledger ok`; (b) a project with an unacknowledged `KEY_RESET` fixture → exit non-zero; (c) a project whose operator key is unreachable → `warn`.
- **Run:** the floor-bypass regression at every surface:
  - MCP: floor `structured`, chill-registry policy → `override_submit` escalates AND `policy_explain`/`policy_list` report `structured`.
  - HTTP: floor `structured`, chill-registry policy → `POST /overrides` escalates (202), never self-clears (201).
  - Hooks: session banner reports the active floor.

---

## Cross-cutting fail-closed checklist (must hold at every surface)

1. **Missing/deleted ledger → `structured`, never `chill`** (only explicit GENESIS yields chill). — Phases 1, 4, 9, 10.
2. **No open / expired session → `posture set` refused, floor unchanged; a session is required on EVERY path including env (D3).** — Phases 3, 5, 7.
3. **Signer error or fingerprint mismatch (against the LEDGER epoch) → refused, no half-written record.** — Phases 2, 5.
4. **Floor read per request/invocation, never cached at startup (no `posture_floor` field on `McpRuntime`); ledger handle held, floor value read fresh.** — Phases 4, 8, 9.
5. **Floor applied at EVERY agent-visible cell-resolution site** (override routing, `policy_explain`, `policy_list`, hooks banner, unified API). — Phases 4, 8, 9.
6. **Operator key never plaintext to caller, never in `.mcp.json`, never in logs; doctor checks key reachability.** — Phases 2, 6, 10, 12.
7. **Rekey is loud: KEY_RESET record + non-zero doctor exit until acknowledged by a TRANSITION verifying against the NEW epoch.** — Phases 10, 11.
8. **Canonicalization is the single `canonical_json` chokepoint** (`sort_keys=True, ensure_ascii=False, allow_nan=False`); `chain_seq` bound into every signed record. — Phases 1, 2, 5.

---

## Appendix A — Review changelog

What changed in response to each critical/high finding:

- **(reality-grounding critical — `_atomic_write_text` does not exist):** Phase 3.1 now defines a local `_atomic_write_json` in `session.py` (temp+`os.replace`); removed all references to importing a nonexistent `install.py` symbol.
- **(reality-grounding critical / Architecture critical / Quality critical / systems critical — explain/list floor bypass):** Promoted "floor at every agent-visible site" to **Decision D0** and wired it in Phase 4 (not Phase 8). Added `test_policy_explain_reflects_floor`, `test_policy_list_reflects_floor`. Added explicit `dispatch_cell = floored_registry.cell_for(policy)` so MCP dispatch never depends on an unflooored `explanation.cell`.
- **(Architecture/systems critical — FlooredRegistry subclass vs wrapper):** Resolved as **Decision D1**: `FlooredRegistry` subclasses `PolicyCellRegistry`, so `explain_policy(registry, ...)` floors transparently without a signature change. Decided before Phase 4 so Phase 8 cannot fork it.
- **(reality-grounding high — AppendOnlyStore method count):** Corrected to 8 members; `PostureLedger` is a domain wrapper that *holds* an `AuditStore` and need not implement the protocol. Removed the "6 methods" assertion.
- **(reality-grounding high / Quality high — SEI conformance oracle omitted):** Added `tests/conformance/test_sei_oracle.py` and its fixture to Task 9.5 scope with an explicit read-and-update step and a CI gate (`ci.yml:25`).
- **(reality-grounding medium — `resolve_for_entry` naming):** Phase 9.1 clarifies the route does NOT call `resolve_for_entry` directly; the service functions call it internally via their `identity=`/`entity_sei=` parameters. Do not import it into `app.py`.
- **(reality-grounding medium — combinations test line count):** Corrected to the full 752-line file.
- **(reality-grounding medium — invented age-file home path):** Replaced `~/.config/legis/operator.age` with project-rooted `operator_age_path()` = `.weft/legis/operator.age`; added the resolver to `config.py` and gitignored it.
- **(Architecture high / systems critical — protected NEED_INPUTS guard):** Phase 9.1 adds an explicit `NEED_INPUTS` pre-check for the protected cell with discriminant aligned to MCP; Phase 9.2 maps it to 422. Test `test_protected_need_inputs`.
- **(Architecture high — ledger-handle vs floor-value caching):** Resolved as **Decision D2**; removed any `posture_floor` field from `McpRuntime`; hold the `PostureLedger` handle only, read `read_floor()` fresh. Test `test_mcp_floor_read_per_invocation`.
- **(Architecture/Quality/systems high — Phase 9 phasing):** Reordered Phase 9: composition-root wiring (9.0) → unified route alongside old (9.1) → new tests green (9.1-9.4a) → delete old routes + paths (9.4b). Bisectable, never an all-tests-fail window.
- **(Architecture medium — read_floor on hot path):** `read_floor()` now uses `get_latest_sequence_and_hash()` + `read_by_seq` (two O(1) queries), not `read_all()`. Test `test_read_floor_uses_tail_read`.
- **(Architecture/Quality medium — over-decomposition):** Consolidated `custody.py` into `signing.py` (6 modules, not 7).
- **(Architecture medium — session unlock_ref ambiguity):** Resolved as **Decision D5**: age-file `unlock_ref` is `None` (re-prompt is the unlock); keychain stores the item id. Test `test_age_backend_unlock_ref_is_none`.
- **(Quality critical — concurrent session race):** Resolved as single-active-session (`test_second_enable_replaces_first`) plus fingerprint validation against the **ledger epoch**, not the session field (`test_set_refused_fingerprint_mismatch`).
- **(Quality critical — protected source/SEI binding survives route collapse):** Added named assertions `test_protected_cell_source_binding_preserved` and `test_protected_cell_sei_binding_preserved`.
- **(Quality high — posture coverage floor):** Added Task 0.3: `'src/legis/posture/': 93.0` in `scripts/check_coverage_floors.py`, landing in the first posture commit.
- **(Quality high — genesis after KEY_RESET / idempotent-after-rekey):** Added `test_genesis_blocked_after_key_reset` and `test_install_idempotent_after_rekey`.
- **(Quality/systems high — KEY_RESET acknowledgment must verify the new-epoch signature):** Resolved as **Decision D6**; doctor now calls `signing.verify` against the new epoch fingerprint. Test `test_key_reset_acknowledged_requires_new_epoch_fingerprint`.
- **(Quality high — Q-M5 batch invariant):** Added `test_no_read_inside_transition_batch`; `transition()` resolves the epoch fingerprint via a tail read BEFORE `append_signed`.
- **(Quality high — unregistered policy under elevated floor):** Added `test_unregistered_policy_respects_floor`.
- **(Quality high — concrete key-in-logs test):** Phase 12 `test_operator_key_never_in_logs` is now a deterministic `caplog`-based behavioral test, not a static scan.
- **(systems critical — per-request DDL lock):** Resolved as **Decision D2**/Task 9.0: ledger opened once with `initialize=True` at startup; per-request reads use the shared instance; never `initialize=True` in a handler.
- **(systems critical — legacy protected_set 403 guard):** Phase 9.1 removes the env-var `protected_set` 403 guard; `FlooredRegistry.cell_for` owns protected routing. Test `test_no_legacy_protected_set_403_guard`.
- **(systems high — hooks banner honesty gap):** Added Task 4.3: the session-context banner reports the active floor.
- **(systems high — CI/headless operator-enable bootstrap):** Phase 7.2 defines the CI sequence; the env path still opens a session (D3) so the `TRANSITION` carries a `session_id`. Test `test_ci_env_backend_opens_session_with_id`.
- **(systems high — idempotency replay vs floor):** Resolved as **Decision D4** (floor-exempt, documented); pinned by `test_idempotent_replay_is_floor_exempt`.
- **(systems high — operator-key accessibility):** Added Task 10.3 (`check_operator_key_accessible`).
- **(Lower-severity items folded in):** off-by-one `protected.py:207` citation corrected in anchors; negative `to_payload` chain-field assertion (`test_to_payload_excludes_chain_fields`); `_atomic_write_json` ownership; `posture_get` unacknowledged-reset flag; double-expire idempotency; wrong-passphrase-mid-window refusal; exact gitignore patterns; published honesty statement (Task 12.1).

---

## Appendix B — Open questions for the operator

**All six resolved by John on 2026-06-16** (questions retained below for context):

- **Q1 — single active session:** confirmed; `operator enable` **replaces** any prior session (one active `operator_session.json`).
- **Q2 — idempotency replays:** **warning variant** chosen (not silent floor-exempt) — the replay returns the original outcome but carries a `floor_warning` discriminant when the current floor is higher than the floor at write time (see D4).
- **Q3 — coverage floor:** raised to **93%**, matching `enforcement/`.
- **Q4 — `cryptography>=42`:** confirmed as the provisional bound; a P3 follow-up to revisit after supply-chain research is filed (Filigree `legis-ea02d6c6a8`).
- **Q5 — `FlooredRegistry` subclass (D1):** confirmed, **with the composition-wrapper fallback pre-approved** so implementation is never blocked mid-phase.
- **Q6 — env-backend CI session (D3):** confirmed; CI runs `legis operator enable --insecure-key-in-env` before `posture set` so every signature carries a `session_id` (no implicit synthetic-session path).

The original questions, for context:

1. **Single active session vs. concurrent sessions.** The plan resolves the concurrent-session race by making `operator enable` **replace** any prior session (exactly one active `operator_session.json`). The spec's accountability model (§6) is compatible with this, but it means a second operator's `enable` silently supersedes the first's window. Confirm single-active-session is acceptable, or specify a multi-session policy (e.g., refuse a second enable while one is live).

2. **Idempotency replays are floor-exempt (D4).** An MCP `override_submit` replay with a stored `idempotency_key` returns the original outcome even if the floor was raised in between. The alternative is to emit a `WARNING` discriminant noting floor-at-time vs floor-now. The plan chooses floor-exempt (the record cannot be unwritten); confirm, or request the warning variant.

3. **Coverage floor target for `src/legis/posture/`.** The plan sets 90% (between `mcp.py` at 80% and `enforcement/` at 93%). Given this is the most security-sensitive new code, confirm 90% or raise to 93% to match `enforcement/`.

4. **`cryptography>=42` lower bound.** The repo currently pins no crypto deps. Confirm `>=42` is acceptable or specify a tighter/looser bound to match your supply-chain policy.

5. **`FlooredRegistry` as a `PolicyCellRegistry` subclass (D1).** This is the cleanest fix for the explain/list honesty gap, but it couples `FlooredRegistry` to `PolicyCellRegistry.__init__`. If `PolicyCellRegistry`'s constructor is awkward to subclass, the fallback is a composition wrapper that re-implements `cell_for`/`default_cell`/`rule_for`. Confirm the subclass approach, or pre-approve the wrapper fallback so implementation isn't blocked mid-phase.

6. **Env-backend session semantics on CI (D3).** The plan requires `legis operator enable --insecure-key-in-env` before any `posture set` in CI, so every signature carries a `session_id`. This adds one bootstrap command to CI pipelines that move the floor. Confirm this is the desired CI ergonomics, or approve a one-shot `legis posture set --insecure-key-in-env` that opens an ephemeral synthetic session implicitly.
