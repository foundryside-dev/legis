# Legis Posture Ratchet + Operator Elevation Sessions — v1 Implementation Plan (FINAL)

This is a test-driven, phase-ordered plan. Each phase respects upstream dependencies. Every task names the test(s) to write **first**, then the implementation, then a verification command. Fail-closed behaviors are called out explicitly. Do not deviate from the canonical-JSON and seq-binding contracts — they are load-bearing for HMAC verification across tools.

**This revision resolves all critical/high review findings before any code is written.** The most consequential changes from the draft: (1) the session+key-custody architecture is now a committed decision (passphrase-cached age-key blob OR keychain reference — see Decision D1); (2) floor injection is centralized in a single `FlooredRegistry` chokepoint instead of scattered call-site parameters; (3) `OPERATOR_SESSION_OPENED` records go in a **separate** session ledger, preserving the "last record = current floor" invariant; (4) `explain_cell` is called with the floored cell so the whole explanation is internally consistent; (5) the HTTP API floor gap is explicitly scoped out with a Filigree tracker; (6) the `PostureLedger` wrapper is eliminated — callers use `AuditStore` directly; (7) doctor chain-checks are refactored to iterate `STORE_DB_SPECS`; (8) `sign()` is always called with `version="v3"`; (9) doctor opens stores with `initialize=False`; (10) `PostureVerifier`/`signer.verify()` exists for read-side audit; (11) a coverage floor is registered for the new package.

---

## Architectural decisions (ADR-level — locked before implementation)

These resolve the critical/high seam-level findings. They are binding; do not relitigate during implementation.

### D1 — Session state model (resolves systems-critical, architecture-critical, quality-critical)

The CLI is stateless-per-invocation (confirmed: `cli.py:main` is a fresh process per call). The "ssh-agent style" in-memory daemon of spec §6 is **deferred to v1.1**. v1 uses a **persisted session file** whose contents depend on the backend, with a clean two-level key hierarchy so the operator key never lands on disk in plaintext:

- **`.weft/legis/operator_session.json`** holds ONLY: `session_id`, `operator_id`, `enabled_at` (epoch float), `ttl_seconds`, `backend_id`, and a backend-specific **`unlock_ref`** (never the operator key, never a passphrase).
- **OS keychain backend:** `unlock_ref` is the keychain item identifier. Each `posture set` within TTL issues a **silent keychain read** (no prompt within the same OS login session, by keychain ACL design). "TTL lapse" is enforced by Legis deleting the session file; the keychain item itself persists across epochs.
- **age-file backend:** at `operator enable`, the operator's passphrase decrypts the operator key once; Legis derives a **session-wrapping key** from a freshly minted random session secret, encrypts the operator key under it, and writes the wrapped blob to `.weft/legis/operator_session.json` (`wrapped_key` field). The session secret is stored in the OS keychain if available, else held only in `unlock_ref` as an `age`-passphrase-recall is **not** done — instead v1 age-file sessions re-prompt for the passphrase on each `posture set` UNLESS the OS keychain is available to hold the session secret. This is the honest tradeoff (spec §6 "low friction"): **age-file without a keychain re-prompts per `posture set`; the session file then holds only metadata.** This is documented in `operator enable` output.
- **env escape hatch:** key is already in `LEGIS_OPERATOR_KEY`; the session file holds only metadata; `sign()` reads env each call.

**"Zeroized on TTL lapse"** means: the session file is deleted, and any `wrapped_key` blob it contained is gone. The operator key in custody (keychain item / age file) is untouched.

This is recorded as an ADR in the repo (`docs/adr/` if present, else inline in `src/legis/posture/session.py` module docstring) per `muna-technical-writer:create-adr` conventions.

### D2 — Floor injection chokepoint (resolves architecture-critical, quality-critical, systems-critical)

Floor is applied at **the registry boundary**, not threaded as a parameter to every caller. Introduce `FlooredRegistry` in `src/legis/posture/floor.py`:

```python
class FlooredRegistry:
    """Wraps a PolicyCellRegistry, raising every cell_for() result to the posture floor."""
    def __init__(self, inner: PolicyCellRegistry, floor: str) -> None: ...
    @property
    def default_cell(self) -> str: return max_cell(self._floor, self._inner.default_cell)
    def cell_for(self, policy: str) -> str: return max_cell(self._floor, self._inner.cell_for(policy))
    def rule_for(self, policy: str): return self._inner.rule_for(policy)  # raw rule, for matched_rule/policy_known
```

- `explain_policy` is called with a `FlooredRegistry`; it computes `raw_cell = rule.cell if rule else registry.default_cell` — which is **already floored** because `default_cell` and the rule lookup both pass through the wrapper. **Critically, `explain_cell` is invoked with the floored cell** (see Task 4.2), so `enabled`/`available_moves`/`required_inputs` are all consistent with the floored cell. `matched_rule` and `policy_known` use `rule_for` (raw), preserving honest "which rule matched" reporting.
- `mcp.py:1691-1696` uses `_floored_registry(runtime)` for BOTH the `simple_engine` selection AND the `explain_policy` call, computed once. No call site does its own `max()`.
- Any future tool or HTTP handler that takes a registry gets flooring for free by constructing `FlooredRegistry`.

The `max_cell` helper lives in `floor.py` and is the ONLY place that indexes `CELL_TIER_ORDER`.

### D3 — Session records live in a separate ledger (resolves architecture-low, quality-critical, quality-medium)

`OPERATOR_SESSION_OPENED` records do **NOT** go in `posture.db`. They go in a sibling **`.weft/legis/posture_sessions.db`** (its own `AuditStore`). This preserves the invariant "`posture.db`'s last record is the current floor" — `read_floor` reads `records[-1]` without filtering by kind, because only `GENESIS|TRANSITION|KEY_RESET` ever land there. `test_every_transition_carries_session_id` (Phase 10) correlates a `TRANSITION.session_id` (in `posture.db`) against an `OPERATOR_SESSION_OPENED.session_id` (in `posture_sessions.db`) by opening both stores. Both DBs are registered in `STORE_DB_SPECS` and get doctor chain-coverage.

> Defensive belt-and-suspenders: `read_floor` still validates that `records[-1].payload["kind"]` is floor-bearing and `payload["floor"] in CELL_TIER_ORDER`; if not, it fails closed to `structured` (see Task 4.1). This guards against future schema drift even though D3 makes mixed-kind reads impossible by construction.

### D4 — No `PostureLedger` wrapper; use `AuditStore` directly (resolves architecture-high)

The draft's 7-module package with a pass-through `PostureLedger` is collapsed. Callers use `AuditStore` directly (exactly as `ProtectedGate`/`SignoffGate` do). Helper free functions in `service.py` (`current_floor_record(store)`, `posture_store_exists(store)`) replace the wrapper methods. Final module layout (5 modules):

```
src/legis/posture/
  __init__.py
  records.py     # PostureRecord dataclass + to_payload(); posture_signing_fields(payload, *, seq); record kinds
  floor.py       # CELL_TIER_ORDER reuse, max_cell, effective_cell, read_floor (fail-closed), FlooredRegistry
  signer.py      # PostureSigner protocol (sign + fingerprint + verify) + EnvSigner/AgeFileSigner/KeychainSigner + mint_key + select_backend
  session.py     # ElevationSession (enable/disable/active/current_session_id) — D1 model, separate sessions store (D3)
  service.py     # posture_show/posture_set/posture_rekey/operator_enable/operator_disable orchestration; helper free fns over AuditStore
```

Errors live in `src/legis/service/errors.py` (NOT a new `posture/errors.py`) — see D5.

### D5 — Posture errors extend the existing service taxonomy (resolves architecture-high)

`PostureError`, `SessionNotOpenError`, `KeyFingerprintMismatchError`, `SignerError`, `LedgerCorruptError`, and `LedgerWriteError` are added to `src/legis/service/errors.py` as peers of the existing errors (alongside `AuditIntegrityError`). The HTTP and MCP adapter error-handler comments at `service/errors.py:4-6` are updated to acknowledge the new types. No cross-package import cycle; the adapters' error taxonomy stays coherent.

### D6 — HTTP API floor enforcement is OUT OF SCOPE for v1 (resolves systems-critical)

The HTTP API (`api/app.py` POST `/overrides`, `/protected/overrides`, `/signoff/request`) does not call `explain_policy`/`cell_for` and is **not** floored in v1. This is a **documented, deliberate gap**, not a silent one. Rationale: v1's single consumer is the posture floor via the MCP/service path (spec §1, §10); the HTTP API is a separate transport whose floor integration is its own risk surface. **Action:** file a Filigree issue ("HTTP API bypasses posture floor — POST /overrides routes by protected-set membership, not floored cell") before merge, and add a one-line comment at `api/app.py:528` pointing to it. The `posture_get` honesty statement (spec §7) is about MCP; the HTTP gap is tracked, not claimed-closed.

### D7 — Floor freshness in MCP: read once at startup, documented (resolves systems-critical, architecture-medium)

`posture_floor` is read **once** at `build_runtime()` and cached on `McpRuntime` for the process lifetime — consistent with how `cell_registry` is already loaded once. A `posture set` during a live MCP session takes effect on the **next MCP process start**. This staleness is documented in: (a) the `posture_get` tool's output-schema description, and (b) the `posture set` CLI command's success output ("active MCP sessions use the floor read at their startup; restart the MCP server to apply immediately"). A test pins this behavior. `posture_floor` on `McpRuntime` is set once and never mutated (a comment marks it; a test asserts it is unchanged across a tool-call sequence).

### D8 — TTL clock seam (resolves quality-critical)

The existing `Clock` protocol (`src/legis/clock.py:14`) is **ISO-string-only by design** and is NOT extended. TTL arithmetic uses a **separate injectable epoch-time callable** `time_fn: Callable[[], float]` (defaults to `time.time`) passed to `ElevationSession`. Tests inject a fake. The existing `Clock` is still used where ISO strings are needed (e.g. `recorded_at`).

### D9 — Concurrent-install / TOCTOU safety (resolves quality-high, systems-critical)

- **Install genesis race:** `install_posture_floor` performs the "exists? → else mint+write" sequence under an **OS-level file lock** (`fcntl.flock` on a `.weft/legis/.posture_install.lock` file) so two concurrent installs cannot both write `GENESIS`. A second install (lock acquired after the first wrote genesis) sees the existing ledger and returns idempotent.
- **Session TOCTOU at signing:** the session-active check is performed **inside the `append_signed` build closure** — under the SQLite `BEGIN IMMEDIATE` lock — so a session expiring between the pre-check and the write causes the closure to return a sentinel that aborts the append and raises `SessionNotOpenError`. This closes the window where a record could be signed under a session that lapsed mid-write.

---

## Global conventions (apply to every phase)

- **Cell ordering:** never use Python `max()` on cell strings. All comparisons go through `max_cell()` (indexing `CELL_TIER_ORDER`, `src/legis/policy/cells.py:22`). `max_cell()` raises `ValueError` on any input not in `CELL_TIER_ORDER` (callers treat that as corrupt → fail-closed).
- **Fail-closed defaults:** absent/corrupt/invalid-floor-value ledger → effective floor is **`structured`**, never `chill` (spec §4, §10). Only an explicit `GENESIS` record makes `chill` the floor. No open session / fingerprint mismatch / signer error / ledger-busy → refuse the transition, floor unchanged (spec §7).
- **Canonical bytes:** posture HMAC uses `canonical_json` (`src/legis/canonical.py:41`) — `sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False`. Use `src/legis/enforcement/signing.py:sign(fields, key, version="v3")` and `verify(...)`. **`version="v3"` is passed explicitly on EVERY call — the function default is `v2` (`signing.py:53`) and relying on it is a silent seq-binding regression.** Do NOT use `weft_signing.py` (it uses `json.dumps` without `ensure_ascii=False`, `weft_signing.py:42` — a different canonicalization; it is for Weft component transport auth, not governance records).
- **Seq-binding:** every keyed record (`TRANSITION`) binds `chain_seq` into the signed field set via the `append_signed(build_payload)` seam (`src/legis/store/audit_store.py:296`), mirroring `ProtectedGate._record_signed()` (method begins at `protected.py:241`; the signing closure is ~`protected.py:274`; `append_signed` is called ~`protected.py:286`). v3 from day one.
- **Single signed-field definition:** `posture_signing_fields(payload, *, seq)` (in `records.py`) is the ONE definition of what gets signed, called from BOTH the write path (inside the `append_signed` closure) AND the read/verify path. Mirrors `protected.signing_fields` (`protected.py:45-92`). `signer.sign(fields)` and `signer.verify(fields, sig)` take a pre-built `posture_signing_fields(...)` dict — never a raw record.
- **Key never returned to caller:** `PostureSigner` exposes only `sign(fields) -> str`, `verify(fields, sig) -> bool`, `fingerprint() -> str`. No method/attribute returns key bytes. Security test (Task 2.1) introspects `dir()` to assert this.
- **Version pinning on read:** posture `TRANSITION` records are v3-only. The read/verify path rejects a `TRANSITION` whose `operator_sig` does not start with `SIG_PREFIX_V3` (`hmac-sha256:v3:`, `signing.py:33`) as a tamper-evidence violation, even though `signing.verify` would accept a v2 sig.
- **Logging:** module-level `logging.getLogger(__name__)`. Never log key bytes or passphrases; fingerprints and `session_id` are OK. `operator enable`/`disable` log at INFO; a TTL-lapse transition (active→False) logs at WARNING.

---

## Coverage floor registration (do this in Phase 1, before any posture code ships)

Add to `FLOORS` in `scripts/check_coverage_floors.py`:
- `'src/legis/posture/': 93.0` — matches the `enforcement/` floor; this package holds the signing seam, fail-closed floor logic, and TTL enforcement.
- After Phase 4's injection changes land, re-baseline `src/legis/mcp.py` (currently `80%`) so the new floored paths are covered, not diluted.

A new package with no registered floor is invisible to the CI coverage gate; register it first so partial test coverage cannot ship green.

---

## Tests directory

`tests/` has no `__init__.py` (verify with `ls`); `pyproject.toml` sets `testpaths=["tests"]`, `pythonpath=["src"]`. Create `tests/posture/` as a plain directory — pytest discovers it automatically. Add `tests/posture/conftest.py` only when shared fixtures (temp posture+sessions stores, fake `time_fn`, mock signer) are needed across files — they will be, so create it in Phase 1 with: a temp-stores fixture, a `FakeClock`/`fake_time` fixture, and a `MockSigner` (deterministic HMAC over a fixed test key).

---

## PHASE 0 — Config plumbing (posture.db + posture_sessions.db URL resolvers)

**Dependency:** none. Everything downstream needs the DB URLs.

### Task 0.1 — Register both posture stores in config

**Files:** `src/legis/config.py`

**Test first** — `tests/test_config.py::test_posture_db_urls_default_and_env_override`:
- `posture_db_url()` returns `sqlite:///.weft/legis/posture.db` (relative to `_store_dir()`) when `LEGIS_POSTURE_DB` is unset; `LEGIS_POSTURE_DB=sqlite:///tmp/x.db` overrides.
- `posture_sessions_db_url()` returns `sqlite:///.weft/legis/posture_sessions.db` by default; `LEGIS_POSTURE_SESSIONS_DB` overrides.
- Both `("LEGIS_POSTURE_DB", "posture.db")` and `("LEGIS_POSTURE_SESSIONS_DB", "posture_sessions.db")` are present in `STORE_DB_SPECS` (`config.py:61`).

**Implementation:**
- Add constants near `config.py:47`: `POSTURE_DB_ENV = "LEGIS_POSTURE_DB"`, `_POSTURE_DB_NAME = "posture.db"`, `POSTURE_SESSIONS_DB_ENV = "LEGIS_POSTURE_SESSIONS_DB"`, `_POSTURE_SESSIONS_DB_NAME = "posture_sessions.db"`.
- Append both `(POSTURE_DB_ENV, _POSTURE_DB_NAME)` and `(POSTURE_SESSIONS_DB_ENV, _POSTURE_SESSIONS_DB_NAME)` to `STORE_DB_SPECS` (`config.py:61`).
- Add `posture_db_url()` and `posture_sessions_db_url()` resolvers following `config.py:114-127`.
- **Docstring amendment (`config.py:29-32`):** change "nothing here touches key material" to: *"nothing here touches key material; the operator-key custody seam is in `src/legis/posture/signer.py` (key minted at install, handed to custody immediately, never stored in config)."* This points to the real custody location rather than implying config now holds keys.

**Verify:** `pytest tests/test_config.py -k posture -q`

---

## PHASE 1 — Posture records + signed-field contract + golden vector

**Dependency:** Phase 0.

### Task 1.1 — PostureRecord + `posture_signing_fields` + canonical golden vector

**Files:** `src/legis/posture/records.py` (new), `tests/posture/conftest.py` (new), `scripts/check_coverage_floors.py` (register floor — see above)

**Test first** — `tests/posture/test_records.py`:
- `test_posture_record_to_payload_roundtrip`: `PostureRecord(kind="GENESIS", floor="chill", key_fingerprint="abc", agent_id="install", recorded_at="2026-06-16T...", rationale="install genesis")` → `to_payload()` yields the expected flat dict; `operator_sig`/`session_id` are absent on GENESIS (placed under `payload["extensions"]` only when present, mirroring the protected-cell convention).
- `test_signing_fields_includes_chain_seq_and_fingerprint`: `posture_signing_fields(payload, seq=5)` includes `chain_seq=5` (v3 binding) AND `key_fingerprint`, plus `kind`, `floor`, `session_id`, `recorded_at`, `agent_id`. **Assert `key_fingerprint` IS in the signed set** (so the epoch is tamper-evident) — document in the test body that this is intentional and non-circular (fingerprint = sha256(key); the key MACs the fields *including* its own fingerprint; this is fine and standard).
- `test_canonical_parity_golden_vector` **(written here, NOT deferred to Phase 10):** for a fixed payload + seq, pin the exact bytes of `canonical_json(posture_signing_fields(payload, seq=N))` against a hard-coded golden string. Assert `sign()` and `verify()` consume byte-identical input. This guards the cross-tool canonical-JSON contract from day one.

**Implementation:**
- Record kinds: `GENESIS`, `TRANSITION`, `KEY_RESET`. (No `OPERATOR_SESSION_OPENED` here — that record's schema lives in `session.py` and writes to the sessions store per D3.)
- `@dataclass(frozen=True, slots=True) PostureRecord` with `kind`, `floor`, `key_fingerprint`, `agent_id`, `recorded_at`, `rationale`, and optional `operator_sig: str | None = None`, `session_id: str | None = None`. Mirror `OverrideRecord` (`override_record.py:18`).
- `to_payload() -> dict`: flat dict; `operator_sig` and `session_id`, when present, go under `payload["extensions"]` (matches `protected.py` extension convention and keeps the signed-field set stable).
- `posture_signing_fields(payload, *, seq) -> dict`: the single signed-field definition — `kind + floor + key_fingerprint + session_id + recorded_at + agent_id`, plus `chain_seq=seq`. Mirror `protected.signing_fields` (`protected.py:45-92`).

**Verify:** `pytest tests/posture/test_records.py -q`

---

## PHASE 2 — PostureSigner seam (sign + verify + fingerprint) + custody backends

**Dependency:** Phase 1.

> **Backend reality (review CRITICAL):** the codebase has ZERO secret-backend infrastructure and `pyproject.toml` (`12-46`) declares no `keyring`/`cryptography`/`age` deps. v1 ships the **env escape hatch** + **age-file** (committed crypto choice below) + **OS keychain** (graceful-unavailable). Optional deps are declared as **extras**, never hard deps.

### Task 2.0 — pyproject optional extras

**Files:** `pyproject.toml`

Add a `[project.optional-dependencies]` section:
- `keychain = ["keyring>=24"]`
- `age = ["cryptography>=42"]` — **only if** the age-file backend uses the `cryptography` package (see Task 2.2 decision).

Backend selection at runtime uses **conditional imports** (`try: import keyring`), not package-install-time gating. Document these as optional extras in the install docs.

### Task 2.1 — PostureSigner protocol (sign/verify/fingerprint) + key minting

**Files:** `src/legis/posture/signer.py` (new)

**Test first** — `tests/posture/test_signer.py`:
- `test_mint_key_is_32_bytes_hex`: `mint_key()` returns `secrets.token_hex(32)`-shaped material (spec §5); assert length/charset.
- `test_signer_never_returns_key`: protocol/ABC exposes only `sign(fields) -> str`, `verify(fields, sig) -> bool`, `fingerprint() -> str`; introspect `dir()` and assert NO public `key`/`key_bytes` attribute or accessor. **Security test — load-bearing.**
- `test_sign_is_v3`: `EnvSigner(...).sign(fields)` returns a string starting with `"hmac-sha256:v3:"` (`SIG_PREFIX_V3`, `signing.py:33`). **Guards the explicit-v3 contract.**
- `test_sign_matches_signing_primitive`: `EnvSigner.sign(fields)` equals `signing.sign(fields, key_bytes, version="v3")`.
- `test_verify_roundtrips_without_exposing_key`: `signer.verify(fields, signer.sign(fields))` is `True`; a tampered `fields` → `False`. Verify is done via `signer.verify`, NOT by re-extracting the key.
- `test_fingerprint_is_sha256_of_key`: `signer.fingerprint() == sha256(key_bytes).hexdigest()` (spec §7 gate).

**Implementation:**
- `class PostureSigner(Protocol)`: `sign(self, fields: dict) -> str`, `verify(self, fields: dict, signature: str) -> bool`, `fingerprint(self) -> str`.
- `mint_key() -> str`: `secrets.token_hex(32)`.
- **Key encoding locked once:** the hex string from `mint_key()` is decoded via `bytes.fromhex(...)` everywhere (mint→fingerprint→sign→verify). `fingerprint()` = `sha256(bytes.fromhex(key_hex)).hexdigest()`.
- `EnvSigner`: reads `LEGIS_OPERATOR_KEY`; logs an honest WARNING on construction (spec §6, §9). `sign`/`verify` delegate to `signing.sign(fields, bytes.fromhex(key), version="v3")` / `signing.verify(fields, sig, bytes.fromhex(key))`. Key bytes held in a private attribute; no public accessor.

**Verify:** `pytest tests/posture/test_signer.py -q`

### Task 2.2 — Age-file backend (crypto choice LOCKED)

**Decision (resolves quality-medium "pick one"):** age-file uses the **`cryptography` package** (declared under the `age` extra), with `scrypt` (stdlib `hashlib.scrypt`) as the passphrase KDF and AES-GCM (authenticated) for the key blob. Rationale: stdlib-only authenticated symmetric encryption is not available without hand-rolling AEAD (unsafe); `cryptography` is the right dependency and is optional. The `age` CLI binary is NOT shelled out in v1.

**Files:** `src/legis/posture/signer.py`

**Test first** — `tests/posture/test_signer.py::test_age_file_roundtrip` (marked `pytest.importorskip("cryptography")`):
- Mint a key, encrypt to a temp `operator.age` with a passphrase (scrypt→AES-GCM), decrypt, assert the recovered key `sign(fields)` equals the original. Real encrypt/decrypt round-trip (spec §10). A wrong passphrase → authentication failure raised, not silent.

**Implementation:**
- `AgeFileSigner`: key encrypted at `~/.config/legis/operator.age`. `scrypt(passphrase, salt, n=2**15, r=8, p=1, dklen=32)` → AES-256-GCM key; store `salt || nonce || ciphertext || tag` framed in the file. `sign()`/`verify()` decrypt the operator key in-memory only during the call, then discard. Per D1, age-file sessions without a keychain re-prompt for the passphrase per `posture set`.

**Verify:** `pytest tests/posture/test_signer.py -k age -q`

### Task 2.3 — OS keychain backend (graceful-unavailable) + backend selection

**Files:** `src/legis/posture/signer.py`

**Test first** — `tests/posture/test_signer.py`:
- `test_keychain_backend_mocked`: with a monkeypatched keychain access layer, store→retrieve→sign→verify round-trips; key bytes never surface to caller (spec §10).
- `test_keychain_unavailable_falls_back`: when the keychain import/access fails, `select_backend(prefer_keychain=True)` returns an `AgeFileSigner` (spec §6 "OS keychain if available, else age-file").
- `test_select_backend_env_only_with_flag`: env backend is only selected when `insecure_env=True`.

**Implementation:**
- `KeychainSigner` behind a conditional import of `keyring` (optional `keychain` extra). On import/access failure raise `BackendUnavailable`.
- `select_backend(*, prefer_keychain=True, insecure_env=False) -> PostureSigner`: keychain → age-file → (only if `insecure_env`) env. Used by install, CLI, and session.

**Verify:** `pytest tests/posture/test_signer.py -k "keychain or select" -q`

---

## PHASE 3 — Elevation session state (separate sessions ledger, epoch-time TTL)

**Dependency:** Phase 0 (sessions store URL), Phase 1 (records), Phase 2 (signer). Independent of floor injection.

### Task 3.1 — Session enable/disable/active with TTL (D1 + D3 + D8)

**Files:** `src/legis/posture/session.py` (new)

**Test first** — `tests/posture/test_session.py` (inject `fake_time`):
- `test_enable_opens_window_and_writes_record`: `enable(ttl_seconds=300)` returns a `session_id`, writes an `OPERATOR_SESSION_OPENED` record `{operator_id, enabled_at, ttl, keychain_auth_ref}` to **`posture_sessions.db`** (D3), and persists `.weft/legis/operator_session.json` (D1: metadata + backend-specific `unlock_ref`/`wrapped_key`, never the operator key).
- `test_active_session_within_ttl`: opened at `t0`, `active()` with `fake_time = t0+299` is `True`.
- `test_ttl_lapse_zeroizes`: `fake_time = t0+301` → `active()` is `False`; the session file is deleted and any `wrapped_key` blob is gone (D1). **Fail-closed.**
- `test_ttl_lapse_logs_expiry`: `caplog` shows a WARNING when `active()` transitions True→False due to TTL.
- `test_disable_ends_early`: `disable()` → `active()` immediately `False`; INFO log emitted.
- `test_session_id_threaded`: the `session_id` from `enable()` is the same one `current_session_id()` returns and a subsequent `posture set` stamps into the signed record. **Accountability — load-bearing.**
- `test_enable_logs_info` / `test_disable_logs_info`: lifecycle observability.

**Implementation:**
- `ElevationSession(sessions_store: AuditStore, *, time_fn: Callable[[], float] = time.time, clock: Clock)`: `time_fn` for TTL math (D8), `clock` for ISO `recorded_at`.
- `enable(signer, ttl_seconds, operator_id, agent_id) -> str`: mint `session_id` (`secrets.token_hex`), record `enabled_at=time_fn()`, `ttl_seconds`, `backend_id`; write `OPERATOR_SESSION_OPENED` to the **sessions** store via `sessions_store.append(...)`; persist `operator_session.json` atomically (temp+rename, mirror `install._atomic_write_text`, `install.py:277-307`). For age-file-with-keychain, store the `wrapped_key`; otherwise metadata-only (D1).
- `active() -> bool`: read session file; `False` if absent, `time_fn() >= enabled_at + ttl_seconds`, or disabled. **Default False (fail-closed).** Logs WARNING on True→False TTL transition.
- `current_session_id() -> str | None`.
- `disable()`: delete/zero the session file; INFO log.
- Atomic writes; concurrent enables last-write-wins (documented). TOCTOU at signing is closed in Phase 4 (D9) by re-checking `active()` inside the `append_signed` closure.

**Verify:** `pytest tests/posture/test_session.py -q`

---

## PHASE 4 — Floor read + FlooredRegistry chokepoint + change gate

**Dependency:** Phases 1–3. Core consumer wiring.

### Task 4.1 — `max_cell`, `effective_cell`, `read_floor`, `FlooredRegistry`

**Files:** `src/legis/posture/floor.py` (new)

**Test first** — `tests/posture/test_floor.py`:
- `test_effective_cell_all_16_combinations`: parametrize all 4×4 `(floor, registry_cell)`; assert `effective_cell(floor, cell) == CELL_TIER_ORDER[max(idx(floor), idx(cell))]`. Explicitly assert floor raises (`chill` registry + `structured` floor → `structured`) and never lowers (`protected` registry + `chill` floor → `protected`).
- `test_max_cell_unknown_value_raises`: `max_cell("bogus", "chill")` raises `ValueError`.
- `test_read_floor_absent_store_is_structured`: empty/missing `posture.db` → `read_floor()` returns `"structured"` (spec §4 — **NOT chill**). **Load-bearing.**
- `test_read_floor_genesis_chill`: GENESIS(chill) → `"chill"`.
- `test_read_floor_corrupt_ledger_is_structured`: `verify_integrity()` False → `"structured"`.
- `test_read_floor_invalid_floor_value_is_structured`: a record with `floor="superstrict"` → `"structured"` (corrupt content ≠ integrity failure; must still fail closed). **Closes the untested edge.**
- `test_read_floor_non_floor_kind_tail_is_structured`: defensive — if `records[-1].payload["kind"]` is not floor-bearing (cannot happen under D3, but guards drift) → `"structured"`.
- `test_floored_registry_raises_default_and_cell`: `FlooredRegistry(inner, "structured").cell_for("X")` where inner→`chill` returns `"structured"`; `.default_cell` is floored; `.rule_for("X")` returns the raw rule unchanged.

**Implementation:**
- `max_cell(*cells: str) -> str`: index into `CELL_TIER_ORDER`; raise `ValueError` on unknown.
- `effective_cell(floor, registry_cell) -> str`: `max_cell(floor, registry_cell)`.
- `read_floor(store: AuditStore | None = None) -> str`: open store at `posture_db_url()` with **`initialize=False, apply_pragmas=False`** (do not create the file on a read); if absent/empty → `"structured"`; if `verify_integrity()` False → `"structured"`; read `records[-1]`; if `payload["kind"]` not in `{GENESIS, TRANSITION, KEY_RESET}` or `payload["floor"]` not in `CELL_TIER_ORDER` → `"structured"`; else return `payload["floor"]`.
- `FlooredRegistry` per D2.

**Verify:** `pytest tests/posture/test_floor.py -q`

### Task 4.2 — Inject floor into `explain_policy` via floored cell (consistent explanation)

**Files:** `src/legis/service/explain.py`

**Test first** — `tests/test_explain.py` (extend):
- `test_explain_policy_applies_floor`: with a `FlooredRegistry` resolving `policy="X"` to `chill` raised to floor `structured`, `explain_policy(...)` returns `.cell == "structured"` **AND** `.enabled`, `.available_moves`, `.required_inputs` match the **structured** cell's semantics (not chill's). **This is the internal-consistency fix.**
- `test_explain_policy_floor_never_lowers`: registry `protected`, floor `chill` → `.cell == "protected"` with protected semantics.
- `test_explain_policy_matched_rule_is_raw`: `matched_rule`/`policy_known` reflect the raw rule lookup (honest "which rule matched"), even when the floor raised the cell.

**Implementation:**
- `explain_policy` takes a registry (now possibly a `FlooredRegistry`). It computes `raw_cell = rule.cell if rule is not None else registry.default_cell` — already floored when the registry is a `FlooredRegistry`. **Pass that floored cell into `explain_cell(...)`** so the entire `PolicyExplanation` (`enabled`/`available_moves`/`required_inputs`) is built for the floored cell — NOT built for the raw cell then `.cell`-replaced. `matched_rule` and `policy_known` use `registry.rule_for(policy)` (raw). No new `floor:` parameter is added to `explain_policy`; flooring is the registry's job (D2).
- `explain_cell` (`explain.py:107`) is unchanged and needs no floor awareness — it dispatches purely on the cell string it is handed.

**Verify:** `pytest tests/test_explain.py -k floor -q`

### Task 4.3 — Wire FlooredRegistry into MCP routing (single chokepoint)

**Files:** `src/legis/mcp.py`

**Test first** — `tests/test_mcp.py` (extend):
- `test_override_submit_routes_by_floored_cell`: registry routes `policy`→`chill`, floor `protected` → `_tool_override_submit` dispatches to the **protected gate** (`mcp.py:1801-1836`), not the chill engine (`mcp.py:1747-1775`). **Load-bearing — cell decision selects the gate.**
- `test_override_submit_engine_selection_floored`: when floor raises `chill`→`structured`, the `simple_engine` pre-selection at `mcp.py:1691-1694` uses the **floored** cell (so it is NOT wired as the chill engine) and the handler reaches the structured signoff branch. Assert engine selection AND final dispatch agree. **Closes the split-engine logic-inconsistency finding.**
- `test_policy_explain_tool_reports_floored_cell`: `_tool_policy_explain` (`mcp.py:1635`) returns the floored cell with consistent fields.
- `test_runtime_floor_immutable`: `runtime.posture_floor` is unchanged across a tool-call sequence (D7).

**Implementation:**
- Read the floor **once** in `build_runtime()` (`mcp.py:192-250`, alongside `cell_registry` at `mcp.py:256`): `posture_floor = read_floor()`; store on `McpRuntime`. Mark it "set once, never mutated" with a comment (D7); do not re-read per request in v1.
- Add `_floored_registry(runtime) -> FlooredRegistry`: `FlooredRegistry(runtime.cell_registry, runtime.posture_floor)`.
- `_tool_override_submit` (`mcp.py:1685-1837`): compute `floored = _floored_registry(runtime).cell_for(policy)` **once before line 1691**; use `floored in ("chill","coached")` for the `simple_engine` guard at `1691-1694`, and pass `_floored_registry(runtime)` to `explain_policy` so `explanation.cell == floored`. Branch on `explanation.cell` as before.
- `_tool_policy_explain` (`mcp.py:1635`): pass `_floored_registry(runtime)` to `explain_policy`.
- `_tool_policy_list` (`mcp.py:1647-1682`): see Task 4.3b.
- `_tool_scan_route` (`mcp.py:1903`) and Wardline `governor.py:99` are **orthogonal** (Wardline cell model is independent) — do NOT change them. Stated explicitly to avoid scope creep.

**Verify:** `pytest tests/test_mcp.py -k "floor or floored" -q`

### Task 4.3b — `policy_list` floor context (decision locked)

**Decision (resolves architecture-high, quality-medium):** `policy_list` (`mcp.py:1647-1682`) iterates `CELL_TIER_ORDER` and calls `explain_cell` per tier — it lists **tier capabilities**, not per-policy routing, so the per-cell rows do NOT change with the floor. **But** its `default_cell` field (`mcp.py:1675`) must not lie about the effective posture. Change the response to surface both:
- keep the per-cell `cells` array unchanged (tier capabilities are floor-independent);
- replace the single `default_cell` field with `registry_default_cell` (raw) **plus** a top-level `posture_floor` field (the effective floor). Agents see both the raw default and the floor, and can compute the effective default as `max(posture_floor, registry_default_cell)`.

**Test first** — `tests/test_mcp.py::test_policy_list_reports_floor_context`: response includes `posture_floor` and `registry_default_cell`; the `cells` rows are unchanged by the floor. Pin the contract.

**Implementation:** in `_tool_policy_list`, add `posture_floor: runtime.posture_floor` and rename `default_cell`→`registry_default_cell` in the response (update the tool's outputSchema accordingly).

**Verify:** `pytest tests/test_mcp.py -k policy_list -q`

### Task 4.4 — The change gate (`posture_set` orchestration) + TOCTOU close

**Files:** `src/legis/posture/service.py` (new); `src/legis/service/errors.py` (extend — D5)

**Test first** — `tests/posture/test_gate.py`:
- `test_set_refused_no_open_session`: `posture_set("structured")` with no active session → `SessionNotOpenError`, **no record appended**, floor unchanged. **Fail-closed.**
- `test_set_refused_fingerprint_mismatch`: active session, current epoch `key_fingerprint != signer.fingerprint()` → `KeyFingerprintMismatchError`, no record (spec §7 step 2). **Fail-closed.**
- `test_set_refused_signer_error`: signer raises → `SignerError`, no record. **Fail-closed.**
- `test_set_refused_ledger_busy`: monkeypatch `AuditStore.append_signed` to raise `sqlalchemy.exc.OperationalError` → `LedgerWriteError`, floor unchanged. **Closes the storage-tier fail-closed contract.**
- `test_set_refused_session_expires_mid_write`: session active at pre-check but `fake_time` advanced past TTL by the time the `append_signed` closure runs → `SessionNotOpenError`, no record. **Closes the TOCTOU window (D9).**
- `test_set_accepted_writes_one_transition`: active session + matching fingerprint + valid signer → exactly ONE `TRANSITION` in `posture.db`, `floor` updated, `operator_sig` present in `extensions`, `session_id == current_session_id()`.
- `test_transition_signature_verifies_via_signer_verify`: the written record's `operator_sig` verifies via `signer.verify(posture_signing_fields(payload, seq=seq), sig)` — NOT by re-extracting the key. And it starts with `hmac-sha256:v3:`.
- `test_multiple_transitions_within_session`: `posture_set("coached")` then `posture_set("structured")` in one session — both succeed, both carry the same `session_id`, `read_floor()` returns `"structured"` (the LAST one).

**Implementation:**
- `posture_set(cell, *, store, sessions_store, signer, session, clock, time_fn, agent_id, rationale) -> AuditRecord`:
  1. `if not session.active(): raise SessionNotOpenError`.
  2. Read current epoch `key_fingerprint` from `current_floor_record(store).payload`; `if signer.fingerprint() != key_fingerprint: raise KeyFingerprintMismatchError`.
  3. Build `PostureRecord(kind="TRANSITION", floor=cell, key_fingerprint=..., session_id=session.current_session_id(), agent_id, recorded_at=clock.now_iso(), rationale)`.
  4. `store.append_signed(build_payload)` where `build_payload(seq, prev_hash)`:
     - **re-check `session.active()` here, under the BEGIN IMMEDIATE lock (D9)** — if expired, raise `SessionNotOpenError` (aborts the append; no partial write);
     - `fields = posture_signing_fields(payload, seq=seq)`;
     - `sig = signer.sign(fields)` (raises → propagate as `SignerError`);
     - attach `sig` to `payload["extensions"]["operator_sig"]`; return payload.
     Wrap `OperationalError`/store exceptions from `append_signed` in `LedgerWriteError`.
  5. Validate `cell in CELL_TIER_ORDER` up front; reject otherwise.
- Helper free functions in `service.py`: `current_floor_record(store) -> AuditRecord | None` (`store.read_all()[-1] if records else None`), `posture_store_exists(store) -> bool`.
- **D5 errors** added to `src/legis/service/errors.py`: `PostureError(ServiceError)`, `SessionNotOpenError`, `KeyFingerprintMismatchError`, `SignerError`, `LedgerCorruptError`, `LedgerWriteError`. Update the adapter comments at `service/errors.py:4-6`.

**Verify:** `pytest tests/posture/test_gate.py -q`

---

## PHASE 5 — Install (genesis record + key mint + CI behavior)

**Dependency:** Phases 1, 2. Idempotency + concurrency safety are critical.

### Task 5.1 — Posture install step

**Files:** `src/legis/install.py`, `src/legis/cli.py`

**Test first** — `tests/test_install.py` (extend):
- `test_install_writes_genesis_chill`: fresh project → single `GENESIS` in `posture.db`, `floor="chill"`, `key_fingerprint` set (spec §5).
- `test_install_idempotent_posture`: install twice → still exactly ONE `GENESIS`, same `key_fingerprint`, floor untouched. **Critical.**
- `test_install_concurrent_genesis_leaves_one_epoch`: two concurrent `install_posture_floor` calls (threads/processes) → exactly ONE distinct `key_fingerprint` in the ledger (D9 file-lock). **Race test.**
- `test_install_mints_and_hands_to_custody`: minted key handed to the selected backend; ledger stores fingerprint + backend id, NEVER the key (assert no key bytes appear in `posture.db` contents).
- `test_install_insecure_env_warns`: `--insecure-key-in-env` selects env backend + honest warning (spec §6, §9); `_safe_mcp_env()` (`install.py:996-1008`) scrubs `LEGIS_OPERATOR_KEY` from any `.mcp.json`.
- `test_install_no_backend_skips_with_warning`: in a headless env with no keychain and no `--insecure-key-in-env`, the posture step returns `(True, "skipped — no custody backend; floor will be fail-closed structured until a key is configured")` and writes **no** ledger (D-CI below). **CI path.**
- `test_install_default_backend_selection`: default = keychain-if-available else age-file; never env unless flag.

**Implementation:**
- `posture_ledger_exists()` idempotency check (mirror `gitignore_rules_present`, `install.py:856-870`): open `posture.db` with `initialize=False`; `if records: return (True, "posture floor already established")` BEFORE minting.
- `install_posture_floor(root, *, backend_choice, insecure_env) -> (ok, message)`:
  1. Acquire the `.weft/legis/.posture_install.lock` OS file lock (D9).
  2. If `posture_ledger_exists()` → return early (idempotent).
  3. **CI/headless behavior (resolves systems-medium):** select backend; if no keychain available AND `insecure_env` is False AND no age passphrase can be obtained non-interactively → return `(True, "skipped — no custody backend; floor fail-closed structured")` and write nothing. CI then runs at fail-closed `structured` (correct: no operator key ⇒ stricter default, never a keyless chill genesis).
  4. Otherwise `key = mint_key()`; hand to backend; `fingerprint = sha256(bytes.fromhex(key)).hexdigest()`.
  5. Write `GENESIS` `floor="chill"`, `key_fingerprint=fingerprint`, `agent_id="install"`, `recorded_at=now`, `rationale="install genesis"`, backend id in `extensions`.
  6. Release the lock.
- Add `LEGIS_OPERATOR_KEY` to `_SECRET_MCP_ENV_KEYS` (`install.py:35-40`/`939-961`) so it is auto-scrubbed from `.mcp.json`.
- Wire the step into `_run_install()` (`cli.py:270-313`) **before** `register_mcp_json()` so an env-escape-hatch key never lands in `.mcp.json`. Return `(ok, message)` like other steps.
- **Install flag model (resolves architecture-medium):** add `--posture` as a **step-selection** flag alongside `--claude-md`/`--agents-md`/etc. Add `--insecure-key-in-env` and `--posture-backend` as **behavior** flags, explicitly EXCLUDED from the `install_all = not any([...])` detection. The step tuple becomes `(install_all or args.posture, "posture floor", lambda: install_posture_floor(project_root, backend_choice=args.posture_backend, insecure_env=args.insecure_key_in_env))`.
- `.gitignore`: the blanket `.weft/legis/` rule already covers `posture.db`, `posture_sessions.db`, and `operator_session.json`; verify the comment at `install.py:843-848` and assert coverage in the gitignore check step (Phase 8 / Task 8.3). The age file (`~/.config/legis/operator.age`) is outside the repo and intentionally not gitignored.

**Verify:** `pytest tests/test_install.py -k posture -q`

---

## PHASE 6 — CLI surfaces (posture / operator commands)

**Dependency:** Phases 1–5 (service layer).

> **Convention (review CRITICAL):** `cli.py` has only ever used flat subcommands. v1 uses **flat commands** — `posture-show`, `posture-set`, `posture-rekey`, `operator-enable`, `operator-disable` — matching the dispatch model at `cli.py:336-463`. Nested `posture <verb>` groups are deferred. Help text may read "posture show".

### Task 6.1 — CLI commands

**Files:** `src/legis/cli.py`

**Test first** — `tests/test_cli.py` (extend, mirror `test_serve_defaults`/`test_check_override_rate`):
- `test_posture_show_keyless`: `posture-show` prints the current effective floor without a session (spec §7 keyless read).
- `test_posture_set_requires_session`: `posture-set structured` with no session → non-zero exit, refusal message, no ledger change. **Fail-closed.**
- `test_operator_enable_opens_window`: `operator-enable --ttl 300` opens a session and writes `OPERATOR_SESSION_OPENED` (to the sessions store).
- `test_posture_set_within_session`: enable → `posture-set structured` → succeeds, writes TRANSITION with the session's `session_id`; success output warns about MCP-staleness (D7).
- `test_operator_disable_ends_session`: `operator-disable` → subsequent `posture-set` refused.
- `test_duration_to_seconds_parses` (parametrized): `"300"→300`, `"5m"→300`, `"5M"→300`, and `"-1"`/`"0"`/`"invalid"` raise. (If `--ttl` is `type=int` seconds-only, this test covers only the int path; see below.)

**Implementation:**
- Extend `build_parser()` (`cli.py:36`) with flat subparsers (pattern at `cli.py:101-116`, `153-169`).
- **TTL (resolves quality-low):** `--ttl` is `type=int`, `metavar="SECONDS"`, default `300`, help "(e.g., 300 for 5 minutes)". If `5m` shorthand is wanted, add a small `duration_to_seconds(raw) -> int` helper in `cli.py` with the parametrized unit test above; do NOT embed parsing in the argparse `type=`.
- Extend `main()` dispatch (`cli.py:336-463`) with `posture-show`/`posture-set`/`posture-rekey`/`operator-enable`/`operator-disable` branches, each constructing the `AuditStore`(s)/`PostureSigner`/`ElevationSession` from config resolvers and calling `service.py` functions.
- `posture-show`: `print(read_floor())` — keyless.
- `operator-enable`: `select_backend(...)`; unlock (keychain prompt / age passphrase / env); `session.enable(...)`.
- `posture-set`: `service.posture_set(...)`; catch `PostureError` → stderr + non-zero exit; on success, print the floor change AND the D7 staleness note.

**Verify:** `pytest tests/test_cli.py -k "posture or operator or duration" -q`

---

## PHASE 7 — MCP `posture_get` read tool

**Dependency:** Phase 4. Read-only; never `posture_set` over MCP (spec §7).

### Task 7.1 — `posture_get` tool

**Files:** `src/legis/mcp.py`

**Test first** — `tests/test_mcp.py`:
- `test_posture_get_reports_floor`: returns the current effective floor (from the cached `runtime.posture_floor`, D7).
- `test_posture_get_absent_ledger_returns_structured`: with no `posture.db`, `posture_get` returns `{"floor": "structured"}` — not `chill`, not an error. **Most important fail-closed path at the API boundary.**
- `test_no_posture_set_tool`: `"posture_set"`/`"posture-set"` NOT in `_AGENT_TOOLS` (`mcp.py:80-104`). **Honest-interface test.**
- `test_posture_get_shares_floor_logic_with_cli`: `posture_get` and CLI `posture-show` return the same value for the same ledger (shared `read_floor`).

**Implementation:**
- Add `"posture_get"` to `_AGENT_TOOLS` (`mcp.py:80-104`). Add NO write tool.
- `_tool_posture_get(runtime, args)`: return `{"floor": runtime.posture_floor}` (cached, D7); optionally per-policy effective cell if `policy` given (via `_floored_registry(runtime).cell_for(policy)`). The outputSchema description states the D7 freshness contract ("floor as read at MCP server startup; restart to pick up a `posture set`").

**Verify:** `pytest tests/test_mcp.py -k posture_get -q`

---

## PHASE 8 — Doctor reconciliation (STORE_DB_SPECS-driven chain checks)

**Dependency:** Phases 1, 4. Report-only — never repairs integrity errors (spec §10, doctor convention C-9(b)).

### Task 8.1 — Refactor chain checks to iterate STORE_DB_SPECS + add posture/sessions coverage

**Files:** `src/legis/doctor.py`

**Test first** — `tests/test_doctor.py` (extend, mirror `check_audit_chain` tests):
- `test_chain_checks_cover_all_store_db_specs`: `collect_checks()` emits a `check_audit_chain` for EVERY entry in `STORE_DB_SPECS` (governance, binding, **posture**, **posture_sessions**) — proving the loop, not hardcoded calls. **Resolves the false auto-extension claim.**
- `test_posture_chain_check_ok`: healthy `posture.db` → `store.posture_chain` `status="ok"`.
- `test_posture_chain_absent_is_ok_and_does_not_create_file`: missing `posture.db` → `status="ok"` AND the file is NOT created (asserts `initialize=False`). **Resolves the file-creation regression.**
- `test_posture_chain_corrupt_is_error_report_only`: tampered chain → `status="error"`, `repairable=False` (`[operator]`). No repair branch.

**Implementation (resolves systems-medium, plan-high "false auto-extension"):**
- **Refactor `collect_checks()` (`doctor.py:653-677`):** replace the two explicit `check_audit_chain` calls (`doctor.py:669-670`) with a loop over `STORE_DB_SPECS`, deriving `cid=f"store.{db_name_without_ext}_chain"` and the URL via the existing `_store_url`/resolver. Posture + sessions are covered automatically because Phase 0 registered them. This removes the dual-registration trap.
- `check_audit_chain` must open with `AuditStore(url, initialize=False, apply_pragmas=False)` (the existing correct pattern at `doctor.py:443`).

**Verify:** `pytest tests/test_doctor.py -k "chain or posture" -q`

### Task 8.2 — Floor-vs-registry report, KEY_RESET epoch surfacing, custody-backend check

**Files:** `src/legis/doctor.py`

**Test first** — `tests/test_doctor.py`:
- `test_posture_floor_vs_registry_report`: surfaces current floor; notes policies whose registry cell is below the floor (informational — floor raises it). Degrades gracefully if the registry fails to load (report-only).
- `test_key_reset_epoch_surfaced_and_nonzero_exit`: a `KEY_RESET` record → a `warn`/`error` `DoctorCheck` (`store.posture_epoch`) naming date + `agent_id`, AND `legis doctor` returns a **non-zero exit code** so CI fails loudly (spec §8, §9 — see D-rekey-CI below). `repairable=False`.
- `test_custody_backend_check_warns_when_unreachable`: configured age-file backend with a missing/zero-byte `operator.age` → a `warn` `DoctorCheck` (`config.posture_custody`), not `error` (keyless read-only operation is still valid).

**Implementation:**
- `check_posture_floor(root)`: read floor (fail-closed structured on absence); load policy-cell registry mirroring `check_policy_cells` precedence (`doctor.py:467-496`); emit report-only `DoctorCheck` (`config.posture_floor`). Handle missing registry gracefully.
- KEY_RESET surfacing: scan `read_all()` for `kind=="KEY_RESET"`; emit `store.posture_epoch` naming date+agent_id; `repairable=False`. **Doctor exit code is non-zero when a KEY_RESET is present and not followed by a subsequent operator-signed TRANSITION that re-raises the floor** (D-rekey-CI). This converts the indelible record from passive log into an active CI blocker.
- `check_posture_custody(root)`: probe the configured backend — for age-file, that `~/.config/legis/operator.age` exists and is non-zero; for keychain, a read-only probe (no key extraction). `warn` (not `error`) if unreachable. Gives operators early warning before a crisis `operator enable`.
- All checks `@dataclass(frozen=True, slots=True) DoctorCheck` (`doctor.py:29-49`), `status ∈ {ok,warn,error}`, never `repairable=True` for integrity. Flow through `doctor_payload()` (`doctor.py:56-64`) so CLI `--format json` and MCP `doctor_get` surface them.

**Verify:** `pytest tests/test_doctor.py -k "posture or epoch or custody" -q`

### Task 8.3 — Gitignore coverage assertion

**Files:** `tests/test_install.py` (or `tests/test_doctor.py`)

**Test:** `test_weft_legis_blanket_covers_session_and_posture`: assert the `.weft/legis/` rule covers `posture.db`, `posture_sessions.db`, and `operator_session.json` (no dedicated rules needed; blanket suffices). Confirms the session-state file is never committed.

**Verify:** `pytest tests/test_install.py -k gitignore -q`

### Task 8.4 — Session-context banner (optional, low priority)

**Files:** `src/legis/hooks.py` (NOT `install.py` — `_instructions_posture` lives at `hooks.py:96-120`)

**Test first** — `tests/test_hooks.py::test_session_context_shows_floor`: `generate_session_context()` (`hooks.py:173-192`) banner includes the current effective floor and flags a recent `KEY_RESET` epoch.

**Implementation:** add a posture getter mirroring `_instructions_posture` (`hooks.py:96-120`); integrate into the banner alongside the existing `_instructions_posture`/`_cells_posture` getters. Report-only. No `install.py` changes.

**Verify:** `pytest tests/test_hooks.py -k posture -q`

---

## PHASE 9 — Rekey / lost-key path

**Dependency:** Phases 1, 2, 5, 6, 8. Keyless but loud.

### Task 9.1 — `posture rekey`

**Files:** `src/legis/posture/service.py`, `src/legis/cli.py`

**Test first** — `tests/posture/test_rekey.py`:
- `test_rekey_requires_no_old_key`: `posture_rekey()` succeeds with no session and no prior-key proof (spec §8).
- `test_rekey_resets_floor_to_chill`: after rekey, `read_floor()` returns `"chill"` regardless of prior floor (spec §8). **Cannot rekey into a high posture.**
- `test_rekey_mints_new_epoch`: new `key_fingerprint` differs from the prior epoch's; new key handed to backend.
- `test_rekey_is_unsigned_and_chain_still_valid`: GENESIS → signed TRANSITION → **unsigned** KEY_RESET: `verify_integrity()` is `True`, and the KEY_RESET record carries NO `operator_sig` in `extensions`. **Confirms unsigned-append on a keyed chain.**
- `test_rekey_writes_key_reset_onto_existing_chain`: prior records preserved; `read_all()` returns full history including old records; chain integrity holds (spec §8, §10).
- `test_rekey_records_attribution`: KEY_RESET carries `agent_id`, `recorded_at` (doctor flags it — Phase 8).
- `test_key_reset_cannot_be_detected_as_forged`: document in the test body that a forged KEY_RESET is **indistinguishable** from a legitimate one at the record level — the defence is doctor visibility + the non-zero exit (D-rekey-CI) + human response, NOT cryptographic denial (spec §8, §9). Threat-model documentation, not an impossible-property assertion.
- `test_transition_before_and_after_rekey`: session→transition(structured)→rekey→new session→transition(coached): the post-rekey transition's `session_id` is from the NEW session and its `key_fingerprint` matches the NEW epoch.

**Implementation:**
- `posture_rekey(*, store, backend_choice, agent_id, rationale) -> AuditRecord`:
  1. `new_key = mint_key()`; hand to selected backend; `new_fingerprint = sha256(bytes.fromhex(new_key)).hexdigest()`.
  2. Build `PostureRecord(kind="KEY_RESET", floor="chill", key_fingerprint=new_fingerprint, agent_id, recorded_at=now, rationale)`.
  3. `store.append(record.to_payload())` — **unsigned** (keyless; the loudness is the indelible record, not a signature). Chains onto existing history (append-only triggers prevent history loss).
- Add `posture-rekey` CLI command (Phase 6 parser): print a loud confirmation that the floor was reset to chill and the operator must `operator-enable` + `posture-set` to climb back (spec §8).

**Verify:** `pytest tests/posture/test_rekey.py -q`

---

## PHASE 10 — Security / honesty test suite (cross-cutting)

**Dependency:** all phases. Consolidates the load-bearing safety assertions (spec §9, §10). Some tests intentionally duplicate earlier ones — this is the audit surface.

**Files:** `tests/posture/test_security.py` (new)

- `test_key_never_returned_to_caller`: across all three backends, no public method/attribute yields raw key bytes; `sign`/`verify` are the only key-consuming surfaces (spec §6). (mirrors 2.1)
- `test_every_transition_carries_session_id`: any `TRANSITION` in `posture.db` has a non-null `session_id` that matches an `OPERATOR_SESSION_OPENED` record's id in `posture_sessions.db` (D3 cross-ledger correlation; both stores opened). **Accountability.**
- `test_session_expiry_refuses_signing`: open session, advance `fake_time` past TTL, `posture_set` → `SessionNotOpenError`, no record (spec §6, §9; D8). **Expiry tier.**
- `test_rekey_resets_to_chill_and_is_loud`: rekey leaves an indelible `KEY_RESET`, resets to chill; an "attacker" rekey is detectable via doctor's non-zero exit (spec §8, §9; D-rekey-CI). **Threat-symmetry.**
- `test_missing_ledger_fail_closed_structured`: deleted/absent `posture.db` → effective floor `structured`, never chill (spec §4). **Fail-closed.**
- `test_v2_transition_rejected_on_read`: a `TRANSITION` whose `operator_sig` starts with `hmac-sha256:v2:` is rejected by the read/verify path as a tamper-evidence violation, even though `signing.verify` would accept it (version-pinning convention). **Closes the v2-downgrade hole.**
- `test_raw_write_threat_residuals` **(renamed/split from the draft's misleading test):**
  - (a) **TRANSITION with `operator_sig`:** a rechain to a new seq position causes `signer.verify(posture_signing_fields(payload, seq=new_seq), sig)` to return `False` — DETECTED (seq-binding + HMAC).
  - (b) **GENESIS/KEY_RESET (keyless):** a delete-and-rechain that preserves seq contiguity is NOT detectable by `verify_integrity()` alone — assert this openly as documentation of the conceded raw-DB-write residual (spec §9). Do not claim `verify_integrity()` catches it.
- `test_env_escape_hatch_warns`: `EnvSigner` construction emits the honest WARNING (spec §6, §9).
- `test_canonical_parity`: re-asserts the Phase 1 golden vector at the security-suite level (the golden bytes already pinned in Task 1.1).

**Verify:** `pytest tests/posture/test_security.py -q`

---

## Final verification (run after all phases)

```
pytest tests/posture tests/test_config.py tests/test_explain.py tests/test_mcp.py tests/test_install.py tests/test_cli.py tests/test_doctor.py tests/test_hooks.py -q
python scripts/check_coverage_floors.py        # posture floor registered; mcp re-baselined
mypy src/legis/posture src/legis/config.py src/legis/service/explain.py src/legis/service/errors.py src/legis/mcp.py
ruff check src/legis/posture src/legis/cli.py src/legis/install.py src/legis/doctor.py
```

## Dependency graph (phase ordering)

```
P0 config ─┬─> P1 records+golden ─┬───────────────────────> P4 floor/FlooredRegistry/gate ──> P6 CLI ──> P9 rekey
           │                      ├─> P3 session (sep. store)┘                                  │
           └─> P2 signer ─────────┘                                                            ├─> P7 MCP posture_get
                                                                                               └─> P8 doctor (STORE_DB_SPECS loop)
           P1+P2 ──────────────────────────────────> P5 install (file-lock genesis) ──────────┘
                                                       (P10 security suite spans all)
```

## Explicit fail-closed checklist (each has a named test)

1. Absent/empty `posture.db` → effective floor **`structured`**, not chill (P4.1, P7.1, P10).
2. Corrupt ledger (`verify_integrity()==False`) → **`structured`** (P4.1).
3. Invalid `floor` value in last record → **`structured`** (P4.1).
4. No open elevation session → `posture set` **refused**, floor unchanged (P4.4, P6, P10).
5. `signer.fingerprint() != key_fingerprint` → **refused** (P4.4).
6. Signer raises → **refused**, no record (P4.4).
7. Ledger busy / store error → `LedgerWriteError`, **refused**, floor unchanged (P4.4).
8. Session expires mid-write (TOCTOU) → **refused** inside the lock, no record (P4.4, D9).
9. TTL lapsed → session inactive → signing **refused** (P3, P10).
10. Install never double-writes GENESIS (idempotent + file-lock vs concurrent) (P5).
11. CI/headless with no backend → posture step **skips**, floor stays fail-closed structured (P5).
12. `rekey` always resets to **chill**; v2 sig on a TRANSITION rejected on read (P9, P10).
13. `posture set` never exposed over MCP; `posture_get` read-only (P7).

---

## Appendix A — Review changelog (what changed per critical/high finding)

- **(systems-critical) Floor cached at MCP startup → stale mid-session.** Resolved as **D7**: documented "read once at startup; restart to apply" contract; surfaced in `posture set` output and `posture_get` schema; `runtime.posture_floor` marked immutable with a pinning test. (Per-request reads explicitly deferred.)
- **(systems-critical) HTTP API floor bypass.** Resolved as **D6**: HTTP API floor enforcement is explicitly OUT OF SCOPE for v1, with a Filigree tracker filed before merge and a pointer comment at `api/app.py:528`. No silent gap.
- **(systems-critical / architecture-critical / quality-critical) Session vs key-custody contradiction.** Resolved as **D1**: committed two-level key hierarchy — session file holds only metadata + backend-specific `unlock_ref`/`wrapped_key`, never the operator key; keychain → silent reads, age-file-without-keychain → per-`set` re-prompt, env → reads env. "Zeroized" defined precisely. Recorded as an ADR.
- **(systems-critical / quality-critical) explain_policy floored-cell consistency.** Resolved in **Task 4.2**: `explain_cell` is now invoked with the floored cell so `enabled`/`available_moves`/`required_inputs` match `.cell`; the test asserts all four, not just `.cell`. `matched_rule`/`policy_known` stay raw.
- **(systems-critical / quality-critical) Split-engine routing at mcp.py:1691-1694.** Resolved in **Task 4.3**: the floored cell is computed once before the block and used for BOTH `simple_engine` selection and `explain_policy`; a test asserts engine selection and final dispatch agree.
- **(architecture-critical) Scattered floor injection / no chokepoint.** Resolved as **D2**: `FlooredRegistry` wraps the registry; `explain_policy` needs no `floor` parameter; every call site (and any future one) gets flooring for free. `max_cell` is the single `CELL_TIER_ORDER` index point.
- **(architecture-high) PostureLedger pass-through wrapper.** Resolved as **D4**: wrapper eliminated; callers use `AuditStore` directly via the existing protocol; package collapsed from 7 to 5 modules with free-function helpers.
- **(architecture-high) policy_list dishonest default_cell.** Resolved in **Task 4.3b**: response now surfaces `posture_floor` + `registry_default_cell`; per-cell rows unchanged; contract pinned by test.
- **(architecture-high) Separate errors module / adapter blast radius.** Resolved as **D5**: posture errors added to `src/legis/service/errors.py` as `ServiceError` peers; adapter comments updated; no new module, no import cycle.
- **(architecture-high / quality-critical / architecture-low) OPERATOR_SESSION_OPENED breaks "last record = floor".** Resolved as **D3**: session records moved to a separate `posture_sessions.db`; `read_floor` reads `records[-1]` safely; defensive kind/floor validation added anyway; cross-ledger correlation test opens both stores.
- **(quality-critical) No testable TTL clock seam.** Resolved as **D8**: separate injectable `time_fn: Callable[[], float]`; existing ISO-only `Clock` untouched; tests inject a fake.
- **(quality-high) No coverage floor for posture package.** Resolved: `src/legis/posture/: 93.0` registered in `scripts/check_coverage_floors.py` in Phase 1; `mcp.py` floor re-baselined after Phase 4.
- **(quality-high) Concurrent-install double-genesis.** Resolved as **D9**: OS file-lock around exists?→mint→write; explicit concurrency test asserts one epoch.
- **(quality-high) Unsigned KEY_RESET untested / forged-rekey claims.** Resolved in **Task 9.1**: `test_rekey_is_unsigned_and_chain_still_valid` + `test_key_reset_cannot_be_detected_as_forged` (documents the conceded threat boundary rather than asserting impossibility).
- **(quality-high) No signer.verify() for read-side audit.** Resolved in **Task 2.1**: `PostureSigner` gains `verify(fields, sig) -> bool`; doctor/read-side verification uses it without exposing key bytes.
- **(quality-high) Canonical golden vector deferred.** Resolved in **Task 1.1**: `test_canonical_parity_golden_vector` written in Phase 1; key_fingerprint-in-signed-set proven non-circular; sign/verify byte-parity asserted.
- **(plan-high / systems-medium) STORE_DB_SPECS "auto-extends chain checks" is false.** Resolved in **Task 8.1**: `collect_checks()` refactored to LOOP over `STORE_DB_SPECS` for chain checks; test asserts every spec entry is covered. The false claim is removed.
- **(plan-high) sign() default is v2.** Resolved globally: every posture `sign()` call passes `version="v3"` explicitly; `test_sign_is_v3` asserts the `hmac-sha256:v3:` prefix; read-side rejects v2 TRANSITIONs.
- **(plan-high) Doctor must use initialize=False.** Resolved in **Task 8.1** and `read_floor` (Task 4.1): all read-side `AuditStore` opens use `initialize=False, apply_pragmas=False`; a test asserts no file is created on a missing-store check.
- **(systems-high) Keyless rekey unobserved in CI.** Resolved as **D-rekey-CI** (Task 8.2): `legis doctor` returns a NON-ZERO exit code when an unacknowledged `KEY_RESET` epoch is present, making CI fail loudly; the indelible record becomes an active blocker, not just a passive log.
- **(systems-high) No custody-backend doctor visibility.** Resolved in **Task 8.2**: `check_posture_custody` probes the configured backend (age-file existence / keychain read-probe) and `warn`s if unreachable.
- **(systems-high) Session file gitignore not verified.** Resolved in **Task 8.3**: explicit test that `.weft/legis/` blanket covers `operator_session.json` + both DBs.
- **(systems-medium) CI install behavior undefined.** Resolved in **Task 5.1**: no-backend headless install SKIPS posture setup with a warning and writes nothing → CI stays at fail-closed structured.
- **(architecture-medium / quality-medium) Backend crypto "pick one" left open.** Resolved in **Task 2.2**: age-file uses `cryptography` (scrypt KDF + AES-GCM) under the optional `age` extra; the test is `importorskip`-guarded; `age` CLI shell-out is NOT used.
- **(medium) PostureSigner unlock lifecycle not captured.** Folded into **D1**: unlock happens at `operator enable`; the session model defines exactly what is held between invocations per backend (keychain reference / wrapped blob / env), so "unlock once, sign many" is concrete per backend without a stateful daemon.
- **(medium) v2-signature acceptance on TRANSITIONs.** Resolved via the read-side version-pinning convention + `test_v2_transition_rejected_on_read`.
- **(low) Off-by-line protected.py anchor (273→241), weft_signing.py misattribution, _instructions_posture in hooks not install, config docstring precision, tamper-test wording.** All corrected inline in the conventions, Task 4.2/8.4 file targets, Task 0.1 docstring text, and Task 10 `test_raw_write_threat_residuals` rename.
- **(low) TTL string parsing.** Resolved in **Task 6.1**: `--ttl` is `type=int` seconds; optional `duration_to_seconds` helper with a parametrized edge-case test if shorthand is wanted.
- **(low) Mutable McpRuntime.posture_floor.** Resolved in **D7 / Task 4.3**: marked set-once with a comment + an immutability test.
- **(low) Install flag-type confusion.** Resolved in **Task 5.1**: `--posture` is a step-selector; `--insecure-key-in-env`/`--posture-backend` are behavior flags excluded from `install_all` detection.

## Appendix B — Open questions for the operator (John)

1. **age-file dependency.** Task 2.2 commits the age-file backend to the `cryptography` package (optional `age` extra), not stdlib and not the `age` CLI binary. This adds an optional dependency to a project that has been deliberately lean (`pyproject.toml` currently has 5 hard deps, zero crypto). Acceptable as an **optional** extra, or do you want the age-file backend deferred to v1.1 and v1 shipping only keychain + env?

2. **age-file session ergonomics (D1).** For the age-file backend *without* an available OS keychain, v1 re-prompts for the passphrase on each `posture set` (the session file holds only metadata; no key/passphrase on disk). This is honest but breaks the "no further prompts within the window" feel of spec §6 for that one configuration. Accept the re-prompt, or require a keychain to hold the session-wrapping secret (making age-file-without-keychain a metadata-only, re-prompting mode by design)?

3. **HTTP API floor gap (D6).** v1 does NOT floor the HTTP API override/signoff routes — only the MCP/service path is the consumer (spec §1). The gap is documented and Filigree-tracked. Confirm this is the intended v1 boundary, or should HTTP `/overrides` etc. also consult the floor in v1?

4. **Doctor non-zero exit on KEY_RESET (D-rekey-CI).** Making `legis doctor` exit non-zero on an unacknowledged `KEY_RESET` turns rekey into a CI blocker (good for catching attacker-forced resets) but will also fail CI for a *legitimate* lost-key rekey until the operator re-raises the floor with a signed TRANSITION. Confirm this friction is desired, or should KEY_RESET be a `warn` (non-blocking) with the exit code reserved for chain corruption only?

5. **`posture_get` per-policy effective cell.** Task 7.1 optionally lets `posture_get` return the floored effective cell for a specific policy. Useful for agents, but it widens the read surface slightly. Include the per-policy form in v1, or ship `posture_get` returning only the global floor?