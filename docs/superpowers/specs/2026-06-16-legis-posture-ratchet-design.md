# Legis posture ratchet + operator elevation sessions — design

**Date:** 2026-06-16
**Status:** Design approved (brainstorm), pre-implementation
**Scope:** v1 — the signed posture floor and the operator-elevation-session primitive it is signed through. The migration of Legis's *existing* keyed operations (protected-cell verdicts, sign-offs, commit signing) onto the same elevation sessions is explicitly **out of scope** and tracked as future state in Filigree (see "Future state").

---

## 1. Problem & motivation

Legis's enforcement surface is a 2×2 of governance cells — `chill | coached | structured | protected` (`src/legis/policy/cells.py:22`). Today the cell a policy lands in is pure **config**: a per-policy registry (`PolicyCellRegistry`) loaded per-invocation from a precedence chain (`LEGIS_POLICY_CELLS` env → `policy/cells.toml` → `LEGIS_DEV_DEFAULT_CELLS=1` → fail-closed `structured`; `src/legis/mcp.py:173`). There is no persisted, global "current posture", and config is — by deliberate doctrine (`repos-hold-code-not-config`; `src/legis/config.py:29` "keys are out of scope") — **not a security boundary**. Anyone who can edit `cells.toml` or set an env var can change governance.

Two things the operator wants that this prevents:

1. **A sane install baseline.** A fresh `legis install` should establish the **lowest active posture (chill)** — "if you didn't at least want chill, you wouldn't have installed Legis" — never "installed but doing nothing", and never the surprising fail-closed-to-`structured` that an *absent* config produces today.
2. **A downgrade ratchet.** Once posture is established, **loosening it must require the operator** — you should not be able to silently drop governance. Because config is freely editable, this is unenforceable unless posture is promoted from config into a **signed governance record**.

The mechanism for "the operator authorizes a change" must respect a hard constraint the operator named explicitly: **the operator key is never exposed unencrypted in the agent's environment.** A key sitting in `LEGIS_OPERATOR_KEY` plaintext is readable by the very agent it is meant to gate, so surface-level gating (CLI-only vs MCP) is theatre — a mission-focused agent just shells out to the CLI. The real control is *"a valid signature cannot be produced without a live human gesture, and the key is never plaintext where the agent can read it."*

## 2. Goals / non-goals

### Goals (v1)
- `legis install` establishes a **chill** posture floor as a signed genesis record.
- Posture floor is a single value that acts as a **floor under** the existing per-policy registry; it is the only key-gated, loosenable setting.
- The floor applies **uniformly across every surface — MCP, HTTP API, and CLI — through one shared `FlooredRegistry` chokepoint.** As part of this, the HTTP API's cell-addressed submit routes are **unified into one policy-routed submit** so the server (not the caller) owns the cell decision; this closes the API floor-bypass door and makes the README's "API/MCP/CLI routed through the same service layer" claim true (see §3a).
- Install **mints** an operator key and hands it to a custody backend; the key is never written to disk in plaintext by Legis (except the explicit env escape hatch).
- An **operator elevation session** (`legis operator enable`) — `sudo` for governance signing — unlocks signing for a short, time-boxed, **attributable** window via an OS keychain prompt.
- A lost key is **recoverable, not catastrophic**: a keyless `rekey` that resets to chill, preserves history, and is loudly recorded.
- Every keyed action is **tamper-evident** and produces exactly one append-only record — no silent path (consistent with `src/legis/enforcement/engine.py`).

### Non-goals (v1)
- Migrating protected-cell verdict/sign-off signing or git-commit signing onto elevation sessions (future state; Filigree).
- 1Password / Vault signer backends (future; v1 ships OS keychain + age-file + env escape hatch).
- Any claim of being **tamper-proof**. Legis is a governance-*honesty* tool; the honest claim here is "an unauthorized change is detectable", not "impossible" (see §9).
- Changing the per-policy registry format or semantics.

## 3. Core model — the posture floor

One new concept: the **posture floor**, a single value in `chill | coached | structured | protected`.

**Effective cell for a policy = `max(posture_floor, registry.cell_for(policy))`** along the existing tier order `CELL_TIER_ORDER` (`src/legis/policy/cells.py:22`).

Consequences:
- The floor can only ever **raise** a policy's effective cell, never lower it.
- The existing `cells.toml` / `LEGIS_POLICY_CELLS` registry is **untouched and stays unsigned** — it can only tighten *above* the floor, so leaving it freely editable is safe by construction. No key is needed to add a tightening rule. This is deliberate: the key belongs only in the path of the *loosenable* setting.
- The floor is the **only** key-gated state and the only thing whose change can loosen the project.

This matches the operator's mental model — one posture knob — while preserving everything already built.

**The `max(floor, …)` is applied once, at the registry boundary, by a `FlooredRegistry` wrapper — the single cross-surface chokepoint.** Every surface that resolves a policy to a cell constructs a `FlooredRegistry(inner_registry, floor)` and calls `cell_for`/`default_cell` through it; no call site does its own `max()`. This is what lets MCP, the HTTP API, and the CLI/hooks all floor identically without duplicated logic. The floor value is read **per request/invocation** via `read_floor()` (a cheap SQLite tail read), so a floor change applies to a long-lived server without a restart.

## 3a. HTTP API governance-routing unification (option b)

The floor's `max(floor, registry.cell_for(policy))` only bites where a policy name is mapped to a cell *by the registry*. Today that mapping happens **only on the MCP/service path** (`src/legis/mcp.py:1693`). The HTTP API instead exposes **one route per cell** and lets the caller address a cell directly (`POST /overrides` = simple-tier self-clear, `POST /protected/overrides`, `POST /signoff/request`, …), so it never calls `cell_for` and the floor cannot reach it. That makes the cell-addressed API a **floor-bypass door**: with `floor=structured`, an API client can still `POST /overrides` and self-clear below the floor.

v1 closes this by **routing the API by policy, exactly like MCP**, rather than bolting on a per-route admission gate:

- The **submit path collapses to one server-routed write.** `POST /overrides` keeps its name but the caller now sends `{policy, entity, rationale, …}`; the server routes via `FlooredRegistry.cell_for(policy)` to the right cell (chill/coached → simple engine; structured → opens a sign-off request; protected → protected gate) and returns a **discriminated outcome** (`accepted` / `blocked` / `escalation_requested{request_seq}` / `signed`), mirroring MCP `override_submit`. The floor now applies to the API through the **same** chokepoint as MCP — no bypass, no separate gate.
- `POST /protected/overrides` and `POST /signoff/request` as distinct *submit* routes are **removed**, folded into the routed `/overrides`.
- **Operator-clear routes stay distinct.** `POST /signoff/{seq}/sign` and `POST /protected/operator-override` are operator *authority* actions ("clear request N" / "operator overrides"), not policy submits; they remain operator-authed routes. The unification is the *propose/submit* path only.
- Non-governance routes (`/git/*`, `/checks/*`, `/signoff/{seq}/bind-issue`, `/filigree/.../closure-gate`) are untouched.

**Why now:** the cell-addressed routes have **no external runtime consumer** (exercised only by legis's own `tests/api/*`; no client SDK). The only cross-member ripple is the **SEI conformance contract** (`docs/federation/sei-conformance.md`), which names these routes — legis-owned, with SEI *semantics* preserved (the unified route keys on SEI identically). That doc + any cross-member SEI conformance vector are updated **in this same release**. Doing the route change now — while the floor concept is brand-new and nothing depends on sub-floor routes staying open — is one atomic contract change instead of two coordinated ones later.

## 4. The posture ledger

A new small append-only, hash-chained ledger at **`.weft/legis/posture.db`** (sibling to the existing audit stores; consistent with `weft-store-consolidation`). It reuses `src/legis/store/audit_store.py` machinery rather than introducing a new crypto/storage stack. The **current floor is the last record.**

Record shape:

| field | meaning |
|---|---|
| `seq`, `prev_hash`, `this_hash` | chain integrity (always present, keyless) |
| `kind` | `GENESIS` \| `TRANSITION` \| `KEY_RESET` |
| `floor` | `chill\|coached\|structured\|protected` |
| `key_fingerprint` | `sha256` of the operator key this epoch trusts (never the key) |
| `operator_sig` | `HMAC(operator_key, canonical(record))` — present on `TRANSITION` |
| `session_id` | the elevation session the signature was produced under (§6) |
| `agent_id`, `recorded_at`, `rationale` | who / when / why (mirrors `OverrideRecord`) |

Canonicalization reuses the existing `canonical.py` contract (the byte-for-byte HMAC contract noted in `cross-tool-canonical-json-contract`).

### Precedence / source-of-truth
- The **signed ledger floor is authoritative.** The `cells.toml`/env registry is layered *above* it via the `max(...)` rule and can never lower the effective cell below the floor.
- **Absent ledger** (genuinely uninstalled, or deleted store) → fall back to the existing fail-closed `structured` default, **never chill** — so a deleted ledger can never silently mean "do nothing". Only an explicit `GENESIS` record makes chill the floor.

## 5. Install behavior

`legis install` with no prior posture ledger:
1. Creates `.weft/legis/posture.db` and writes the **`GENESIS` record: `floor = chill`**.
2. **Mints the operator key** — `secrets.token_hex(32)`. This is net-new behaviour: `src/legis/config.py:31` currently states Legis touches no key material, and this design **explicitly amends that doctrine** for this one operator-authority key.
3. Hands the key to the **chosen custody backend** (§6). What lands in the ledger is the key **fingerprint + backend id**, never the key.

The genesis record needs no signature (it establishes the trusted fingerprint). Install must remain idempotent: a second `install` over an existing ledger leaves the floor and key epoch untouched.

This **inverts the absent-config default for installed projects**: an installed project always has an explicit chill floor record; the fail-closed-to-`structured` behaviour is retained only for the genuinely-uninstalled / missing-ledger case (§4).

## 6. Custody & signing — the key never lands in the agent's env

A small **`PostureSigner` seam**: `legis posture set` / `operator enable` hand the signer *canonical record bytes* and receive an `operator_sig`; the signer holds the key, the agent process never sees key bytes.

Backends (v1):

| backend | key at rest | unlock | friction |
|---|---|---|---|
| **OS keychain** ⭐ (macOS Keychain / Secret Service / Windows Credential Manager) | secure element / login keychain | biometric / OS auth | none — no manual env import |
| **age-encrypted file** (`~/.config/legis/operator.age`) | encrypted on disk, portable | passphrase | low — see re-prompt note below |
| **env escape hatch** (`LEGIS_OPERATOR_KEY`) | **plaintext in env** | none | escape hatch only — CI/headless; emits an honest warning that this exposes the key to the process. elspeth-parity, de-emphasized. |

**Crypto is a mandatory dependency.** The age-file backend uses the `cryptography` package (scrypt KDF + AES-GCM); it is a hard dependency, not an optional extra — encrypted-at-rest custody is core to this feature and only grows in importance. (No `age` CLI shell-out.)

**age-file session ergonomics (accepted friction).** For the age-file backend *without* an available OS keychain to hold a session-wrapping secret, each `posture set` within the window **re-prompts for the passphrase** — the session file holds only metadata, never the key or passphrase. This is the honest trade-off and is intentional: the friction is the point; anyone who wants the smooth "no further prompts in the window" experience uses the keychain backend.

Default backend at install: **OS keychain if available, else age-file**; the env escape hatch only on an explicit `--insecure-key-in-env`.

Deferred to v2: 1Password (`op`) and Vault (`vault kv`) backends — thin session wrappers over the same minted key.

### Operator elevation sessions — `sudo` for governance signing

Per-action keychain prompts are replaced by a **time-boxed elevation session**:

```
legis operator enable [--ttl 5m]
   └─ OS keychain prompt ── human auths ──or not
         └─ on auth: a session is opened for the TTL. The key NEVER lands on disk in
            plaintext; the session file holds only metadata + a backend-specific unlock
            reference (keychain item id, or an age session-wrapped blob), never the key
               └─ within the window: posture set (and, future, sign-offs/verdicts/commits)
                  are signed on request — keychain backend: silent (no further prompt);
                  age-file-without-keychain: re-prompts per set (accepted friction)
                     └─ TTL lapses → session file deleted (any wrapped blob gone) → locked
```

- **v1 session model is a persisted session file, not an in-memory daemon.** `legis` is a fresh process per CLI invocation, so the "ssh-agent style" long-lived signing daemon is deferred to v1.1. v1 uses a two-level key hierarchy: at `enable`, custody is unlocked once; the operator key is held only via a backend-specific unlock reference in `.weft/legis/operator_session.json` (keychain item id, or an age-wrapped blob whose wrapping secret lives in the keychain) — never the raw key, never a passphrase. "Zeroized on TTL lapse" = the session file (and any wrapped blob it held) is deleted; the key in custody is untouched.
- **Default TTL: 5 minutes**, configurable via `--ttl`; `legis operator disable` ends it early.
- The human's act of enabling **is** "humans on the loop, not in the loop" — a declaration of presence supervising a burst of work, not per-signature approval.

### Accountability model
`operator enable` writes its own attributable record — `OPERATOR_SESSION_OPENED { operator_id, enabled_at, ttl, keychain_auth_ref }` — and **every signature produced in the window carries that `session_id`.** The trail reads back as: *"operator X opened a 5-minute window at 14:02; within it the floor moved chill→structured."* The enable is, in effect, the operator's countersignature on the whole window. The window is not a weakness to be hidden but the **accountability act** itself: "I fired `enable` and I own what it signed."

## 7. The change gate

Changing the floor = appending a `TRANSITION` record. The gate:
1. Caller invokes `legis posture set <cell>` (requires an open elevation session).
2. The signer (holding the unlocked key for the current epoch) signs the canonical record; Legis verifies `sha256(key) == key_fingerprint` of the current epoch before accepting.
3. Valid signature → record written. No open session / fingerprint mismatch / signer failure → **refused, fail-closed, floor unchanged.** Exactly one outcome, no silent pass.

**Surfaces:**
- CLI: `legis posture show` (keyless read), `legis posture set <cell>` (session-gated), `legis posture rekey` (§8), `legis operator enable|disable`.
- MCP/service: a read-only `posture_get` tool so the agent can learn the global floor **and the floored effective cell for a given policy**; **no `posture set` over MCP.** This is not a security boundary (the agent can shell out) but an honest interface statement — moving the floor is an operator action. The actual control is custody (§6), not surface.
- HTTP API: the unified policy-routed `POST /overrides` (§3a) enforces the floor through the shared `FlooredRegistry` chokepoint; the floor itself is **not** set over the API (operator action). The API reads the floor per-request.

## 8. Re-key / lost-key path

Losing the key must be **embarrassing, not catastrophic** — "you're re-signing everything because you lost your key", not "you can no longer prove you operate this project, rebuild the repo."

`legis posture rekey`:
- **Requires no old key** (you lost it) — but is therefore, by definition, a keyless way to become the operator. It is made safe by being **loud and self-limiting**:
  - It **resets the floor to chill** and mints a **new** operator key (into the chosen backend). You cannot rekey directly into a high posture; to get back up you `operator enable` + `posture set` with the new key (the "embarrassing, re-sign everything" part).
  - It writes a **`KEY_RESET` genesis record chained onto the existing history** — history is preserved, not nuked — recording that the operator key was reset without proof of the prior key.
  - `legis doctor` surfaces the reset prominently ("posture key epoch reset on <date> by <agent_id>").
- **Threat symmetry / honesty:** an attacker can also run `rekey` to force chill — but only in the loudest possible way (an indelible, dated, attributed `KEY_RESET`). They cannot silently downgrade, and they cannot rekey *into* a chosen posture. This is exactly Legis's tamper-**evident** stance: the honest claim is "an unauthorized posture reset leaves a permanent mark", not "is impossible".

## 9. Honesty / threat model statement (published, per Legis doctrine)

Legis states its own residual limits rather than hiding them in comments (`README.md` "Known security limitations"):

- **Tamper-evident, not tamper-proof.** A holder of raw write access to `.weft/legis/posture.db` can delete-and-re-chain or truncate — the already-conceded raw-DB-write tier (`README.md:137`). The floor ledger inherits, not worsens, that residual; the optional HeadAnchor mitigation pattern applies.
- **The elevation window admits unsupervised signing.** Inside an open window the agent can sign without further human gesture — by design. Safety rests on a short TTL and the operator's presence; this is reframed (§6) as accountability, and is strictly better than a key living in env indefinitely.
- **TTY/prompt interception is the conceded "mission-focused agent" tier.** If `posture set` runs in a shell the agent fully controls, a sufficiently capable agent could intercept the one human-approved signing. Keychain/hardware backends are strictly better than file/passphrase here (interception yields no key, at most one approved signature). This is the same tier the operator named ("by the time an agent is that mission-focused, nothing stops it").

## 10. Testing strategy

- **Floor semantics:** `max(floor, registry.cell_for(policy))` across all 16 (floor × registry-cell) combinations; registry can tighten above floor, never below.
- **Ledger:** genesis on fresh install; idempotent re-install; chain integrity; missing-ledger → fail-closed `structured` (not chill).
- **Gate:** transition refused with no open session; refused on fingerprint mismatch; accepted with valid session; fail-closed on signer error; exactly one record per outcome.
- **Custody backends:** keychain (mocked secure store), age-file (real encrypt/decrypt round-trip), env escape hatch emits warning. Signer never returns key bytes to caller.
- **Elevation session:** enable opens window + writes `OPERATOR_SESSION_OPENED`; TTL lapse zeroizes; `disable` ends early; every in-window signature carries `session_id`.
- **Rekey:** resets to chill, mints new epoch, writes `KEY_RESET` onto existing chain (history preserved), needs no old key, doctor flags it.
- **Doctor reconciliation:** floor-vs-registry report; ledger discontinuity / epoch-reset surfaced; **`legis doctor` exits non-zero on an unacknowledged `KEY_RESET`** so a rekey (legitimate or attacker-forced) fails CI loudly; zero-byte/missing store handled report-only (consistent with existing doctor posture).
- **API unification:** unified `POST /overrides` routes by policy through `FlooredRegistry` and returns the discriminated outcome for each cell; a `floor=structured` floor refuses a would-be chill self-clear (no bypass); operator-clear routes (`/signoff/{seq}/sign`, `/protected/operator-override`) unchanged; existing `tests/api/*` rewritten against the unified route; `docs/federation/sei-conformance.md` updated and the SEI conformance vector re-pinned to the new route surface.

## 11. Future state (tracked in Filigree, not built here)

Unify **all** of Legis's keyed operations onto the elevation-session primitive built here:
- Migrate protected-cell verdict signing and sign-off signing off env-plaintext keys (`LEGIS_HMAC_KEY`, `LEGIS_WARDLINE_ARTIFACT_KEY`) onto elevation sessions.
- Route git-commit signing through the same unlock.
- Add 1Password / Vault signer backends.

These share v1's primitive but each is its own risk surface and spec.

## 12. Decisions resolved during brainstorm

- Posture = a **global floor** under the per-policy registry (not whole-registry signing, not `default_cell`-only). chill is the base.
- Install **mints** the key (the opt-in moment); custody default is OS keychain, env is an escape hatch.
- **Any** floor change needs the key (the key exists from install, so direction-aware ratcheting is unnecessary); registry tightening above the floor stays keyless.
- Custody is the real control, **not** CLI-vs-MCP surface gating.
- Elevation sessions (`operator enable`, 5-min TTL) replace per-action prompts and provide the accountability record.
- Lost key → keyless `rekey` that resets to chill, preserves history, is loudly recorded.
- v1 scope = elevation-session primitive + posture floor as its only consumer; the rest is future state.

### Decisions resolved post-plan (2026-06-16, against the workflow plan + review)

- **API governance-routing unification is IN scope for v1 (option b).** The HTTP API's cell-addressed submit routes collapse into one policy-routed `POST /overrides`, so the floor applies through the shared `FlooredRegistry` chokepoint across MCP + API + CLI. Chosen over a per-route admission gate because the cell-addressed API is a real floor-bypass door, it has no external runtime consumer, and unifying now is one atomic contract change instead of a coordinated breaking change later. (Reverses the plan's D6, which had scoped the API out.)
- **`cryptography` is a mandatory dependency** (age-file backend; scrypt + AES-GCM). Not an optional extra.
- **age-file-without-keychain re-prompts per `posture set`** — accepted friction; the smooth window is the keychain backend's benefit.
- **`legis doctor` exits non-zero on an unacknowledged `KEY_RESET`** — the rekey friction is intended (CI fails until the operator re-raises the floor with a signed transition).
- **`posture_get` returns the per-policy floored effective cell**, not just the global floor.
- **The floor is read per request/invocation** (not cached at startup) so a long-lived API/MCP server applies a floor change without a restart. (Supersedes the plan's D7 startup-read.)
- **SEI conformance contract** (`docs/federation/sei-conformance.md`) + cross-member SEI vector are updated in this same release to track the unified route surface.
