# Posture read_floor Fail-Closed Integrity Gate — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `PostureLedger.read_floor()` fail closed when the ledger cannot prove its own chain integrity, so a raw-DB-written/forged tail record can no longer silently set the routing floor (legis-476ab6f125; PRD-0005 criterion 1).

**Architecture:** `read_floor()` gains a `verify_integrity()` gate (the existing keyless O(N) chain re-hash on `AuditStore`) before its descending floor scan; a failed verification returns `None`, which every caller already maps to the fail-closed `structured` default. The keyless hot read proves **integrity + tail-kind** — NOT operator authorization. Cryptographic `operator_sig` verification under the epoch key stays the operator-side `doctor` check, but note its true scope: `doctor` verifies `operator_sig` only in `_transition_acknowledges` (`doctor.py:649`), reached only via `check_posture_key_reset` (`doctor.py:677`, which early-returns "no key-epoch reset" at `:707` when there is none) **when there is a `KEY_RESET` to acknowledge**. A file-write attacker who *recomputes* the keyless chain on a forged floor-lowering `TRANSITION` of a **non-rekeyed** ledger is therefore caught by **neither** this hot read **nor** `doctor` today — it is a pure conceded raw-file-write residual (`README.md:137`), pinned by an explicit characterization test, not implied-closed.

**Tech Stack:** Python 3.12, SQLAlchemy Core over SQLite, `uv`, pytest. No new dependencies.

**Prerequisites:**
- Work on a feature branch / worktree, NOT `main` (e.g. `git switch -c fix/posture-read-floor-verify-integrity`). Per the authority grant, the merge to main + any publish is owner-gated; this plan ends at a green branch + an accepted finding.
- `uv sync --dev` already run; `.venv` present.
- Read context (already grounded): `src/legis/posture/ledger.py:92` (`read_floor`), `src/legis/store/audit_store.py:362` (`verify_integrity`, keyless), `src/legis/doctor.py:649` (`_transition_acknowledges`) / `:677` (`check_posture_key_reset` — KEY_RESET-ack path only, early-returns at `:707` with no reset), `tests/posture/test_security_honesty.py` (fixtures + the suite the two new tests land in), `tests/posture/test_ledger.py:128` (`test_read_floor_uses_tail_read` — the one existing test the fix retires; see Task 1 Step 5), `tests/store/test_audit_store.py:22,78` (the canonical `sqlite3.connect` raw-DB-write pattern the new tests reuse), `README.md:137` (the conceded residual to cite).

**Scope fence (PRD-0005 non-goals):** Do NOT add operator-key verification to the hot read, do NOT touch `src/legis/store/audit_store.py` or `canonical.py` (the cross-tool HMAC contract), do NOT re-architect the posture subsystem. The change touches exactly: `read_floor()` + the module docstring in `ledger.py`; **two new tests** in `test_security_honesty.py`; and **one rewritten test** in `test_ledger.py` (`test_read_floor_uses_tail_read`, whose "must not call read_all" premise the integrity gate deliberately retires).

**Scope acknowledgment (tracked follow-ups, NOT this PR):** three sibling reads call `read_all()` with no `verify_integrity()` gate — `epoch_reset_unacknowledged` (`ledger.py:120`), `current_epoch_fingerprint` (`ledger.py:151`), `session_opened_recorded` (`ledger.py:299`). `read_floor` is the P0 (it alone feeds the routing chokepoint `floored_registry` with no downstream keyed check) and is closed here. The siblings that feed `set_floor` are defended downstream by the operator key; but `epoch_reset_unacknowledged` feeds the agent-facing `posture_get` MCP tool (`mcp.py:2550`) with **no** keyed backstop — file a follow-up for it. Do not let these remain silently scoped out (the plan's own honesty discipline: make residuals explicit, never implied-closed).

---

### Task 1: read_floor fails closed on a chain-integrity break

**Files:**
- Modify: `src/legis/posture/ledger.py` — `read_floor` (lines 92–118: add the gate + honest docstring) **and** the module docstring (lines 13–18, which currently claims the floor is found "never the O(N) `read_all` loop" — false post-fix).
- Test (new): `tests/posture/test_security_honesty.py` (add one test, reuse existing fixtures)
- Test (rewrite): `tests/posture/test_ledger.py` — `test_read_floor_uses_tail_read` (Step 5; its premise is retired by the gate)

**Step 1: Write the failing test**

Add to `tests/posture/test_security_honesty.py`. Module imports needed at top (add if absent): `import json`, `import sqlite3`, and `from legis.posture.ledger import _sqlite_file` (the production URL→path helper, so the raw write hits the exact file the store engine uses). Reuses the file's existing `_genesis`, `_MemSigner`, `_open_recorded_session`, `set_floor`, `FixedClock`, `KIND_TRANSITION`, `mint_key`.

```python
def test_read_floor_fails_closed_on_integrity_break(tmp_path):
    """A raw-DB tail record that lowers the floor but breaks the keyless hash
    chain must NOT be trusted: read_floor() fails closed (returns None ->
    structured), never the forged floor. (legis-476ab6f125; PRD-0005 crit 1.)

    Uses the canonical raw-file-write attacker model (sqlite3.connect, as in
    tests/store/test_audit_store.py:22,78), not the ORM. In-place-edit / reorder
    / seq-gap tamper is already pinned for the same gate at
    tests/store/test_audit_store.py:78 and :246; this test exercises the
    tail-append vector through read_floor specifically.
    """
    key_hex = mint_key()
    key_bytes = bytes.fromhex(key_hex)
    ledger, _ = _genesis(tmp_path, key_hex=key_hex)  # GENESIS @ chill

    # Elevate to protected via a signed transition so a downgrade is visible.
    _open_recorded_session(ledger, signer=_MemSigner(key_bytes))
    set_floor(
        "protected", ledger=ledger, signer=_MemSigner(key_bytes),
        agent_id="op", rationale="tighten", clock=FixedClock("t1"),
    )
    assert ledger.read_floor() == "protected"

    # Simulate a raw-file-write attacker: append a tail row claiming
    # floor="chill" with a BROKEN chain (garbage hashes). INSERT is allowed:
    # the append-only triggers block only UPDATE/DELETE.
    head_seq, _ = ledger.store.get_latest_sequence_and_hash()
    forged = {
        "kind": KIND_TRANSITION, "floor": "chill", "operator_sig": None,
        "key_fingerprint": "x", "agent_id": "attacker", "recorded_at": "t9",
        "rationale": "forged", "session_id": None,
    }
    conn = sqlite3.connect(str(_sqlite_file(ledger._url)))
    try:
        conn.execute(
            "INSERT INTO audit_log (seq, payload, content_hash, prev_hash, "
            "chain_hash) VALUES (:seq, :payload, :ch, :ph, :xh)",
            {
                "seq": head_seq + 1, "payload": json.dumps(forged),
                "ch": "0" * 64,  # does NOT match payload -> verify_integrity fails
                "ph": "0" * 64, "xh": "0" * 64,
            },
        )
        conn.commit()
    finally:
        conn.close()

    # Pre-fix: the descending scan returns the forged "chill". Post-fix: the
    # broken chain fails verify_integrity, so read_floor fails closed.
    assert ledger.read_floor() is None
```

**Why this test:** It pins the finding's load-bearing defense — an integrity-breaking forged tail (the realistic naive raw writer) must fail closed. It asserts the *integrity* path (the real fix), not a presence check.

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/posture/test_security_honesty.py::test_read_floor_fails_closed_on_integrity_break -v`

Expected output (RED — the bug):
```
FAILED ... assert 'chill' is None
```
(`read_floor()` currently returns the forged `"chill"`; the assertion `is None` fails — the right reason.)

**Step 3: Write minimal implementation**

In `src/legis/posture/ledger.py`, edit `read_floor` (currently lines 92–118): replace the docstring and insert the `verify_integrity()` gate immediately after the absent-file early return, before `_assert_no_batch_in_progress`.

```python
    def read_floor(self) -> str | None:
        """The current floor (latest authoritative floor record), or ``None``.

        Fail-closed: the floor sets routing, so the ledger must first PROVE its
        own integrity. ``verify_integrity()`` (an O(N) keyless chain re-hash)
        gates the read; a chain that does not verify — a raw-write in-place edit,
        reorder, or seq gap — yields ``None`` (callers map ``None`` -> the
        fail-closed ``structured`` default), never the tampered floor. A missing
        DB file or an empty store also report ``None`` (``verify_integrity`` is
        True on an empty store; the table-absence check returns ``None`` below).

        The O(N) integrity walk runs on EVERY resolution (the floor is never
        cached, design D2) and is deliberate: it is bounded by operator-action
        volume (genesis/transition/rekey are operator-gated; session-open churn
        is bounded by TTL expiry + human-in-the-loop enabling), immaterial at
        posture-ledger scale on local SQLite, and an *unverified* hot read was
        the whole bug. The two failure modes are both fail-closed but
        asymmetric: a DETECTED tamper (a clean walk that does not verify)
        resolves to ``None`` -> ``structured``; an I/O fault (locked/corrupt DB
        raising ``OperationalError``) propagates as an exception and aborts the
        read — neither is a pass. Do NOT wrap the gate in a try/except that
        downgrades that raise to a permissive default.

        SCOPE (honesty): the chain is keyless SHA, so this proves integrity +
        tail-kind but NOT operator authorization. A file-write attacker who
        *recomputes* the keyless chain on a forged floor-lowering ``TRANSITION``
        passes this gate; on a non-rekeyed ledger that forgery is caught by
        NEITHER this keyless hot read NOR ``doctor`` today — it is a PURE
        conceded raw-file-write residual (README "Known security limitations",
        README.md:137). ``doctor``'s keyed ``operator_sig`` verification
        (``_transition_acknowledges``, doctor.py:649) covers ONLY the
        ``KEY_RESET``-acknowledgment path (D6), not a ``TRANSITION`` on a ledger
        with no reset to acknowledge. A general per-transition ``operator_sig``
        audit in ``doctor`` would close the residual operator-side, but that is
        separate follow-up, not this change. See
        ``test_read_floor_fails_closed_on_integrity_break`` and
        ``test_read_floor_recomputed_chain_forgery_is_conceded_residual``.
        """
        path = _sqlite_file(self._url)
        if path is not None and not path.exists():
            return None
        # Fail closed if the chain cannot prove integrity: a tampered/forged
        # ledger must not be trusted to set the routing floor. verify_integrity()
        # returns True on an empty store, so an absent/empty ledger still reads
        # as None via the table-absence check below, not a spurious failure.
        if not self.store.verify_integrity():
            return None
        self.store._assert_no_batch_in_progress("read_floor")
        with self.store._engine.begin() as conn:
            if not self.store._has_log_table(conn):
                return None
            rows = conn.execute(
                select(self.store._log.c.payload)
                .order_by(self.store._log.c.seq.desc())
            )
            for row in rows:
                payload = json.loads(row.payload)
                kind = payload.get("kind")
                floor = payload.get("floor")
                if kind in self._FLOOR_RECORD_KINDS and floor is not None:
                    return floor
        return None
```

Then update the **module docstring** (`ledger.py:13–18`) so it no longer claims the floor is found "never the O(N) `read_all` loop" — that invariant is retired by the gate. Replace that bullet with:

```
  * The current floor is the latest authoritative floor record's ``floor`` field
    (``GENESIS`` / ``TRANSITION`` / ``KEY_RESET``). An O(N) keyless
    ``verify_integrity`` walk GATES the read (fail-closed: a chain that does not
    verify yields ``None`` -> ``structured``); the floor itself is then found by
    one descending payload scan from the tail, never a repeated point-read loop
    over metadata. Metadata records such as ``OPERATOR_SESSION_OPENED`` must not
    lower the effective floor, even if they carry a stale ``floor`` field.
```

**Why minimal:** Only the `verify_integrity()` gate + the two honesty docstrings are added; the existing descending scan is untouched. No operator-key handling (deliberately out of the keyless hot read — that is `doctor`'s job and a PRD non-goal). `verify_integrity()` opens/closes its own connection (NullPool), so the subsequent `_engine.begin()` scan is safe; the double O(N) pass is immaterial on a small posture ledger and avoids touching the sensitive `audit_store` HMAC layer. **This consciously reverses a prior architecture decision:** the 2026-06-16 posture-ratchet spec (`docs/superpowers/specs/2026-06-16-legis-posture-ratchet-plan.md:509`) optimized `read_floor()` to stay *off* `read_all()` on the per-request hot path; integrity-before-trust now takes precedence over that O(1) optimization. The tradeoff is intentional and bounded (see the docstring), not an oversight — security before hot-path thrift, justified by the small operator-gated ledger. (The existing `_assert_no_batch_in_progress("read_floor")` is now belt-and-suspenders — `verify_integrity()` runs the same guard first — but is harmless and documents intent; leave it.)

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/posture/test_security_honesty.py::test_read_floor_fails_closed_on_integrity_break -v`

Expected output:
```
PASSED
```

**Step 5: Rewrite the one existing test the gate retires**

`tests/posture/test_ledger.py:128–136` (`test_read_floor_uses_tail_read`) monkeypatches `ledger.store.read_all` to RAISE `AssertionError("read_floor must not call read_all (hot path)")`, then asserts `read_floor() == "chill"` on a valid genesis chain. Post-fix, `read_floor()` legitimately calls `read_all` via `verify_integrity()`; `verify_integrity` catches only `(JSONDecodeError, TypeError, ValueError)` (`audit_store.py:373`), so the `AssertionError` propagates and the test **errors**. Its "must not call read_all" premise is exactly the property the integrity-before-trust gate deliberately supersedes — rewrite it to assert the new contract:

```python
def test_read_floor_verifies_integrity_before_returning_floor(tmp_path):
    """read_floor() gates on verify_integrity() before the tail scan: on a valid
    chain the gate passes and the floor is returned. Supersedes the old
    'read_floor must not call read_all' guard — the integrity-before-trust gate
    DELIBERATELY calls read_all via verify_integrity; that property is RETIRED,
    not regressed. (legis-476ab6f125.)
    """
    ledger = PostureLedger(_url(tmp_path), initialize=True)
    ledger.genesis(key_fingerprint="ab" * 32, agent_id="installer", recorded_at="t0")
    assert ledger.store.verify_integrity() is True
    assert ledger.read_floor() == "chill"
```

(The `read_by_seq`-patching sibling `test_read_floor_does_not_point_read_each_metadata_tail` at `:139` is UNAFFECTED — `verify_integrity` does not call `read_by_seq`.)

> **TWO TRAPS — DO NOT:** (a) do NOT flip this test to `is None`: a valid genesis chain MUST read `"chill"`, and flipping it wouldn't pass anyway (the old `_boom` raised before any assertion). (b) do NOT "fix" a red `test_read_floor_uses_tail_read` by weakening or reverting the `verify_integrity()` gate to restore the no-`read_all` property — that reintroduces the exact false-green this finding closes. The rename + rewrite IS the fix.

Run: `uv run pytest tests/posture/test_ledger.py::test_read_floor_verifies_integrity_before_returning_floor -v` → `PASSED`.

**Step 6: Commit**

```bash
git add src/legis/posture/ledger.py tests/posture/test_security_honesty.py tests/posture/test_ledger.py
git commit -m "fix(posture): read_floor fails closed on a chain-integrity break

read_floor() now gates on verify_integrity() before returning the floor, so
a raw-DB-written/forged tail record that breaks the keyless hash chain can no
longer silently set the routing floor (it maps to the fail-closed structured
default). Cryptographic operator_sig verification stays the operator-side
doctor check (KEY_RESET-acknowledgment path only); a recomputed-chain forgery
remains the conceded raw-file-write residual (README.md:137).

Retires test_read_floor_uses_tail_read's 'must not call read_all' premise (the
integrity gate supersedes it) and corrects the now-false module docstring.

Closes the load-bearing half of legis-476ab6f125 (PRD-0005 criterion 1).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

**Definition of Done:**
- [ ] New test written and fails for the right reason (returns "chill" pre-fix)
- [ ] `read_floor` gates on `verify_integrity()` and fails closed to `None`
- [ ] `read_floor` docstring + module docstring (lines 13–18) updated to state the new O(N) cost, the fail-closed asymmetry, and the keyless-read honesty scope (no false `doctor` backstop claim)
- [ ] `test_read_floor_uses_tail_read` rewritten to the new contract (NOT flipped to `is None`, gate NOT weakened)
- [ ] New test passes post-fix; rewritten test passes
- [ ] Committed

---

### Task 2: document the recomputed-chain forgery residual (characterization test)

**Files:**
- Test (new): `tests/posture/test_security_honesty.py` (add one test — no production change)

**Step 1: Write the documentation test**

This test PASSES on the Task-1 code (it asserts a *known limit*, not a new behavior). It exists so the residual is visible and executable in the suite, never implied-closed — the cardinal-sin guard for an honesty tool (a green test an attacker walks around). Reuses the Task-1 imports (`json`, `sqlite3`, `_sqlite_file`) plus the canonical-chain primitives.

```python
def test_read_floor_recomputed_chain_forgery_is_conceded_residual(tmp_path):
    """DOCUMENTS the limit so it is visible in the suite, not implied-closed.

    A file-write attacker who *recomputes* the KEYLESS chain (valid content_hash,
    prev_hash, chain_hash) on a forged floor-lowering TRANSITION passes
    verify_integrity() — the keyless hot read CANNOT detect this. On a
    non-rekeyed ledger it is caught by NEITHER this hot read NOR `doctor`:
    doctor's operator_sig verification (_transition_acknowledges) runs ONLY on
    the KEY_RESET-acknowledgment path, and there is no KEY_RESET here. It is the
    conceded raw-file-write residual (README "Known security limitations",
    README.md:137). A general per-transition operator_sig audit in doctor would
    close it operator-side (separate follow-up). If a future change makes
    read_floor reject this, that is a STRENGTHENING: update this test
    deliberately — do not let it silently flip for the wrong reason.
    """
    from legis.canonical import canonical_json, content_hash
    # Recompute the chain with the PRODUCTION primitive so the residual is not
    # undermined by a divergent re-implementation (precedent: test_audit_store.py:10).
    from legis.store.audit_store import _chain

    key_hex = mint_key()
    key_bytes = bytes.fromhex(key_hex)
    ledger, _ = _genesis(tmp_path, key_hex=key_hex)
    _open_recorded_session(ledger, signer=_MemSigner(key_bytes))
    set_floor(
        "protected", ledger=ledger, signer=_MemSigner(key_bytes),
        agent_id="op", rationale="tighten", clock=FixedClock("t1"),
    )
    assert ledger.read_floor() == "protected"

    # Forge a floor-lowering TRANSITION with a CORRECTLY recomputed keyless chain.
    head_seq, head_chain = ledger.store.get_latest_sequence_and_hash()
    forged = {
        "kind": KIND_TRANSITION, "floor": "chill", "operator_sig": "junk",
        "key_fingerprint": "x", "agent_id": "attacker", "recorded_at": "t9",
        "rationale": "forged", "session_id": None,
    }
    c_hash = content_hash(forged)            # correct keyless content hash
    chain_hash = _chain(head_chain, c_hash)  # correct keyless chain link
    conn = sqlite3.connect(str(_sqlite_file(ledger._url)))
    try:
        conn.execute(
            "INSERT INTO audit_log (seq, payload, content_hash, prev_hash, "
            "chain_hash) VALUES (:seq, :payload, :ch, :ph, :xh)",
            {
                "seq": head_seq + 1, "payload": canonical_json(forged),
                "ch": c_hash, "ph": head_chain, "xh": chain_hash,
            },
        )
        conn.commit()
    finally:
        conn.close()

    # Integrity holds (keyless chain valid) -> the keyless read is fooled.
    # This asserts the DOCUMENTED RESIDUAL, not a desired guarantee.
    assert ledger.store.verify_integrity() is True
    assert ledger.read_floor() == "chill"
```

**Why this test:** Without it, a reader could believe Task 1 fully "authenticated the tail". It makes the conceded residual an executable fact tied to `README.md:137`, and a tripwire: a future change that closes the residual must update this test on purpose.

**Step 2: Run test to verify it passes**

Run: `uv run pytest "tests/posture/test_security_honesty.py::test_read_floor_recomputed_chain_forgery_is_conceded_residual" -v`

Expected output:
```
PASSED
```

(If it FAILS because `read_floor()` returned `None`, the keyless chain was not recomputed correctly in the fixture — `payload` must be `canonical_json(forged)` and `content_hash`/`chain_hash` must be the production-primitive values so `verify_integrity` accepts it. Fix the fixture, not the assertion.)

**Step 3: Commit**

```bash
git add tests/posture/test_security_honesty.py
git commit -m "test(posture): pin the recomputed-chain forgery as a documented residual

read_floor's keyless integrity gate cannot detect a file-write attacker who
recomputes the keyless chain; on a non-rekeyed ledger that is caught by neither
the hot read nor doctor (doctor's operator_sig check is the KEY_RESET-ack path
only). It is the conceded raw-file-write residual (README.md:137). This
characterization test makes the limit visible in the suite so it is never
implied-closed.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

**Definition of Done:**
- [ ] Documentation test added and passing
- [ ] Docstring/name make clear it asserts a residual, not a guarantee, and name the precise reason doctor does not catch it (no KEY_RESET)
- [ ] Committed

---

### Task 3: full verification (suite + coverage floor + gates)

**Files:** none (verification only).

**Step 1: Run the full posture suite — confirm no regression**

Run: `uv run pytest tests/posture -v`

Expected: all pass — **after** the Task 1 Step 5 rewrite of `test_read_floor_uses_tail_read`. That is the ONLY existing test the gate disturbs (it monkeypatched `read_all` to forbid it; the gate now legitimately calls it). It is a valid-chain test, not a bug-asserting one, so it is *rewritten to the new contract in Task 1*, never "flipped to expect `None`". No other existing test asserts the bug: the valid-chain tests (`test_rekey_preserves_existing_floor`, `test_tty_session_expiry`, `test_every_signature_carries_session_id`, `test_read_floor_does_not_point_read_each_metadata_tail`) build well-formed chains, so `verify_integrity()` is True and their behavior is unchanged. **If `test_read_floor_uses_tail_read` is still red here, the remedy is the Task 1 rewrite — NOT weakening the `verify_integrity()` gate.**

**Step 2: Run the per-package coverage floor (posture ≥ 93%)**

Run: `uv run pytest tests/posture --cov=legis.posture --cov-report=term-missing`
then: `uv run python scripts/check_coverage_floors.py`

Expected: `src/legis/posture/` ≥ 93.0% (both branches of the single added conditional are covered — the `False`→`None` path by Task 1's new test, the integrity-holds path by Task 2 and the existing valid-chain tests). No floor breach.

**Step 3: Run the CI-equivalent gates**

Run, expecting all green:
```bash
uv run pytest --cov=legis --cov-fail-under=88
uv run mypy src/legis
uv run ruff check src
uv run legis governance-gate
```

Expected output: pytest passes with total coverage ≥ 88; mypy clean; ruff clean (E4/E7/E9/F); governance-gate passes. (`read_floor` returns `str | None` unchanged, so mypy is unaffected.)

**Definition of Done:**
- [ ] `tests/posture` green; the one disturbed test rewritten (Task 1 Step 5), the fix NOT weakened
- [ ] Posture per-package coverage ≥ 93%; global ≥ 88
- [ ] mypy + ruff + governance-gate green
- [ ] Branch ready for review (NOT merged — owner-gated)

---

## After execution — acceptance + closeout (product-owner, post-merge)

Once the branch is green and merged (owner-gated), this finding is **accepted** against PRD-0005 criterion 1:
- Close `legis-476ab6f125` in the tracker with the close commit (walk proposed→…→done; `commit=main@<sha>`).
- The north-star (`metrics.md`: open governance-honesty defects) drops 3 → 2.
- File the **scope-acknowledgment follow-ups** (rank 4 of the review): a finding for `epoch_reset_unacknowledged` (feeds the agent-facing `posture_get` MCP read with no keyed backstop), and note `current_epoch_fingerprint` / `session_opened_recorded` as the same class (defended downstream by the operator key, lower priority).
- Note a **diagnostic-honesty follow-on** (rank 8): post-fix, `doctor.check_posture_ledger` (`doctor.py:578`, warn at `:603`) maps `read_floor()==None` to a "re-run `legis install`" warn — but `None` now also means "chain verification failed", so the warn misdirects an operator (who should investigate storage / restore from backup; `check_posture_chain` already surfaces the real error). Not a false-green (it is a warn), but worth a cleanup so the two `None` causes are distinguished.
- Then plan the next finding (`legis-0c310712a7`, the un-anchored protected batch) — note its overlap risk with PRD-0005's "shared store-transaction wrapper" assumption.

## Validate before execution (recommended — security-critical)

This is a governance-honesty security fix on a 93%-floor package. **RECOMMENDED:** re-run `/review-plan docs/plans/2026-06-26-posture-read-floor-verify-integrity.md` for reality/architecture/quality/systems verdicts before execution (a prior review's synthesis does not carry forward).

**Review history:** a 7-agent + synthesizer review (2026-06-26) returned **CHANGES_REQUESTED** on the prior draft and is fully addressed here:
- **Blocker 1** (rank 1, HIGH): the prior draft missed that `test_ledger.py::test_read_floor_uses_tail_read` breaks (errors) under the gate and gave a misdirecting "expect `None`" remedy that could nudge an implementer to weaken the gate. → Now `test_ledger.py` is in scope, Task 1 Step 5 rewrites the test to the new contract with explicit "do not weaken the gate / do not flip to `is None`" guardrails, and Task 3 Step 1 is corrected.
- **Blocker 2** (rank 2, HIGH): the prior docstrings claimed `doctor`'s `operator_sig` check backstops the recomputed-chain residual — false (`doctor` checks `operator_sig` only on the KEY_RESET-acknowledgment path; Task 2's forged TRANSITION has no KEY_RESET). → Architecture note, `read_floor` docstring, and the Task 2 test docstring now state the residual is caught by neither hot read nor doctor; doctor locators corrected to the verified lines (`_transition_acknowledges` `:649`, `check_posture_key_reset` `:677`, early "no key-epoch reset" return `:707`) after a round-2 grep caught an offset-shifted earlier read.
- Folded in: stale module docstring (rank 3), sibling-read scope acknowledgment + `epoch_reset_unacknowledged` follow-up (rank 4), faithful `sqlite3` raw-write pattern replacing ORM internals (rank 5), in-place-edit/seq-gap coverage comment (rank 6), deliberate-O(N) docstring bound (rank 7), `doctor` diagnostic follow-on (rank 8), and the fail-closed-asymmetry / belt-and-suspenders notes (rank 9).
