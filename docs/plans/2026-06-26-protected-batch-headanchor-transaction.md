# Protected-Gate Transaction + HeadAnchor Advance — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Give `ProtectedGate` an owned `transaction()` context manager that advances the `HeadAnchor` after the batch commits — parity with `SignoffGate.transaction()` — so a protected record committed inside a batch can no longer leave the anchor at the pre-batch head, where a later tail-truncation would go undetected (legis-0c310712a7; PRD-0005 criterion 2).

**Architecture:** `ProtectedGate._record_signed()` (`protected.py:286-292`) correctly defers the per-append anchor advance when `self._store.in_batch()` is true (a mid-batch head read is batch-forbidden, Q-M5), trusting a batch *owner* to advance the anchor after commit — but `ProtectedGate` has no such owner, unlike `SignoffGate.transaction()` (`signoff.py:177-189`). This plan adds the missing owner: a `ProtectedGate.transaction()` `@contextmanager` that wraps `self._store.transaction()` and, after commit, calls `self._anchor.update(*self._store.get_latest_sequence_and_hash())`. It is a near-verbatim mirror of the sign-off precedent.

**Threat reality (state it honestly — this is a DOUBLY-LATENT/preventive fix, not a live-exploited path):** grounding the current callers shows **no code path batches protected appends today, and production wires no anchor at all**. `route_findings` (`route_findings` spans `wardline/governor.py:46-177`; `txn_owner` is chosen at `117-122`) sets its `txn_owner` to `signoff` or `engine` and routes only BLOCK_ESCALATE / SURFACE_OVERRIDE / SURFACE_ONLY — there is **no protected cell in the governor**. Both transports **construct `ProtectedGate` with `anchor=None`** (the constructors at `api/app.py:376-379` and `mcp.py:266-269`) and call `operator_override()`/`submit()` outside any batch. So today the gap is *doubly* latent: the `_record_signed` anchor guard at `protected.py:291` never advances anything because **the anchor is absent (`None`), not merely unadvanced**, AND no caller opens a batch around a protected append. The exposure the finding names is a *future* deployment that both wires an anchor AND wraps a protected append in an `AuditStore.transaction()` with no owner to advance the anchor — for which there is currently no safe API. This fix supplies that API (parity), so the value is **entirely preventive**.

**PRD-0005 overlap question — RESOLVED by grounding:** PRD-0005 flagged a possible "shared store-transaction wrapper used by both posture and protected." There is none: `route_findings`'s batch owner is `signoff`/`engine` (never protected), and the posture ledger is a **separate** `AuditStore` (`src/legis/posture/ledger.py`) with its own writes. This finding is isolated from legis-476ab6f125 (already closed) and from posture; sequencing is unaffected.

**Tech Stack:** Python 3.12, SQLAlchemy Core over SQLite, `uv`, pytest. No new dependencies.

**Prerequisites:**
- Work on a feature branch / worktree, NOT `main` (e.g. `git switch -c fix/protected-batch-headanchor`). Per the authority grant, the merge to main + any publish is owner-gated; this plan ends at a green branch + an accepted finding.
- `uv sync --dev` already run; `.venv` present.
- Read context (already grounded): `src/legis/enforcement/protected.py` (`ProtectedGate.__init__` 207-239 → `self._store`/`self._anchor`/`self._key`; `_record_signed` 241-301 with the `in_batch()` anchor guard at 291; `operator_override` 389-413 — the deterministic, judge-free append path the tests use), `src/legis/enforcement/signoff.py:177-189` (the `transaction()` precedent to mirror VERBATIM), `src/legis/store/head_anchor.py` (`HeadAnchor.update`/`check`, `AnchorError`), `src/legis/store/audit_store.py` (`transaction` 180, `in_batch` 214, `get_latest_sequence_and_hash` 444, append-only triggers `audit_log_no_update`/`audit_log_no_delete` at 166/173), `tests/store/test_head_anchor.py:42-72` (the raw-truncation helper + `test_anchor_detects_tail_truncation` precedent), `tests/store/test_batch_read_free_invariant.py:27-31` (the on-disk-store fixture), `tests/enforcement/test_protected_submit.py` (the existing `ProtectedGate` construction fixtures).

**Scope fence (PRD-0005 non-goals):** Do NOT modify `src/legis/store/audit_store.py`, `head_anchor.py`, or `canonical.py` (the cross-tool HMAC + anchor contracts). Do NOT re-architect the enforcement cell. Do NOT add a protected cell to `route_findings` (out of scope — and routing-coupling is a separate design question). The change is confined to `ProtectedGate` (add `transaction()` + one import) + two tests.

---

### Task 1: add ProtectedGate.transaction() that advances the anchor after commit

**Files:**
- Modify: `src/legis/enforcement/protected.py` — add `from contextlib import contextmanager` to the imports, and add a `transaction()` method on `ProtectedGate` (mirroring `signoff.py:177-189`).
- Test (new): `tests/enforcement/test_protected_transaction.py`

**Step 1: Write the failing test**

Create `tests/enforcement/test_protected_transaction.py`. Uses the raw-truncation pattern from `tests/store/test_head_anchor.py:42-45` and the on-disk store from `tests/store/test_batch_read_free_invariant.py`. `operator_override` is the deterministic append (it bypasses the judge — `protected.py:400-413`), so a stub judge that is never consulted is correct.

```python
import sqlite3

import pytest

from legis.clock import FixedClock
from legis.enforcement.protected import ProtectedGate
from legis.enforcement.verdict import Verdict
from legis.identity.entity_key import EntityKey
from legis.store.audit_store import AuditStore
from legis.store.head_anchor import AnchorError, HeadAnchor

KEY = b"k" * 32
CLOCK = "2026-06-26T12:00:00+00:00"


class _UnusedJudge:
    """operator_override bypasses the judge; if it is consulted, fail loudly."""

    def evaluate(self, record):  # pragma: no cover - must never be called
        raise AssertionError("judge must not be consulted on operator_override")


def _anchored_gate(tmp_path):
    store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
    anchor = HeadAnchor(str(tmp_path / "gov.anchor"), KEY)
    gate = ProtectedGate(store, FixedClock(CLOCK), _UnusedJudge(), KEY, anchor=anchor)
    return store, anchor, gate


def _override(gate, rationale):
    return gate.operator_override(
        policy="protected/secrets",
        entity_key=EntityKey.from_locator("m.f"),
        rationale=rationale,
        operator_id="op",
        file_fingerprint="fp",
        ast_path="m.f",
    )


def _truncate_to(db_path, keep_seq):
    """Raw out-of-band tail truncation (drops the append-only triggers first)."""
    con = sqlite3.connect(db_path)
    try:
        con.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
        con.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
        con.execute("DELETE FROM audit_log WHERE seq > ?", (keep_seq,))
        con.commit()
    finally:
        con.close()


def test_protected_transaction_advances_anchor_so_truncation_is_detected(tmp_path):
    """A protected append batched through ProtectedGate.transaction() advances the
    HeadAnchor after commit, so a later tail-truncation back to the pre-batch head
    is DETECTED (parity with SignoffGate.transaction()). legis-0c310712a7.
    """
    store, anchor, gate = _anchored_gate(tmp_path)
    # A pre-batch protected append (outside any batch -> anchor advances normally).
    _override(gate, "pre-batch")
    pre_seq, _ = store.get_latest_sequence_and_hash()

    # Batch a protected append through the NEW owned transaction API.
    with gate.transaction():
        _override(gate, "in-batch")

    # The transaction() advanced the anchor to the in-batch record's head.
    head_seq, _ = store.get_latest_sequence_and_hash()
    assert head_seq == pre_seq + 1

    # Truncate the in-batch record out of band, back to the pre-batch head.
    _truncate_to(str(tmp_path / "gov.db"), pre_seq)

    # The anchor remembers the higher head -> truncation is detected.
    with pytest.raises(AnchorError):
        anchor.check(store.read_all())
```

**Why this test:** It pins the finding's fix — the owned transaction API advances the anchor so a batched protected append is truncation-detectable. It exercises the real out-of-band attacker (raw `sqlite3` truncation), not a mock.

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/enforcement/test_protected_transaction.py::test_protected_transaction_advances_anchor_so_truncation_is_detected -v`

Expected output (RED — the finding's exact gap, "ProtectedGate has no transaction wrapper"):
```
FAILED ... AttributeError: 'ProtectedGate' object has no attribute 'transaction'
```

**Step 3: Write minimal implementation**

In `src/legis/enforcement/protected.py`: add the import (top of file, with the other stdlib imports) —
```python
from contextlib import contextmanager
```
— and add this method to `ProtectedGate` (place it next to `verify_integrity`/`records`, e.g. after `operator_override`). It is a verbatim mirror of `SignoffGate.transaction()` (`signoff.py:177-189`):

```python
    @contextmanager
    def transaction(self):
        """Group this gate's protected appends into one all-or-nothing batch and
        advance the anchor once after commit — parity with
        ``SignoffGate.transaction()`` (signoff.py).

        The per-append anchor advance is deferred inside a batch (the head read
        is batch-forbidden, Q-M5; see the ``in_batch()`` guard in
        ``_record_signed``). Advance it once here after the batch commits and the
        write lock is released. An exception inside the batch rolls back and
        propagates before this runs, so the anchor never advances past a
        rolled-back head (AUD-1: the anchor only ever lags, never overshoots).
        """
        with self._store.transaction():
            yield
        if self._anchor is not None:
            self._anchor.update(*self._store.get_latest_sequence_and_hash())
```

**Why minimal:** This is the exact `SignoffGate` precedent — no new anchor logic, no change to `_record_signed` (its `in_batch()` deferral is already correct; this supplies the missing owner that re-advances after commit). `audit_store.py` / `head_anchor.py` are untouched.

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/enforcement/test_protected_transaction.py::test_protected_transaction_advances_anchor_so_truncation_is_detected -v`

Expected output:
```
PASSED
```

**Step 5: Commit**

```bash
git add src/legis/enforcement/protected.py tests/enforcement/test_protected_transaction.py
git commit -m "fix(protected): add ProtectedGate.transaction() that advances the anchor

A protected record appended inside a batch defers its HeadAnchor advance
(the mid-batch head read is forbidden, Q-M5) and, unlike SignoffGate, had no
transaction owner to re-advance it after commit — so a batched protected
append could leave the anchor at the pre-batch head and a later tail-truncation
would go undetected. Add ProtectedGate.transaction(), a verbatim mirror of
SignoffGate.transaction(), as that owner.

Closes legis-0c310712a7 (PRD-0005 criterion 2).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

**Definition of Done:**
- [ ] Test written and fails for the right reason (AttributeError: no `transaction`)
- [ ] `from contextlib import contextmanager` added; `ProtectedGate.transaction()` added, mirroring `signoff.py:177-189`
- [ ] Test passes post-fix
- [ ] No other tests broken
- [ ] Committed

---

### Task 2: document the raw-batch parity residual (characterization test)

**Files:**
- Test (new): `tests/enforcement/test_protected_transaction.py` (add one test — no production change)

**Step 1: Write the documentation test**

This PASSES on the Task-1 code — it asserts a KNOWN LIMIT (parity with `SignoffGate`), so it is the honesty tripwire: a protected append inside a **raw** `store.transaction()` (bypassing `gate.transaction()`) still leaves the anchor stale, because nobody advances it after commit. The supported safe path is `gate.transaction()`; a raw batch owner must advance the anchor itself. This mirrors the residual-pinning discipline used for legis-476ab6f125.

```python
def test_raw_store_transaction_bypasses_anchor_advance_documented_residual(tmp_path):
    """DOCUMENTS the parity limit (not a defense): a protected append inside a RAW
    store.transaction() — bypassing gate.transaction() — defers the anchor advance
    (in_batch() is true) and nothing re-advances it, so a truncation back to the
    pre-batch head is NOT detected. The supported safe path is gate.transaction()
    (Task 1); a caller that owns a raw batch must advance the anchor itself,
    identically to SignoffGate. If a future change closes this (e.g. an after-commit
    hook on AuditStore.transaction), update this test deliberately. legis-0c310712a7.
    """
    store, anchor, gate = _anchored_gate(tmp_path)
    _override(gate, "pre-batch")
    pre_seq, _ = store.get_latest_sequence_and_hash()

    # RAW batch (NOT gate.transaction()): the append's anchor advance is deferred
    # and never re-applied.
    with store.transaction():
        _override(gate, "in-raw-batch")

    # The anchor is STALE at the pre-batch head (the residual).
    _truncate_to(str(tmp_path / "gov.db"), pre_seq)

    # Stale anchor == truncated DB head -> truncation is NOT detected.
    anchor.check(store.read_all())  # does not raise: asserts the DOCUMENTED residual
```

**Why this test:** It makes the parity limit executable so it is never implied-closed — and, paired with Task 1, it is the before/after: raw batch → stale anchor → undetected; `gate.transaction()` → advanced anchor → detected.

**Step 2: Run test to verify it passes**

Run: `uv run pytest "tests/enforcement/test_protected_transaction.py::test_raw_store_transaction_bypasses_anchor_advance_documented_residual" -v`

Expected output:
```
PASSED
```

(If it FAILS because `anchor.check` raised, the raw batch unexpectedly advanced the anchor — investigate; do NOT silence it by weakening the assertion.)

**Step 3: Commit**

```bash
git add tests/enforcement/test_protected_transaction.py
git commit -m "test(protected): pin the raw-batch anchor-advance residual

A protected append inside a raw store.transaction() (bypassing gate.transaction())
leaves the anchor stale — the supported safe path is gate.transaction(). This
characterization test makes the parity limit visible so it is never implied-closed.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

**Definition of Done:**
- [ ] Documentation test added and passing
- [ ] Name/docstring make clear it asserts a residual, not a guarantee
- [ ] Committed

---

### Task 3: full verification (suite + coverage floor + gates)

**Files:** none (verification only).

**Step 1: Run the enforcement suite**

Run: `uv run pytest tests/enforcement tests/store -q`

Expected: all pass. The change is purely additive (a new method + import), so no existing test should change behavior. Watch for any test that constructs `ProtectedGate` positionally and could be affected by the new import (none expected).

**Step 2: Per-package coverage floor**

Run: `uv run pytest tests/enforcement --cov=legis.enforcement --cov-report=term-missing`
then: `uv run python scripts/check_coverage_floors.py`

Expected: the `enforcement/` per-package floor (see the `FLOORS` dict in `scripts/check_coverage_floors.py`) holds. The new `transaction()` method's body is covered by Task 1; the deferred-advance path (`in_batch()` true) by Task 2.

**Step 3: CI-equivalent gates**

Run, expecting all green:
```bash
uv run pytest --cov=legis --cov-fail-under=88
uv run mypy src/legis
uv run ruff check src
uv run legis governance-gate
```

Expected: pytest passes with total coverage ≥ 88; mypy clean (the `@contextmanager` return type matches `SignoffGate.transaction`'s, which already type-checks); ruff clean; governance-gate passes.

**Definition of Done:**
- [ ] `tests/enforcement` + `tests/store` green
- [ ] `enforcement/` per-package floor holds; global ≥ 88
- [ ] mypy + ruff + governance-gate green
- [ ] Branch ready for review (NOT merged — owner-gated)

---

## After execution — acceptance + closeout (product-owner, post-merge)

Once the branch is green and merged (owner-gated), this finding is **accepted** against PRD-0005 criterion 2:
- Close `legis-0c310712a7` in the tracker (walk confirmed→fixing→verifying→closed; `commit=main@<sha>`).
- The north-star (`metrics.md`: open governance-honesty defects) drops **2 → 1**.
- Then plan the last finding (`legis-0186c23a2c`, the unbounded policy-boundary root) — the third and final PRD-0005 item; no overlap with this fix.

## Validate before execution (recommended — security-critical)

This is a governance-honesty security fix on a coverage-floored package. **RECOMMENDED:** run `/review-plan docs/plans/2026-06-26-protected-batch-headanchor-transaction.md` (reality/architecture/quality/systems) — or the same ultracode multi-agent review used for legis-476ab6f125 — before execution. Reviewer attention points: (1) confirm `route_findings` truly has no protected cell (the "latent" framing rests on it); (2) confirm `operator_override` is judge-free so the stub judge is sound; (3) confirm the `_truncate_to` trigger-drop + delete reproduces a real out-of-band truncation that `HeadAnchor.check` detects; (4) confirm the new method is a faithful mirror of `SignoffGate.transaction()` with no anchor-overshoot risk.

## Review fold-ins (round-1 multi-agent review: APPROVED_WITH_WARNINGS — fold in during execution, none block)

A 7-agent + synthesizer review returned **GO** with these non-blocking improvements; apply them as you execute:

1. **(rank 1, medium — the highest-value gap) Add a production-default UNANCHORED test in Task 1.** Both transports wire `anchor=None`, so the only production-reachable path of `transaction()` is the `self._anchor is None` no-op arm — and both new tests use `_anchored_gate()`, so that arm is untested (line-coverage floors won't catch it; `pyproject` has no `branch=True`). Add:
   ```python
   def test_protected_transaction_is_safe_without_an_anchor(tmp_path):
       """The production default: ProtectedGate has anchor=None. transaction()
       must still batch atomically (the if-anchor guard is a no-op, not a crash)."""
       store = AuditStore(f"sqlite:///{tmp_path / 'gov.db'}")
       gate = ProtectedGate(store, FixedClock(CLOCK), _UnusedJudge(), KEY)  # no anchor=
       with gate.transaction():
           _override(gate, "in-batch")
       assert len(store.read_all()) == 1
       assert store.verify_integrity() is True
   ```
2. **(rank 2, low) Task 2 — add a landing assertion** after the raw `with store.transaction(): _override(...)` and before `_truncate_to`: `assert store.get_latest_sequence_and_hash()[0] == pre_seq + 1` — proves the `in_batch()`-deferred branch was actually taken, so the residual test can't pass for the wrong reason (a silently no-op'd append). Keep the "do NOT silence by weakening the assertion" guidance.
3. **(rank 3, low) Task 1 — fix the now-contradicting comment** in `_record_signed` (`protected.py:287-290`): it still says "the protected gate is not itself a batch owner." Bring it to `SignoffGate._append` parity (`signoff.py:110-111`): the per-append advance is deferred inside a batch (Q-M5) and `ProtectedGate.transaction()` advances it once after commit. No production-logic change.
4. **(rank 5, low) Task 1 — comment `_truncate_to`**: `# No survivor re-chain needed: AnchorError fires on the head_seq comparison before chain_hash is checked.` Optionally `assert not store.verify_integrity()` after the truncation to make the broken-chain state explicit.
5. **(rank 6, low) `transaction()` docstring — add a nesting caveat**: `gate.transaction()` must be the OUTERMOST batch owner for its store; nesting it inside another gate's transaction on the same thread raises `RuntimeError` (fail-closed, the batch-forbidden read — inherited from the `SignoffGate` contract). Documentation only.
6. **(rank 7, low, OPTIONAL) consider an AUD-1 no-overshoot rollback test**: open an anchored `gate.transaction()`, `_override` inside, `raise` before exit, catch, then assert `len(store.read_all()) == pre_batch_count` and `anchor.check(store.read_all())` does not raise — makes the docstring's no-overshoot claim executable.
7. **(Task 3 DoD — real gap) Add the two CI gates the plan omitted** (CLAUDE.md lists them): `uv run legis policy-boundary-check --root src --repo-root .` and `uv run pytest tests/conformance/test_sei_oracle.py`. A pure-additive enforcement contextmanager is very unlikely to trip either, but the "all CI gates green" DoD requires them.
