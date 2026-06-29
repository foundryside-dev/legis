"""Phase 4 / Task 4.3 — the session banner reports the governing posture floor.

Honesty (D0): an agent reading the session context must see the floor that is
actually governing this project, not assume ``chill`` from "cells config:
absent". A missing ledger reads as the fail-closed ``structured`` default,
reported distinctly from an installed-at-``chill`` floor.
"""

from __future__ import annotations

import hashlib

from legis.config import posture_db_url
from legis.crypto import signing as enf_signing
from legis.hooks import generate_session_context
from legis.install import inject_instructions
from legis.posture.ledger import PostureLedger


def _seed_floor(db_url: str, floor: str) -> None:
    """A posture ledger with a GENESIS (chill) and an optional raise to ``floor``."""
    ledger = PostureLedger(db_url, initialize=True)
    key = b"k" * 32
    fp = hashlib.sha256(key).hexdigest()
    ledger.genesis(key_fingerprint=fp, agent_id="installer", recorded_at="t0")
    if floor != "chill":

        class _MemSigner:
            def __init__(self, held_key=key):
                self._key = held_key

            def fingerprint(self) -> str:
                return fp

            def sign(self, fields: dict) -> str:
                return enf_signing.sign(fields, self._key, version="v3")

        ledger.transition(
            floor,
            signer=_MemSigner(),
            session_id="s",
            key_fingerprint=fp,
            agent_id="op",
            rationale="raise",
            recorded_at="t1",
        )


def test_banner_reports_floor_absent(tmp_path, monkeypatch):
    # No ledger at all -> the banner is honest that the floor is unset and the
    # process is fail-closed to structured, NOT silently chill.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LEGIS_POLICY_CELLS", raising=False)
    inject_instructions(tmp_path / "CLAUDE.md")
    context = generate_session_context()
    assert "posture floor: none (fail-closed structured)" in context
    assert "\n" not in context  # still a single-line banner


def test_banner_reports_floor_chill_distinct_from_absent(tmp_path, monkeypatch):
    # An installed-but-unraised project shows chill, NOT "none" — the banner
    # distinguishes "no ledger" from "floor is genuinely chill".
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LEGIS_POLICY_CELLS", raising=False)
    inject_instructions(tmp_path / "CLAUDE.md")
    _seed_floor(posture_db_url(), "chill")
    context = generate_session_context()
    assert "posture floor: chill" in context
    assert "none (fail-closed structured)" not in context


def test_banner_reports_floor_present(tmp_path, monkeypatch):
    # A raised floor is surfaced so the agent plans against the real posture.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LEGIS_POLICY_CELLS", raising=False)
    inject_instructions(tmp_path / "CLAUDE.md")
    _seed_floor(posture_db_url(), "structured")
    context = generate_session_context()
    assert "posture floor: structured" in context
