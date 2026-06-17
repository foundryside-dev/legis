"""G12 — real-Filigree integration scaffold for bind-issue + closure-gate.

`test_signoff_binding.py` proves the bind LOGIC against ``FakeFiligree``, whose
``associations_for_entity`` returns ``[]`` — so it can never assert the attach was
actually PERSISTED, nor that the bound fields round-trip a real server. That is the
G12 gap (weft-513aa35a08): an echo is not persistence.

This module closes it against a RUNNING Filigree daemon. It is skipped unless the
environment names one, so it is safe in offline CI and runnable the moment the Weft
daemon is up (the same ``:8749`` server-mode marker the incident stands up):

    LEGIS_FILIGREE_TEST_URL   base URL of a live Filigree (e.g. http://127.0.0.1:8749)
    LEGIS_FILIGREE_TEST_ISSUE an existing issue id on that server to bind to

It asserts the full chain end to end over real HTTP:
  bind -> real Filigree attach -> read the association back (persistence, not echo)
       -> record in a local BindingLedger
       -> legis closure-gate (real HTTP via TestClient) flips to allowed + evidence.

G11 posture (weft-c7e3486246): Filigree's classic route is transport-open, so
legis does not emit dead ``X-Weft-*`` transport headers. The app-level
``binding_signature`` still persists and the local BindingLedger remains the
verifier.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    not (os.environ.get("LEGIS_FILIGREE_TEST_URL") and os.environ.get("LEGIS_FILIGREE_TEST_ISSUE")),
    reason=(
        "real-Filigree integration: set LEGIS_FILIGREE_TEST_URL + "
        "LEGIS_FILIGREE_TEST_ISSUE to a running daemon + existing issue to run"
    ),
)


def _contains(association: dict, value: object) -> bool:
    """True if ``value`` appears among an association's values.

    Field-name-tolerant: the producer may name the column ``content_hash`` or
    ``content_hash_at_attach``, ``signature`` or ``binding_signature``. We assert
    the bound VALUES persisted without pinning the server's column names (which is
    exactly the kind of hand-transcribed coupling the conformance vectors retire).
    """
    return any(cell == value for cell in association.values())


def test_real_filigree_bind_persists_then_clears_closure_gate(tmp_path):
    from fastapi.testclient import TestClient

    from legis.api.app import create_app
    from legis.clock import FixedClock
    from legis.filigree.client import HttpFiligreeClient
    from legis.governance.binding_ledger import BindingLedger
    from legis.governance.signoff_binding import bind_signoff_to_issue
    from legis.identity.entity_key import EntityKey
    from legis.store.audit_store import AuditStore

    base_url = os.environ["LEGIS_FILIGREE_TEST_URL"]
    issue_id = os.environ["LEGIS_FILIGREE_TEST_ISSUE"]
    # Unique opaque SEI per run so re-runs never collide on the entity association.
    entity_id = f"loomweave:eid:legis-g12-{uuid.uuid4().hex}"
    content_hash = f"blake3:{uuid.uuid4().hex}"
    signoff_seq = 7

    # Real transport: no injected fetch -> HttpFiligreeClient signs (if a key is
    # provisioned) and talks real HTTP to the daemon.
    client = HttpFiligreeClient(base_url)
    app_level_key = b"g12-binding-attestation-key"
    ledger = BindingLedger(
        AuditStore(f"sqlite:///{tmp_path / 'bind.db'}"),
        FixedClock("2026-06-02T12:00:00+00:00"),
        key=b"g12-ledger-key",
    )

    out = bind_signoff_to_issue(
        client,
        issue_id=issue_id,
        entity_key=EntityKey.from_sei(entity_id),
        content_hash=content_hash,
        signoff_seq=signoff_seq,
        key=app_level_key,
        ledger=ledger,
    )
    assert out["signoff_seq"] == signoff_seq
    assert out["binding_seq"] == 1
    assert out["binding_signature"].startswith("hmac-sha256:")

    # PERSISTENCE, not echo: read the association back off the real server and
    # assert every bound field round-tripped. This is the assertion FakeFiligree
    # structurally cannot make (it returns []).
    associations = client.associations_for_entity(entity_id)
    assert associations, "real Filigree returned no association — the bind did not persist"
    mine = [a for a in associations if _contains(a, entity_id)]
    assert mine, f"no persisted association references entity {entity_id!r}"
    assoc = mine[0]
    assert _contains(assoc, issue_id), "bound issue_id did not persist"
    assert _contains(assoc, content_hash), "bound content_hash did not persist"
    assert _contains(assoc, signoff_seq), "bound signoff_seq did not persist"
    # G11 observed: the app-level binding_signature is STORED verbatim by the
    # classic route (it does not verify it). Its presence in the persisted row is
    # the live evidence behind the transport-open posture.
    assert _contains(assoc, out["binding_signature"]), (
        "binding_signature did not persist — Filigree stores it verbatim (G11)"
    )

    # closure-gate over real HTTP (legis's own surface), fed by the real-bind ledger.
    gate = TestClient(create_app(binding_ledger=ledger))
    resp = gate.get(f"/filigree/issues/{issue_id}/closure-gate")
    assert resp.status_code == 200
    body = resp.json()
    assert body["allowed"] is True
    assert body["evidence"]["signoff_seq"] == signoff_seq
    assert body["evidence"]["content_hash"] == content_hash


def test_real_filigree_bind_succeeds_on_transport_open_route():
    """G11 evidence: the bind is transport-open by design.

    Legis emits no ``X-Weft-*`` headers and the classic route accepts the write;
    the app-level binding_signature/BindingLedger carry governance proof.
    """
    from legis.filigree.client import HttpFiligreeClient
    from legis.governance.signoff_binding import bind_signoff_to_issue
    from legis.identity.entity_key import EntityKey

    base_url = os.environ["LEGIS_FILIGREE_TEST_URL"]
    issue_id = os.environ["LEGIS_FILIGREE_TEST_ISSUE"]
    entity_id = f"loomweave:eid:legis-g12-keyless-{uuid.uuid4().hex}"

    client = HttpFiligreeClient(base_url)  # no key in env -> unsigned transport
    out = bind_signoff_to_issue(
        client,
        issue_id=issue_id,
        entity_key=EntityKey.from_sei(entity_id),
        content_hash=f"blake3:{uuid.uuid4().hex}",
        signoff_seq=1,
    )
    assert out["loomweave_entity_id"] == entity_id  # accepted, unauthenticated
