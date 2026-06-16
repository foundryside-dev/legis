"""Phase 6 — install mints the operator key + writes the GENESIS floor record.

Fail-closed / idempotent (plan Task 6.1, spec §5):
  * a fresh install writes exactly one ``GENESIS`` with ``floor="chill"`` and the
    minted key's fingerprint; ``operator_sig`` is absent (keyless genesis);
  * the minted 32-byte hex key is handed to the selected custody backend and is
    NEVER written to the ledger (fingerprint + backend id only) nor to
    ``.mcp.json``;
  * a SECOND install over an existing ledger (GENESIS *or* KEY_RESET tail) is a
    no-op — no second GENESIS, no re-mint, floor + epoch unchanged;
  * ``.gitignore`` gains the root-anchored ``operator_session.json`` /
    ``operator.age`` rules.
"""

from __future__ import annotations

import json

import pytest

from legis import install
from legis.posture import (
    KIND_GENESIS,
    KIND_KEY_RESET,
    PostureLedger,
    key_fingerprint,
)


@pytest.fixture()
def project(tmp_path, monkeypatch):
    """A fresh project root that is also the cwd.

    ``posture_db_url()`` resolves ``.weft/legis/legis-posture.db`` relative to
    cwd, so install (and the read-back ledger) must run with cwd == project
    root, exactly as the CLI does (``project_root = Path.cwd()``).
    """
    monkeypatch.chdir(tmp_path)
    # Keep the env clean of any inherited operator key so the escape-hatch tests
    # are deterministic.
    monkeypatch.delenv("LEGIS_OPERATOR_KEY", raising=False)
    return tmp_path


def _records(project_root):
    led = PostureLedger(
        install.posture_db_url_for_install(), initialize=False
    )
    return led.store.read_all()


# ---------------------------------------------------------------------------
# GENESIS write
# ---------------------------------------------------------------------------


def test_install_creates_posture_db_with_genesis(project):
    install.install_posture(project, backend="age-file", key_sink=lambda k, b: None)

    db = project / ".weft" / "legis" / "legis-posture.db"
    assert db.exists()

    recs = _records(project)
    assert len(recs) == 1
    payload = recs[0].payload
    assert payload["kind"] == KIND_GENESIS
    assert payload["floor"] == "chill"
    assert payload["key_fingerprint"]  # present
    assert payload.get("operator_sig") is None  # keyless genesis


def test_install_mints_key_to_backend(project):
    handed: list[tuple[str, str]] = []

    def sink(key_hex: str, backend: str) -> None:
        handed.append((key_hex, backend))

    fp = install.install_posture(project, backend="age-file", key_sink=sink)

    # The key was handed to the backend exactly once.
    assert len(handed) == 1
    key_hex, backend = handed[0]
    assert backend == "age-file"
    assert len(key_hex) == 64  # 32 bytes hex

    # The ledger stores only the fingerprint — never the key.
    recs = _records(project)
    payload = recs[0].payload
    assert payload["key_fingerprint"] == key_fingerprint(key_hex)
    assert payload["key_fingerprint"] == fp
    blob = json.dumps([r.payload for r in recs])
    assert key_hex not in blob


def test_install_idempotent(project):
    fp1 = install.install_posture(
        project, backend="age-file", key_sink=lambda k, b: None
    )
    recs1 = _records(project)

    handed: list[str] = []
    fp2 = install.install_posture(
        project, backend="age-file", key_sink=lambda k, b: handed.append(k)
    )
    recs2 = _records(project)

    assert len(recs1) == 1
    assert len(recs2) == 1  # no second GENESIS
    assert handed == []  # no re-mint on the second pass
    assert fp2 == fp1  # epoch fingerprint unchanged
    assert recs2[0].payload["floor"] == "chill"


def test_install_idempotent_after_rekey(project):
    # Genesis, then chain a KEY_RESET tail (the Phase-11 rekey shape) directly so
    # a second install must NOT re-genesis a ledger whose tail is KEY_RESET.
    install.install_posture(project, backend="age-file", key_sink=lambda k, b: None)
    led = PostureLedger(install.posture_db_url_for_install(), initialize=True)
    led.store.append(
        {
            "kind": KIND_KEY_RESET,
            "floor": "chill",
            "key_fingerprint": key_fingerprint("ab" * 32),
            "operator_sig": None,
            "session_id": None,
            "agent_id": "operator",
            "recorded_at": "2026-06-17T00:00:00Z",
            "rationale": "rekey",
        }
    )
    before = _records(project)
    assert before[-1].payload["kind"] == KIND_KEY_RESET

    handed: list[str] = []
    install.install_posture(
        project, backend="age-file", key_sink=lambda k, b: handed.append(k)
    )
    after = _records(project)
    assert len(after) == len(before)  # no re-genesis
    assert handed == []  # no re-mint
    assert after[-1].payload["kind"] == KIND_KEY_RESET


# ---------------------------------------------------------------------------
# Key never leaks into .mcp.json
# ---------------------------------------------------------------------------


def test_operator_key_not_in_mcp_json(project, monkeypatch):
    monkeypatch.setenv("LEGIS_OPERATOR_KEY", "de" * 32)
    monkeypatch.setenv("LEGIS_OPERATOR_KEY_AGE_PASSPHRASE", "hunter2")

    # Seed an existing .mcp.json whose env carries the operator-key family so we
    # exercise the scrub path on an existing entry too.
    mcp = project / ".mcp.json"
    mcp.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "legis": {
                        "type": "stdio",
                        "command": "legis",
                        "args": ["mcp", "--agent-id", "x"],
                        "env": {
                            "LEGIS_OPERATOR_KEY": "de" * 32,
                            "LEGIS_OPERATOR_KEY_AGE_PASSPHRASE": "hunter2",
                            "SAFE_VAR": "ok",
                        },
                    }
                }
            }
        )
    )

    install.register_mcp_json(project, "x")

    data = json.loads(mcp.read_text())
    env = data["mcpServers"]["legis"]["env"]
    assert "LEGIS_OPERATOR_KEY" not in env
    assert not any(k.startswith("LEGIS_OPERATOR_KEY") for k in env)
    assert env.get("SAFE_VAR") == "ok"  # unrelated operator env preserved
    # And the rejected set itself names the operator key.
    assert "LEGIS_OPERATOR_KEY" in install._REJECTED_MCP_ENV_KEYS


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------


def test_install_age_file_sink_writes_wrapped_blob_no_plaintext(project, monkeypatch):
    monkeypatch.setenv("LEGIS_OPERATOR_KEY_AGE_PASSPHRASE", "correct horse")
    fp = install.install_posture(project, backend="age-file")

    age = project / ".weft" / "legis" / "operator.age"
    assert age.exists()
    blob = age.read_bytes()
    assert blob  # non-empty wrapped blob

    # The wrapped blob round-trips to a key whose fingerprint is the GENESIS fp,
    # and the blob never contains the plaintext key hex.
    from legis.posture import key_fingerprint, unwrap_key

    recovered = unwrap_key(blob, "correct horse")
    assert key_fingerprint(recovered) == fp
    assert recovered.encode() not in blob


def test_install_age_file_sink_refuses_without_passphrase(project, monkeypatch):
    monkeypatch.delenv("LEGIS_OPERATOR_KEY_AGE_PASSPHRASE", raising=False)
    with pytest.raises(install.OperatorKeyCustodyError):
        install.install_posture(project, backend="age-file")
    # Fail-closed: no GENESIS was written, no age blob persisted.
    db = project / ".weft" / "legis" / "legis-posture.db"
    if db.exists():
        recs = _records(project)
        assert recs == []
    assert not (project / ".weft" / "legis" / "operator.age").exists()


def test_install_default_backend_selection(project, monkeypatch):
    # keychain available -> keychain
    monkeypatch.setattr(install, "_keychain_available", lambda: True)
    assert install.choose_install_backend(insecure_env=False) == "keychain"

    # keychain unavailable -> age-file
    monkeypatch.setattr(install, "_keychain_available", lambda: False)
    assert install.choose_install_backend(insecure_env=False) == "age-file"

    # env only with the explicit opt-in
    assert install.choose_install_backend(insecure_env=True) == "env"


# ---------------------------------------------------------------------------
# .gitignore
# ---------------------------------------------------------------------------


def test_install_gitignores_session_and_age(project):
    install.ensure_gitignore(project)
    gi = (project / ".gitignore").read_text()
    lines = {ln.strip() for ln in gi.splitlines()}
    assert "/.weft/legis/operator_session.json" in lines
    assert "/.weft/legis/operator.age" in lines
