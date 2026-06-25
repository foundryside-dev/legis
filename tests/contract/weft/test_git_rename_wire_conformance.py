"""Shared Weft conformance test: the legis -> Loomweave git-rename wire contract.

This is the PRODUCER half of a single cross-member golden,
``vectors/git_renames.v1.json``. The byte-identical file is vendored into
Loomweave at ``crates/loomweave-cli/tests/fixtures/weft/git_renames.v1.json``;
its in-module oracle drives the REAL ``parse_legis_rename_json`` over the same
bytes. This file proves the SAME projection from legis's side, two ways:

1. **Live recipe** — fabricate a real rename in a temp git repo, call the REAL
   ``GET /git/renames`` via ``TestClient`` (exactly like the existing
   ``tests/contract/test_git_renames_contract.py``), and assert its projected
   ``(old_path, new_path)`` pairs *contain* the golden's real rename. Membership,
   not strict equality: ``commit_sha``/blobs are nondeterministic per fabrication
   and the empty-``new_path`` skip item is synthetic (git never emits it), so a
   live re-run cannot reproduce the frozen array byte-for-byte — only the
   projected real-rename pair is stable. That projection is what the consumer
   actually reads; everything else it ignores.

2. **Layer-1 byte-pin** — recompute the git blob sha1 of the *frozen* golden file
   in-process and assert it equals ``VENDORED_BLOB_SHA``. This is the
   canonicalization-drift detector: if anyone re-serializes the golden (key
   order, whitespace, trailing newline) on either side, the bytes change, the
   sha1 stops reproducing, and CI fails before the drift can reach production.
   Loomweave's consumer oracle pins the SAME constant against the SAME bytes, so
   the two repos are locked to one wire shape.

Why this exists (Weft incident 2026-06-10, root cause #2 / G16,
clarion-73dff1d2d1): the ``/git/renames`` shape and Loomweave's
``parse_legis_rename_json`` were hand-aligned with no shared test. A producer key
rename (``old_path`` -> anything else) or an envelope migration (``[...]`` ->
``{"renames":[...]}``) zeroes the rename signal with no error, orphaning
renamed-with-edit entities under fresh SEIs. A contract fix without its vector
just re-creates the drift; this golden + the two oracles is how the fix is real.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from legis.api.app import create_app

VECTOR_PATH = Path(__file__).parent / "vectors" / "git_renames.v1.json"

# The git blob sha1 of the frozen golden bytes:
#   sha1(b"blob <len>\0" + bytes). NOT git — recomputed in-process below and by
#   Loomweave's consumer oracle over the byte-identical vendored copy. Re-pin only
#   by re-freezing the golden from the real endpoint and updating BOTH repos.
VENDORED_BLOB_SHA = "74f69ee81b030a31f9fdd37dc1c49543fbe389c2"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


def _project_pairs(items: list[dict]) -> list[tuple[str, str]]:
    """Re-implements Loomweave's parse_legis_rename_json projection: array ->
    (old_path, new_path) pairs, skipping any item whose path is missing,
    non-string, or empty. Kept inline so this producer oracle is self-contained
    and mirrors the consumer's contract exactly."""
    out: list[tuple[str, str]] = []
    for it in items:
        old, new = it.get("old_path"), it.get("new_path")
        if isinstance(old, str) and isinstance(new, str) and old and new:
            out.append((old, new))
    return out


def test_vendored_golden_blob_sha_is_byte_pinned() -> None:
    """Layer-1: the frozen golden's bytes reproduce VENDORED_BLOB_SHA. Tamper the
    file and this fails before any wire drift can ship. Loomweave pins the same
    constant against the byte-identical vendored copy."""
    data = VECTOR_PATH.read_bytes()
    recomputed = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    assert recomputed == VENDORED_BLOB_SHA, (
        f"golden bytes changed: {recomputed} != pinned {VENDORED_BLOB_SHA}. "
        "Re-freeze from the real endpoint and update BOTH repos' constant."
    )


def test_golden_is_a_flat_array_with_the_three_required_shapes() -> None:
    """The golden is a RAW /git/renames array (not the wrapped vector envelope),
    because parse_legis_rename_json calls value.as_array(); an object would parse
    to empty. It must carry: >=1 real rename, an item with extra ignored fields,
    and an empty-new_path item the consumer skips."""
    import json

    array = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    assert isinstance(array, list), "consumer requires a flat top-level array"
    pairs = _project_pairs(array)
    # The real rename survives projection.
    assert ("auth.py", "authn.py") in pairs
    # The empty-new_path item is dropped (synthetic skip case).
    assert any(it.get("new_path") == "" for it in array), "skip case present"
    assert ("ghost.py", "") not in pairs and not any(
        p[0] == "ghost.py" for p in pairs
    ), "empty new_path must not project to a pair"
    # The real item carries the extra fields the consumer ignores.
    real = next(it for it in array if it.get("new_path") == "authn.py")
    for ignored in ("commit_sha", "similarity", "old_blob", "new_blob"):
        assert ignored in real, f"real item should carry ignored field {ignored}"


def test_real_endpoint_projects_the_golden_real_rename(tmp_path: Path) -> None:
    """Drive the REAL GET /git/renames over a fabricated rename and assert its
    projected pairs CONTAIN the golden's real rename. The live array can carry
    only the real rename (the skip item is synthetic), so membership — not strict
    equality — is the right contract; it is exactly what the consumer reads."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "auth.py").write_text("def login():\n    return 1\n" * 5)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip()
    (repo / "authn.py").write_text((repo / "auth.py").read_text())
    (repo / "auth.py").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "rename auth -> authn")

    client = TestClient(create_app(repo_path=str(repo)))
    resp = client.get("/git/renames", params={"rev_range": f"{base}..HEAD"})
    assert resp.status_code == 200, resp.text
    items = resp.json()
    assert isinstance(items, list), "Loomweave requires an array"
    live_pairs = _project_pairs(items)

    import json

    golden = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    # The golden's projected pairs == the live endpoint's projected pairs. The
    # synthetic empty-new_path skip item drops out of BOTH projections, so this is
    # exact equality, not membership — it also catches the live endpoint emitting
    # any rename the golden does not (an over-carry the consumer would silently
    # accept). The pair is stable regardless of git's reported similarity %.
    assert _project_pairs(golden) == [("auth.py", "authn.py")]
    assert live_pairs == _project_pairs(golden), (
        f"real endpoint projection diverged from the golden; "
        f"live={live_pairs} golden={_project_pairs(golden)}"
    )
