"""The policy-boundary fingerprint must be stable across Python interpreters.

dogfood: legis-13b4e97bf4. The fingerprint canonicalization used to be a raw
``ast.dump`` hash, whose text is Python-version-dependent: 3.13 omits
default-empty AST fields (an empty ``arguments`` node) where 3.12 lists
``posonlyargs`` / ``args`` / ``kwonlyargs`` etc. A fingerprint pinned under one
interpreter then reports a spurious mismatch under another. The fix replaces the
``ast.dump`` text with a serializer that emits EVERY field of every node in a
fixed order, so empty fields cannot be silently dropped — version-stable by
construction.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from legis.policy.decorator import fingerprint_source, get_normalized_ast_str

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"

# A snippet whose AST has an ``arguments`` node with several empty subfields —
# exactly the shape that differs between ``ast.dump`` on 3.12 vs 3.13.
_SNIPPET = "def t():\n    assert True\n"


def test_normalized_ast_str_emits_empty_fields():
    # The version-stability invariant: empty argument-list fields are emitted
    # explicitly, never dropped (raw ast.dump on 3.13 omits these). This is the
    # property that neutralizes the interpreter difference.
    dumped = get_normalized_ast_str(_SNIPPET)
    for field in ("posonlyargs=[]", "args=[]", "kwonlyargs=[]", "defaults=[]"):
        assert field in dumped, f"{field!r} missing from {dumped!r}"


@pytest.mark.skipif(
    shutil.which("python3.12") is None, reason="needs python3.12 for cross-interp check"
)
def test_fingerprint_identical_across_python_minor():
    # Decisive end-to-end proof: the repo's OWN fingerprint over one fixed source
    # must be byte-identical under the in-process interpreter and under
    # python3.12. Before the fix these differed; after it they match.
    here_fp = fingerprint_source(_SNIPPET)

    prog = (
        "import sys\n"
        f"sys.path.insert(0, {str(_SRC)!r})\n"
        "from legis.policy.decorator import fingerprint_source\n"
        f"sys.stdout.write(fingerprint_source({_SNIPPET!r}))\n"
    )
    other = subprocess.run(
        ["python3.12", "-c", prog],
        capture_output=True,
        text=True,
    )
    assert other.returncode == 0, other.stderr
    assert other.stdout == here_fp, (
        f"fingerprint drifted across interpreters: "
        f"{sys.version_info[:2]} -> {here_fp}, 3.12 -> {other.stdout}"
    )
