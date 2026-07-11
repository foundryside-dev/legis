from __future__ import annotations

from pathlib import Path


_PLAINWEAVE_DOCS = (
    Path("CHANGELOG.md"),
    Path("README.md"),
    Path("docs/guide/configuration.md"),
    Path("docs/guide/cli-reference.md"),
    Path("docs/guide/reading-legis-output.md"),
    Path("docs/superpowers/specs/2026-07-11-plainweave-doctor-binding-design.md"),
)


def _normalize(text: str) -> str:
    markup = str.maketrans("", "", "`*_")
    return " ".join(text.lower().translate(markup).split())


def test_plainweave_docs_disclose_project_json_normalization() -> None:
    documents = {
        path: _normalize(path.read_text(encoding="utf-8")) for path in _PLAINWEAVE_DOCS
    }
    combined = "\n".join(documents.values())

    assert all("semantically changes only" in text for text in documents.values())
    assert all("two-space indentation" in text for text in documents.values())
    assert "detected newline sequence" in combined
    assert "final-newline presence" in combined
    assert "file mode" in combined

    forbidden = (
        "repair changes only PLAINWEAVE_MCP_CMD",
        "repair changes only that nested environment value",
        "repair then changes only the nested PLAINWEAVE_MCP_CMD value",
        "repair changes only that target and preserves surrounding safe config",
        "repair changes only the nested PLAINWEAVE_MCP_CMD value",
        "preserves arbitrary json whitespace",
    )
    assert all(_normalize(claim) not in combined for claim in forbidden)
