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

_OPERATOR_PLAINWEAVE_DOCS = (
    Path("README.md"),
    Path("docs/guide/configuration.md"),
    Path("docs/guide/cli-reference.md"),
    Path("docs/guide/reading-legis-output.md"),
)


def _normalize(text: str) -> str:
    markup = str.maketrans("", "", "`*_")
    return " ".join(text.lower().translate(markup).split())


def _paragraphs(text: str) -> list[str]:
    return [paragraph for paragraph in text.split("\n\n") if paragraph.strip()]


def test_operator_docs_explain_plainweave_runtime_autodiscovery_migration() -> None:
    for path in _OPERATOR_PLAINWEAVE_DOCS:
        text = path.read_text(encoding="utf-8")
        normalized = _normalize(text)

        assert "runtime autodiscovery" in normalized, path
        assert "PLAINWEAVE_MCP_CMD" in text, path
        assert "legacy" in normalized or "retired" in normalized, path

        for paragraph in _paragraphs(text):
            if "PLAINWEAVE_MCP_CMD" in paragraph:
                context = _normalize(paragraph)
                assert "legacy" in context or "retired" in context, (path, paragraph)


def test_plainweave_changelog_names_runtime_autodiscovery_fix() -> None:
    changelog = _normalize(Path("CHANGELOG.md").read_text(encoding="utf-8"))

    assert "legis-3622e80f2e" in changelog
    assert "multi-project" in changelog
    assert "oscillation" in changelog
    assert "convergence" in changelog


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
