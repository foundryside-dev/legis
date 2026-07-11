from __future__ import annotations

import re
from pathlib import Path

import pytest


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

_CANONICAL_DISCOVERY_DOCS = (
    Path("README.md"),
    Path("CHANGELOG.md"),
    Path("docs/guide/configuration.md"),
    Path("docs/guide/cli-reference.md"),
    Path("docs/guide/reading-legis-output.md"),
    Path(
        "docs/superpowers/specs/2026-07-12-plainweave-runtime-autodiscovery-design.md"
    ),
)

_SECRET_HANDLING_DOCS = (
    Path("docs/guide/configuration.md"),
    Path("docs/guide/cli-reference.md"),
    Path("docs/guide/reading-legis-output.md"),
    Path(
        "docs/superpowers/specs/2026-07-12-plainweave-runtime-autodiscovery-design.md"
    ),
)

_PLAINWEAVE_PDR = Path(
    "docs/product/decisions/0008-consume-plainweave-preflight-advisory-sibling.md"
)


def _normalize(text: str) -> str:
    markup = str.maketrans("", "", "`*_")
    return " ".join(text.lower().translate(markup).split())


def _paragraphs(text: str) -> list[str]:
    return [paragraph for paragraph in text.split("\n\n") if paragraph.strip()]


_FORWARD_RUNTIME_READ_CLAIM = re.compile(
    r"\b(?:the\s+)?runtime\b"
    r"(?P<negation>(?:(?!\bruntime\b|\bread(?:s)?\b|plainweavemcpcmd|[.;!?]).){0,80})"
    r"\bread(?:s)?\b"
    r"(?:(?!\bruntime\b|\bread(?:s)?\b|[.;!?]).){0,100}"
    r"\bplainweavemcpcmd\b"
)
_PASSIVE_RUNTIME_READ_CLAIM = re.compile(
    r"\bplainweavemcpcmd\b"
    r"(?P<negation>(?:(?!plainweavemcpcmd|\bruntime\b|\bread\b|[.;!?]).){0,100})"
    r"\bread\s+by\s+(?:the\s+)?runtime\b"
)


def _assert_no_active_plainweave_runtime_claims(text: str) -> None:
    normalized = _normalize(text)
    claims = [
        (match.start(), "forward", match)
        for match in _FORWARD_RUNTIME_READ_CLAIM.finditer(normalized)
    ]
    claims.extend(
        (match.start(), "passive", match)
        for match in _PASSIVE_RUNTIME_READ_CLAIM.finditer(normalized)
    )

    active_claims: list[str] = []
    for _position, direction, match in sorted(claims, key=lambda item: item[0]):
        negation = " ".join(match.group("negation").split())
        if direction == "forward":
            directly_negated = bool(
                re.search(
                    r"(?:(?:does|will|must|should|can)\s+not|no\s+longer)$",
                    negation,
                )
            )
        else:
            directly_negated = bool(
                re.search(r"(?:is\s+not|is\s+no\s+longer)$", negation)
            )
        if not directly_negated:
            active_claims.append(match.group(0))

    assert not active_claims, f"active Plainweave runtime claims: {active_claims}"


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


def test_current_docs_distinguish_both_plainweave_discovery_paths() -> None:
    local_entry_path = re.compile(
        r"\beither\b.{0,80}\bvalid\b.{0,40}\broot-pinned\b.{0,80}"
        r"\bplainweave mcp entry\b.{0,30}\bby itself\b"
    )
    initialized_fallback_path = re.compile(
        r"\bor\b.{0,30}\.plainweave/plainweave\.db\b.{0,30}\bplus\b"
        r".{0,40}\btrusted\b.{0,40}\bnon-project-local\b.{0,40}"
        r"\bplainweave-mcp\b.{0,20}\bon path\b"
    )
    incorrect_and_contracts = (
        ".plainweave/plainweave.db plus either a valid local",
        "requires local .plainweave/plainweave.db plus a valid local",
        "plainweave signals are the binding contract: 1. "
        ".plainweave/plainweave.db establishes initialized plainweave state; "
        "and 2. a valid local",
    )

    for path in _CANONICAL_DISCOVERY_DOCS:
        text = _normalize(path.read_text(encoding="utf-8"))

        assert local_entry_path.search(text), path
        assert initialized_fallback_path.search(text), path
        assert all(contract not in text for contract in incorrect_and_contracts), path


def test_current_docs_distinguish_project_and_global_secret_handling() -> None:
    project_contract = re.compile(
        r"\bproject repair\b.{0,30}\brefuses\b.{0,50}\bunsafe\b.{0,30}"
        r"\bsecret-bearing\b.{0,40}\.mcp\.json environment tables\b"
        r".{0,40}\bleaves the file unchanged\b"
    )
    global_contract = re.compile(
        r"\bglobal remove-only repair\b.{0,30}\baccepts\b.{0,30}"
        r"\bstring-valued environment entries\b.{0,40}\bpreserves\b"
        r".{0,30}\bunrelated entry\b.{0,40}\bsecret-shaped names\b"
    )

    for path in _SECRET_HANDLING_DOCS:
        text = _normalize(path.read_text(encoding="utf-8"))

        assert project_contract.search(text), path
        assert global_contract.search(text), path


def test_plainweave_runtime_claim_scanner_checks_every_claim() -> None:
    rejected = (
        "The runtime reads PLAINWEAVE_MCP_CMD as active configuration while "
        "doctor removes a legacy key.",
        "The runtime does not read PLAINWEAVE_MCP_CMD. Later, the runtime reads "
        "PLAINWEAVE_MCP_CMD as active configuration.",
    )
    accepted = (
        "The runtime does not read PLAINWEAVE_MCP_CMD.",
        "PLAINWEAVE_MCP_CMD is retired and is not read by the runtime.",
    )

    for text in rejected:
        with pytest.raises(AssertionError, match="active Plainweave runtime claims"):
            _assert_no_active_plainweave_runtime_claims(text)

    for text in accepted:
        _assert_no_active_plainweave_runtime_claims(text)


def test_current_docs_do_not_restore_plainweave_environment_runtime_config() -> None:
    current_docs = (*_CANONICAL_DISCOVERY_DOCS, _PLAINWEAVE_PDR)
    for path in current_docs:
        text = path.read_text(encoding="utf-8")

        assert "PLAINWEAVE_MCP_CMD" in text, path
        _assert_no_active_plainweave_runtime_claims(text)

    pdr = _PLAINWEAVE_PDR.read_text(encoding="utf-8")
    amendment, _context = pdr.split("## Context", maxsplit=1)
    normalized_amendment = _normalize(amendment)
    target = (
        "../../superpowers/specs/2026-07-12-plainweave-runtime-autodiscovery-design.md"
    )

    assert "2026-07-12 amendment" in normalized_amendment
    assert "current composition" in normalized_amendment
    assert "plainweavemcpcmd" in normalized_amendment
    assert "retired" in normalized_amendment
    assert "active-project runtime autodiscovery" in normalized_amendment
    assert f"]({target})" in amendment
    assert (_PLAINWEAVE_PDR.parent / target).resolve().is_file()

    recorded_call = pdr.split("## The call (recorded, not re-decided)", maxsplit=1)[
        1
    ].split("## Rationale", maxsplit=1)[0]
    assert "`runtime.plainweave` from `PLAINWEAVE_MCP_CMD`" in recorded_call


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
