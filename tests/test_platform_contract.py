from __future__ import annotations

import tomllib
from pathlib import Path


def test_package_and_docs_declare_posix_platform_contract() -> None:
    metadata = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    classifiers = metadata["project"]["classifiers"]
    readme = Path("README.md").read_text(encoding="utf-8")
    configuration = Path("docs/guide/configuration.md").read_text(encoding="utf-8")

    assert "Operating System :: POSIX" in classifiers
    assert "Operating System :: OS Independent" not in classifiers
    assert "Windows is not currently supported" in readme
    assert "POSIX-only safety boundary" in configuration
    assert "legis install --mcp" in configuration
