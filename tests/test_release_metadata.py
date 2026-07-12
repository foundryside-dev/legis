from __future__ import annotations

import re
import tomllib
from pathlib import Path

from legis import __version__


def test_public_release_metadata_matches_package_version() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    readme = Path("README.md").read_text(encoding="utf-8")
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    project_version = project["project"]["version"]
    release_line = ".".join(project_version.split(".")[:2]) + ".x"
    released_headings = re.findall(r"^## \[([^]]+)]", changelog, flags=re.MULTILINE)

    assert project_version == __version__
    assert released_headings[0] == "Unreleased"
    assert released_headings[1] == project_version
    assert f"Legis is at **`{project_version}`**" in readme
    assert f"The {release_line} line" in readme
    assert "last week" not in readme.lower()
    assert (
        f"[Unreleased]: https://github.com/foundryside-dev/legis/compare/v{project_version}...HEAD"
        in changelog
    )
    release_links = {
        version: (base, target)
        for version, base, target in re.findall(
            r"^\[(\d+\.\d+\.\d+)]: .*?/compare/"
            r"v(\d+\.\d+\.\d+)\.\.\.v(\d+\.\d+\.\d+)$",
            changelog,
            flags=re.MULTILINE,
        )
    }
    current = tuple(int(part) for part in project_version.split("."))
    previous = max(
        [
            version
            for version in release_links
            if tuple(int(part) for part in version.split(".")) < current
        ],
        key=lambda version: tuple(int(part) for part in version.split(".")),
    )
    assert release_links[project_version] == (previous, project_version)
