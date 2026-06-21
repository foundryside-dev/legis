import re
from pathlib import Path


def test_site_kit_fetch_is_pinned_to_reviewed_weft_commit():
    script = Path("site/scripts/fetch-site-kit.mjs").read_text(encoding="utf-8")

    match = re.search(
        r"const WEFT_SITE_KIT_COMMIT = '([0-9a-f]{40})';",
        script,
    )
    assert match, "fetch-site-kit must pin @weft/site-kit to a reviewed commit"
    assert "fetch', '--depth', '1', 'origin', WEFT_SITE_KIT_COMMIT" in script
    assert "checkout', '--detach', 'FETCH_HEAD" in script
    assert "rev-parse', 'HEAD" in script
    assert "actualCommit !== WEFT_SITE_KIT_COMMIT" in script


def test_pages_workflow_fetches_site_kit_before_install():
    workflow = Path(".github/workflows/deploy-site.yml").read_text(encoding="utf-8")

    assert "npm run fetch-site-kit" in workflow
    assert "npm install --no-audit --no-fund" in workflow
