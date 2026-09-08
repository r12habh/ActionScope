from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from actionscope import __version__
from scripts.pre_release_check import validate_citation_metadata

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "filename",
    [
        "CITATION.cff",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "GOVERNANCE.md",
        "SECURITY.md",
        "SUPPORT.md",
    ],
)
def test_community_health_file_exists(filename: str) -> None:
    assert (ROOT / filename).is_file()


def test_citation_metadata_matches_package() -> None:
    citation = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))

    assert citation["cff-version"] == "1.2.0"
    assert str(citation["version"]) == __version__
    assert citation["repository-code"] == "https://github.com/r12habh/ActionScope"
    assert citation["license"] == "MIT"
    assert citation["authors"]


def test_readme_links_community_files() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for filename in (
        "CITATION.cff",
        "CODE_OF_CONDUCT.md",
        "GOVERNANCE.md",
        "SUPPORT.md",
    ):
        assert f"]({filename})" in readme


@pytest.mark.parametrize("content", ["", "not-a-mapping\n"])
def test_release_check_rejects_non_mapping_citation(content: str, tmp_path) -> None:
    citation_path = tmp_path / "CITATION.cff"
    citation_path.write_text(content, encoding="utf-8")

    valid, detail = validate_citation_metadata(citation_path, __version__)

    assert valid is False
    assert "YAML mapping" in detail
