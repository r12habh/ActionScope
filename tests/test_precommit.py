"""Offline pinning gate and pre-commit manifest regressions."""

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

from actionscope.hooks import main

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("suffix", ["yml", "yaml"])
@pytest.mark.parametrize("ref", ["v4", "main", "abc123f"])
def test_gate_rejects_mutable_refs(tmp_path: Path, suffix: str, ref: str) -> None:
    workflow = tmp_path / ".github" / "workflows" / f"ci.{suffix}"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        f"    steps:\n      - uses: actions/checkout@{ref}\n"
    )
    with patch("urllib.request.urlopen", side_effect=AssertionError("network call")):
        result = CliRunner().invoke(main, [str(tmp_path)])
    assert result.exit_code == 1
    assert f"actions/checkout@{ref}" in result.output


def test_gate_accepts_sha_and_local_actions(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - uses: actions/checkout@{'a' * 40}\n"
        "      - uses: ./.github/actions/build\n"
        "      - uses: $/actions/build\n"
    )
    assert CliRunner().invoke(main, [str(tmp_path)]).exit_code == 0


def test_gate_catches_reusable_workflow(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: push\njobs:\n  call:\n"
        "    uses: owner/repo/.github/workflows/test.yml@main\n"
    )
    assert CliRunner().invoke(main, [str(tmp_path)]).exit_code == 1


def test_invalid_yaml_is_not_a_successful_check(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("jobs: [not closed")
    assert CliRunner().invoke(main, [str(tmp_path)]).exit_code == 2


def test_hook_metadata_scans_once_and_uses_offline_default() -> None:
    hooks = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text())
    assert {h["id"] for h in hooks} == {"actionscope", "actionscope-pins"}
    assert all(h["pass_filenames"] is False and h["require_serial"] for h in hooks)
    assert "--offline --fail-on critical" in hooks[0]["entry"]
    assert hooks[1]["entry"] == "actionscope-check-pins"


def test_gate_on_coverage_fixture() -> None:
    result = CliRunner().invoke(main, [str(ROOT / "tests/fixtures/coverage_repo")])
    assert result.exit_code == 1
    assert "unpinned" in result.output
