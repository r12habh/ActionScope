import os
import shutil
import subprocess

import pytest
from click.testing import CliRunner

from actionscope.cli import main
from actionscope.review import _changes, _demo, git_diff


def git(path, *args):
    subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)


def test_real_git_diff_from_subdirectory(tmp_path):
    from pathlib import Path

    demo = Path(__file__).resolve().parents[1] / "examples/agent-review"
    shutil.copytree(demo / "base", tmp_path, dirs_exist_ok=True)
    git(tmp_path, "init")
    git(tmp_path, "add", ".github")
    git(
        tmp_path,
        "-c",
        "user.name=Example",
        "-c",
        "user.email=test@example.org",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-m",
        "base",
    )
    shutil.copytree(demo / "head", tmp_path, dirs_exist_ok=True)
    path = tmp_path / ".github/workflows/review.yml"
    path.rename(path.with_name("untracked.yml"))
    data, _ = git_diff(path.parent, "HEAD")
    assert {a["presence"] for a in data["agents"]} == {"base only", "head only"}
    assert not path.exists()


def test_no_claim_or_download_for_absent_permission():
    result = CliRunner().invoke(
        main, ["review", "--demo", "Can it use iam:CreateUser?"]
    )
    assert result.exit_code == 0
    assert "Effective access is unknown" in result.output


def test_removed_fields_retained_and_changes_grouped():
    rows, sources = _changes(_demo())
    row = next(r for r in rows if r.check == "use_bedrock")
    assert {f["status"] for f in sources[row.pointer]} == {"added", "removed"}
    assert any(r.check == "anthropic_api_key" for r in rows)


def test_symlinked_base_refused_even_if_head_is_empty(tmp_path):
    git(tmp_path, "init")
    (tmp_path / ".github").symlink_to("external")
    git(tmp_path, "add", ".github")
    git(
        tmp_path,
        "-c",
        "user.name=Example",
        "-c",
        "user.email=test@example.org",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-m",
        "symlink",
    )
    (tmp_path / ".github").unlink()
    with pytest.raises(ValueError, match="not a Git tree"):
        git_diff(tmp_path, "HEAD")


def test_missing_revision_has_actionable_cli_error(tmp_path):
    git(tmp_path, "init")
    run = CliRunner().invoke(main, ["review", "--repo", str(tmp_path)])
    assert run.exit_code != 0
    assert "--base-ref" in run.output and "Traceback" not in run.output


@pytest.mark.skipif(
    os.environ.get("ACTIONSCOPE_TEST_LOCAL_MODEL") != "1",
    reason="Requires cached AI model",
)
def test_real_model_retrieves_removed_api_key():
    result = CliRunner().invoke(
        main, ["review", "--demo", "--limit", "1", "Was the Anthropic API key removed?"]
    )
    assert result.exit_code == 0, result.output
    assert "anthropic_api_key" in result.output and "removed:" in result.output
    assert "[base:" in result.output
