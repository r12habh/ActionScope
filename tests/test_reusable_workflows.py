"""Tests for reusable workflow discovery and authenticated inspection."""

from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from actionscope.analyzers.reusable_workflows import (
    _fetch_external_workflow,
    scan_reusable_workflows,
)


class _RawResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> "_RawResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _size: int = -1) -> bytes:
        return self.payload


def _write_workflow(repo: Path, name: str, body: str) -> Path:
    workflow_dir = repo / ".github" / "workflows"
    workflow_dir.mkdir(parents=True, exist_ok=True)
    path = workflow_dir / name
    path.write_text(body, encoding="utf-8")
    return path


def _external_caller(repo: Path, ref: str = "v1") -> Path:
    return _write_workflow(
        repo,
        "caller.yml",
        f"""
name: Caller
on: push
jobs:
  deploy:
    uses: acme/platform/.github/workflows/deploy.yml@{ref}
""",
    )


def _external_deploy_workflow() -> dict:
    return {
        "on": "workflow_call",
        "permissions": {"id-token": "write"},
        "jobs": {
            "deploy": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "uses": "aws-actions/configure-aws-credentials@v4",
                        "with": {
                            "role-to-assume": (
                                "arn:aws:iam::123456789012:role/shared-deploy"
                            )
                        },
                    }
                ],
            }
        },
    }


def test_external_reusable_workflow_without_token_is_explicitly_uninspected(
    tmp_path: Path,
) -> None:
    _external_caller(tmp_path)

    result = scan_reusable_workflows(str(tmp_path))

    assert len(result.references) == 1
    assert result.references[0].status == "no_token"
    assert "--github-token" in str(result.references[0].error)
    assert result.errors == []


def test_external_tag_reference_is_reported_as_unpinned(tmp_path: Path) -> None:
    _external_caller(tmp_path, ref="v1")

    result = scan_reusable_workflows(str(tmp_path))

    assert len(result.unpinned_actions) == 1
    assert result.unpinned_actions[0].uses.endswith("@v1")
    assert result.unpinned_actions[0].pin_type == "tag"
    assert result.unpinned_actions[0].step_name == "Reusable workflow call"


def test_external_full_sha_reference_is_not_reported_as_unpinned(
    tmp_path: Path,
) -> None:
    _external_caller(tmp_path, ref="a" * 40)

    result = scan_reusable_workflows(str(tmp_path))

    assert result.references[0].pin_type == "sha"
    assert result.unpinned_actions == []


@patch(
    "actionscope.analyzers.reusable_workflows._fetch_external_workflow"
)
def test_external_workflow_is_fetched_and_analyzed_with_token(
    fetch_workflow,
    tmp_path: Path,
) -> None:
    _external_caller(tmp_path)
    fetch_workflow.return_value = (_external_deploy_workflow(), None)

    result = scan_reusable_workflows(str(tmp_path), github_token="token")

    assert result.references[0].status == "inspected"
    assert len(result.credential_sources) == 1
    assert result.credential_sources[0].role_arn == (
        "arn:aws:iam::123456789012:role/shared-deploy"
    )
    assert result.credential_sources[0].workflow_file == (
        "acme/platform/.github/workflows/deploy.yml@v1"
    )
    fetch_workflow.assert_called_once_with(
        "acme/platform",
        ".github/workflows/deploy.yml",
        "v1",
        "token",
    )


def test_local_reusable_workflow_is_scanned_when_caller_file_is_target(
    tmp_path: Path,
) -> None:
    caller = _write_workflow(
        tmp_path,
        "caller.yml",
        """
name: Caller
on: push
jobs:
  deploy:
    uses: ./.github/workflows/deploy.yml
""",
    )
    reusable = _write_workflow(
        tmp_path,
        "deploy.yml",
        """
name: Deploy
on: workflow_call
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/local-deploy
""",
    )

    result = scan_reusable_workflows(str(caller))

    assert result.references[0].status == "inspected"
    assert result.references[0].target_workflow == str(reusable.resolve())
    assert len(result.credential_sources) == 1
    assert result.credential_sources[0].workflow_file == str(reusable.resolve())


def test_local_reusable_workflows_are_not_double_analyzed_for_repo_scan(
    tmp_path: Path,
) -> None:
    _write_workflow(
        tmp_path,
        "caller.yml",
        """
on: push
jobs:
  deploy:
    uses: ./.github/workflows/deploy.yml
""",
    )
    _write_workflow(
        tmp_path,
        "deploy.yml",
        """
on: workflow_call
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
""",
    )

    result = scan_reusable_workflows(str(tmp_path))

    assert result.references[0].status == "inspected"
    assert result.credential_sources == []


def test_local_recursion_records_nested_calls(tmp_path: Path) -> None:
    caller = _write_workflow(
        tmp_path,
        "caller.yml",
        """
on: push
jobs:
  middle:
    uses: ./.github/workflows/middle.yml
""",
    )
    _write_workflow(
        tmp_path,
        "middle.yml",
        """
on: workflow_call
jobs:
  leaf:
    uses: ./.github/workflows/leaf.yml
""",
    )
    _write_workflow(
        tmp_path,
        "leaf.yml",
        """
on: workflow_call
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
""",
    )

    result = scan_reusable_workflows(str(caller))

    assert [reference.depth for reference in result.references] == [1, 2]
    assert all(
        reference.status == "inspected" for reference in result.references
    )


def test_depth_limit_counts_the_top_level_caller(tmp_path: Path) -> None:
    caller = _write_workflow(
        tmp_path,
        "level-0.yml",
        """
on: push
jobs:
  next:
    uses: ./.github/workflows/level-1.yml
""",
    )
    for level in range(1, 11):
        next_job = (
            f"jobs:\n  next:\n    uses: ./.github/workflows/level-{level + 1}.yml\n"
            if level < 10
            else "jobs: {}\n"
        )
        _write_workflow(
            tmp_path,
            f"level-{level}.yml",
            f"on: workflow_call\n{next_job}",
        )

    result = scan_reusable_workflows(str(caller))

    assert [reference.depth for reference in result.references] == list(
        range(1, 11)
    )
    assert [reference.status for reference in result.references[:-1]] == [
        "inspected"
    ] * 9
    assert result.references[-1].status == "depth_limit"
    assert "10 total levels" in str(result.references[-1].error)


def test_workflow_limit_stops_after_fifty_unique_targets(tmp_path: Path) -> None:
    jobs = "\n".join(
        f"  call-{index}:\n    uses: ./.github/workflows/called-{index}.yml"
        for index in range(51)
    )
    caller = _write_workflow(
        tmp_path,
        "caller.yml",
        f"on: push\njobs:\n{jobs}\n",
    )
    for index in range(51):
        _write_workflow(
            tmp_path,
            f"called-{index}.yml",
            "on: workflow_call\njobs: {}\n",
        )

    result = scan_reusable_workflows(str(caller))

    assert len(result.references) == 51
    assert [reference.status for reference in result.references[:50]] == [
        "inspected"
    ] * 50
    assert result.references[-1].status == "workflow_limit"
    assert "50-workflow limit" in str(result.references[-1].error)


def test_local_cycle_is_detected_without_infinite_recursion(tmp_path: Path) -> None:
    caller = _write_workflow(
        tmp_path,
        "caller.yml",
        """
on: push
jobs:
  deploy:
    uses: ./.github/workflows/deploy.yml
""",
    )
    _write_workflow(
        tmp_path,
        "deploy.yml",
        """
on: workflow_call
jobs:
  caller:
    uses: ./.github/workflows/caller.yml
""",
    )

    result = scan_reusable_workflows(str(caller))

    assert [reference.status for reference in result.references] == [
        "inspected",
        "cycle",
    ]


@patch(
    "actionscope.analyzers.reusable_workflows._fetch_external_workflow"
)
def test_external_workflow_fetches_each_unique_target_once(
    fetch_workflow,
    tmp_path: Path,
) -> None:
    _external_caller(tmp_path)
    nested = {
        "on": "workflow_call",
        "jobs": {
            "one": {
                "uses": "acme/platform/.github/workflows/leaf.yml@v1"
            },
            "two": {
                "uses": "acme/platform/.github/workflows/leaf.yml@v1"
            },
        },
    }
    leaf = {
        "on": "workflow_call",
        "jobs": {"test": {"runs-on": "ubuntu-latest", "steps": []}},
    }
    fetch_workflow.side_effect = [(nested, None), (leaf, None)]

    result = scan_reusable_workflows(str(tmp_path), github_token="token")

    assert fetch_workflow.call_count == 2
    assert len(result.references) == 3
    assert all(reference.status == "inspected" for reference in result.references)


@patch(
    "actionscope.analyzers.reusable_workflows._fetch_external_workflow"
)
def test_shared_external_workflow_retains_each_root_caller(
    fetch_workflow,
    tmp_path: Path,
) -> None:
    for name in ("caller-a.yml", "caller-b.yml"):
        _write_workflow(
            tmp_path,
            name,
            """
on: push
jobs:
  deploy:
    uses: acme/platform/.github/workflows/deploy.yml@v1
""",
        )
    fetch_workflow.return_value = (
        {
            "on": "workflow_call",
            "jobs": {
                "review": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "run": (
                                "echo '${{ github.event.pull_request.title }}'"
                            )
                        }
                    ],
                }
            },
        },
        None,
    )

    result = scan_reusable_workflows(str(tmp_path), github_token="token")

    fetch_workflow.assert_called_once()
    root_names = {
        Path(reference.root_workflow or "").name
        for reference in result.references
    }
    assert root_names == {
        "caller-a.yml",
        "caller-b.yml",
    }
    assert len(result.script_injection_findings) == 1


@patch(
    "actionscope.analyzers.reusable_workflows._fetch_external_workflow"
)
def test_fetch_error_is_reported_without_crashing(
    fetch_workflow,
    tmp_path: Path,
) -> None:
    _external_caller(tmp_path)
    fetch_workflow.return_value = (None, "not found")

    result = scan_reusable_workflows(str(tmp_path), github_token="token")

    assert result.references[0].status == "fetch_error"
    assert result.references[0].error == "not found"
    assert "Could not inspect reusable workflow" in result.errors[0]


@patch(
    "actionscope.analyzers.reusable_workflows._fetch_external_workflow"
)
def test_dynamic_external_reference_is_not_fetched(
    fetch_workflow,
    tmp_path: Path,
) -> None:
    _external_caller(tmp_path, ref="${{ inputs.ref }}")

    result = scan_reusable_workflows(str(tmp_path), github_token="token")

    assert result.references[0].status == "invalid_reference"
    assert "dynamic" in str(result.references[0].error)
    fetch_workflow.assert_not_called()


@patch(
    "actionscope.analyzers.reusable_workflows._fetch_external_workflow"
)
def test_external_reference_rejects_path_traversal(
    fetch_workflow,
    tmp_path: Path,
) -> None:
    _write_workflow(
        tmp_path,
        "caller.yml",
        """
on: push
jobs:
  deploy:
    uses: acme/platform/.github/workflows/../../private.yml@v1
""",
    )

    result = scan_reusable_workflows(str(tmp_path), github_token="token")

    assert result.references[0].status == "invalid_reference"
    assert "must use owner/repo" in str(result.references[0].error)
    fetch_workflow.assert_not_called()


def test_local_reference_rejects_workflow_directory_traversal(
    tmp_path: Path,
) -> None:
    caller = _write_workflow(
        tmp_path,
        "caller.yml",
        """
on: push
jobs:
  deploy:
    uses: ./.github/workflows/../../private.yml
""",
    )
    (tmp_path / "private.yml").write_text(
        "on: workflow_call\njobs: {}\n",
        encoding="utf-8",
    )

    result = scan_reusable_workflows(str(caller))

    assert result.references[0].status == "invalid_reference"
    assert "directly under .github/workflows" in str(
        result.references[0].error
    )


@patch(
    "actionscope.analyzers.reusable_workflows._fetch_external_workflow"
)
def test_compromised_action_inside_external_workflow_is_detected(
    fetch_workflow,
    tmp_path: Path,
) -> None:
    _external_caller(tmp_path)
    fetch_workflow.return_value = (
        {
            "on": "workflow_call",
            "jobs": {
                "triage": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "actions-cool/issues-helper@v3"}
                    ],
                }
            },
        },
        None,
    )

    result = scan_reusable_workflows(str(tmp_path), github_token="token")

    assert len(result.compromised_action_findings) == 1
    assert result.compromised_action_findings[0].uses_ref == (
        "actions-cool/issues-helper@v3"
    )


@patch(
    "actionscope.analyzers.reusable_workflows._fetch_external_workflow"
)
def test_script_injection_inside_external_workflow_is_detected(
    fetch_workflow,
    tmp_path: Path,
) -> None:
    _external_caller(tmp_path)
    fetch_workflow.return_value = (
        {
            "on": "workflow_call",
            "jobs": {
                "review": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "run": (
                                "echo '${{ github.event.pull_request.title }}'"
                            )
                        }
                    ],
                }
            },
        },
        None,
    )

    result = scan_reusable_workflows(str(tmp_path), github_token="token")

    assert len(result.script_injection_findings) == 1
    assert result.script_injection_findings[0].workflow_file.endswith(
        "deploy.yml@v1"
    )


@patch("actionscope.analyzers.reusable_workflows.urlopen")
def test_external_fetch_uses_authenticated_github_contents_api(
    open_url,
) -> None:
    open_url.return_value = _RawResponse(
        b"on: workflow_call\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
    )

    data, error = _fetch_external_workflow(
        "acme/platform",
        ".github/workflows/deploy.yml",
        "v1",
        "secret-token",
    )

    assert error is None
    assert isinstance(data, dict)
    request = open_url.call_args.args[0]
    assert request.full_url == (
        "https://api.github.com/repos/acme/platform/contents/"
        ".github/workflows/deploy.yml?ref=v1"
    )
    assert request.headers["Authorization"] == "Bearer secret-token"


@patch("actionscope.analyzers.reusable_workflows.urlopen")
def test_external_fetch_returns_clear_not_found_error(open_url) -> None:
    open_url.side_effect = HTTPError("url", 404, "not found", {}, None)

    data, error = _fetch_external_workflow(
        "acme/platform",
        ".github/workflows/missing.yml",
        "v1",
        "token",
    )

    assert data is None
    assert error == "not found or token cannot access the repository"
