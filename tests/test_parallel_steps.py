"""Regression tests for parallel and background workflow steps (#154).

GitHub Actions lets a job run steps concurrently, either by marking a step
``background: true`` or by grouping steps under ``parallel:``. Grouped steps
are nested one level down, so every detector must expand the groups before
inspecting ``uses`` and ``run``.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Callable
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

from actionscope.analyzers.artifact_poisoning import executes_after_download
from actionscope.cli import main
from actionscope.parsers.steps import expand_steps, job_steps
from actionscope.parsers.workflow import GitHubWorkflowLoader
from actionscope.resolvers.pin_resolver import resolve_pins_for_workflow

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "coverage_repo"
FULL_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


def test_expand_steps_flattens_parallel_groups_in_order() -> None:
    checkout = {"uses": "actions/checkout@v4"}
    server = {"id": "app", "run": "npm start", "background": True}
    frontend = {"run": "npm run build:frontend"}
    backend = {"run": "npm run build:backend"}
    stop = {"name": "Stop app", "cancel": "app"}

    steps = [checkout, server, {"parallel": [frontend, backend]}, stop]

    assert expand_steps(steps) == [checkout, server, frontend, backend, stop]


def test_expand_steps_drops_malformed_entries() -> None:
    step = {"run": "make"}

    assert expand_steps(None) == []
    assert expand_steps("run: make") == []
    assert expand_steps(["make", None, step, {"parallel": ["make", step]}]) == [
        step,
        step,
    ]
    assert job_steps(None) == []
    assert job_steps({"steps": {"run": "make"}}) == []


def test_expand_steps_does_not_reenter_a_cyclic_group() -> None:
    steps = yaml.load(
        "steps: &steps\n  - run: make\n  - parallel: *steps\n",
        GitHubWorkflowLoader,
    )["steps"]

    assert expand_steps(steps) == [{"run": "make"}]


def test_cyclic_group_does_not_hide_other_workflows(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "cyclic.yml").write_text(
        "on: pull_request_target\n"
        "jobs:\n"
        "  loop:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: &steps\n"
        "      - parallel: *steps\n",
        encoding="utf-8",
    )
    (workflows / "deploy.yml").write_text(
        "on: pull_request_target\n"
        "permissions:\n"
        "  id-token: write\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@v4\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::123456789012:role/deploy\n"
        '      - run: echo "${{ github.event.pull_request.title }}"\n',
        encoding="utf-8",
    )

    report = _scan_json(tmp_path)

    assert report["summary"]["credential_sources"] == 1
    assert report["summary"]["script_injection_risks"] == 1
    assert not [error for error in report["errors"] if "Recursion" in error]


def _artifact_workflow(steps: list) -> dict:
    return {
        "on": {"workflow_run": {"workflows": ["build"]}},
        "jobs": {"publish": {"steps": steps}},
    }


DOWNLOAD = {"uses": "actions/download-artifact@v4"}
EXECUTE = {"run": "bash ./artifact/install.sh"}


@pytest.mark.parametrize(
    ("steps", "expected"),
    [
        ([{"parallel": [EXECUTE, DOWNLOAD]}], True),
        ([{**EXECUTE, "background": "true"}, DOWNLOAD], True),
        ([{**EXECUTE, "background": "false"}, DOWNLOAD], False),
        ([EXECUTE, DOWNLOAD], False),
        ([{"parallel": [EXECUTE]}, DOWNLOAD], False),
    ],
    ids=[
        "parallel-sibling",
        "background-before-download",
        "background-false",
        "sequential-before-download",
        "earlier-parallel-group",
    ],
)
def test_concurrent_execution_counts_as_after_download(
    steps: list, expected: bool
) -> None:
    workflow = _artifact_workflow(steps)

    assert executes_after_download(workflow) is expected


@pytest.mark.parametrize(
    "control",
    [
        {"wait": "installer"},
        {"wait": ["installer"]},
        {"cancel": "installer"},
        {"wait-all": None},
    ],
    ids=["wait", "wait-list", "cancel", "wait-all"],
)
def test_background_control_ends_execution_before_later_download(
    control: dict,
) -> None:
    workflow = _artifact_workflow(
        [{**EXECUTE, "id": "installer", "background": True}, control, DOWNLOAD]
    )

    assert executes_after_download(workflow) is False


def test_control_for_another_background_step_does_not_end_execution() -> None:
    workflow = _artifact_workflow(
        [
            {**EXECUTE, "id": "installer", "background": True},
            {"cancel": "monitor"},
            DOWNLOAD,
        ]
    )

    assert executes_after_download(workflow) is True


def test_wait_all_ends_unnamed_background_execution() -> None:
    workflow = _artifact_workflow(
        [{**EXECUTE, "background": True}, {"wait-all": None}, DOWNLOAD]
    )

    assert executes_after_download(workflow) is False


def _wrap_in_parallel_group(steps: list) -> list:
    return [{"parallel": steps}]


def _mark_background(steps: list) -> list:
    return [
        {**step, "background": True} if isinstance(step, dict) else step
        for step in steps
    ]


def _rewrite_workflows(repo: Path, transform: Callable[[list], list]) -> None:
    for workflow in sorted((repo / ".github" / "workflows").glob("*.y*ml")):
        data = yaml.load(workflow.read_text(encoding="utf-8"), GitHubWorkflowLoader)
        for job in (data.get("jobs") or {}).values():
            if isinstance(job, dict) and isinstance(job.get("steps"), list):
                job["steps"] = transform(job["steps"])
        workflow.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _scan_json(repo: Path) -> dict:
    result = CliRunner().invoke(
        main,
        ["scan", str(repo), "--output-format", "json", "--no-color", "--offline"],
    )
    assert result.exit_code == 0, result.output[:500]
    text = result.stdout.replace(str(repo.resolve()), "REPO").replace(
        str(repo), "REPO"
    )
    return json.loads(text)


@pytest.mark.parametrize(
    "transform",
    [_wrap_in_parallel_group, _mark_background],
    ids=["parallel-group", "background"],
)
def test_concurrent_steps_scan_like_sequential_steps(
    tmp_path: Path, transform: Callable[[list], list]
) -> None:
    sequential = tmp_path / "sequential" / "repo"
    concurrent = tmp_path / "concurrent" / "repo"
    shutil.copytree(FIXTURE, sequential)
    shutil.copytree(FIXTURE, concurrent)
    _rewrite_workflows(concurrent, transform)

    expected = _scan_json(sequential)
    actual = _scan_json(concurrent)

    summary = expected["summary"]
    for detector in (
        "credential_sources",
        "github_token_risks",
        "unpinned_actions",
        "exposure_paths",
        "script_injection_risks",
        "artifact_poisoning_risks",
        "ai_agent_injection_risks",
        "compromised_actions",
        "environment_issues",
    ):
        assert summary[detector] > 0, f"fixture no longer exercises {detector}"
    assert actual == expected


def test_pin_resolver_resolves_actions_inside_parallel_groups() -> None:
    workflow = {
        "jobs": {
            "build": {
                "steps": [
                    {
                        "parallel": [
                            {"uses": "actions/checkout@v4"},
                            {"uses": f"actions/setup-python@{FULL_SHA}"},
                        ]
                    }
                ]
            }
        }
    }
    payload = json.dumps({"object": {"type": "commit", "sha": FULL_SHA}}).encode()

    with patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = payload
        pins = resolve_pins_for_workflow(workflow, "ci.yml", delay_seconds=0)

    assert [pin.original_ref for pin in pins] == ["actions/checkout@v4"]
    assert pins[0].resolved_sha == FULL_SHA


def test_pin_resolver_skips_same_repository_lock_references() -> None:
    workflow = {
        "jobs": {
            "call": {"uses": "$/shared/.github/workflows/test.yml@main"},
            "build": {
                "steps": [
                    {"uses": "$/shared/action@main"},
                    {"uses": "actions/checkout@v4"},
                ]
            },
        }
    }
    payload = json.dumps({"object": {"type": "commit", "sha": FULL_SHA}}).encode()

    with patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = payload
        pins = resolve_pins_for_workflow(workflow, "ci.yml", delay_seconds=0)

    assert [pin.original_ref for pin in pins] == ["actions/checkout@v4"]
