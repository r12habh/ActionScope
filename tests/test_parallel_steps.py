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
