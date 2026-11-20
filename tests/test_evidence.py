import json
from copy import deepcopy

import pytest
import yaml

from actionscope.evidence import AGENT, AWS, compare, snapshot

ROLE = "arn:aws:iam::123456789012:role/fixture"
CLAUDE = {"uses": f"{AGENT}@v1", "with": {"prompt": "private text"}}
SETUP = {"uses": f"{AWS}@v4", "with": {"role-to-assume": ROLE}}
FILE = ".github/workflows/review.yml"


def workflow(root, steps, **extra):
    path = root / FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    job = dict(steps=steps, **extra)
    path.write_text(
        yaml.safe_dump(
            {
                "on": "pull_request",
                "permissions": "write-all",
                "jobs": {"review": job, "delivery": {"steps": [deepcopy(SETUP)]}},
            }
        )
    )
    return path


def test_compare_prose_only_no_change(tmp_path):
    workflow(tmp_path, [CLAUDE])
    before = snapshot(tmp_path)
    workflow(tmp_path, [CLAUDE | {"with": {"prompt": "different"}}])
    facts = compare(before, snapshot(tmp_path))["agents"][0]["facts"]
    assert {f["status"] for f in facts} == {"unchanged"}


def test_only_preceding_setup_in_same_job(tmp_path):
    workflow(tmp_path, [CLAUDE, SETUP], permissions={})
    facts = next(iter(snapshot(tmp_path).values()))
    assert not any(f.category == "aws" for f in facts)
    assert any(f.value == "empty permission map" for f in facts)
    assert not any(f.value == "write-all" for f in facts)


def test_removed_agent_and_dynamic_role(tmp_path):
    workflow(
        tmp_path,
        [dict(SETUP) | {"with": {"role-to-assume": "${{ secrets.X }}"}}, CLAUDE],
    )
    job = compare(snapshot(tmp_path), {})["agents"][0]
    assert job["presence"] == "base only"
    assert all(f["status"] == "removed" for f in job["facts"])
    assert any(f["value"] == "unresolved" for f in job["facts"])


def test_conditions_and_args_compared_but_not_echoed(tmp_path):
    workflow(tmp_path, [CLAUDE])
    before = snapshot(tmp_path)
    workflow(
        tmp_path,
        [CLAUDE | {"if": "private-value", "with": {"claude_args": "private-args"}}],
    )
    result = compare(before, snapshot(tmp_path))
    assert "private-" not in json.dumps(result)
    assert {
        f["field"] for f in result["agents"][0]["facts"] if f["status"] == "added"
    } == {"step condition", "Claude CLI arguments"}


def test_swapping_credential_setups_changes_ordered_facts(tmp_path):
    second = SETUP | {"with": {"role-to-assume": ROLE + "-second"}}
    workflow(tmp_path, [SETUP, second, CLAUDE])
    before = snapshot(tmp_path)
    workflow(tmp_path, [second, SETUP, CLAUDE])
    facts = compare(before, snapshot(tmp_path))["agents"][0]["facts"]
    assert {(f["field"], f["value"]) for f in facts if f["status"] == "added"} == {
        ("preceding AWS credential setup #1", ROLE + "-second"),
        ("preceding AWS credential setup #2", ROLE),
    }


@pytest.mark.parametrize("bad", ["jobs: [", "a: &x {}\njobs: *x", "jobs: {}\njobs: {}"])
def test_ambiguous_input_refused(tmp_path, bad):
    workflow(tmp_path, [CLAUDE]).write_text(bad)
    with pytest.raises(ValueError):
        snapshot(tmp_path)


def test_auth_migration_has_both_citations_but_no_values(tmp_path):
    workflow(tmp_path, [CLAUDE | {"with": {"anthropic_api_key": "private-old"}}])
    before = snapshot(tmp_path)
    workflow(
        tmp_path,
        [
            CLAUDE
            | {
                "with": {
                    "anthropic_federation_rule_id": "private-new",
                    "anthropic_organization_id": "private-org",
                }
            }
        ],
    )
    result = compare(before, snapshot(tmp_path))
    assert "private-" not in json.dumps(result)
    facts = [
        f
        for f in result["agents"][0]["facts"]
        if f["field"] == "Claude authentication inputs"
    ]
    assert {
        (f["status"], (f["base_source"] or f["head_source"]).split("/")[-1])
        for f in facts
    } == {
        ("removed", "anthropic_api_key"),
        ("added", "anthropic_federation_rule_id"),
        ("added", "anthropic_organization_id"),
    }


@pytest.mark.parametrize("extension, readable", [("", True), (" || true", False)])
def test_only_exact_same_repository_guard_is_described(tmp_path, extension, readable):
    expr = "github.event.pull_request.head.repo.full_name == github.repository"
    workflow(tmp_path, [CLAUDE], **{"if": "${{ " + expr + extension + " }}"})
    facts = next(iter(snapshot(tmp_path).values()))
    guard = next(f for f in facts if f.field == "job condition")
    assert ("same repository" in guard.value) is readable
    assert "github.event" not in guard.value


@pytest.mark.parametrize(
    "activities,readable",
    [
        (["opened", "synchronize"], True),
        (["opened", "private-activity"], False),
    ],
)
def test_activity_filters_keep_other_filters_opaque(tmp_path, activities, readable):
    path = workflow(tmp_path, [CLAUDE])
    flow = yaml.safe_load(path.read_text())
    flow["on"] = {"pull_request": {"types": activities, "branches": ["private-branch"]}}
    path.write_text(yaml.safe_dump(flow))
    facts = next(iter(snapshot(tmp_path).values()))
    assert any(f.source.endswith("/pull_request/types") for f in facts) is readable
    assert any(f.field == "event filters" for f in facts)
    assert all("private-" not in f.value for f in facts)
