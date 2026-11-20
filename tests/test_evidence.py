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
