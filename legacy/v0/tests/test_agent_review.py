import json
import os
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from actionscope.agent_review import AGENT, AWS, compare, snapshot
from actionscope.cli import main

DEMO = Path(__file__).resolve().parents[1] / "examples" / "agent-review"
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


def review(base, head, *args):
    return CliRunner().invoke(
        main,
        [
            "agent-review",
            "--base",
            str(base),
            "--head",
            str(head),
            "--format",
            "json",
            *args,
        ],
    )


def test_demo_without_ai_preserves_known_and_unknown():
    result = review(DEMO / "base", DEMO / "head")
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["review_questions"] == []
    facts = data["agents"][0]["facts"]
    assert any(
        f["field"] == "GITHUB_TOKEN id-token"
        and f["status"] == "added"
        and f["head_source"].endswith("/jobs/review/permissions/id-token")
        for f in facts
    )
    assert any(f["value"].endswith(": unknown") for f in facts)
    assert "REVIEW_API_KEY" not in result.output


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


def test_report_join_uses_absolute_workflow_and_exact_role(tmp_path):
    workflow(tmp_path, [SETUP, CLAUDE])
    binding = {
        "workflow_file": str(tmp_path / FILE),
        "job_name": "review",
        "role_arn": ROLE,
        "actions": [{"action": "bedrock:InvokeModel"}],
    }
    path = tmp_path / "scan.json"
    path.write_text(
        json.dumps(
            {
                "scan_path": str(tmp_path),
                "findings": [
                    binding,
                    binding
                    | {"role_arn": ROLE + "x", "actions": [{"action": "iam:*"}]},
                ],
            }
        )
    )
    result = review(
        tmp_path, tmp_path, "--base-report", str(path), "--head-report", str(path)
    )
    assert result.exit_code == 0
    assert "bedrock:InvokeModel" in result.output and "iam:*" not in result.output
    assert "report#/findings/0/actions/0" in result.output
    path.write_text(json.dumps({"scan_path": "/", "findings": []}))
    assert (
        review(
            tmp_path, tmp_path, "--base-report", str(path), "--head-report", str(path)
        ).exit_code
        != 0
    )


def test_ambiguous_policy_is_unknown(tmp_path):
    workflow(tmp_path, [SETUP, CLAUDE])
    binding = {
        "workflow_file": FILE,
        "job_name": "review",
        "role_arn": ROLE,
        "actions": [{"action": "s3:*"}],
    }
    facts = next(iter(snapshot(tmp_path, {"findings": [binding, binding]}).values()))
    assert not any("s3:*" in f.value for f in facts)
    assert any("unknown" in f.value for f in facts)


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


def test_changed_notaction_exclusion_is_not_unchanged(tmp_path):
    workflow(tmp_path, [SETUP, CLAUDE])

    def report(excluded):
        return {
            "findings": [
                {
                    "workflow_file": FILE,
                    "job_name": "review",
                    "role_arn": ROLE,
                    "actions": [
                        {"action": "*", "resource": "*", "excluded_actions": [excluded]}
                    ],
                }
            ]
        }

    result = compare(
        snapshot(tmp_path, report("iam:*")), snapshot(tmp_path, report("s3:*"))
    )
    facts = result["agents"][0]["facts"]
    assert any(f["status"] == "added" and "except s3:*" in f["value"] for f in facts)
    assert any(f["status"] == "removed" and "except iam:*" in f["value"] for f in facts)


def test_empty_does_not_load_model(tmp_path):
    assert review(tmp_path, tmp_path, "--intent", "classify this").exit_code == 0


@pytest.mark.parametrize(
    "bad", ["jobs: [", "bad: &A [ok]\njobs: *A", "jobs: {}\njobs: {}"]
)
def test_bad_yaml_fails_instead_of_showing_removal(tmp_path, bad):
    path = workflow(tmp_path, [CLAUDE])
    path.write_text(bad)
    assert review(DEMO / "head", tmp_path).exit_code != 0


def test_no_symlink_following(tmp_path):
    (tmp_path / ".github").symlink_to(DEMO / "head" / ".github")
    assert review(tmp_path, DEMO / "head").exit_code != 0


def test_exact_iam_query_abstains_without_model(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps({"findings": [{"actions": [{"action": "ec2:DescribeInstances"}]}]})
    )
    run = CliRunner().invoke(main, ["explain", str(path), "ec2:TerminateInstances?"])
    assert run.exit_code == 0 and "Access is unknown" in run.output


def test_model_only_ranks_cited_checks(monkeypatch):
    from actionscope import agent_review as ar

    monkeypatch.setattr(ar, "load_encoder", lambda download: object())
    monkeypatch.setattr(ar, "rank_rows", lambda q, rows, encoder, limit: rows[::-1])
    plain = json.loads(review(DEMO / "base", DEMO / "head").output)
    ai = json.loads(review(DEMO / "base", DEMO / "head", "--intent", "Bedrock").output)
    assert plain["agents"] == ai["agents"]
    assert ai["review_questions"]
    for q in ai["review_questions"]:
        _, _, i, _, j = q["evidence"].split("/")
        assert ai["agents"][int(i)]["facts"][int(j)]["status"] == "added"


@pytest.mark.skipif(
    os.environ.get("ACTIONSCOPE_TEST_LOCAL_MODEL") != "1",
    reason="Opt in with cached weights and the ai extra",
)
@pytest.mark.parametrize(
    ("question", "expected_field"),
    [
        ("Why request an OIDC token?", "GITHUB_TOKEN id-token"),
        ("Is scope limited? I need the role policy evidence", "role policy evidence"),
    ],
)
def test_real_model_selects_relevant_evidence(question, expected_field):
    run = review(DEMO / "base", DEMO / "head", "--intent", question)
    assert run.exit_code == 0, run.output
    data = json.loads(run.output)
    _, _, i, _, j = data["review_questions"][0]["evidence"].split("/")
    assert data["agents"][int(i)]["facts"][int(j)]["field"] == expected_field
