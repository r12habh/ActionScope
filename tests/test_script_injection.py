"""Tests for GitHub Actions script injection detection."""

from pathlib import Path
from shutil import copyfile

from actionscope.analyzers.script_injection import (
    analyze_step_for_injection,
    find_untrusted_expressions_in_text,
    is_run_step,
    is_via_env,
    scan_workflow_for_injections,
    scan_workflows_for_injection,
)
from actionscope.models import RiskLevel
from actionscope.parsers.workflow import parse_workflow_file

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "workflows"


def _parse_fixture(name: str) -> dict:
    data = parse_workflow_file(str(FIXTURE_DIR / name))
    assert data is not None
    return data


def _repo_with_workflow(tmp_path: Path, fixture_name: str) -> Path:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    copyfile(FIXTURE_DIR / fixture_name, workflow_dir / fixture_name)
    return tmp_path


def test_find_untrusted_expressions_finds_pr_title() -> None:
    expressions = find_untrusted_expressions_in_text(
        'echo "${{ github.event.pull_request.title }}"'
    )

    assert expressions == ["${{ github.event.pull_request.title }}"]


def test_find_untrusted_expressions_returns_empty_for_safe_content() -> None:
    assert find_untrusted_expressions_in_text('echo "$PR_TITLE"') == []


def test_is_via_env_returns_true_for_env_pattern() -> None:
    step = {
        "env": {"PR_TITLE": "${{ github.event.pull_request.title }}"},
        "run": 'echo "$PR_TITLE"',
    }

    assert is_via_env(step, "${{ github.event.pull_request.title }}") is True


def test_is_via_env_returns_false_for_direct_injection() -> None:
    step = {"run": 'echo "${{ github.event.pull_request.title }}"'}

    assert is_via_env(step, "${{ github.event.pull_request.title }}") is False


def test_direct_injection_in_pr_target_is_critical() -> None:
    data = _parse_fixture("injection_test.yml")

    findings = scan_workflow_for_injections(data, "injection_test.yml")

    assert any(f.risk_level is RiskLevel.CRITICAL for f in findings)


def test_safe_env_var_pattern_produces_no_finding() -> None:
    step = {
        "env": {"PR_TITLE": "${{ github.event.pull_request.title }}"},
        "run": 'echo "$PR_TITLE"',
    }

    assert analyze_step_for_injection(step, "test", "ci.yml", "pull_request") == []


def test_github_head_ref_detected_as_untrusted() -> None:
    assert find_untrusted_expressions_in_text("${{ github.head_ref }}")


def test_github_event_issue_body_detected_as_untrusted() -> None:
    assert find_untrusted_expressions_in_text("${{ github.event.issue.body }}")


def test_github_event_comment_body_detected_as_untrusted() -> None:
    assert find_untrusted_expressions_in_text("${{ github.event.comment.body }}")


def test_github_event_discussion_body_detected_as_untrusted() -> None:
    assert find_untrusted_expressions_in_text("${{ github.event.discussion.body }}")


def test_issue_comment_body_direct_run_usage_produces_finding() -> None:
    data = {
        "on": "issue_comment",
        "jobs": {
            "reply": {
                "steps": [
                    {
                        "name": "echo comment",
                        "run": "echo ${{ github.event.comment.body }}",
                    }
                ]
            }
        },
    }

    findings = scan_workflow_for_injections(data, "issue-comment.yml")

    assert len(findings) == 1
    assert findings[0].untrusted_expression == "${{ github.event.comment.body }}"
    assert findings[0].injection_method == "direct"
    assert findings[0].risk_level is not RiskLevel.INFO


def test_discussion_body_direct_run_usage_produces_finding() -> None:
    data = {
        "on": "discussion",
        "jobs": {
            "triage": {
                "steps": [
                    {
                        "name": "echo discussion",
                        "run": "echo ${{ github.event.discussion.body }}",
                    }
                ]
            }
        },
    }

    findings = scan_workflow_for_injections(data, "discussion.yml")

    assert len(findings) == 1
    assert findings[0].untrusted_expression == "${{ github.event.discussion.body }}"
    assert findings[0].injection_method == "direct"
    assert findings[0].risk_level is not RiskLevel.INFO


def test_multiple_injections_in_one_step_produce_multiple_findings() -> None:
    step = {
        "run": (
            "echo ${{ github.event.pull_request.title }} "
            "${{ github.event.issue.body }}"
        )
    }

    findings = analyze_step_for_injection(step, "test", "ci.yml")

    assert len(findings) == 2


def test_scan_workflows_for_injection_finds_fixture(tmp_path: Path) -> None:
    repo = _repo_with_workflow(tmp_path, "injection_test.yml")

    findings, errors = scan_workflows_for_injection(str(repo))

    assert errors == []
    assert len(findings) == 2


def test_push_trigger_head_commit_is_high_not_critical() -> None:
    data = {
        "on": "push",
        "jobs": {
            "test": {
                "steps": [
                    {"run": "echo ${{ github.event.head_commit.message }}"}
                ]
            }
        },
    }

    findings = scan_workflow_for_injections(data, "push.yml")

    assert findings[0].risk_level is RiskLevel.HIGH


def test_step_with_no_run_key_produces_no_finding() -> None:
    assert (
        analyze_step_for_injection(
            {"uses": "actions/checkout@v4"},
            "test",
            "ci.yml",
        )
        == []
    )


def test_pull_request_body_detected_correctly() -> None:
    assert find_untrusted_expressions_in_text("${{ github.event.pull_request.body }}")


def test_finding_has_non_empty_recommendation() -> None:
    findings = analyze_step_for_injection(
        {"run": "echo ${{ github.event.pull_request.title }}"},
        "test",
        "ci.yml",
    )

    assert findings[0].recommendation


def test_injection_method_is_direct_for_direct_injection() -> None:
    findings = analyze_step_for_injection(
        {"run": "echo ${{ github.event.pull_request.title }}"},
        "test",
        "ci.yml",
    )

    assert findings[0].injection_method == "direct"


def test_is_run_step_detects_run_steps() -> None:
    assert is_run_step({"run": "echo hi"})
