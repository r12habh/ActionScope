"""Tests for AI agent prompt injection surface detection."""

from pathlib import Path

from actionscope.analyzers.ai_agent_injection import (
    analyze_ai_agent_injection_surface,
    classify_agent,
    detect_ai_agent_steps,
    find_untrusted_inputs_in_step,
    has_untrusted_trigger,
)
from actionscope.analyzers.github_token import analyze_workflow_permissions
from actionscope.models import AwsCredentialSource, GitHubTokenPermission, RiskLevel
from actionscope.parsers.workflow import parse_workflow_file

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "workflows"


def _fixture() -> dict:
    data = parse_workflow_file(str(FIXTURE_DIR / "ai_agent_test.yml"))
    assert data is not None
    return data


def _credential(workflow_file: str) -> AwsCredentialSource:
    return AwsCredentialSource(
        workflow_file=workflow_file,
        job_name="review",
        step_name="Configure AWS credentials",
        role_arn="arn:aws:iam::123456789012:role/ai-review-role",
        uses_access_keys=False,
        uses_oidc=True,
        aws_region="us-east-1",
    )


def _write_permission(
    workflow_file: str,
    job_name: str = "ai",
) -> GitHubTokenPermission:
    return GitHubTokenPermission(
        workflow_file=workflow_file,
        job_name=job_name,
        scope="contents",
        access="write",
        risk_level=RiskLevel.HIGH,
    )


def test_detect_ai_agent_steps_finds_claude_code_action() -> None:
    steps = detect_ai_agent_steps(_fixture())

    assert steps[0][1] == "Run Claude Code"


def test_detect_ai_agent_steps_finds_api_key_env_var() -> None:
    data = {
        "jobs": {
            "ai": {
                "steps": [
                    {
                        "name": "AI review",
                        "env": {"ANTHROPIC_API_KEY": "${{ secrets.KEY }}"},
                    }
                ]
            }
        }
    }

    assert detect_ai_agent_steps(data)


def test_has_untrusted_trigger_true_for_pull_request() -> None:
    assert has_untrusted_trigger({"on": "pull_request"})


def test_has_untrusted_trigger_true_for_pull_request_target() -> None:
    assert has_untrusted_trigger({"on": {"pull_request_target": {}}})


def test_has_untrusted_trigger_false_for_push_only() -> None:
    assert not has_untrusted_trigger({"on": "push"})


def test_find_untrusted_inputs_detects_pr_body_in_with_block() -> None:
    step = {"with": {"prompt": "${{ github.event.pull_request.body }}"}}

    assert find_untrusted_inputs_in_step(step) == ["github.event.pull_request.body"]


def test_find_untrusted_inputs_detects_pr_body_in_run_block() -> None:
    step = {"run": "echo ${{ github.event.pull_request.body }}"}

    assert find_untrusted_inputs_in_step(step) == ["github.event.pull_request.body"]


def test_classify_agent_returns_claude_code_for_anthropics_action() -> None:
    assert classify_agent("anthropics/claude-code-action@v1") == "claude_code"


def test_classify_agent_returns_expected_labels_for_supported_actions() -> None:
    assert classify_agent("google-github-actions/run-gemini-cli@v1") == "gemini_cli"
    assert classify_agent("opencode-ai/opencode@v1") == "opencode"
    assert classify_agent("continuedev/continue@v1") == "continue"


def test_detect_ai_agent_steps_finds_supported_action_patterns() -> None:
    data = {
        "jobs": {
            "ai": {
                "steps": [
                    {
                        "name": "Run Gemini",
                        "uses": "google-github-actions/run-gemini-cli@v1",
                    },
                    {"name": "Run OpenCode", "uses": "opencode-ai/opencode@v1"},
                    {"name": "Run Continue", "uses": "continuedev/continue@v1"},
                ]
            }
        }
    }

    steps = detect_ai_agent_steps(data)

    assert [step[1] for step in steps] == [
        "Run Gemini",
        "Run OpenCode",
        "Run Continue",
    ]


def test_pull_request_agent_with_write_token_and_untrusted_input_is_critical() -> None:
    workflow_file = "agent.yml"
    data = {
        "on": "pull_request",
        "jobs": {
            "ai": {
                "steps": [
                    {
                        "name": "Run Gemini",
                        "uses": "google-github-actions/run-gemini-cli@v1",
                        "with": {
                            "prompt": "Review ${{ github.event.pull_request.body }}",
                        },
                    }
                ]
            }
        },
    }

    findings = analyze_ai_agent_injection_surface(
        data,
        workflow_file,
        [],
        [_write_permission(workflow_file)],
    )

    assert findings[0].agent_type == "gemini_cli"
    assert findings[0].has_write_permissions is True
    assert findings[0].risk_level is RiskLevel.CRITICAL


def test_fixture_workflow_produces_critical_finding() -> None:
    workflow_file = str(FIXTURE_DIR / "ai_agent_test.yml")
    data = _fixture()
    perms = analyze_workflow_permissions(data, workflow_file)

    findings = analyze_ai_agent_injection_surface(
        data,
        workflow_file,
        [_credential(workflow_file)],
        perms,
    )

    assert findings[0].risk_level is RiskLevel.CRITICAL


def test_ai_agent_with_only_push_trigger_produces_low_finding() -> None:
    data = {
        "on": "push",
        "jobs": {
            "ai": {
                "steps": [
                    {"name": "Run Claude", "uses": "anthropics/claude-code-action@v1"}
                ]
            }
        },
    }

    findings = analyze_ai_agent_injection_surface(data, "ai.yml", [], [])

    assert findings[0].risk_level is RiskLevel.LOW


def test_missing_api_key_secret_reduces_risk_level() -> None:
    data = {
        "on": "pull_request",
        "permissions": {"contents": "read"},
        "jobs": {
            "ai": {
                "steps": [
                    {"name": "Run Claude", "uses": "anthropics/claude-code-action@v1"}
                ]
            }
        },
    }

    findings = analyze_ai_agent_injection_surface(data, "ai.yml", [], [])

    assert findings[0].risk_level is RiskLevel.LOW


def test_ai_agent_finding_has_non_empty_recommendation() -> None:
    workflow_file = str(FIXTURE_DIR / "ai_agent_test.yml")
    data = _fixture()
    perms = analyze_workflow_permissions(data, workflow_file)

    finding = analyze_ai_agent_injection_surface(
        data,
        workflow_file,
        [_credential(workflow_file)],
        perms,
    )[0]

    assert finding.recommendation


def test_cross_correlation_with_aws_credentials_detected() -> None:
    workflow_file = str(FIXTURE_DIR / "ai_agent_test.yml")
    data = _fixture()
    perms = analyze_workflow_permissions(data, workflow_file)

    finding = analyze_ai_agent_injection_surface(
        data,
        workflow_file,
        [_credential(workflow_file)],
        perms,
    )[0]

    assert finding.has_aws_secret_access is True


def test_detect_ai_agent_steps_finds_continue_by_step_name() -> None:
    data = {
        "jobs": {
            "ai": {
                "steps": [
                    {"name": "Run Continue review", "run": "continue review"}
                ]
            }
        }
    }

    assert detect_ai_agent_steps(data)
