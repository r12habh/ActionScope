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
from actionscope.models import AwsCredentialSource, RiskLevel
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


def test_detect_ai_agent_steps_finds_supported_agent_actions() -> None:
    data = {
        "jobs": {
            "ai": {
                "steps": [
                    {
                        "name": "Run Gemini review",
                        "uses": "google-github-actions/run-gemini-cli@v1",
                    },
                    {"name": "Run OpenCode", "uses": "opencode/run@v1"},
                    {"name": "Run Continue", "uses": "continue-dev/continue@v1"},
                ]
            }
        }
    }

    steps = detect_ai_agent_steps(data)

    assert [step[1] for step in steps] == [
        "Run Gemini review",
        "Run OpenCode",
        "Run Continue",
    ]


def test_classify_agent_returns_expected_supported_agent_types() -> None:
    assert classify_agent("google-github-actions/run-gemini-cli@v1") == "gemini_cli"
    assert classify_agent("opencode/run@v1") == "opencode"
    assert classify_agent("continue-dev/continue@v1") == "continue"


def test_untrusted_ai_agent_action_with_write_permissions_is_critical() -> None:
    workflow_file = "ai-agent-review.yml"
    data = {
        "on": "pull_request",
        "permissions": {"contents": "write", "pull-requests": "write"},
        "jobs": {
            "ai": {
                "steps": [
                    {
                        "name": "Run Gemini review",
                        "uses": "google-github-actions/run-gemini-cli@v1",
                        "with": {
                            "prompt": "Review ${{ github.event.pull_request.body }}"
                        },
                    }
                ]
            }
        },
    }
    perms = analyze_workflow_permissions(data, workflow_file)

    finding = analyze_ai_agent_injection_surface(data, workflow_file, [], perms)[0]

    assert finding.agent_type == "gemini_cli"
    assert finding.untrusted_inputs == ["github.event.pull_request.body"]
    assert finding.has_write_permissions is True
    assert finding.risk_level is RiskLevel.CRITICAL


def test_copilot_fuzzy_step_name_with_run_block_is_detected() -> None:
    data = {
        "jobs": {
            "ai": {
                "steps": [
                    {"name": "Run Copilot review", "run": "echo review"}
                ]
            }
        }
    }

    steps = detect_ai_agent_steps(data)

    assert steps[0][1] == "Run Copilot review"
    assert classify_agent(steps[0][1]) == "copilot_agent"


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
