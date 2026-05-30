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


def test_detect_ai_agent_steps_finds_gemini_opencode_and_continue_actions() -> None:
    data = {
        "jobs": {
            "review": {
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

    assert [step_name for _, step_name, _ in steps] == [
        "Run Gemini review",
        "Run OpenCode",
        "Run Continue",
    ]
    assert [classify_agent(step["uses"]) for _, _, step in steps] == [
        "gemini_cli",
        "opencode",
        "continue",
    ]


def test_detect_ai_agent_steps_finds_copilot_named_run_step() -> None:
    data = {
        "jobs": {
            "review": {
                "steps": [
                    {
                        "name": "Run Copilot review",
                        "run": "echo '${{ github.event.pull_request.body }}'",
                    }
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


def test_gemini_agent_with_untrusted_input_and_write_token_is_critical() -> None:
    data = {
        "on": "pull_request",
        "permissions": {"contents": "write"},
        "jobs": {
            "review": {
                "steps": [
                    {
                        "name": "Run Gemini review",
                        "uses": "google-github-actions/run-gemini-cli@v1",
                        "with": {
                            "prompt": (
                                "Review ${{ github.event.pull_request.body }}"
                            )
                        },
                        "env": {
                            "GEMINI_API_KEY": "${{ secrets.GEMINI_API_KEY }}"
                        },
                    }
                ]
            }
        },
    }
    workflow_file = "ai.yml"
    perms = analyze_workflow_permissions(data, workflow_file)

    findings = analyze_ai_agent_injection_surface(data, workflow_file, [], perms)

    assert len(findings) == 1
    assert findings[0].agent_type == "gemini_cli"
    assert findings[0].has_api_key_secret is True
    assert findings[0].has_write_permissions is True
    assert findings[0].untrusted_inputs == ["github.event.pull_request.body"]
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
