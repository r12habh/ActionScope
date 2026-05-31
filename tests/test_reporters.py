"""Tests for JSON and Markdown reporters."""

import json
from pathlib import Path

from actionscope.models import (
    AwsCredentialSource,
    EnvironmentFinding,
    GitHubTokenPermission,
    IamAction,
    PolicyFinding,
    RiskLevel,
    ScanResult,
    WorkflowCredentialBinding,
)
from actionscope.reporters.json_reporter import to_json, write_json
from actionscope.reporters.markdown import to_markdown, to_markdown_from_dict


def _sample_binding() -> WorkflowCredentialBinding:
    credential = AwsCredentialSource(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        step_name="Configure AWS credentials",
        role_arn="arn:aws:iam::123456789012:role/ci-deploy",
        uses_access_keys=False,
        uses_oidc=True,
        aws_region="us-east-1",
    )
    policy = PolicyFinding(
        source_file="terraform/role.tf",
        source_type="terraform",
        role_arn="arn:aws:iam::123456789012:role/ci-deploy",
        actions=[
            IamAction(
                "iam:PassRole",
                "Permissions management",
                RiskLevel.CRITICAL,
                "Can pass roles to AWS services",
                "*",
            ),
            IamAction(
                "ec2:TerminateInstances",
                "Write",
                RiskLevel.HIGH,
                "Terminate instances",
                "*",
            ),
            IamAction(
                "s3:GetObject",
                "Read",
                RiskLevel.LOW,
                "Read object",
                "arn:aws:s3:::bucket/*",
            ),
        ],
        has_passrole=True,
        has_privilege_escalation=True,
        overall_risk=RiskLevel.CRITICAL,
    )
    return WorkflowCredentialBinding(
        credential_source=credential,
        policy_finding=policy,
        policy_source="terraform",
        match_confidence="high",
        match_reason="exact role ARN match",
    )


def test_to_json_is_valid_json() -> None:
    binding = _sample_binding()
    pf = binding.policy_finding
    assert pf is not None
    result = ScanResult(
        scan_path="/repo",
        workflow_count=1,
        credential_sources=[binding.credential_source],
        policy_findings=[pf],
        bindings=[binding],
    )
    result.overall_risk = RiskLevel.CRITICAL

    raw = to_json(result)
    data = json.loads(raw)
    assert data["scan_path"] == "/repo"


def test_json_overall_risk_is_lowercase_string_not_enum() -> None:
    result = ScanResult(bindings=[_sample_binding()])
    result.overall_risk = RiskLevel.CRITICAL

    data = json.loads(to_json(result))
    assert data["overall_risk"] == "critical"
    assert data["overall_risk"] != "CRITICAL"


def test_json_findings_structure() -> None:
    binding = _sample_binding()
    assert binding.policy_finding is not None
    result = ScanResult(
        workflow_count=1,
        credential_sources=[binding.credential_source],
        policy_findings=[binding.policy_finding],
        bindings=[binding],
    )
    result.overall_risk = RiskLevel.CRITICAL

    data = json.loads(to_json(result))
    assert len(data["findings"]) == 1
    f0 = data["findings"][0]
    assert f0["workflow_file"] == ".github/workflows/deploy.yml"
    assert f0["job_name"] == "deploy"
    assert f0["role_arn"].endswith("ci-deploy")
    assert f0["auth_type"] == "oidc"
    assert f0["policy_source"] == "terraform"
    assert f0["match_confidence"] == "high"
    assert f0["overall_risk"] == "critical"
    assert f0["has_passrole"] is True
    assert f0["has_privilege_escalation"] is True
    assert len(f0["actions"]) == 3
    assert f0["actions"][0]["action"] == "iam:PassRole"
    assert f0["actions"][0]["risk_level"] == "critical"
    assert f0["actions"][0]["access_level"] == "Permissions management"


def test_to_json_includes_errors() -> None:
    err = "Could not parse .github/workflows/broken.yml: invalid YAML"
    result = ScanResult(errors=[err])
    result.overall_risk = RiskLevel.INFO

    data = json.loads(to_json(result))
    assert data["errors"] == [err]


def test_write_json_creates_file(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    binding = _sample_binding()
    pf = binding.policy_finding
    assert pf is not None
    result = ScanResult(
        scan_path=str(tmp_path),
        bindings=[binding],
        policy_findings=[pf],
    )
    result.overall_risk = RiskLevel.HIGH

    write_json(result, str(out))
    assert out.is_file()
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["overall_risk"] == "high"


def test_to_markdown_contains_header() -> None:
    result = ScanResult(bindings=[_sample_binding()])
    result.overall_risk = RiskLevel.CRITICAL

    md = to_markdown(result)
    assert "## 🔍 ActionScope" in md


def test_to_markdown_has_collapsible_details() -> None:
    result = ScanResult(bindings=[_sample_binding()])
    result.overall_risk = RiskLevel.CRITICAL

    md = to_markdown(result)
    assert "<details>" in md
    assert "<summary>All IAM Actions (click to expand)</summary>" in md
    assert "</details>" in md


def test_to_markdown_includes_match_confidence() -> None:
    result = ScanResult(bindings=[_sample_binding()])
    result.overall_risk = RiskLevel.CRITICAL

    md = to_markdown(result)
    assert "Match Confidence" in md
    assert "| Match Confidence | high |" in md


def test_to_markdown_empty_findings_no_crash() -> None:
    result = ScanResult()
    result.overall_risk = RiskLevel.INFO

    md = to_markdown(result)
    assert "## 🔍 ActionScope — Blast Radius Report" in md
    assert "No workflow credential bindings" in md


def test_to_markdown_summary_counts_non_policy_findings() -> None:
    result = ScanResult(
        github_token_permissions=[
            GitHubTokenPermission(
                workflow_file=".github/workflows/scorecard.yml",
                job_name="analysis",
                scope="id-token",
                access="write",
                risk_level=RiskLevel.HIGH,
            )
        ],
        environment_findings=[
            EnvironmentFinding(
                workflow_file=".github/workflows/docker.yml",
                job_name="build",
                environment_name=None,
                has_aws_credentials=True,
                role_arn="arn:aws:iam::123456789012:role/ecr-pusher",
                finding_type="deploy_without_environment",
                risk_level=RiskLevel.MEDIUM,
                description="Deploy job has no GitHub Environment.",
                recommendation="Add environment: production.",
            )
        ],
    )

    md = to_markdown(result)

    assert "| 🟠 High | 1 |" in md
    assert "| 🟡 Medium | 1 |" in md


def test_to_markdown_from_dict_summary_counts_all_finding_shapes() -> None:
    md = to_markdown_from_dict(
        {
            "scan_path": "/repo",
            "overall_risk": "critical",
            "workflow_count": 1,
            "summary": {"credential_sources": 1},
            "findings": [
                {
                    "workflow_file": ".github/workflows/deploy.yml",
                    "job_name": "deploy",
                    "role_arn": "arn:aws:iam::123456789012:role/deploy",
                    "auth_type": "oidc",
                    "policy_source": "terraform",
                    "match_confidence": "high",
                    "overall_risk": "medium",
                    "has_passrole": False,
                    "has_privilege_escalation": False,
                    "actions": [
                        {
                            "action": "s3:GetObject",
                            "access_level": "Read",
                            "risk_level": "low",
                        }
                    ],
                }
            ],
            "github_token_permissions": [
                {
                    "workflow_file": ".github/workflows/scorecard.yml",
                    "job_name": "analysis",
                    "scope": "id-token",
                    "access": "write",
                    "risk_level": "high",
                }
            ],
            "environment_findings": [
                {
                    "workflow_file": ".github/workflows/docker.yml",
                    "job_name": "build",
                    "finding_type": "deploy_without_environment",
                    "risk_level": "medium",
                }
            ],
        }
    )

    assert "| 🟠 High | 1 |" in md
    assert "| 🟡 Medium | 2 |" in md
    assert "| 🟢 Low | 0 |" in md
