"""Tests for the ActionScope Click CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from actionscope import __version__
from actionscope.cli import main
from actionscope.models import IamAction, PolicyFinding, RiskLevel


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_scan_safe_repo_exits_zero(runner: CliRunner, cli_repo_safe: Path) -> None:
    result = runner.invoke(main, ["scan", str(cli_repo_safe)])
    assert result.exit_code == 0


def test_scan_nonexistent_path_fails(runner: CliRunner) -> None:
    bad = Path("/nonexistent/path/actionscope_missing_repo")
    result = runner.invoke(main, ["scan", str(bad)])
    assert result.exit_code != 0


def test_scan_json_output_valid(runner: CliRunner, cli_repo_safe: Path) -> None:
    result = runner.invoke(
        main,
        ["scan", str(cli_repo_safe), "--output-format", "json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert "overall_risk" in data


def test_fail_on_critical_exits_one_when_critical(
    runner: CliRunner, cli_repo_critical: Path
) -> None:
    result = runner.invoke(
        main,
        ["scan", str(cli_repo_critical), "--fail-on", "critical"],
    )
    assert result.exit_code == 1


def test_fail_on_critical_exits_zero_when_not_critical(
    runner: CliRunner, cli_repo_safe: Path
) -> None:
    result = runner.invoke(
        main,
        ["scan", str(cli_repo_safe), "--fail-on", "critical"],
    )
    assert result.exit_code == 0


def test_aws_verify_prints_running_message(
    runner: CliRunner, cli_repo_safe: Path
) -> None:
    result = runner.invoke(
        main,
        ["scan", str(cli_repo_safe), "--aws-verify"],
    )
    assert result.exit_code == 0
    assert "Running AWS verification" in result.output


def test_failed_aws_verify_keeps_critical_cloudformation_evidence(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "deploy.yml").write_text(
        """
on: push
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v5
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy-role
          aws-region: us-east-1
""",
        encoding="utf-8",
    )
    (tmp_path / "template.yml").write_text(
        """
Resources:
  DeployRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: github-deploy-role
      AssumeRolePolicyDocument:
        Statement: []
      Policies:
        - PolicyName: Admin
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: iam:PassRole
                Resource: "*"
""",
        encoding="utf-8",
    )
    failed = PolicyFinding(
        source_file="aws://iam/role/github-deploy-role",
        source_type="aws_verified",
        role_arn="arn:aws:iam::123456789012:role/github-deploy-role",
        actions=[
            IamAction(
                action="aws:VerifyRolePolicies",
                access_level="Info",
                risk_level=RiskLevel.INFO,
                description="AWS verification error: access_denied",
                resource="arn:aws:iam::123456789012:role/github-deploy-role",
            )
        ],
        metadata={"aws_verification_status": "error"},
    )

    monkeypatch.setattr(
        "actionscope.verifiers.aws_verifier.check_boto3_available",
        lambda: None,
    )
    monkeypatch.setattr(
        "actionscope.verifiers.aws_verifier.verify_all_credential_sources",
        lambda _sources: ([failed], ["AWS verification access denied"]),
    )

    result = runner.invoke(
        main,
        [
            "scan",
            str(tmp_path),
            "--aws-verify",
            "--output-format",
            "json",
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["overall_risk"] == "critical"
    assert data["findings"][0]["policy_source"] == "cloudformation"


def test_aws_verify_does_not_replace_same_name_role_in_another_account(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "deploy.yml").write_text(
        """
on: push
permissions:
  contents: read
  id-token: write
jobs:
  account-one:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v5
        with:
          role-to-assume: arn:aws:iam::111111111111:role/shared-deploy
          aws-region: us-east-1
  account-two:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v5
        with:
          role-to-assume: arn:aws:iam::222222222222:role/shared-deploy
          aws-region: us-east-1
""",
        encoding="utf-8",
    )
    (tmp_path / "template.yml").write_text(
        """
Resources:
  DeployRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: shared-deploy
      AssumeRolePolicyDocument:
        Statement: []
      Policies:
        - PolicyName: Admin
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: iam:PassRole
                Resource: "*"
""",
        encoding="utf-8",
    )
    successful = PolicyFinding(
        source_file="aws://iam/role/shared-deploy",
        source_type="aws_verified",
        role_arn="arn:aws:iam::111111111111:role/shared-deploy",
        actions=[],
        overall_risk=RiskLevel.LOW,
        metadata={"aws_verification_status": "success"},
    )
    failed = PolicyFinding(
        source_file="aws://iam/role/shared-deploy",
        source_type="aws_verified",
        role_arn="arn:aws:iam::222222222222:role/shared-deploy",
        actions=[],
        metadata={"aws_verification_status": "error"},
    )

    monkeypatch.setattr(
        "actionscope.verifiers.aws_verifier.check_boto3_available",
        lambda: None,
    )
    monkeypatch.setattr(
        "actionscope.verifiers.aws_verifier.verify_all_credential_sources",
        lambda _sources: ([successful, failed], ["AWS verification access denied"]),
    )

    result = runner.invoke(
        main,
        ["scan", str(tmp_path), "--aws-verify", "--output-format", "json"],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)
    bindings = {finding["job_name"]: finding for finding in data["findings"]}
    assert bindings["account-one"]["policy_source"] == "aws_verified"
    assert bindings["account-two"]["policy_source"] == "cloudformation"
    assert bindings["account-two"]["overall_risk"] == "critical"


def test_version_flag_prints_version(runner: CliRunner) -> None:
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert f"ActionScope v{__version__}" in result.output.strip()


def test_hidden_version_command(runner: CliRunner) -> None:
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"ActionScope v{__version__}"


def test_scan_markdown_output(runner: CliRunner, cli_repo_safe: Path) -> None:
    result = runner.invoke(
        main,
        ["scan", str(cli_repo_safe), "--output-format", "markdown"],
    )
    assert result.exit_code == 0
    assert "## 🔍 ActionScope" in result.output


def test_scan_sarif_output_valid(runner: CliRunner, cli_repo_safe: Path) -> None:
    result = runner.invoke(
        main,
        ["scan", str(cli_repo_safe), "--output-format", "sarif"],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["version"] == "2.1.0"


def test_scan_json_reports_uninspected_external_reusable_workflow(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "caller.yml").write_text(
        """
on: push
jobs:
  deploy:
    uses: acme/platform/.github/workflows/deploy.yml@v1
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        main,
        ["scan", str(tmp_path), "--output-format", "json"],
        env={"GITHUB_TOKEN": ""},
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["reusable_workflows"][0]["status"] == "no_token"
    assert data["summary"]["uninspected_reusable_workflows"] == 1
    assert data["unpinned_actions"][0]["uses"].endswith("@v1")


def test_report_help_exists(runner: CliRunner) -> None:
    result = runner.invoke(main, ["report", "--help"])
    assert result.exit_code == 0
    assert "Render a previously saved ActionScope JSON scan result" in result.output


def test_report_from_json_renders_markdown(
    runner: CliRunner,
    cli_repo_safe: Path,
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "actionscope.json"
    scan_result = runner.invoke(
        main,
        [
            "scan",
            str(cli_repo_safe),
            "--output-format",
            "json",
            "--output-file",
            str(output_file),
        ],
    )
    assert scan_result.exit_code == 0

    report_result = runner.invoke(
        main,
        ["report", "--from-json", str(output_file), "--format", "markdown"],
    )

    assert report_result.exit_code == 0
    assert "## 🔍 ActionScope" in report_result.output
