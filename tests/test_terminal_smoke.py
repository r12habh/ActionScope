"""Smoke coverage for the Rich terminal reporter."""

import io

from rich.console import Console

from actionscope.models import (
    AwsCredentialSource,
    EnvironmentFinding,
    ExposurePath,
    GitHubTokenPermission,
    IamAction,
    PolicyFinding,
    ReusableWorkflowReference,
    RiskLevel,
    ScanResult,
    WorkflowCredentialBinding,
)
from actionscope.reporters.terminal import render_scan_result


def test_render_scan_result_shows_reusable_workflow_status() -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=120)
    result = ScanResult(
        reusable_workflows=[
            ReusableWorkflowReference(
                caller_workflow=".github/workflows/caller.yml",
                caller_job="deploy",
                uses="acme/platform/.github/workflows/deploy.yml@v1",
                target_workflow=(
                    "acme/platform/.github/workflows/deploy.yml@v1"
                ),
                repository="acme/platform",
                ref="v1",
                pin_type="tag",
                is_local=False,
                status="no_token",
                depth=1,
                error="pass --github-token",
            )
        ]
    )

    render_scan_result(result, console)

    output = buffer.getvalue()
    assert "Reusable Workflows (1 call(s))" in output
    assert "caller.yml" in output
    assert "deploy" in output
    assert "acme/platform/.github/workflows/deploy.yml@v1" in output
    assert "Pin: tag" in output
    assert "Depth: 1" in output
    assert "no token" in output


def test_render_scan_result_escapes_reusable_workflow_markup() -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=120)
    reference = ReusableWorkflowReference(
        caller_workflow=".github/workflows/[red]caller.yml",
        caller_job="[bold]deploy[/bold]",
        uses="acme/platform/.github/workflows/[blue]deploy[/blue].yml@v1",
        target_workflow="acme/platform/.github/workflows/deploy.yml@v1",
        repository="acme/platform",
        ref="v1",
        pin_type="tag",
        is_local=False,
        status="fetch_error",
        depth=1,
        error="[yellow]API error[/yellow]",
    )

    render_scan_result(ScanResult(reusable_workflows=[reference]), console)

    output = buffer.getvalue()
    assert "[red]caller.yml" in output
    assert "[bold]deploy[/bold]" in output
    assert "[blue]deploy[/blue].yml@v1" in output
    assert "[yellow]API error[/yellow]" in output


def test_render_scan_result_shows_correlated_exposure_path() -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=120)
    path = ExposurePath(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        action_kind="unpinned",
        action_ref="third-party/deploy@v1",
        action_step="Deploy helper",
        credential_step="Configure AWS credentials",
        role_arn="arn:aws:iam::123456789012:role/deploy",
        auth_type="oidc",
        policy_source="terraform",
        policy_source_file="terraform/deploy.tf",
        match_confidence="high",
        reachable_actions=["iam:PassRole", "s3:PutObject"],
        has_privilege_escalation=True,
        risk_level=RiskLevel.CRITICAL,
    )

    render_scan_result(ScanResult(exposure_paths=[path]), console)

    output = buffer.getvalue()
    assert "Correlated Exposure Paths (1 found)" in output
    assert "deploy.yml → deploy" in output
    assert "third-party/deploy@v1" in output
    assert "Policy context: terraform, high confidence" in output
    assert "iam:PassRole, s3:PutObject" in output
    assert "Privilege-escalation path is reachable" in output


def test_render_scan_result_smoke_full_scan_result() -> None:
    credential = AwsCredentialSource(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        step_name="Configure AWS credentials",
        role_arn="arn:aws:iam::123456789012:role/github-deploy-role",
        uses_access_keys=False,
        uses_oidc=True,
        aws_region="us-east-1",
    )

    matched_actions = [
        IamAction(
            "iam:PassRole",
            "Perm Mgmt",
            RiskLevel.CRITICAL,
            "Pass role",
            "*",
        ),
        IamAction(
            "ec2:TerminateInstances",
            "Write",
            RiskLevel.HIGH,
            "Terminate",
            "*",
        ),
        IamAction(
            "s3:GetObject",
            "Read",
            RiskLevel.LOW,
            "Read object",
            "*",
        ),
    ]

    matched_policy = PolicyFinding(
        source_file="terraform/deploy.tf",
        source_type="terraform",
        role_arn="arn:aws:iam::123456789012:role/github-deploy-role",
        actions=matched_actions,
        has_passrole=True,
        overall_risk=RiskLevel.CRITICAL,
    )

    unmatched_policy = PolicyFinding(
        source_file="terraform/iam.tf",
        source_type="terraform",
        role_arn=None,
        actions=[
            IamAction(
                "iam:PassRole",
                "Perm Mgmt",
                RiskLevel.CRITICAL,
                "",
                "*",
            ),
        ],
        has_passrole=True,
        overall_risk=RiskLevel.CRITICAL,
    )

    binding = WorkflowCredentialBinding(
        credential_source=credential,
        policy_finding=matched_policy,
        policy_source="terraform",
    )

    github_perm = GitHubTokenPermission(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        scope="contents",
        access="write",
        risk_level=RiskLevel.MEDIUM,
    )

    result = ScanResult(
        scan_path="/path/to/repo",
        workflow_count=3,
        credential_sources=[credential],
        github_token_permissions=[github_perm],
        policy_findings=[matched_policy, unmatched_policy],
        bindings=[binding],
        errors=["Could not parse .github/workflows/broken.yml: yaml error"],
    )

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=120)

    render_scan_result(result, console=console)

    output = buf.getvalue()
    assert "ActionScope" in output
    assert "CRITICAL" in output


def test_render_scan_result_explains_missing_policy_source() -> None:
    credential = AwsCredentialSource(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        step_name="Configure AWS credentials",
        role_arn="arn:aws:iam::123456789012:role/ci-deploy",
        uses_access_keys=False,
        uses_oidc=True,
        aws_region="us-east-1",
    )
    binding = WorkflowCredentialBinding(
        credential_source=credential,
        policy_finding=None,
        policy_source="not_found",
    )
    result = ScanResult(
        scan_path="/path/to/repo",
        workflow_count=1,
        credential_sources=[credential],
        bindings=[binding],
    )

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=120)

    render_scan_result(result, console=console)

    output = buf.getvalue()
    assert "Policy not found in repo for role" in output
    assert "*.tf files (Terraform)" in output
    assert "**/iam/*.json" in output
    assert "**/policies/*.json" in output
    assert "actionscope scan /path/to/infra-repo" in output
    assert "actionscope scan . --aws-verify" in output
    assert "iam:GetRole" in output
    assert "iam:ListAttachedRolePolicies" in output


def test_render_scan_result_summary_counts_non_policy_findings() -> None:
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

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=120)

    render_scan_result(result, console=console)

    output = buf.getvalue()
    assert "High: 1" in output
    assert "Medium: 1" in output
