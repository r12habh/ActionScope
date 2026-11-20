"""Tests for ActionScope dataclass models."""

from actionscope.models import (
    AwsCredentialSource,
    GitHubTokenPermission,
    PolicyFinding,
    RiskLevel,
    ScanResult,
    WorkflowCredentialBinding,
)


def credential_source() -> AwsCredentialSource:
    """Return a minimal AWS credential source for binding tests."""
    return AwsCredentialSource(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        step_name="Configure AWS credentials",
        role_arn="arn:aws:iam::123456789012:role/ci-deploy",
        uses_access_keys=False,
        uses_oidc=True,
        aws_region="us-east-1",
    )


def policy_finding(risk_level: RiskLevel) -> PolicyFinding:
    """Return a policy finding with the requested overall risk."""
    return PolicyFinding(
        source_file="policy.json",
        source_type="json_policy",
        role_arn=None,
        overall_risk=risk_level,
    )


def binding_for(finding: PolicyFinding) -> WorkflowCredentialBinding:
    """Return a workflow credential binding for a policy finding."""
    return WorkflowCredentialBinding(
        credential_source=credential_source(),
        policy_finding=finding,
        policy_source="json",
    )


def github_token_permission(risk_level: RiskLevel) -> GitHubTokenPermission:
    """Return a GITHUB_TOKEN permission with the requested risk."""
    return GitHubTokenPermission(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        scope="contents",
        access="write",
        risk_level=risk_level,
    )


def test_risk_level_critical_greater_than_high() -> None:
    assert RiskLevel.CRITICAL > RiskLevel.HIGH


def test_risk_level_high_greater_than_medium() -> None:
    assert RiskLevel.HIGH > RiskLevel.MEDIUM


def test_risk_level_medium_greater_than_low() -> None:
    assert RiskLevel.MEDIUM > RiskLevel.LOW


def test_risk_level_low_greater_than_info() -> None:
    assert RiskLevel.LOW > RiskLevel.INFO


def test_risk_level_max_returns_highest() -> None:
    assert max([RiskLevel.INFO, RiskLevel.HIGH, RiskLevel.MEDIUM]) is RiskLevel.HIGH


def test_has_critical_findings_true_for_token_permission() -> None:
    result = ScanResult(
        github_token_permissions=[github_token_permission(RiskLevel.CRITICAL)]
    )

    assert result.has_critical_findings() is True


def test_has_critical_findings_true_for_bound_policy() -> None:
    result = ScanResult(bindings=[binding_for(policy_finding(RiskLevel.CRITICAL))])

    assert result.has_critical_findings() is True


def test_has_critical_findings_false_without_critical() -> None:
    result = ScanResult(
        github_token_permissions=[github_token_permission(RiskLevel.HIGH)],
        bindings=[binding_for(policy_finding(RiskLevel.MEDIUM))],
    )

    assert result.has_critical_findings() is False


def test_findings_by_risk_filters_policy_findings() -> None:
    high = policy_finding(RiskLevel.HIGH)
    low = policy_finding(RiskLevel.LOW)
    result = ScanResult(policy_findings=[high, low])

    assert result.findings_by_risk(RiskLevel.HIGH) == [high]


def test_findings_by_risk_filters_github_token_permissions() -> None:
    medium = github_token_permission(RiskLevel.MEDIUM)
    low = github_token_permission(RiskLevel.LOW)
    result = ScanResult(github_token_permissions=[medium, low])

    assert result.findings_by_risk(RiskLevel.MEDIUM) == [medium]


def test_findings_by_risk_includes_bound_policy_without_policy_list() -> None:
    critical = policy_finding(RiskLevel.CRITICAL)
    result = ScanResult(bindings=[binding_for(critical)])

    assert result.findings_by_risk(RiskLevel.CRITICAL) == [critical]


def test_findings_by_risk_deduplicates_bound_policy() -> None:
    high = policy_finding(RiskLevel.HIGH)
    result = ScanResult(policy_findings=[high], bindings=[binding_for(high)])

    assert result.findings_by_risk(RiskLevel.HIGH) == [high]


def test_post_init_computes_overall_risk_from_bindings() -> None:
    result = ScanResult(
        bindings=[
            binding_for(policy_finding(RiskLevel.LOW)),
            binding_for(policy_finding(RiskLevel.CRITICAL)),
        ]
    )

    assert result.overall_risk is RiskLevel.CRITICAL


def test_post_init_computes_overall_risk_from_github_tokens() -> None:
    result = ScanResult(
        github_token_permissions=[
            github_token_permission(RiskLevel.LOW),
            github_token_permission(RiskLevel.HIGH),
        ]
    )

    assert result.overall_risk is RiskLevel.HIGH


def test_empty_scan_result_has_info_risk() -> None:
    result = ScanResult(overall_risk=RiskLevel.CRITICAL)

    assert result.overall_risk is RiskLevel.INFO
