"""Tests for the ActionScope risk correlation engine."""

from actionscope.analyzers.risk_engine import (
    build_bindings,
    build_scan_result,
    compute_overall_risk,
    match_role_to_policies,
)
from actionscope.models import (
    AwsCredentialSource,
    GitHubTokenPermission,
    PolicyFinding,
    RiskLevel,
    WorkflowCredentialBinding,
    get_unmatched_findings,
)


def credential_source(
    role_arn: str | None = "arn:aws:iam::123456789012:role/github-deploy-role",
    workflow_file: str = ".github/workflows/deploy.yml",
) -> AwsCredentialSource:
    """Create an AWS credential source for risk-engine tests."""
    return AwsCredentialSource(
        workflow_file=workflow_file,
        job_name="deploy",
        step_name="Configure AWS credentials",
        role_arn=role_arn,
        uses_access_keys=role_arn is None,
        uses_oidc=role_arn is not None,
        aws_region="us-east-1",
    )


def policy_finding(
    risk: RiskLevel,
    source_file: str = "/repo/terraform/github-deploy-role.tf",
    source_type: str = "terraform",
    role_name: str | None = None,
) -> PolicyFinding:
    """Create a policy finding for risk-engine tests."""
    return PolicyFinding(
        source_file=source_file,
        source_type=source_type,
        role_arn=None,
        overall_risk=risk,
        role_name=role_name,
    )


def token_permission(risk: RiskLevel) -> GitHubTokenPermission:
    """Create a GITHUB_TOKEN permission for risk-engine tests."""
    return GitHubTokenPermission(
        workflow_file=".github/workflows/ci.yml",
        job_name="",
        scope="contents",
        access="write",
        risk_level=risk,
    )


def binding_for(finding: PolicyFinding | None) -> WorkflowCredentialBinding:
    """Create a binding for risk-engine tests."""
    return WorkflowCredentialBinding(
        credential_source=credential_source(),
        policy_finding=finding,
        policy_source="terraform" if finding else "not_found",
    )


def test_match_role_to_policies_returns_none_when_role_arn_is_none() -> None:
    assert match_role_to_policies(credential_source(role_arn=None), []) is None


def test_match_role_to_policies_returns_none_for_dynamic_reference_arn() -> None:
    source = credential_source(role_arn="${{ secrets.ROLE_ARN }}")

    assert match_role_to_policies(source, [policy_finding(RiskLevel.HIGH)]) is None


def test_match_role_to_policies_finds_match_by_role_name_in_file_path() -> None:
    finding = policy_finding(
        RiskLevel.HIGH,
        source_file="/repo/terraform/github-deploy-role-policy.tf",
    )

    assert match_role_to_policies(credential_source(), [finding]) is finding


def test_match_role_to_policies_prefers_explicit_role_name_metadata() -> None:
    finding = policy_finding(
        RiskLevel.HIGH,
        source_file="/repo/terraform/iam.tf",
        role_name="github-deploy-role",
    )

    assert match_role_to_policies(credential_source(), [finding]) is finding


def test_build_bindings_creates_not_found_when_no_policy_matches() -> None:
    bindings = build_bindings([credential_source()], [], "/repo")

    assert len(bindings) == 1
    assert bindings[0].policy_finding is None
    assert bindings[0].policy_source == "not_found"
    assert bindings[0].match_confidence == "none"


def test_build_bindings_reports_high_confidence_for_role_relationship() -> None:
    finding = policy_finding(
        RiskLevel.HIGH,
        source_file="/repo/terraform/iam.tf",
        role_name="github-deploy-role",
    )

    bindings = build_bindings([credential_source()], [finding], "/repo")

    assert bindings[0].policy_finding is finding
    assert bindings[0].match_confidence == "high"
    assert "Terraform role relationship" in bindings[0].match_reason


def test_build_bindings_creates_dynamic_reference_for_secret_refs() -> None:
    bindings = build_bindings(
        [credential_source(role_arn="${{ secrets.ROLE_ARN }}")],
        [],
        "/repo",
    )

    assert bindings[0].policy_source == "dynamic_reference"


def test_compute_overall_risk_returns_critical_when_binding_is_critical() -> None:
    risk = compute_overall_risk(
        [binding_for(policy_finding(RiskLevel.CRITICAL))],
        [],
        [],
    )

    assert risk is RiskLevel.CRITICAL


def test_compute_overall_risk_returns_info_when_no_bindings_have_findings() -> None:
    risk = compute_overall_risk([binding_for(None)], [], [])

    assert risk is RiskLevel.INFO


def test_get_unmatched_findings_returns_policies_not_tied_to_workflow() -> None:
    matched = policy_finding(RiskLevel.HIGH, source_file="/repo/matched.tf")
    unmatched = policy_finding(RiskLevel.LOW, source_file="/repo/unmatched.tf")

    result = get_unmatched_findings([binding_for(matched)], [matched, unmatched])

    assert result == [unmatched]


def test_build_scan_result_produces_correct_workflow_count() -> None:
    sources = [
        credential_source(workflow_file=".github/workflows/deploy.yml"),
        credential_source(workflow_file=".github/workflows/deploy.yml"),
        credential_source(workflow_file=".github/workflows/release.yml"),
    ]

    result = build_scan_result("/repo", sources, [], [], [])

    assert result.workflow_count == 2


def test_scan_result_has_critical_findings_for_critical_overall_risk() -> None:
    critical = policy_finding(RiskLevel.CRITICAL)

    result = build_scan_result("/repo", [], [], [critical], [])

    assert result.overall_risk is RiskLevel.CRITICAL
    assert result.has_critical_findings() is True


def test_empty_repo_produces_info_scan_result() -> None:
    result = build_scan_result("/repo", [], [], [], [])

    assert result.overall_risk is RiskLevel.INFO
    assert result.workflow_count == 0
    assert result.bindings == []


def test_github_token_critical_risk_propagates_to_overall_scan_result() -> None:
    result = build_scan_result(
        "/repo",
        [],
        [token_permission(RiskLevel.CRITICAL)],
        [],
        [],
    )

    assert result.overall_risk is RiskLevel.CRITICAL
