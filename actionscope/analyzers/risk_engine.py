"""Risk correlation engine for building final ActionScope scan results."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from actionscope.analyzers.privesc_detector import detect_privesc_paths
from actionscope.models import (
    AwsCredentialSource,
    GitHubTokenPermission,
    PolicyFinding,
    RiskLevel,
    ScanResult,
    UnpinnedActionFinding,
    WorkflowCredentialBinding,
    get_unmatched_findings,
)


def match_role_to_policies(
    credential_source: AwsCredentialSource,
    policy_findings: list[PolicyFinding],
) -> Optional[PolicyFinding]:
    """Find a policy finding that appears to belong to an AWS role."""
    role_arn = credential_source.role_arn
    if role_arn is None:
        return None

    if _is_dynamic_reference(role_arn):
        return None

    for finding in policy_findings:
        if finding.role_arn == role_arn:
            return finding

    role_name = _role_name_from_arn(role_arn)
    if role_name is None:
        return None

    normalized_role_name = role_name.lower()
    for finding in _aws_verified_findings(policy_findings):
        if _finding_matches_role_name(finding, normalized_role_name):
            return finding

    for finding in policy_findings:
        if finding.source_type == "aws_verified":
            continue

        if (
            finding.role_arn
            and normalized_role_name
            == finding.role_arn.strip("/").rsplit("/", 1)[-1].lower()
        ):
            return finding

        if normalized_role_name in finding.source_file.lower():
            return finding

        if _file_contains(finding.source_file, role_name):
            return finding

    return None


def build_bindings(
    credential_sources: list[AwsCredentialSource],
    policy_findings: list[PolicyFinding],
    repo_path: str,
) -> list[WorkflowCredentialBinding]:
    """Bind workflow credential sources to matching policy findings."""
    _ = repo_path
    bindings: list[WorkflowCredentialBinding] = []

    for credential_source in credential_sources:
        policy_finding = match_role_to_policies(
            credential_source,
            policy_findings,
        )

        if policy_finding is not None:
            policy_source = _policy_source_for(policy_finding)
        elif credential_source.role_arn is None:
            policy_source = "no_role"
        elif _is_dynamic_reference(credential_source.role_arn):
            policy_source = "dynamic_reference"
        else:
            policy_source = "not_found"

        bindings.append(
            WorkflowCredentialBinding(
                credential_source=credential_source,
                policy_finding=policy_finding,
                policy_source=policy_source,
            )
        )

    return bindings


def compute_overall_risk(
    bindings: list[WorkflowCredentialBinding],
    github_token_perms: list[GitHubTokenPermission],
    unmatched_policy_findings: list[PolicyFinding],
) -> RiskLevel:
    """Compute the highest risk across bindings, token perms, and policies."""
    binding_risks = [
        binding.policy_finding.overall_risk
        for binding in bindings
        if binding.policy_finding is not None
    ]
    token_risks = [
        permission.risk_level
        for permission in github_token_perms
        if permission.risk_level >= RiskLevel.MEDIUM
    ]
    unmatched_risks = [
        finding.overall_risk for finding in unmatched_policy_findings
    ]

    return max(
        binding_risks + token_risks + unmatched_risks,
        default=RiskLevel.INFO,
    )


def build_scan_result(
    repo_path: str,
    credential_sources: list[AwsCredentialSource],
    github_token_perms: list[GitHubTokenPermission],
    policy_findings: list[PolicyFinding],
    unpinned_actions: list[UnpinnedActionFinding] | list[str] | None = None,
    errors: list[str] | None = None,
) -> ScanResult:
    """Build the final correlated scan result."""
    if errors is None:
        if unpinned_actions and all(
            isinstance(item, str) for item in unpinned_actions
        ):
            errors = list(unpinned_actions)
            unpinned_actions = []
        else:
            errors = []

    normalized_unpinned = [
        finding
        for finding in (unpinned_actions or [])
        if isinstance(finding, UnpinnedActionFinding)
    ]

    for finding in policy_findings:
        finding.privesc_paths = detect_privesc_paths(finding, finding.source_file)

    bindings = build_bindings(credential_sources, policy_findings, repo_path)
    unmatched_findings = get_unmatched_findings(bindings, policy_findings)
    overall_risk = compute_overall_risk(
        bindings,
        github_token_perms,
        unmatched_findings,
    )
    workflow_count = len(
        {source.workflow_file for source in credential_sources}
        | {perm.workflow_file for perm in github_token_perms}
    )

    result = ScanResult(
        scan_path=repo_path,
        workflow_count=workflow_count,
        credential_sources=credential_sources,
        github_token_permissions=github_token_perms,
        unpinned_actions=normalized_unpinned,
        policy_findings=policy_findings,
        bindings=bindings,
        errors=errors,
    )
    result.overall_risk = overall_risk
    return result


def _role_name_from_arn(role_arn: str) -> str | None:
    marker = ":role/"
    if marker not in role_arn:
        return None

    role_path = role_arn.split(marker, 1)[1].strip("/")
    if not role_path:
        return None

    return role_path.rsplit("/", 1)[-1]


def _is_dynamic_reference(value: str | None) -> bool:
    if value is None:
        return False
    return "${{" in value and "}}" in value


def _policy_source_for(policy_finding: PolicyFinding) -> str:
    if policy_finding.source_type == "json_policy":
        return "json"
    return policy_finding.source_type


def _aws_verified_findings(
    policy_findings: list[PolicyFinding],
) -> list[PolicyFinding]:
    return [
        finding
        for finding in policy_findings
        if finding.source_type == "aws_verified"
    ]


def _finding_matches_role_name(
    finding: PolicyFinding,
    normalized_role_name: str,
) -> bool:
    if not finding.role_arn:
        return False
    return normalized_role_name == finding.role_arn.strip("/").rsplit("/", 1)[
        -1
    ].lower()


def _file_contains(filepath: str, needle: str) -> bool:
    try:
        return needle.lower() in Path(filepath).read_text(encoding="utf-8").lower()
    except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError) as exc:
        _warn(f"Could not read file {filepath} for role matching: {exc}")
        return False


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)
