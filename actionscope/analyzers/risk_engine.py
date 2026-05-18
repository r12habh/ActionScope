"""Risk correlation engine for building final ActionScope scan results."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from actionscope.analyzers.ai_agent_injection import scan_for_ai_agent_injection
from actionscope.analyzers.artifact_poisoning import scan_for_artifact_poisoning
from actionscope.analyzers.oidc_trust import scan_oidc_trust_policies
from actionscope.analyzers.privesc_detector import detect_privesc_paths
from actionscope.analyzers.script_injection import scan_workflows_for_injection
from actionscope.models import (
    AiAgentInjectionFinding,
    ArtifactPoisoningFinding,
    AwsCredentialSource,
    GitHubTokenPermission,
    OidcTrustFinding,
    PolicyFinding,
    RiskLevel,
    ScanResult,
    ScriptInjectionFinding,
    UnpinnedActionFinding,
    WorkflowCredentialBinding,
    get_unmatched_findings,
)


@dataclass(frozen=True)
class _PolicyMatch:
    finding: PolicyFinding | None
    confidence: str
    reason: str


def match_role_to_policies(
    credential_source: AwsCredentialSource,
    policy_findings: list[PolicyFinding],
) -> Optional[PolicyFinding]:
    """Find a policy finding that appears to belong to an AWS role."""
    return _match_role_to_policy_with_confidence(
        credential_source,
        policy_findings,
    ).finding


def _match_role_to_policy_with_confidence(
    credential_source: AwsCredentialSource,
    policy_findings: list[PolicyFinding],
) -> _PolicyMatch:
    """Find the best policy match plus confidence metadata."""
    role_arn = credential_source.role_arn
    if role_arn is None:
        return _PolicyMatch(None, "none", "credential source does not declare a role")

    if _is_dynamic_reference(role_arn):
        return _PolicyMatch(None, "none", "role ARN is a dynamic reference")

    for finding in policy_findings:
        if finding.role_arn == role_arn:
            return _PolicyMatch(finding, "high", "exact role ARN match")

    role_name = _role_name_from_arn(role_arn)
    if role_name is None:
        return _PolicyMatch(None, "none", "role ARN is not a static IAM role ARN")

    normalized_role_name = role_name.lower()
    for finding in _aws_verified_findings(policy_findings):
        if _finding_matches_role_name(finding, normalized_role_name):
            return _PolicyMatch(finding, "high", "AWS-verified role name match")

    for finding in policy_findings:
        if finding.source_type == "aws_verified":
            continue

        if finding.role_name and normalized_role_name == finding.role_name.lower():
            return _PolicyMatch(finding, "high", "Terraform role relationship match")

        if (
            finding.role_arn
            and normalized_role_name
            == finding.role_arn.strip("/").rsplit("/", 1)[-1].lower()
        ):
            return _PolicyMatch(finding, "high", "role name extracted from finding")

        if normalized_role_name in finding.source_file.lower():
            return _PolicyMatch(finding, "medium", "role name appears in policy path")

        if _file_contains(finding.source_file, role_name):
            return _PolicyMatch(finding, "low", "role name appears in policy file")

    return _PolicyMatch(None, "none", "no matching policy found")


def build_bindings(
    credential_sources: list[AwsCredentialSource],
    policy_findings: list[PolicyFinding],
    repo_path: str,
) -> list[WorkflowCredentialBinding]:
    """Bind workflow credential sources to matching policy findings."""
    _ = repo_path
    bindings: list[WorkflowCredentialBinding] = []

    for credential_source in credential_sources:
        match = _match_role_to_policy_with_confidence(
            credential_source,
            policy_findings,
        )
        policy_finding = match.finding

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
                match_confidence=match.confidence,
                match_reason=match.reason,
            )
        )

    return bindings


def compute_overall_risk(
    bindings: list[WorkflowCredentialBinding],
    github_token_perms: list[GitHubTokenPermission],
    unmatched_policy_findings: list[PolicyFinding],
    oidc_trust_findings: list[OidcTrustFinding] | None = None,
    script_injection_findings: list[ScriptInjectionFinding] | None = None,
    artifact_poisoning_findings: list[ArtifactPoisoningFinding] | None = None,
    ai_agent_injection_findings: list[AiAgentInjectionFinding] | None = None,
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
    detector_risks = [
        finding.risk_level
        for findings in (
            oidc_trust_findings or [],
            script_injection_findings or [],
            artifact_poisoning_findings or [],
            ai_agent_injection_findings or [],
        )
        for finding in findings
    ]

    return max(
        binding_risks + token_risks + unmatched_risks + detector_risks,
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

    oidc_trust_findings, oidc_errors = _safe_scan_oidc(repo_path)
    script_injection_findings, script_errors = _safe_scan_script_injection(repo_path)
    artifact_poisoning_findings, artifact_errors = _safe_scan_artifact_poisoning(
        repo_path
    )
    ai_agent_injection_findings, ai_errors = _safe_scan_ai_agent_injection(
        repo_path,
        credential_sources,
        github_token_perms,
    )
    errors.extend(oidc_errors + script_errors + artifact_errors + ai_errors)

    bindings = build_bindings(credential_sources, policy_findings, repo_path)
    unmatched_findings = get_unmatched_findings(bindings, policy_findings)
    overall_risk = compute_overall_risk(
        bindings,
        github_token_perms,
        unmatched_findings,
        oidc_trust_findings,
        script_injection_findings,
        artifact_poisoning_findings,
        ai_agent_injection_findings,
    )
    workflow_count = len(
        {source.workflow_file for source in credential_sources}
        | {perm.workflow_file for perm in github_token_perms}
        | {finding.workflow_file for finding in normalized_unpinned}
        | {finding.workflow_file for finding in script_injection_findings}
        | {finding.workflow_file for finding in artifact_poisoning_findings}
        | {finding.workflow_file for finding in ai_agent_injection_findings}
    )

    result = ScanResult(
        scan_path=repo_path,
        workflow_count=workflow_count,
        credential_sources=credential_sources,
        github_token_permissions=github_token_perms,
        unpinned_actions=normalized_unpinned,
        oidc_trust_findings=oidc_trust_findings,
        script_injection_findings=script_injection_findings,
        artifact_poisoning_findings=artifact_poisoning_findings,
        ai_agent_injection_findings=ai_agent_injection_findings,
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
    if finding.role_name and normalized_role_name == finding.role_name.lower():
        return True
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


def _safe_scan_oidc(repo_path: str) -> tuple[list[OidcTrustFinding], list[str]]:
    try:
        return scan_oidc_trust_policies(repo_path)
    except Exception as exc:
        return [], [f"Could not scan OIDC trust policies: {exc}"]


def _safe_scan_script_injection(
    repo_path: str,
) -> tuple[list[ScriptInjectionFinding], list[str]]:
    try:
        return scan_workflows_for_injection(repo_path)
    except Exception as exc:
        return [], [f"Could not scan script injection risks: {exc}"]


def _safe_scan_artifact_poisoning(
    repo_path: str,
) -> tuple[list[ArtifactPoisoningFinding], list[str]]:
    try:
        return scan_for_artifact_poisoning(repo_path)
    except Exception as exc:
        return [], [f"Could not scan artifact poisoning risks: {exc}"]


def _safe_scan_ai_agent_injection(
    repo_path: str,
    credential_sources: list[AwsCredentialSource],
    github_token_perms: list[GitHubTokenPermission],
) -> tuple[list[AiAgentInjectionFinding], list[str]]:
    try:
        return scan_for_ai_agent_injection(
            repo_path,
            credential_sources=credential_sources,
            github_token_perms=github_token_perms,
        )
    except Exception as exc:
        return [], [f"Could not scan AI agent injection risks: {exc}"]
