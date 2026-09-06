"""Risk correlation engine for building final ActionScope scan results."""

from __future__ import annotations

import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from actionscope.analyzers.ai_agent_injection import scan_for_ai_agent_injection
from actionscope.analyzers.artifact_poisoning import scan_for_artifact_poisoning
from actionscope.analyzers.compromised_actions import scan_for_compromised_actions
from actionscope.analyzers.exposure_paths import build_exposure_paths
from actionscope.analyzers.github_environments import scan_environment_usage
from actionscope.analyzers.oidc_trust import scan_oidc_trust_policies
from actionscope.analyzers.privesc_detector import detect_privesc_paths
from actionscope.analyzers.script_injection import scan_workflows_for_injection
from actionscope.coverage import build_coverage_gaps
from actionscope.findings import build_finding_records
from actionscope.models import (
    AiAgentInjectionFinding,
    ArtifactPoisoningFinding,
    AwsCredentialSource,
    CompromisedActionFinding,
    CoverageGap,
    EnvironmentFinding,
    ExposurePath,
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
from actionscope.parsers.terraform_refs import parse_resource_reference

if TYPE_CHECKING:
    from actionscope.analyzers.reusable_workflows import ReusableWorkflowScan
    from actionscope.config import ActionScopeConfig


@dataclass(frozen=True)
class _PolicyMatch:
    finding: PolicyFinding | None
    confidence: str
    reason: str
    matched_findings: tuple[PolicyFinding, ...] = ()


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

    matchable_findings = [
        finding
        for finding in policy_findings
        if not _is_failed_aws_verification(finding)
    ]
    exact_arn_matches = [
        finding for finding in matchable_findings if finding.role_arn == role_arn
    ]
    if exact_arn_matches:
        return _policy_match(
            exact_arn_matches,
            credential_source,
            "high",
            "exact role ARN match",
        )

    role_name = _role_name_from_arn(role_arn)
    if role_name is None:
        return _PolicyMatch(None, "none", "role ARN is not a static IAM role ARN")

    normalized_role_name = role_name.lower()
    verified_matches = [
        finding
        for finding in _aws_verified_findings(matchable_findings)
        if _finding_matches_role_name(finding, normalized_role_name)
    ]
    if verified_matches:
        return _policy_match(
            verified_matches,
            credential_source,
            "high",
            "AWS-verified role name match",
        )

    repository_findings = [
        finding
        for finding in matchable_findings
        if finding.source_type != "aws_verified"
    ]
    relationship_matches = [
        finding
        for finding in repository_findings
        if finding.role_name
        and normalized_role_name == finding.role_name.lower()
    ]
    if relationship_matches:
        identity_groups: dict[tuple[str, ...], list[PolicyFinding]] = {}
        for finding in relationship_matches:
            identity = _repository_role_identity(finding, normalized_role_name)
            identity_groups.setdefault(identity, []).append(finding)

        if len(identity_groups) > 1:
            return _PolicyMatch(
                None,
                "none",
                "multiple infrastructure roles share the role name; "
                "repository evidence is ambiguous",
            )

        proven_matches = next(iter(identity_groups.values()))
        source_types = {finding.source_type for finding in relationship_matches}
        relationship = (
            {
                "terraform": "Terraform",
                "cloudformation": "CloudFormation/SAM",
            }.get(next(iter(source_types)), "Repository IAM")
            if len(source_types) == 1
            else "Repository IAM"
        )
        return _policy_match(
            proven_matches,
            credential_source,
            "high",
            f"{relationship} role relationship match",
        )

    path_matches = [
        finding
        for finding in repository_findings
        if normalized_role_name in finding.source_file.lower()
    ]
    if path_matches:
        if len(path_matches) > 1:
            return _PolicyMatch(
                None,
                "none",
                "multiple policies match the role name by path only",
            )
        return _policy_match(
            path_matches,
            credential_source,
            "medium",
            "role name appears in policy path",
        )

    content_matches = [
        finding
        for finding in repository_findings
        if _file_contains(finding.source_file, role_name)
    ]
    if content_matches:
        if len(content_matches) > 1:
            return _PolicyMatch(
                None,
                "none",
                "multiple policies match the role name by file content only",
            )
        return _policy_match(
            content_matches,
            credential_source,
            "low",
            "role name appears in policy file",
        )

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
                matched_policy_findings=list(match.matched_findings),
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
    compromised_action_findings: list[CompromisedActionFinding] | None = None,
    environment_findings: list[EnvironmentFinding] | None = None,
    exposure_paths: list[ExposurePath] | None = None,
) -> RiskLevel:
    """Compute risk from workflow-reachable findings and detector results.

    Unmatched policy files remain visible as low-confidence audit context, but
    they cannot establish a workflow blast radius and therefore do not raise the
    repository's overall workflow risk.
    """
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
    _ = unmatched_policy_findings
    detector_risks = [
        finding.risk_level
        for findings in (
            oidc_trust_findings or [],
            script_injection_findings or [],
            artifact_poisoning_findings or [],
            ai_agent_injection_findings or [],
            compromised_action_findings or [],
            environment_findings or [],
            exposure_paths or [],
        )
        for finding in findings
    ]

    return max(
        binding_risks + token_risks + detector_risks,
        default=RiskLevel.INFO,
    )


def build_scan_result(
    repo_path: str,
    credential_sources: list[AwsCredentialSource],
    github_token_perms: list[GitHubTokenPermission],
    policy_findings: list[PolicyFinding],
    unpinned_actions: list[UnpinnedActionFinding] | list[str] | None = None,
    errors: list[str] | None = None,
    reusable_scan: ReusableWorkflowScan | None = None,
    offline: bool = False,
    config: ActionScopeConfig | None = None,
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

    hard_block_findings = []
    for finding in policy_findings:
        if config is not None:
            from actionscope.config import apply_action_overrides

            hard_block_findings.extend(apply_action_overrides(finding, config))
        finding.privesc_paths = detect_privesc_paths(finding, finding.source_file)
        if config is not None:
            from actionscope.config import (
                add_custom_privesc_paths,
                recompute_policy_risk,
            )

            add_custom_privesc_paths(finding, config)
            recompute_policy_risk(finding)

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
    if offline:
        compromised_action_findings, compromised_errors = (
            _safe_scan_compromised_actions(repo_path, offline=True)
        )
    else:
        compromised_action_findings, compromised_errors = (
            _safe_scan_compromised_actions(repo_path)
        )
    environment_findings, environment_errors = _safe_scan_environments(
        repo_path,
        credential_sources,
        oidc_trust_findings,
        deploy_job_patterns=(config.deploy_job_patterns if config else ()),
        non_deploy_job_patterns=(
            config.non_deploy_job_patterns if config else ()
        ),
    )
    if reusable_scan is not None:
        script_injection_findings.extend(
            reusable_scan.script_injection_findings
        )
        artifact_poisoning_findings.extend(
            reusable_scan.artifact_poisoning_findings
        )
        ai_agent_injection_findings.extend(
            reusable_scan.ai_agent_injection_findings
        )
        compromised_action_findings.extend(
            reusable_scan.compromised_action_findings
        )
        environment_findings.extend(reusable_scan.environment_findings)
    errors.extend(
        oidc_errors
        + script_errors
        + artifact_errors
        + ai_errors
        + compromised_errors
        + environment_errors
    )

    bindings = build_bindings(credential_sources, policy_findings, repo_path)
    if config is not None:
        from actionscope.config import add_custom_privesc_paths, recompute_policy_risk

        for binding in bindings:
            if binding.policy_finding is None:
                continue
            add_custom_privesc_paths(binding.policy_finding, config)
            recompute_policy_risk(binding.policy_finding)
    exposure_paths = build_exposure_paths(
        bindings,
        normalized_unpinned,
        compromised_action_findings,
    )
    unmatched_findings = get_unmatched_findings(bindings, policy_findings)
    overall_risk = compute_overall_risk(
        bindings,
        github_token_perms,
        unmatched_findings,
        oidc_trust_findings,
        script_injection_findings,
        artifact_poisoning_findings,
        ai_agent_injection_findings,
        compromised_action_findings,
        environment_findings,
        exposure_paths,
    )
    workflow_count = len(
        {source.workflow_file for source in credential_sources}
        | {perm.workflow_file for perm in github_token_perms}
        | {finding.workflow_file for finding in normalized_unpinned}
        | {finding.workflow_file for finding in script_injection_findings}
        | {finding.workflow_file for finding in artifact_poisoning_findings}
        | {finding.workflow_file for finding in ai_agent_injection_findings}
        | {finding.workflow_file for finding in compromised_action_findings}
        | {finding.workflow_file for finding in environment_findings}
        | {
            reference.caller_workflow
            for reference in (reusable_scan.references if reusable_scan else [])
        }
        | {
            reference.target_workflow
            for reference in (reusable_scan.references if reusable_scan else [])
            if reference.status == "inspected"
        }
    )

    result = ScanResult(
        scan_path=repo_path,
        workflow_count=workflow_count,
        credential_sources=credential_sources,
        github_token_permissions=github_token_perms,
        unpinned_actions=normalized_unpinned,
        reusable_workflows=(
            list(reusable_scan.references) if reusable_scan is not None else []
        ),
        oidc_trust_findings=oidc_trust_findings,
        script_injection_findings=script_injection_findings,
        artifact_poisoning_findings=artifact_poisoning_findings,
        ai_agent_injection_findings=ai_agent_injection_findings,
        compromised_action_findings=compromised_action_findings,
        environment_findings=environment_findings,
        policy_findings=policy_findings,
        bindings=bindings,
        exposure_paths=exposure_paths,
        hard_block_findings=hard_block_findings,
        errors=errors,
    )
    result.overall_risk = overall_risk
    return finalize_scan_metadata(result, config=config)


def finalize_scan_metadata(
    result: ScanResult,
    config: ActionScopeConfig | None = None,
) -> ScanResult:
    """Build coverage and normalized findings without aborting the scan."""
    if config is not None:
        from actionscope.config import apply_severity_overrides_to_findings

        apply_severity_overrides_to_findings(result, config)
    try:
        result.coverage_gaps = build_coverage_gaps(result)
    except Exception as exc:
        message = f"Could not describe scan coverage: {exc}"
        result.errors.append(message)
        result.coverage_gaps = [
            CoverageGap(
                gap_type="coverage_normalization_error",
                description=message,
            )
        ]

    try:
        result.finding_records = build_finding_records(result)
    except Exception as exc:
        message = f"Could not normalize findings: {exc}"
        result.errors.append(message)
        result.finding_records = []
        result.coverage_gaps.append(
            CoverageGap(
                gap_type="finding_normalization_error",
                description=message,
            )
        )

    result.coverage_status = (
        "partial" if result.coverage_gaps or result.errors else "complete"
    )
    if config is not None:
        from actionscope.config import apply_result_configuration

        apply_result_configuration(result, config)
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
        and finding.metadata.get("aws_verification_status") != "error"
    ]


def _is_failed_aws_verification(finding: PolicyFinding) -> bool:
    return (
        finding.source_type == "aws_verified"
        and finding.metadata.get("aws_verification_status") == "error"
    )


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


def _repository_role_identity(
    finding: PolicyFinding,
    normalized_role_name: str,
) -> tuple[str, ...]:
    """Return the narrowest repository-scoped identity proven by parser data."""
    source_path = Path(finding.source_file)
    if finding.source_type == "terraform":
        # Terraform files in one directory form a module and may split a role's
        # inline and attached policies across files. The parser records the
        # referenced role resource when that relationship is explicit; retain
        # it so same-named roles using different provider aliases are not
        # merged. A literal role name does not prove shared identity, so keep
        # that evidence scoped to its policy resource.
        role_reference = finding.metadata.get("terraform_role_reference")
        role_address = _terraform_role_address(role_reference)
        if role_address:
            return (
                "terraform",
                str(source_path.parent),
                "role_resource",
                role_address,
            )

        policy_address = str(
            finding.metadata.get("terraform_address") or source_path
        )
        return (
            "terraform",
            str(source_path.parent),
            "unproven_role",
            policy_address,
            normalized_role_name,
        )

    if finding.source_type == "cloudformation":
        logical_id = finding.metadata.get("cloudformation_logical_id")
        return (
            "cloudformation",
            str(source_path),
            str(logical_id or ""),
            normalized_role_name,
        )

    # Standalone policy formats do not prove that two files describe the same
    # deployed role. Keep each file as a separate identity unless an exact ARN
    # matched earlier in the correlation flow.
    return (finding.source_type, str(source_path), normalized_role_name)


def _terraform_role_address(value: object) -> str | None:
    """Extract an aws_iam_role resource address from a Terraform reference."""
    reference = parse_resource_reference(value, "aws_iam_role")
    return reference.instance_address if reference else None


def _policy_match(
    findings: list[PolicyFinding],
    credential_source: AwsCredentialSource,
    confidence: str,
    reason: str,
) -> _PolicyMatch:
    matched = tuple(findings)
    finding = (
        findings[0]
        if len(findings) == 1
        else _aggregate_policy_findings(findings, credential_source)
    )
    if len(findings) > 1:
        reason = f"{reason}; aggregated {len(findings)} policy sources"
    return _PolicyMatch(finding, confidence, reason, matched)


def _aggregate_policy_findings(
    findings: list[PolicyFinding],
    credential_source: AwsCredentialSource,
) -> PolicyFinding:
    """Combine every matched permission source into one effective role view."""
    actions = []
    seen_actions: set[tuple[str, str, str, RiskLevel]] = set()
    for finding in findings:
        for action in finding.actions:
            key = (
                action.action.lower(),
                action.resource,
                action.access_level,
                action.risk_level,
            )
            if key not in seen_actions:
                actions.append(action)
                seen_actions.add(key)

    role_name = _role_name_from_arn(credential_source.role_arn)
    source_files = list(dict.fromkeys(finding.source_file for finding in findings))
    policy_names = list(
        dict.fromkeys(
            finding.policy_name
            for finding in findings
            if finding.policy_name is not None
        )
    )
    unresolved_policy_attachments = _unresolved_policy_attachments(findings)
    uninspectable_policy_elements = _uninspectable_policy_elements(findings)
    policy_coverage_complete = all(
        finding.metadata.get("policy_coverage_complete") is not False
        for finding in findings
    ) and not unresolved_policy_attachments and not uninspectable_policy_elements
    aggregate = PolicyFinding(
        source_file=source_files[0],
        source_type=findings[0].source_type,
        role_arn=credential_source.role_arn,
        actions=actions,
        has_star_action=any(finding.has_star_action for finding in findings),
        has_star_resource=any(finding.has_star_resource for finding in findings),
        has_passrole=any(finding.has_passrole for finding in findings),
        overall_risk=max(
            (finding.overall_risk for finding in findings),
            default=RiskLevel.INFO,
        ),
        role_name=role_name or next(
            (finding.role_name for finding in findings if finding.role_name),
            None,
        ),
        policy_name=f"effective-policy-set ({len(findings)} sources)",
        metadata={
            "aggregated_policy_count": len(findings),
            "aggregated_source_files": source_files,
            "aggregated_policy_names": policy_names,
            "policy_coverage_complete": policy_coverage_complete,
            "unresolved_policy_attachments": unresolved_policy_attachments,
            "uninspectable_policy_elements": uninspectable_policy_elements,
        },
    )

    detected_paths = detect_privesc_paths(aggregate, aggregate.source_file)
    path_by_id = {
        path.path_id: path
        for finding in findings
        for path in finding.privesc_paths
    }
    path_by_id.update({path.path_id: path for path in detected_paths})
    aggregate.privesc_paths = list(path_by_id.values())
    aggregate.has_privilege_escalation = bool(aggregate.privesc_paths) or any(
        finding.has_privilege_escalation for finding in findings
    )
    aggregate.overall_risk = max(
        [aggregate.overall_risk]
        + [action.risk_level for action in aggregate.actions]
        + [path.severity for path in aggregate.privesc_paths]
    )
    return aggregate


def _unresolved_policy_attachments(
    findings: list[PolicyFinding],
) -> list[str]:
    attachments: list[str] = []
    for finding in findings:
        values = finding.metadata.get("unresolved_policy_attachments", [])
        if isinstance(values, list):
            attachments.extend(str(value) for value in values)
    return list(dict.fromkeys(attachments))


def _uninspectable_policy_elements(
    findings: list[PolicyFinding],
) -> list[str]:
    elements: list[str] = []
    for finding in findings:
        values = finding.metadata.get("uninspectable_policy_elements", [])
        if isinstance(values, list):
            elements.extend(str(value) for value in values)
    return list(dict.fromkeys(elements))


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
        return [], [_scan_error("OIDC trust policy scan", exc)]


def _safe_scan_script_injection(
    repo_path: str,
) -> tuple[list[ScriptInjectionFinding], list[str]]:
    try:
        return scan_workflows_for_injection(repo_path)
    except Exception as exc:
        return [], [_scan_error("script injection scan", exc)]


def _safe_scan_artifact_poisoning(
    repo_path: str,
) -> tuple[list[ArtifactPoisoningFinding], list[str]]:
    try:
        return scan_for_artifact_poisoning(repo_path)
    except Exception as exc:
        return [], [_scan_error("artifact poisoning scan", exc)]


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
        return [], [_scan_error("AI agent injection scan", exc)]


def _safe_scan_compromised_actions(
    repo_path: str,
    *,
    offline: bool = False,
) -> tuple[list[CompromisedActionFinding], list[str]]:
    try:
        return scan_for_compromised_actions(repo_path, offline=offline)
    except Exception as exc:
        return [], [_scan_error("compromised actions scan", exc)]


def _safe_scan_environments(
    repo_path: str,
    credential_sources: list[AwsCredentialSource],
    oidc_trust_findings: list[OidcTrustFinding],
    *,
    deploy_job_patterns: tuple[str, ...] = (),
    non_deploy_job_patterns: tuple[str, ...] = (),
) -> tuple[list[EnvironmentFinding], list[str]]:
    try:
        return scan_environment_usage(
            repo_path,
            credential_sources,
            oidc_trust_findings,
            deploy_job_patterns=deploy_job_patterns,
            non_deploy_job_patterns=non_deploy_job_patterns,
        )
    except Exception as exc:
        return [], [_scan_error("GitHub Environments scan", exc)]


def _scan_error(scan_name: str, exc: Exception) -> str:
    return (
        f"Scan incomplete: {scan_name} failed with "
        f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
    )
