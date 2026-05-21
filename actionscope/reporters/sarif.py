"""SARIF 2.1.0 output for GitHub Code Scanning integration.

SARIF spec: https://sarifweb.azurewebsites.net/
GitHub SARIF requirements:
  https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from actionscope import __version__
from actionscope.models import (
    GitHubTokenPermission,
    PolicyFinding,
    RiskLevel,
    ScanResult,
    WorkflowCredentialBinding,
)

RISK_TO_SARIF_SEVERITY = {
    RiskLevel.CRITICAL: "error",
    RiskLevel.HIGH: "error",
    RiskLevel.MEDIUM: "warning",
    RiskLevel.LOW: "note",
    RiskLevel.INFO: "none",
}

RISK_TO_SECURITY_SEVERITY = {
    RiskLevel.CRITICAL: "9.0",
    RiskLevel.HIGH: "7.0",
    RiskLevel.MEDIUM: "5.0",
    RiskLevel.LOW: "3.0",
    RiskLevel.INFO: "0.0",
}

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def to_sarif(result: ScanResult) -> str:
    """Convert a ScanResult to SARIF 2.1.0 JSON for GitHub Code Scanning."""
    rules = _build_rules()
    results: list[dict[str, Any]] = []

    for binding in result.bindings:
        if binding.policy_finding is None:
            continue

        workflow_file = binding.credential_source.workflow_file
        policy_finding = binding.policy_finding

        if policy_finding.overall_risk >= RiskLevel.MEDIUM:
            results.append(
                _make_result(
                    rule_id="AS001",
                    message=_blast_radius_message(binding),
                    level=RISK_TO_SARIF_SEVERITY[policy_finding.overall_risk],
                    security_severity=RISK_TO_SECURITY_SEVERITY[
                        policy_finding.overall_risk
                    ],
                    location_path=workflow_file,
                    location_line=1,
                )
            )

        for privesc in getattr(policy_finding, "privesc_paths", []):
            results.append(
                _make_result(
                    rule_id="AS002",
                    message=(
                        f"{privesc.path_name}: {privesc.description}. "
                        f"Attack: {privesc.example_attack}"
                    ),
                    level="error",
                    security_severity="9.5",
                    location_path=workflow_file,
                    location_line=1,
                )
            )

        if policy_finding.has_passrole:
            results.append(
                _make_result(
                    rule_id="AS003",
                    message=(
                        "iam:PassRole is allowed on this role. This can create "
                        "a privilege escalation path if the resource is '*' or "
                        "overly broad."
                    ),
                    level="error",
                    security_severity="9.0",
                    location_path=workflow_file,
                    location_line=1,
                )
            )

    for permission in result.github_token_permissions:
        if permission.risk_level >= RiskLevel.HIGH:
            results.append(_github_token_result(permission))

    for binding in result.bindings:
        if binding.credential_source.uses_access_keys:
            results.append(
                _make_result(
                    rule_id="AS005",
                    message=(
                        "This workflow uses static AWS access keys stored as "
                        "GitHub secrets. Consider migrating to OIDC role "
                        "assumption, which does not require storing long-lived "
                        "credentials."
                    ),
                    level="warning",
                    security_severity="5.0",
                    location_path=binding.credential_source.workflow_file,
                    location_line=1,
                )
            )

    for finding in result.unpinned_actions:
        short_sha = finding.pin_type == "short_sha"
        results.append(
            _make_result(
                rule_id="AS006",
                message=(
                    f"External action '{finding.uses}' is not pinned to a full "
                    "40-character commit SHA. "
                    + (
                        "Short SHA-like refs are still mutable or ambiguous. "
                        if short_sha
                        else "Version tags and branches are mutable. "
                    )
                    + "Pin to a full SHA to reduce supply-chain risk."
                ),
                level="warning",
                security_severity="4.0",
                location_path=finding.workflow_file,
                location_line=1,
            )
        )

    for finding in result.oidc_trust_findings:
        results.append(
            _make_result(
                rule_id="AS008" if finding.issue_id == "missing_sub" else "AS007",
                message=f"{finding.issue_description}. Evidence: {finding.evidence}",
                level=RISK_TO_SARIF_SEVERITY[finding.risk_level],
                security_severity=RISK_TO_SECURITY_SEVERITY[finding.risk_level],
                location_path=finding.source_file,
                location_line=1,
            )
        )

    for finding in result.script_injection_findings:
        results.append(
            _make_result(
                rule_id="AS009",
                message=(
                    f"Direct script injection risk: {finding.untrusted_expression}. "
                    f"{finding.description}"
                ),
                level=RISK_TO_SARIF_SEVERITY[finding.risk_level],
                security_severity=RISK_TO_SECURITY_SEVERITY[finding.risk_level],
                location_path=finding.workflow_file,
                location_line=1,
            )
        )

    for finding in result.artifact_poisoning_findings:
        results.append(
            _make_result(
                rule_id="AS010",
                message=f"Artifact poisoning risk: {finding.description}",
                level=RISK_TO_SARIF_SEVERITY[finding.risk_level],
                security_severity=RISK_TO_SECURITY_SEVERITY[finding.risk_level],
                location_path=finding.workflow_file,
                location_line=1,
            )
        )

    for finding in result.ai_agent_injection_findings:
        results.append(
            _make_result(
                rule_id="AS012" if finding.has_aws_secret_access else "AS011",
                message=(
                    f"AI agent prompt injection surface ({finding.agent_type}): "
                    f"{finding.description}"
                ),
                level=RISK_TO_SARIF_SEVERITY[finding.risk_level],
                security_severity=RISK_TO_SECURITY_SEVERITY[finding.risk_level],
                location_path=finding.workflow_file,
                location_line=1,
            )
        )

    for finding in result.compromised_action_findings:
        results.append(
            _make_result(
                rule_id="AS013",
                message=(
                    f"Known-compromised action {finding.uses_ref}: "
                    f"{finding.description} Advisory: {finding.advisory_url}"
                ),
                level="error",
                security_severity="10.0",
                location_path=finding.workflow_file,
                location_line=1,
            )
        )

    for finding in result.environment_findings:
        results.append(
            _make_result(
                rule_id="AS014",
                message=(
                    f"GitHub Environment issue ({finding.finding_type}): "
                    f"{finding.description}"
                ),
                level=RISK_TO_SARIF_SEVERITY[finding.risk_level],
                security_severity=RISK_TO_SECURITY_SEVERITY[finding.risk_level],
                location_path=finding.workflow_file,
                location_line=1,
            )
        )

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ActionScope",
                        "version": __version__,
                        "informationUri": "https://github.com/r12habh/ActionScope",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)


def write_sarif(result: ScanResult, output_path: str) -> None:
    """Write SARIF JSON to a file."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(to_sarif(result))


def to_sarif_from_dict(data: dict[str, Any]) -> str:
    """Convert a saved ActionScope JSON payload to SARIF without re-scanning."""
    results: list[dict[str, Any]] = []

    for finding in data.get("findings", []):
        workflow_file = str(finding.get("workflow_file", ""))
        risk = _risk_from_string(str(finding.get("overall_risk", "info")))
        if risk >= RiskLevel.MEDIUM:
            results.append(
                _make_result(
                    rule_id="AS001",
                    message=(
                        f"[{risk.name}] Workflow '{workflow_file}' assumes "
                        f"{finding.get('role_arn') or 'an AWS role'}."
                    ),
                    level=RISK_TO_SARIF_SEVERITY[risk],
                    security_severity=RISK_TO_SECURITY_SEVERITY[risk],
                    location_path=workflow_file,
                    location_line=1,
                )
            )

        if finding.get("has_passrole"):
            results.append(
                _make_result(
                    rule_id="AS003",
                    message=(
                        "iam:PassRole is allowed on this role. This can create "
                        "a privilege escalation path if the resource is '*' or "
                        "overly broad."
                    ),
                    level="error",
                    security_severity="9.0",
                    location_path=workflow_file,
                    location_line=1,
                )
            )

        if finding.get("auth_type") == "access_keys":
            results.append(
                _make_result(
                    rule_id="AS005",
                    message=(
                        "This workflow uses static AWS access keys stored as "
                        "GitHub secrets. Consider migrating to OIDC role "
                        "assumption."
                    ),
                    level="warning",
                    security_severity="5.0",
                    location_path=workflow_file,
                    location_line=1,
                )
            )

    for permission in data.get("github_token_permissions", []):
        risk = _risk_from_string(str(permission.get("risk_level", "info")))
        if risk >= RiskLevel.HIGH:
            results.append(
                _make_result(
                    rule_id="AS004",
                    message=(
                        f"GITHUB_TOKEN has '{permission.get('scope')}: "
                        f"{permission.get('access')}' permission in "
                        f"{permission.get('workflow_file')}"
                    ),
                    level=RISK_TO_SARIF_SEVERITY[risk],
                    security_severity=RISK_TO_SECURITY_SEVERITY[risk],
                    location_path=str(permission.get("workflow_file", "")),
                    location_line=1,
                )
            )

    for finding in data.get("unpinned_actions", []):
        short_sha = finding.get("pin_type") == "short_sha"
        results.append(
            _make_result(
                rule_id="AS006",
                message=(
                    f"External action '{finding.get('uses')}' is not pinned "
                    "to a full 40-character commit SHA. "
                    + (
                        "Short SHA-like refs are still mutable or ambiguous. "
                        if short_sha
                        else "Version tags and branches are mutable. "
                    )
                    + "Pin to a full SHA to reduce supply-chain risk."
                ),
                level="warning",
                security_severity="4.0",
                location_path=str(finding.get("workflow_file", "")),
                location_line=1,
            )
        )

    for finding in data.get("oidc_trust_findings", []):
        risk = _risk_from_string(str(finding.get("risk_level", "info")))
        results.append(
            _make_result(
                rule_id=(
                    "AS008"
                    if finding.get("issue_id") == "missing_sub"
                    else "AS007"
                ),
                message=str(finding.get("issue_description", "OIDC trust issue")),
                level=RISK_TO_SARIF_SEVERITY[risk],
                security_severity=RISK_TO_SECURITY_SEVERITY[risk],
                location_path=str(finding.get("source_file", "")),
                location_line=1,
            )
        )

    for finding in data.get("script_injection_findings", []):
        risk = _risk_from_string(str(finding.get("risk_level", "info")))
        results.append(
            _make_result(
                rule_id="AS009",
                message=str(finding.get("description", "Script injection risk")),
                level=RISK_TO_SARIF_SEVERITY[risk],
                security_severity=RISK_TO_SECURITY_SEVERITY[risk],
                location_path=str(finding.get("workflow_file", "")),
                location_line=1,
            )
        )

    for finding in data.get("artifact_poisoning_findings", []):
        risk = _risk_from_string(str(finding.get("risk_level", "info")))
        results.append(
            _make_result(
                rule_id="AS010",
                message=str(finding.get("description", "Artifact poisoning risk")),
                level=RISK_TO_SARIF_SEVERITY[risk],
                security_severity=RISK_TO_SECURITY_SEVERITY[risk],
                location_path=str(finding.get("workflow_file", "")),
                location_line=1,
            )
        )

    for finding in data.get("ai_agent_injection_findings", []):
        risk = _risk_from_string(str(finding.get("risk_level", "info")))
        results.append(
            _make_result(
                rule_id="AS012" if finding.get("has_aws_secret_access") else "AS011",
                message=str(
                    finding.get("description", "AI agent prompt injection surface")
                ),
                level=RISK_TO_SARIF_SEVERITY[risk],
                security_severity=RISK_TO_SECURITY_SEVERITY[risk],
                location_path=str(finding.get("workflow_file", "")),
                location_line=1,
            )
        )

    for finding in data.get("compromised_action_findings", []):
        results.append(
            _make_result(
                rule_id="AS013",
                message=(
                    f"Known-compromised action {finding.get('uses_ref')}: "
                    f"{finding.get('description', '')} "
                    f"Advisory: {finding.get('advisory_url', '')}"
                ),
                level="error",
                security_severity="10.0",
                location_path=str(finding.get("workflow_file", "")),
                location_line=1,
            )
        )

    for finding in data.get("environment_findings", []):
        risk = _risk_from_string(str(finding.get("risk_level", "info")))
        results.append(
            _make_result(
                rule_id="AS014",
                message=str(
                    finding.get("description", "GitHub Environment issue")
                ),
                level=RISK_TO_SARIF_SEVERITY[risk],
                security_severity=RISK_TO_SECURITY_SEVERITY[risk],
                location_path=str(finding.get("workflow_file", "")),
                location_line=1,
            )
        )

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ActionScope",
                        "version": __version__,
                        "informationUri": "https://github.com/r12habh/ActionScope",
                        "rules": _build_rules(),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def _risk_from_string(value: str) -> RiskLevel:
    try:
        return RiskLevel(value.lower())
    except ValueError:
        return RiskLevel.INFO


def _github_token_result(permission: GitHubTokenPermission) -> dict[str, Any]:
    return _make_result(
        rule_id="AS004",
        message=(
            f"GITHUB_TOKEN has '{permission.scope}: {permission.access}' "
            f"permission in {permission.workflow_file}"
            + (f" (job: {permission.job_name})" if permission.job_name else "")
        ),
        level=RISK_TO_SARIF_SEVERITY[permission.risk_level],
        security_severity=RISK_TO_SECURITY_SEVERITY[permission.risk_level],
        location_path=permission.workflow_file,
        location_line=1,
    )


def _make_result(
    rule_id: str,
    message: str,
    level: str,
    security_severity: str,
    location_path: str,
    location_line: int,
) -> dict[str, Any]:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "properties": {
            "security-severity": security_severity,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": location_path.lstrip("/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": location_line,
                    },
                }
            }
        ],
    }


def _build_rules() -> list[dict[str, Any]]:
    return [
        {
            "id": "AS001",
            "name": "AwsBlastRadiusDetected",
            "shortDescription": {
                "text": "GitHub Actions workflow has AWS blast radius"
            },
            "fullDescription": {
                "text": (
                    "A GitHub Actions workflow assumes an AWS IAM role with "
                    "permissions that could cause significant impact if the "
                    "workflow is compromised."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {"tags": ["security", "aws", "iam"]},
        },
        {
            "id": "AS002",
            "name": "PrivilegeEscalationPath",
            "shortDescription": {
                "text": "IAM privilege escalation path detected"
            },
            "fullDescription": {
                "text": (
                    "The AWS IAM role assumed by this workflow contains "
                    "permissions that could be combined to escalate privileges "
                    "within the AWS account."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {
                "tags": ["security", "aws", "iam", "privilege-escalation"]
            },
        },
        {
            "id": "AS003",
            "name": "IamPassRoleDetected",
            "shortDescription": {"text": "iam:PassRole detected in workflow role"},
            "fullDescription": {
                "text": (
                    "iam:PassRole allows passing an IAM role to an AWS service. "
                    "When granted on wildcard resources, this can enable "
                    "privilege escalation to any role in the account."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {
                "tags": ["security", "aws", "iam", "privilege-escalation"]
            },
        },
        {
            "id": "AS004",
            "name": "DangerousGitHubTokenPermission",
            "shortDescription": {
                "text": "GITHUB_TOKEN has elevated permissions"
            },
            "fullDescription": {
                "text": (
                    "The GITHUB_TOKEN for this workflow has write-level "
                    "permissions that expand what the workflow can do to the "
                    "repository. Elevated permissions increase the impact of a "
                    "compromised workflow."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {"tags": ["security", "github-actions", "permissions"]},
        },
        {
            "id": "AS005",
            "name": "StaticAwsCredentialsUsed",
            "shortDescription": {
                "text": "Workflow uses static AWS access keys"
            },
            "fullDescription": {
                "text": (
                    "This workflow uses static AWS access keys stored as "
                    "GitHub secrets. Static keys are long-lived and create a "
                    "larger credential exposure surface than OIDC role "
                    "assumption."
                )
            },
            "helpUri": (
                "https://docs.github.com/en/actions/security-for-github-actions/"
                "security-hardening-your-deployments/"
                "configuring-openid-connect-in-amazon-web-services"
            ),
            "properties": {"tags": ["security", "aws", "credentials"]},
        },
        {
            "id": "AS006",
            "name": "UnpinnedGitHubAction",
            "shortDescription": {
                "text": "External action not pinned to commit SHA"
            },
            "fullDescription": {
                "text": (
                    "This workflow references an external GitHub Action by tag, "
                    "branch, or without a ref. Mutable action references can be "
                    "retargeted by maintainers or attackers after compromise."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {
                "tags": ["security", "github-actions", "supply-chain"]
            },
        },
        {
            "id": "AS007",
            "name": "OIDCWildcardSubject",
            "shortDescription": {
                "text": "GitHub OIDC trust policy is too broadly scoped"
            },
            "fullDescription": {
                "text": (
                    "The AWS trust policy for a GitHub Actions OIDC role uses "
                    "wildcards or insufficient branch/environment scoping, "
                    "allowing more workflows to assume the role than intended."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {"tags": ["security", "aws", "oidc", "iam"]},
        },
        {
            "id": "AS008",
            "name": "OIDCMissingSubCondition",
            "shortDescription": {
                "text": "GitHub OIDC trust policy is missing a sub condition"
            },
            "fullDescription": {
                "text": (
                    "The AWS trust policy does not constrain the GitHub OIDC "
                    "subject claim. Older roles with this condition missing can "
                    "allow unintended GitHub workflows to assume the role."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {"tags": ["security", "aws", "oidc", "iam"]},
        },
        {
            "id": "AS009",
            "name": "ScriptInjectionRisk",
            "shortDescription": {
                "text": "Untrusted GitHub context is interpolated into run"
            },
            "fullDescription": {
                "text": (
                    "A workflow run block directly interpolates attacker-"
                    "controlled GitHub event content, which can lead to shell "
                    "command injection."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {
                "tags": ["security", "github-actions", "script-injection"]
            },
        },
        {
            "id": "AS010",
            "name": "ArtifactPoisoningRisk",
            "shortDescription": {
                "text": "workflow_run downloads and executes artifacts"
            },
            "fullDescription": {
                "text": (
                    "A privileged workflow_run workflow downloads artifacts "
                    "from another workflow and executes content after download."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {
                "tags": ["security", "github-actions", "artifact-poisoning"]
            },
        },
        {
            "id": "AS011",
            "name": "AiAgentInjectionSurface",
            "shortDescription": {
                "text": "AI coding agent may process untrusted GitHub content"
            },
            "fullDescription": {
                "text": (
                    "An AI coding agent runs in a workflow triggered by "
                    "untrusted GitHub content and may be prompt-injected by "
                    "PR, issue, or comment text."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {
                "tags": ["security", "github-actions", "ai-agent"]
            },
        },
        {
            "id": "AS012",
            "name": "AiAgentWithAws",
            "shortDescription": {
                "text": "AI coding agent runs alongside AWS credentials"
            },
            "fullDescription": {
                "text": (
                    "An AI coding agent runs in a workflow that also configures "
                    "AWS credentials, increasing the impact of prompt injection."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {
                "tags": ["security", "github-actions", "ai-agent", "aws"]
            },
        },
        {
            "id": "AS013",
            "name": "KnownCompromisedAction",
            "shortDescription": {
                "text": "Workflow uses a known-compromised GitHub Action"
            },
            "fullDescription": {
                "text": (
                    "This workflow references a GitHub Action with a documented "
                    "supply-chain compromise. Mutable tags can be retargeted to "
                    "credential-stealing commits."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {
                "tags": ["security", "github-actions", "supply-chain"]
            },
        },
        {
            "id": "AS014",
            "name": "GitHubEnvironmentOidcScope",
            "shortDescription": {
                "text": "Deploy job is missing GitHub Environment hardening"
            },
            "fullDescription": {
                "text": (
                    "AWS deploy workflows should use GitHub Environments and "
                    "OIDC trust policies scoped to the environment subject so "
                    "environment protection rules can gate role access."
                )
            },
            "helpUri": "https://github.com/r12habh/ActionScope#readme",
            "properties": {
                "tags": ["security", "github-actions", "oidc", "environment"]
            },
        },
    ]


def _blast_radius_message(binding: WorkflowCredentialBinding) -> str:
    credential_source = binding.credential_source
    policy_finding: PolicyFinding | None = binding.policy_finding
    if policy_finding is None:
        return "AWS credential source found but policy could not be determined."

    risk_label = policy_finding.overall_risk.name
    role_info = (
        f"role {credential_source.role_arn}"
        if credential_source.role_arn
        else "an AWS role"
    )
    action_count = len(policy_finding.actions)

    message = (
        f"[{risk_label}] Workflow '{credential_source.workflow_file}' "
        f"(job: {credential_source.job_name}) assumes {role_info} with "
        f"{action_count} IAM action(s) analyzed."
    )

    if policy_finding.has_passrole:
        message += " Role includes iam:PassRole."
    if policy_finding.has_star_action:
        message += " Role has Action: * (all permissions)."
    if policy_finding.has_privilege_escalation:
        message += " Privilege escalation path detected."

    return message
