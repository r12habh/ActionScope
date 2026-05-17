"""Privilege escalation path detector for AWS IAM policy findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from actionscope.models import IamAction, PolicyFinding, RiskLevel

ESCALATION_PATHS: list[dict[str, Any]] = [
    {
        "id": "passrole_wildcard",
        "name": "IAM PassRole + Wildcard Resource",
        "required_actions": ["iam:PassRole"],
        "required_resource_pattern": "*",
        "description": (
            "Can pass any IAM role to an AWS service, enabling escalation "
            "to roles with higher privileges"
        ),
        "severity": RiskLevel.CRITICAL,
        "example_attack": (
            "Pass a role with admin access to a Lambda function, then invoke "
            "it to execute with elevated permissions"
        ),
    },
    {
        "id": "create_policy_version",
        "name": "Create New IAM Policy Version",
        "required_actions": ["iam:CreatePolicyVersion"],
        "required_resource_pattern": "*",
        "description": (
            "Can create a new version of any IAM policy, potentially making "
            "it grant admin access"
        ),
        "severity": RiskLevel.CRITICAL,
        "example_attack": "Create a new policy version with Action:* Resource:*",
    },
    {
        "id": "create_access_key",
        "name": "Create IAM User Access Key",
        "required_actions": ["iam:CreateAccessKey"],
        "required_resource_pattern": "*",
        "description": (
            "Can create access keys for any IAM user, including "
            "higher-privileged users"
        ),
        "severity": RiskLevel.CRITICAL,
        "example_attack": "Create an access key for an admin IAM user",
    },
    {
        "id": "attach_role_policy",
        "name": "Attach Policy to Any Role",
        "required_actions": ["iam:AttachRolePolicy"],
        "required_resource_pattern": "*",
        "description": "Can attach the AdministratorAccess policy to any role",
        "severity": RiskLevel.CRITICAL,
        "example_attack": "Attach AdministratorAccess to the current role",
    },
    {
        "id": "update_assume_role",
        "name": "Modify Role Trust Policy",
        "required_actions": ["iam:UpdateAssumeRolePolicy"],
        "required_resource_pattern": "*",
        "description": (
            "Can modify who can assume any role, enabling lateral movement "
            "to more privileged roles"
        ),
        "severity": RiskLevel.CRITICAL,
        "example_attack": (
            "Modify an admin role's trust policy to allow assumption by the "
            "current identity"
        ),
    },
    {
        "id": "lambda_create_function",
        "name": "Create Lambda + PassRole",
        "required_actions": ["lambda:CreateFunction", "iam:PassRole"],
        "required_resource_pattern": "*",
        "description": (
            "Can create a Lambda function with a more privileged role, then "
            "invoke it to execute arbitrary code as that role"
        ),
        "severity": RiskLevel.CRITICAL,
        "example_attack": "Create Lambda with admin role, invoke to get credentials",
    },
    {
        "id": "ec2_run_instances",
        "name": "EC2 RunInstances + PassRole",
        "required_actions": ["ec2:RunInstances", "iam:PassRole"],
        "required_resource_pattern": "*",
        "description": (
            "Can launch EC2 instances with instance profiles attached to "
            "more privileged roles"
        ),
        "severity": RiskLevel.CRITICAL,
        "example_attack": "Launch EC2 with admin instance profile, access metadata",
    },
    {
        "id": "cloudformation_create",
        "name": "CloudFormation CreateStack + PassRole",
        "required_actions": ["cloudformation:CreateStack", "iam:PassRole"],
        "required_resource_pattern": "*",
        "description": (
            "Can create a CloudFormation stack with a role that has higher "
            "privileges, executing arbitrary AWS actions"
        ),
        "severity": RiskLevel.CRITICAL,
        "example_attack": "Create stack with admin role to create IAM admin user",
    },
    {
        "id": "create_login_profile",
        "name": "Create IAM User Login Profile",
        "required_actions": ["iam:CreateLoginProfile"],
        "required_resource_pattern": "*",
        "description": (
            "Can create a login profile (password) for any IAM user, enabling "
            "AWS console access with that user's permissions"
        ),
        "severity": RiskLevel.CRITICAL,
        "example_attack": (
            "Create a login profile for an admin IAM user, then sign in to the "
            "AWS console as that user"
        ),
    },
    {
        "id": "add_user_to_group",
        "name": "Add IAM User to Group",
        "required_actions": ["iam:AddUserToGroup"],
        "required_resource_pattern": "*",
        "description": (
            "Can add any IAM user to any group, granting the user all "
            "permissions attached to that group"
        ),
        "severity": RiskLevel.CRITICAL,
        "example_attack": (
            "Add the current user to the Administrators group to inherit "
            "admin permissions"
        ),
    },
    {
        "id": "update_login_profile",
        "name": "Update IAM User Login Profile",
        "required_actions": ["iam:UpdateLoginProfile"],
        "required_resource_pattern": "*",
        "description": (
            "Can reset the console password for any IAM user, potentially "
            "enabling takeover of higher-privileged accounts"
        ),
        "severity": RiskLevel.CRITICAL,
        "example_attack": (
            "Reset the password for an admin IAM user and sign in to the "
            "AWS console as that user"
        ),
    },
    {
        "id": "set_default_policy_version",
        "name": "Set Default IAM Policy Version",
        "required_actions": ["iam:SetDefaultPolicyVersion"],
        "required_resource_pattern": "*",
        "description": (
            "Can change which version of a managed policy is the default "
            "(active) version, potentially activating a version that grants "
            "broader permissions"
        ),
        "severity": RiskLevel.CRITICAL,
        "example_attack": (
            "Create a new policy version that grants admin access, then set "
            "it as the default version"
        ),
    },
    {
        "id": "glue_create_dev_endpoint",
        "name": "Glue CreateDevEndpoint + PassRole",
        "required_actions": ["glue:CreateDevEndpoint", "iam:PassRole"],
        "required_resource_pattern": "*",
        "description": (
            "Can create a Glue development endpoint with a more privileged "
            "role and execute arbitrary code as that role via SSH"
        ),
        "severity": RiskLevel.CRITICAL,
        "example_attack": (
            "Create a Glue dev endpoint with an admin role, SSH into the "
            "endpoint, and exfiltrate AWS credentials from instance metadata"
        ),
    },
]


@dataclass
class PrivescFinding:
    """A matched AWS IAM privilege escalation path."""

    path_id: str
    path_name: str
    description: str
    example_attack: str
    severity: RiskLevel
    matched_actions: list[str]
    source_file: str


def detect_privesc_paths(
    policy_finding: PolicyFinding,
    source_file: str,
) -> list[PrivescFinding]:
    """Detect known AWS IAM privilege escalation paths in a policy finding."""
    if not policy_finding.actions:
        return []

    findings: list[PrivescFinding] = []
    for path in ESCALATION_PATHS:
        required_actions = [
            str(action) for action in path.get("required_actions", [])
        ]
        matched_actions = _matched_required_actions(
            required_actions,
            policy_finding.actions,
        )
        if len(matched_actions) != len(required_actions):
            continue

        if path.get("required_resource_pattern") == "*" and not _has_wildcard_match(
            required_actions,
            policy_finding.actions,
        ):
            continue

        findings.append(
            PrivescFinding(
                path_id=str(path["id"]),
                path_name=str(path["name"]),
                description=str(path["description"]),
                example_attack=str(path["example_attack"]),
                severity=path["severity"],
                matched_actions=matched_actions,
                source_file=source_file,
            )
        )

    return findings


def format_privesc_summary(findings: list[PrivescFinding]) -> str:
    """Return a plain-English multiline summary for terminal output."""
    if not findings:
        return ""

    plural = "path" if len(findings) == 1 else "paths"
    lines = [
        f"⚠️  {len(findings)} privilege escalation {plural} detected:",
        "",
    ]
    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"{index}. {finding.path_name} ({finding.severity.name})",
                f"   Attack: {finding.example_attack}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def _matched_required_actions(
    required_actions: list[str],
    actions: list[IamAction],
) -> list[str]:
    matched: list[str] = []
    for required_action in required_actions:
        match = next(
            (
                action.action
                for action in actions
                if _action_matches(required_action, action.action)
            ),
            None,
        )
        if match is not None:
            matched.append(match)
    return matched


def _has_wildcard_match(
    required_actions: list[str],
    actions: list[IamAction],
) -> bool:
    return any(
        _action_matches(required_action, action.action)
        and _resource_is_broad(action.resource)
        for required_action in required_actions
        for action in actions
    )


def _action_matches(required_action: str, candidate_action: str) -> bool:
    required = required_action.strip().lower()
    candidate = candidate_action.strip().lower()
    if candidate == "*":
        return True
    if candidate == required:
        return True
    if candidate.endswith(":*"):
        candidate_service = candidate.split(":", 1)[0]
        required_service = required.split(":", 1)[0]
        return candidate_service == required_service
    return False


def _resource_is_broad(resource: str) -> bool:
    resources = [part.strip().lower() for part in resource.split(",")]
    return any(
        candidate == "*"
        or candidate == "arn:aws:*"
        or candidate.startswith("arn:aws:*")
        for candidate in resources
    )
