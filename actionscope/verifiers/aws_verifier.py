"""AWS IAM verifier for fetching live role policies in read-only mode."""

from __future__ import annotations

import json
import sys
import time
from typing import Any
from urllib.parse import unquote

try:
    import boto3
    import botocore.exceptions

    HAS_BOTO3 = True
except ImportError:  # pragma: no cover - exercised when optional extra missing
    boto3 = None
    botocore = None
    HAS_BOTO3 = False

from actionscope.models import AwsCredentialSource, IamAction, PolicyFinding, RiskLevel
from actionscope.parsers.policy_json import extract_actions_from_policy

_API_SLEEP_SECONDS = 0.2
_REQUIRED_PERMISSIONS = (
    "iam:GetRole",
    "iam:ListAttachedRolePolicies",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:ListRolePolicies",
    "iam:GetRolePolicy",
)


def check_boto3_available() -> None:
    """Raise when the optional AWS dependencies are not installed."""
    if not HAS_BOTO3:
        raise RuntimeError(
            "AWS verification requires boto3. Install with: "
            "pip install actionscope[aws]"
        )


def get_iam_client(region: str = "us-east-1"):
    """Return a boto3 IAM client using the caller's default AWS credentials."""
    check_boto3_available()

    try:
        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials is None:
            raise RuntimeError(_missing_credentials_message())
        return session.client("iam", region_name=region)
    except botocore.exceptions.NoCredentialsError as exc:
        raise RuntimeError(_missing_credentials_message()) from exc
    except botocore.exceptions.PartialCredentialsError as exc:
        raise RuntimeError(_missing_credentials_message()) from exc


def extract_role_name_from_arn(role_arn: str) -> str | None:
    """Extract the role name from a valid IAM role ARN."""
    if not isinstance(role_arn, str):
        return None

    marker = ":role/"
    if not role_arn.startswith("arn:aws:iam::") or marker not in role_arn:
        return None

    role_path = role_arn.split(marker, 1)[1].strip("/")
    if not role_path:
        return None

    return role_path.rsplit("/", 1)[-1]


def is_dynamic_reference(role_arn: str) -> bool:
    """Return True when a role ARN is a GitHub Actions expression."""
    if not isinstance(role_arn, str):
        return False
    return "${{" in role_arn and "}}" in role_arn


def fetch_role_policies(role_name: str, iam_client) -> dict:
    """Fetch all managed and inline policy documents attached to a role."""
    try:
        role_response = _call_iam(iam_client.get_role, RoleName=role_name)
        role = role_response.get("Role", {})
        role_arn = str(role.get("Arn", ""))

        managed_policies: list[dict[str, Any]] = []
        inline_policies: list[dict[str, Any]] = []
        all_statements: list[dict[str, Any]] = []

        attached_paginator = iam_client.get_paginator("list_attached_role_policies")
        for page in attached_paginator.paginate(RoleName=role_name):
            _sleep_between_api_calls()
            for attached in page.get("AttachedPolicies", []):
                policy_name = str(attached.get("PolicyName", ""))
                policy_arn = str(attached.get("PolicyArn", ""))
                policy_response = _call_iam(
                    iam_client.get_policy,
                    PolicyArn=policy_arn,
                )
                default_version_id = policy_response["Policy"]["DefaultVersionId"]
                version_response = _call_iam(
                    iam_client.get_policy_version,
                    PolicyArn=policy_arn,
                    VersionId=default_version_id,
                )
                document = _parse_policy_document(
                    version_response["PolicyVersion"]["Document"]
                )
                managed_policies.append(
                    {
                        "policy_name": policy_name,
                        "policy_arn": policy_arn,
                        "document": document,
                    }
                )
                all_statements.extend(_statements_from_document(document))

        inline_paginator = iam_client.get_paginator("list_role_policies")
        for page in inline_paginator.paginate(RoleName=role_name):
            _sleep_between_api_calls()
            for policy_name in page.get("PolicyNames", []):
                policy_response = _call_iam(
                    iam_client.get_role_policy,
                    RoleName=role_name,
                    PolicyName=policy_name,
                )
                document = _parse_policy_document(policy_response["PolicyDocument"])
                inline_policies.append(
                    {
                        "policy_name": str(policy_name),
                        "document": document,
                    }
                )
                all_statements.extend(_statements_from_document(document))

        return {
            "role_name": role_name,
            "role_arn": role_arn,
            "managed_policies": managed_policies,
            "inline_policies": inline_policies,
            "all_statements": all_statements,
        }
    except botocore.exceptions.ClientError as exc:
        return _client_error_dict(exc, role_name)
    except Exception as exc:
        return {
            "error": "aws_api_error",
            "role_name": role_name,
            "detail": str(exc),
        }


def verify_credential_source(
    credential_source: AwsCredentialSource,
    iam_client,
) -> PolicyFinding | None:
    """Fetch and classify the live AWS policies for one credential source."""
    role_arn = credential_source.role_arn
    if role_arn is None:
        return None

    if is_dynamic_reference(role_arn):
        _warn(f"Skipping dynamic role ARN reference: {role_arn}")
        return None

    role_name = extract_role_name_from_arn(role_arn)
    if role_name is None:
        _warn(f"Skipping invalid IAM role ARN: {role_arn}")
        return None

    fetched = fetch_role_policies(role_name, iam_client)
    if "error" in fetched:
        return _error_policy_finding(
            source_file=f"aws://iam/role/{role_name}",
            role_arn=role_arn,
            error=str(fetched.get("error", "aws_api_error")),
            detail=str(fetched.get("detail", "")),
        )

    policy_document = {
        "Version": "2012-10-17",
        "Statement": fetched.get("all_statements", []),
    }
    finding = extract_actions_from_policy(
        policy_document,
        source_file=f"aws://iam/role/{role_name}",
    )
    finding.source_type = "aws_verified"
    finding.role_arn = role_arn
    finding.metadata["aws_verification_status"] = "success"
    return finding


def verify_all_credential_sources(
    credential_sources: list[AwsCredentialSource],
    region: str = "us-east-1",
) -> tuple[list[PolicyFinding], list[str]]:
    """Verify all concrete role ARNs found in workflow credential sources."""
    check_boto3_available()
    if not credential_sources:
        return [], []

    iam_client = get_iam_client(region=region)

    findings: list[PolicyFinding] = []
    errors: list[str] = []
    seen_role_arns: set[str] = set()

    for credential_source in credential_sources:
        role_arn = credential_source.role_arn
        if role_arn is None:
            continue
        if role_arn in seen_role_arns:
            continue
        seen_role_arns.add(role_arn)

        if is_dynamic_reference(role_arn):
            message = f"Skipping dynamic role ARN reference: {role_arn}"
            errors.append(message)
            print(
                f"Verifying role: {role_arn}... ✗ (dynamic reference)",
                file=sys.stderr,
            )
            continue

        role_name = extract_role_name_from_arn(role_arn)
        if role_name is None:
            message = f"Skipping invalid IAM role ARN: {role_arn}"
            errors.append(message)
            print(f"Verifying role: {role_arn}... ✗ (invalid ARN)", file=sys.stderr)
            continue

        print(f"Verifying role: {role_name}...", end=" ", file=sys.stderr)
        finding = verify_credential_source(credential_source, iam_client)
        detail = _error_detail_from_finding(finding) if finding is not None else ""
        if finding is None:
            errors.append(f"No AWS policy finding produced for role: {role_arn}")
            print("✗ (not verified)", file=sys.stderr)
        elif detail:
            findings.append(finding)
            errors.append(f"AWS verification for {role_name}: {detail}")
            print(f"✗ ({detail})", file=sys.stderr)
        elif finding.actions:
            findings.append(finding)
            print("✓", file=sys.stderr)
        else:
            findings.append(finding)
            errors.append(f"AWS verification for {role_name}: no actions found")
            print("✗ (no actions found)", file=sys.stderr)

        time.sleep(_API_SLEEP_SECONDS)

    return findings, errors


def _call_iam(function: Any, **kwargs: Any) -> Any:
    response = function(**kwargs)
    _sleep_between_api_calls()
    return response


def _sleep_between_api_calls() -> None:
    time.sleep(_API_SLEEP_SECONDS)


def _parse_policy_document(document: Any) -> dict[str, Any]:
    if isinstance(document, dict):
        return document

    if not isinstance(document, str):
        return {}

    decoded = unquote(document)
    try:
        parsed = json.loads(decoded)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _statements_from_document(document: dict[str, Any]) -> list[dict[str, Any]]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    return [statement for statement in statements if isinstance(statement, dict)]


def _client_error_dict(exc: Any, role_name: str) -> dict[str, str]:
    error = exc.response.get("Error", {})
    code = str(error.get("Code", "ClientError"))
    detail = str(error.get("Message", exc))

    normalized = code.lower()
    if normalized == "nosuchentity":
        return {
            "error": "role_not_found",
            "role_name": role_name,
            "detail": detail,
        }
    if normalized in {"accessdenied", "accessdeniedexception"}:
        return {
            "error": "access_denied",
            "role_name": role_name,
            "detail": detail,
        }
    return {
        "error": "client_error",
        "role_name": role_name,
        "detail": f"{code}: {detail}",
    }


def _error_policy_finding(
    source_file: str,
    role_arn: str,
    error: str,
    detail: str,
) -> PolicyFinding:
    description = f"AWS verification error: {error}"
    if detail:
        description = f"{description} — {detail}"
    return PolicyFinding(
        source_file=source_file,
        source_type="aws_verified",
        role_arn=role_arn,
        actions=[
            IamAction(
                action="aws:VerifyRolePolicies",
                access_level="Info",
                risk_level=RiskLevel.INFO,
                description=description,
                resource=role_arn,
            )
        ],
        overall_risk=RiskLevel.INFO,
        metadata={
            "aws_verification_status": "error",
            "aws_verification_error": error,
        },
    )


def _error_detail_from_finding(finding: PolicyFinding) -> str:
    if not finding.actions:
        return ""
    action = finding.actions[0]
    if action.action == "aws:VerifyRolePolicies":
        return action.description.removeprefix("AWS verification error: ")
    return ""


def _missing_credentials_message() -> str:
    return (
        "No AWS credentials found. Configure with: aws configure\n"
        "Or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.\n"
        "ActionScope only needs these IAM read permissions:\n"
        f"{', '.join(_REQUIRED_PERMISSIONS)}"
    )


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)
