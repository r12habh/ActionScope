"""Terraform HCL parser for extracting AWS IAM resources and policies."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import hcl2

from actionscope.analyzers.iam_risk import classify_actions, get_overall_risk
from actionscope.models import IamAction, PolicyFinding, RiskLevel

PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:attachrolepolicy",
    "iam:createpolicyversion",
    "iam:createloginprofile",
    "iam:addusertogroup",
    "iam:updateloginprofile",
    "iam:setdefaultpolicyversion",
}


def find_terraform_files(repo_path: str) -> list[str]:
    """Find Terraform .tf files under a repository path."""
    repo = Path(repo_path).expanduser()
    if not repo.is_dir():
        return []

    files = []
    for path in repo.rglob("*.tf"):
        if ".terraform" in path.parts:
            continue
        if path.name == ".terraform.lock.hcl":
            continue
        files.append(path.resolve())

    return [str(path) for path in sorted(files)]


def parse_terraform_file(filepath: str) -> dict | None:
    """Parse a Terraform file with python-hcl2."""
    try:
        with Path(filepath).open("r", encoding="utf-8") as terraform_file:
            data = hcl2.load(terraform_file)
    except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError) as exc:
        _warn(f"Could not read Terraform file {filepath}: {exc}")
        return None
    except Exception as exc:
        _warn(f"Could not parse Terraform file {filepath}: {exc}")
        return None

    return data if isinstance(data, dict) else None


def extract_iam_policies_from_terraform(
    tf_data: dict,
    source_file: str,
) -> list[PolicyFinding]:
    """Extract IAM policy definitions from parsed Terraform data."""
    findings: list[PolicyFinding] = []

    for resource_type, _resource_name, body in _iter_blocks(tf_data.get("resource")):
        if resource_type == "aws_iam_policy":
            findings.append(
                _finding_from_policy_value(body.get("policy"), source_file)
            )
        elif resource_type == "aws_iam_role_policy":
            findings.append(
                _finding_from_policy_value(
                    body.get("policy"),
                    source_file,
                    role_arn=_clean_string(body.get("role")),
                )
            )
        elif resource_type == "aws_iam_role":
            assume_role_policy = body.get("assume_role_policy")
            if assume_role_policy is not None:
                findings.append(
                    _finding_from_policy_value(assume_role_policy, source_file)
                )

    for data_type, _data_name, body in _iter_blocks(tf_data.get("data")):
        if data_type == "aws_iam_policy_document":
            findings.append(_finding_from_policy_document(body, source_file))

    return findings


def scan_terraform_files(repo_path: str) -> tuple[list[PolicyFinding], list[str]]:
    """Find and parse all Terraform files in a repository."""
    findings: list[PolicyFinding] = []
    errors: list[str] = []

    for terraform_file in find_terraform_files(repo_path):
        tf_data = parse_terraform_file(terraform_file)
        if tf_data is None:
            errors.append(f"Could not parse Terraform file: {terraform_file}")
            continue

        findings.extend(extract_iam_policies_from_terraform(tf_data, terraform_file))

    return findings, errors


def _iter_blocks(blocks: Any) -> Any:
    """Yield (type, name, body) for Terraform resource/data blocks.

    python-hcl2 may return ``resource`` / ``data`` as a list of single-key dicts
    or as one dict mapping resource types to nested maps.
    """
    if blocks is None:
        return

    if isinstance(blocks, dict):
        blocks_list: list[Any] = [blocks]
    elif isinstance(blocks, list):
        blocks_list = blocks
    else:
        return

    for block in blocks_list:
        if not isinstance(block, dict):
            continue
        for block_type, named_blocks in block.items():
            block_type = _clean_string(block_type)
            if isinstance(named_blocks, dict):
                for block_name, body in named_blocks.items():
                    if isinstance(body, dict):
                        yield block_type, _clean_string(block_name), body
            elif isinstance(named_blocks, list):
                for item in named_blocks:
                    if not isinstance(item, dict):
                        continue
                    for block_name, body in item.items():
                        if isinstance(body, dict):
                            yield block_type, _clean_string(block_name), body


def _finding_from_policy_value(
    policy_value: Any,
    source_file: str,
    role_arn: str | None = None,
) -> PolicyFinding:
    policy_data = _parse_policy_value(policy_value)
    if policy_data is None:
        return _empty_finding(source_file, role_arn=role_arn)

    statements = policy_data.get("Statement", [])
    return _finding_from_statements(statements, source_file, role_arn=role_arn)


def _finding_from_policy_document(body: dict, source_file: str) -> PolicyFinding:
    statements = body.get("statement", [])
    return _finding_from_statements(statements, source_file, terraform_document=True)


def _finding_from_statements(
    statements: Any,
    source_file: str,
    terraform_document: bool = False,
    role_arn: str | None = None,
) -> PolicyFinding:
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        statements = []

    actions: list[IamAction] = []
    has_star_action = False
    has_star_resource = False
    has_passrole = False
    has_privilege_escalation = False

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        if _has_not_actions(statement):
            _warn(f"Skipping not_actions statement in {source_file}")
            continue

        effect = _statement_value(statement, "effect", "Effect")
        if _clean_string(effect or "").lower() == "deny":
            continue
        if effect is not None and _clean_string(effect).lower() != "allow":
            continue

        raw_actions = _statement_value(
            statement,
            "actions" if terraform_document else "Action",
            "Action",
            "actions",
        )
        raw_resources = _statement_value(
            statement,
            "resources" if terraform_document else "Resource",
            "Resource",
            "resources",
        )

        statement_actions = _string_list(raw_actions)
        resources = _string_list(raw_resources)
        if not statement_actions or not resources:
            continue

        resource = _resource_for_analysis(resources)
        classified_actions = classify_actions(statement_actions, resource=resource)
        actions.extend(classified_actions)

        normalized_actions = {action.action.lower() for action in classified_actions}
        has_star_action = has_star_action or "*" in statement_actions
        has_passrole = has_passrole or "iam:passrole" in normalized_actions

        statement_has_star_resource = resource == "*"
        statement_has_write_or_permissions = any(
            _is_write_or_permissions_action(action)
            for action in classified_actions
        )
        if statement_has_star_resource and statement_has_write_or_permissions:
            has_star_resource = True

        if statement_has_star_resource and (
            "iam:passrole" in normalized_actions
            or bool(PRIVILEGE_ESCALATION_ACTIONS & normalized_actions)
        ):
            has_privilege_escalation = True

    return PolicyFinding(
        source_file=source_file,
        source_type="terraform",
        role_arn=role_arn,
        actions=actions,
        has_star_action=has_star_action,
        has_star_resource=has_star_resource,
        has_passrole=has_passrole,
        has_privilege_escalation=has_privilege_escalation,
        overall_risk=get_overall_risk(actions),
    )


def _parse_policy_value(policy_value: Any) -> dict | None:
    if isinstance(policy_value, dict):
        return _normalize_terraform_value(policy_value)

    if not isinstance(policy_value, str):
        return None

    value = _clean_string(policy_value)
    jsonencode_arg = _extract_jsonencode_argument(value)
    if jsonencode_arg is not None:
        try:
            parsed = hcl2.loads(f"policy = {jsonencode_arg}")
        except Exception:
            return None
        policy = parsed.get("policy")
        return _normalize_terraform_value(policy) if isinstance(policy, dict) else None

    if value.startswith("${") and value.endswith("}"):
        return None

    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return None

    return data if isinstance(data, dict) else None


def _extract_jsonencode_argument(value: str) -> str | None:
    marker = "jsonencode("
    start = value.find(marker)
    if start == -1:
        return None

    start += len(marker)
    depth = 1
    in_string = False
    escape_next = False

    for index in range(start, len(value)):
        char = value[index]
        if escape_next:
            escape_next = False
            continue
        if char == "\\":
            escape_next = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return value[start:index]

    return None


def _normalize_terraform_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            _clean_string(key): _normalize_terraform_value(item)
            for key, item in value.items()
            if key != "__is_block__"
        }

    if isinstance(value, list):
        return [_normalize_terraform_value(item) for item in value]

    if isinstance(value, str):
        return _clean_string(value)

    return value


def _statement_value(statement: dict, *keys: str) -> Any:
    for key in keys:
        if key in statement:
            return statement[key]
    return None


def _has_not_actions(statement: dict) -> bool:
    return any(
        key in statement for key in ("not_actions", "NotAction", "not_action")
    )


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [_clean_string(value)]

    if isinstance(value, list):
        return [_clean_string(item) for item in value if isinstance(item, str)]

    return []


def _resource_for_analysis(resources: list[str]) -> str:
    if "*" in resources or any(
        _looks_variable_like(resource) for resource in resources
    ):
        return "*"
    return ", ".join(resources)


def _looks_variable_like(value: str) -> bool:
    normalized = value.strip()
    return (
        "${" in normalized
        or normalized.startswith("var.")
        or normalized.startswith("local.")
        or normalized.startswith("module.")
    )


def _is_write_or_permissions_action(action: IamAction) -> bool:
    return action.access_level in {"All", "Write", "Permissions management"} or (
        action.risk_level >= RiskLevel.MEDIUM
    )


def _empty_finding(source_file: str, role_arn: str | None = None) -> PolicyFinding:
    return PolicyFinding(
        source_file=source_file,
        source_type="terraform",
        role_arn=role_arn,
        actions=[],
        overall_risk=RiskLevel.INFO,
    )


def _clean_string(value: Any) -> str:
    if not isinstance(value, str):
        return str(value)

    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] == '"':
        return stripped[1:-1]
    return stripped


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)
