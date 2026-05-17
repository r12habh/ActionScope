"""Terraform HCL parser for extracting AWS IAM resources and policies."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import hcl2

from actionscope.analyzers.iam_risk import classify_actions, get_overall_risk
from actionscope.models import IamAction, PolicyFinding, RiskLevel

PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:attachrolepolicy",
    "iam:createpolicyversion",
}
IAM_ROLE_ARN_RE = re.compile(r"^arn:[^:]+:iam::\d{12}:role/.+")


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
    return _extract_iam_policies_from_parsed_files([(source_file, tf_data)])


def _extract_iam_policies_from_parsed_files(
    parsed_files: list[tuple[str, dict]],
) -> list[PolicyFinding]:
    """Extract IAM findings and resolve simple Terraform IAM relationships."""
    findings: list[PolicyFinding] = []
    data_documents: dict[str, PolicyFinding] = {}
    managed_policies: dict[str, PolicyFinding] = {}
    role_names: dict[str, str] = {}
    attachments: list[tuple[str, str, dict]] = []

    for source_file, tf_data in parsed_files:
        for data_type, data_name, body in _iter_blocks(tf_data.get("data")):
            if data_type != "aws_iam_policy_document":
                continue

            address = f"{data_type}.{data_name}"
            finding = _finding_from_policy_document(
                body,
                source_file,
                policy_name=data_name,
                metadata={"terraform_address": address},
            )
            data_documents[address] = finding
            findings.append(finding)

    for source_file, tf_data in parsed_files:
        for resource_type, resource_name, body in _iter_blocks(tf_data.get("resource")):
            address = f"{resource_type}.{resource_name}"

            if resource_type == "aws_iam_role":
                role_name = _role_name_from_role_resource(resource_name, body)
                if role_name:
                    role_names[address] = role_name
                continue

            if resource_type == "aws_iam_policy":
                policy_name = _clean_optional_string(body.get("name")) or resource_name
                finding = _finding_from_policy_value(
                    body.get("policy"),
                    source_file,
                    policy_name=policy_name,
                    metadata={"terraform_address": address},
                    data_documents=data_documents,
                )
                managed_policies[address] = finding
                findings.append(finding)
                continue

            if resource_type == "aws_iam_role_policy":
                role_reference = _clean_optional_string(body.get("role"))
                role_name = _resolve_role_reference(role_reference, role_names)
                finding = _finding_from_policy_value(
                    body.get("policy"),
                    source_file,
                    role_arn=_role_arn_if_literal(role_reference),
                    role_name=role_name,
                    policy_name=_clean_optional_string(body.get("name"))
                    or resource_name,
                    metadata={
                        "terraform_address": address,
                        "terraform_role_reference": role_reference or "",
                    },
                    data_documents=data_documents,
                )
                findings.append(finding)
                continue

            if resource_type == "aws_iam_role_policy_attachment":
                attachments.append((source_file, address, body))

    for _source_file, attachment_address, body in attachments:
        role_reference = _clean_optional_string(body.get("role"))
        policy_reference = _clean_optional_string(body.get("policy_arn"))
        role_name = _resolve_role_reference(role_reference, role_names)
        policy_address = _resolve_policy_reference(policy_reference)

        if not role_name or not policy_address:
            continue

        finding = managed_policies.get(policy_address)
        if finding is None:
            continue

        finding.role_name = role_name
        finding.metadata["terraform_attachment"] = attachment_address
        finding.metadata["terraform_role_reference"] = role_reference or ""

    return findings


def scan_terraform_files(repo_path: str) -> tuple[list[PolicyFinding], list[str]]:
    """Find and parse all Terraform files in a repository."""
    errors: list[str] = []
    parsed_files: list[tuple[str, dict]] = []

    for terraform_file in find_terraform_files(repo_path):
        tf_data = parse_terraform_file(terraform_file)
        if tf_data is None:
            errors.append(f"Could not parse Terraform file: {terraform_file}")
            continue

        parsed_files.append((terraform_file, tf_data))

    findings = _extract_iam_policies_from_parsed_files(parsed_files)
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
    role_name: str | None = None,
    policy_name: str | None = None,
    metadata: dict[str, object] | None = None,
    data_documents: dict[str, PolicyFinding] | None = None,
) -> PolicyFinding:
    referenced_document = _referenced_policy_document(
        policy_value,
        data_documents or {},
    )
    if referenced_document is not None:
        finding = _clone_policy_finding(
            referenced_document,
            source_file=source_file,
            role_arn=role_arn,
            role_name=role_name,
            policy_name=policy_name,
            metadata=metadata,
        )
        return finding

    policy_data = _parse_policy_value(policy_value, source_file)
    if policy_data is None:
        return _empty_finding(
            source_file,
            role_arn=role_arn,
            role_name=role_name,
            policy_name=policy_name,
            metadata=metadata,
        )

    statements = policy_data.get("Statement", [])
    return _finding_from_statements(
        statements,
        source_file,
        role_arn=role_arn,
        role_name=role_name,
        policy_name=policy_name,
        metadata=metadata,
    )


def _finding_from_policy_document(
    body: dict,
    source_file: str,
    policy_name: str | None = None,
    metadata: dict[str, object] | None = None,
) -> PolicyFinding:
    statements = body.get("statement", [])
    return _finding_from_statements(
        statements,
        source_file,
        terraform_document=True,
        policy_name=policy_name,
        metadata=metadata,
    )


def _finding_from_statements(
    statements: Any,
    source_file: str,
    terraform_document: bool = False,
    role_arn: str | None = None,
    role_name: str | None = None,
    policy_name: str | None = None,
    metadata: dict[str, object] | None = None,
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
        role_name=role_name,
        policy_name=policy_name,
        metadata=metadata or {},
    )


def _parse_policy_value(
    policy_value: Any,
    source_file: str | None = None,
) -> dict | None:
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

    file_arg = _extract_file_argument(value)
    if file_arg is not None and source_file is not None:
        return _parse_policy_file(file_arg, source_file)

    if value.startswith("${") and value.endswith("}"):
        return None

    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return None

    return data if isinstance(data, dict) else None


def _referenced_policy_document(
    policy_value: Any,
    data_documents: dict[str, PolicyFinding],
) -> PolicyFinding | None:
    if not isinstance(policy_value, str):
        return None

    reference = _terraform_reference_body(policy_value)
    if reference is None or not reference.endswith(".json"):
        return None

    address = reference.removesuffix(".json")
    return data_documents.get(address)


def _clone_policy_finding(
    finding: PolicyFinding,
    source_file: str,
    role_arn: str | None = None,
    role_name: str | None = None,
    policy_name: str | None = None,
    metadata: dict[str, object] | None = None,
) -> PolicyFinding:
    merged_metadata = dict(finding.metadata)
    merged_metadata.update(metadata or {})
    merged_metadata["referenced_policy_document"] = (
        finding.metadata.get("terraform_address") or finding.policy_name or ""
    )

    return PolicyFinding(
        source_file=source_file,
        source_type=finding.source_type,
        role_arn=role_arn,
        actions=list(finding.actions),
        has_star_action=finding.has_star_action,
        has_star_resource=finding.has_star_resource,
        has_passrole=finding.has_passrole,
        has_privilege_escalation=finding.has_privilege_escalation,
        overall_risk=finding.overall_risk,
        privesc_paths=list(finding.privesc_paths),
        role_name=role_name or finding.role_name,
        policy_name=policy_name or finding.policy_name,
        metadata=merged_metadata,
    )


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


def _extract_file_argument(value: str) -> str | None:
    marker = "file("
    start = value.find(marker)
    if start == -1:
        return None

    start += len(marker)
    end = value.find(")", start)
    if end == -1:
        return None

    raw_arg = value[start:end].strip()
    if not raw_arg:
        return None
    if raw_arg[0] in {"'", '"'} and raw_arg[-1:] == raw_arg[0]:
        raw_arg = raw_arg[1:-1]

    if any(marker in raw_arg for marker in ("${", "var.", "local.", "path.")):
        return None
    return raw_arg


def _parse_policy_file(policy_path: str, source_file: str) -> dict | None:
    base_dir = Path(source_file).resolve().parent
    candidate = (base_dir / policy_path).resolve()
    try:
        if not candidate.is_relative_to(base_dir):
            _warn(f"Skipping Terraform file() outside module directory: {policy_path}")
            return None
        with candidate.open("r", encoding="utf-8") as policy_file:
            data = json.load(policy_file)
    except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError) as exc:
        _warn(f"Could not read Terraform policy file {candidate}: {exc}")
        return None
    except json.JSONDecodeError as exc:
        _warn(f"Could not parse Terraform policy file {candidate}: {exc}")
        return None

    return data if isinstance(data, dict) else None


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


def _role_name_from_role_resource(resource_name: str, body: dict) -> str | None:
    _ = resource_name
    explicit_name = _clean_optional_string(body.get("name"))
    if explicit_name and not _looks_variable_like(explicit_name):
        return explicit_name.strip("/").rsplit("/", 1)[-1]
    return None


def _resolve_role_reference(
    role_reference: str | None,
    role_names: dict[str, str],
) -> str | None:
    if not role_reference:
        return None

    reference = _terraform_reference_body(role_reference)
    if reference:
        if reference.startswith("aws_iam_role."):
            address = ".".join(reference.split(".")[:2])
            return role_names.get(address)
        return None

    if role_reference.startswith("arn:"):
        marker = ":role/"
        if marker not in role_reference:
            return None
        return role_reference.split(marker, 1)[1].strip("/").rsplit("/", 1)[-1]

    if _looks_variable_like(role_reference):
        return None

    return role_reference.strip("/").rsplit("/", 1)[-1]


def _resolve_policy_reference(policy_reference: str | None) -> str | None:
    if not policy_reference:
        return None

    reference = _terraform_reference_body(policy_reference)
    if reference is None:
        return None

    if reference.startswith("aws_iam_policy."):
        parts = reference.split(".")
        if len(parts) >= 2:
            return ".".join(parts[:2])
    return None


def _role_arn_if_literal(role_reference: str | None) -> str | None:
    if role_reference and IAM_ROLE_ARN_RE.match(role_reference):
        return role_reference
    return None


def _terraform_reference_body(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    clean = _clean_string(value)
    if clean.startswith("${") and clean.endswith("}"):
        clean = clean[2:-1].strip()

    if clean.startswith(("aws_iam_", "data.aws_iam_")):
        if clean.startswith("data."):
            clean = clean.removeprefix("data.")
        return clean
    return None


def _empty_finding(
    source_file: str,
    role_arn: str | None = None,
    role_name: str | None = None,
    policy_name: str | None = None,
    metadata: dict[str, object] | None = None,
) -> PolicyFinding:
    return PolicyFinding(
        source_file=source_file,
        source_type="terraform",
        role_arn=role_arn,
        actions=[],
        overall_risk=RiskLevel.INFO,
        role_name=role_name,
        policy_name=policy_name,
        metadata=metadata or {},
    )


def _clean_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    return _clean_string(value)


def _clean_string(value: Any) -> str:
    if not isinstance(value, str):
        return str(value)

    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] == '"':
        return stripped[1:-1]
    return stripped


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)
