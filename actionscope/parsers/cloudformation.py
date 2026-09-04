"""CloudFormation and SAM parser for repository-local IAM policy evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterator

import yaml

from actionscope.models import PolicyFinding
from actionscope.parsers.policy_json import extract_actions_from_policy

_PEEK_BYTES = 131_072
_SKIPPED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "vendor",
    "venv",
}
_INTRINSIC_NAMES = {
    "And": "Fn::And",
    "Base64": "Fn::Base64",
    "Cidr": "Fn::Cidr",
    "Equals": "Fn::Equals",
    "FindInMap": "Fn::FindInMap",
    "GetAtt": "Fn::GetAtt",
    "GetAZs": "Fn::GetAZs",
    "If": "Fn::If",
    "ImportValue": "Fn::ImportValue",
    "Join": "Fn::Join",
    "Not": "Fn::Not",
    "Or": "Fn::Or",
    "Ref": "Ref",
    "Select": "Fn::Select",
    "Split": "Fn::Split",
    "Sub": "Fn::Sub",
    "Transform": "Fn::Transform",
}


class CloudFormationLoader(yaml.SafeLoader):
    """YAML loader that preserves CloudFormation intrinsic functions."""


def _construct_intrinsic(
    loader: CloudFormationLoader,
    tag_suffix: str,
    node: yaml.Node,
) -> dict[str, Any]:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return {_INTRINSIC_NAMES.get(tag_suffix, tag_suffix): value}


CloudFormationLoader.add_multi_constructor("!", _construct_intrinsic)


def find_cloudformation_files(repo_path: str) -> list[str]:
    """Return repository files whose content resembles CloudFormation or SAM."""
    repo = Path(repo_path).expanduser()
    if not repo.is_dir():
        return []

    candidates: list[Path] = []
    for pattern in ("*.yaml", "*.yml", "*.json"):
        for path in repo.rglob(pattern):
            try:
                relative_parts = path.relative_to(repo).parts
            except ValueError:
                relative_parts = path.parts
            if any(part in _SKIPPED_DIRS for part in relative_parts):
                continue
            if _looks_like_cloudformation(path):
                candidates.append(path.resolve())
    return [str(path) for path in sorted(set(candidates))]


def parse_cloudformation_file(filepath: str) -> dict | None:
    """Parse one JSON or YAML CloudFormation/SAM template."""
    data, error = _load_cloudformation_file(filepath)
    if error:
        _warn(error)
    return data


def _load_cloudformation_file(filepath: str) -> tuple[dict | None, str | None]:
    """Return a supported template and an error only for malformed input."""
    path = Path(filepath)
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json" or text.lstrip().startswith("{"):
            data = json.loads(text)
        else:
            data = yaml.load(text, Loader=CloudFormationLoader)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        return None, f"Could not parse CloudFormation file {filepath}: {exc}"

    if not isinstance(data, dict) or not is_cloudformation_template(data):
        return None, None
    return data, None


def is_cloudformation_template(data: dict) -> bool:
    """Return True when a mapping contains CloudFormation-style resources."""
    resources = data.get("Resources")
    if not isinstance(resources, dict):
        return False
    return any(
        isinstance(resource, dict)
        and str(resource.get("Type", "")).startswith(
            ("AWS::IAM::", "AWS::Serverless::")
        )
        for resource in resources.values()
    )


def iter_cloudformation_iam_roles(
    template: dict,
) -> Iterator[tuple[str, str, dict]]:
    """Yield logical ID, best available role name, and role properties."""
    resources = template.get("Resources") or {}
    if not isinstance(resources, dict):
        return
    for logical_id, resource in resources.items():
        if not isinstance(resource, dict) or resource.get("Type") != "AWS::IAM::Role":
            continue
        properties = resource.get("Properties") or {}
        if not isinstance(properties, dict):
            continue
        role_name = _static_string(properties.get("RoleName")) or str(logical_id)
        yield str(logical_id), role_name, properties


def extract_iam_policies_from_cloudformation(
    template: dict,
    source_file: str,
) -> list[PolicyFinding]:
    """Extract role-linked IAM permission policies from a parsed template."""
    resources = template.get("Resources") or {}
    if not isinstance(resources, dict):
        return []

    role_names = {
        logical_id: _static_string(properties.get("RoleName"))
        for logical_id, _display_name, properties in iter_cloudformation_iam_roles(
            template
        )
    }
    findings: list[PolicyFinding] = []

    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        resource_type = str(resource.get("Type", ""))
        properties = resource.get("Properties") or {}
        if not isinstance(properties, dict):
            continue

        if resource_type == "AWS::IAM::Role":
            documents = _role_inline_policy_documents(properties)
            if documents:
                finding = _finding_from_documents(
                    documents,
                    source_file,
                    role_name=role_names.get(str(logical_id)),
                    policy_name=f"{logical_id}.Policies",
                    metadata={
                        "cloudformation_logical_id": str(logical_id),
                        "cloudformation_resource_type": resource_type,
                    },
                )
                findings.append(finding)
            continue

        if resource_type in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}:
            document = properties.get("PolicyDocument")
            if not isinstance(document, dict):
                continue
            targets = _role_targets(properties.get("Roles"), role_names)
            if not targets:
                targets = [(None, None)]
            for role_name, role_arn in targets:
                findings.append(
                    _finding_from_documents(
                        [document],
                        source_file,
                        role_name=role_name,
                        role_arn=role_arn,
                        policy_name=(
                            _static_string(properties.get("PolicyName"))
                            or _static_string(properties.get("ManagedPolicyName"))
                            or str(logical_id)
                        ),
                        metadata={
                            "cloudformation_logical_id": str(logical_id),
                            "cloudformation_resource_type": resource_type,
                        },
                    )
                )
            continue

        if resource_type.startswith("AWS::Serverless::"):
            documents = _collect_policy_documents(properties.get("Policies"))
            if not documents:
                continue
            role_value = properties.get("Role")
            role_arn = _literal_role_arn(role_value)
            role_name = _role_name_from_arn(role_arn)
            findings.append(
                _finding_from_documents(
                    documents,
                    source_file,
                    role_name=role_name,
                    role_arn=role_arn,
                    policy_name=f"{logical_id}.Policies",
                    metadata={
                        "cloudformation_logical_id": str(logical_id),
                        "cloudformation_resource_type": resource_type,
                    },
                )
            )

    return findings


def scan_cloudformation_files(
    repo_path: str,
) -> tuple[list[PolicyFinding], list[str]]:
    """Find, parse, and analyze CloudFormation and SAM templates."""
    findings: list[PolicyFinding] = []
    errors: list[str] = []
    for template_file in find_cloudformation_files(repo_path):
        template, error = _load_cloudformation_file(template_file)
        if error:
            errors.append(error)
            continue
        if template is None:
            continue
        findings.extend(
            extract_iam_policies_from_cloudformation(template, template_file)
        )
    return findings, errors


def _finding_from_documents(
    documents: list[dict],
    source_file: str,
    *,
    role_name: str | None = None,
    role_arn: str | None = None,
    policy_name: str | None = None,
    metadata: dict[str, object] | None = None,
) -> PolicyFinding:
    statements: list[Any] = []
    for document in documents:
        raw = document.get("Statement")
        if isinstance(raw, list):
            statements.extend(raw)
        elif isinstance(raw, dict):
            statements.append(raw)

    normalized = {
        "Version": "2012-10-17",
        "Statement": [
            statement
            for statement in (
                _normalize_statement_for_analysis(item) for item in statements
            )
            if statement is not None
        ],
    }
    finding = extract_actions_from_policy(normalized, source_file)
    finding.source_type = "cloudformation"
    finding.role_name = role_name
    finding.role_arn = role_arn
    finding.policy_name = policy_name
    finding.metadata = metadata or {}
    return finding


def _normalize_statement_for_analysis(value: Any) -> dict | None:
    if not isinstance(value, dict):
        return None
    statement = dict(value)
    effect = _static_string(statement.get("Effect"))
    if effect is not None:
        statement["Effect"] = effect

    actions = _static_strings(statement.get("Action"), preserve_dynamic=False)
    resources = _static_strings(statement.get("Resource"), preserve_dynamic=True)
    if actions:
        statement["Action"] = actions[0] if len(actions) == 1 else actions
    if resources:
        statement["Resource"] = resources[0] if len(resources) == 1 else resources
    return statement


def _role_inline_policy_documents(properties: dict) -> list[dict]:
    policies = properties.get("Policies") or []
    if isinstance(policies, dict):
        policies = [policies]
    if not isinstance(policies, list):
        return []
    return [
        document
        for policy in policies
        if isinstance(policy, dict)
        for document in [policy.get("PolicyDocument")]
        if isinstance(document, dict)
    ]


def _collect_policy_documents(value: Any) -> list[dict]:
    if isinstance(value, list):
        return [
            document for item in value for document in _collect_policy_documents(item)
        ]
    if not isinstance(value, dict):
        return []
    if "Statement" in value:
        return [value]
    return [
        document
        for item in value.values()
        for document in _collect_policy_documents(item)
    ]


def _role_targets(
    value: Any,
    role_names: dict[str, str | None],
) -> list[tuple[str | None, str | None]]:
    values = value if isinstance(value, list) else [value]
    targets: list[tuple[str | None, str | None]] = []
    for item in values:
        if item is None:
            continue
        if isinstance(item, dict) and isinstance(item.get("Ref"), str):
            targets.append((role_names.get(item["Ref"]), None))
            continue
        static = _static_string(item)
        if static is None:
            continue
        role_arn = _literal_role_arn(static)
        targets.append((_role_name_from_arn(role_arn) or static, role_arn))
    return targets


def _static_strings(value: Any, *, preserve_dynamic: bool) -> list[str]:
    values = value if isinstance(value, list) else [value]
    output: list[str] = []
    for item in values:
        static = _static_string(item)
        if static is None:
            if preserve_dynamic and isinstance(item, dict) and item:
                intrinsic = str(next(iter(item)))
                output.append(f"<dynamic:{intrinsic}>")
            continue
        if "${" in static and not preserve_dynamic:
            continue
        output.append(static)
    return output


def _static_string(value: Any) -> str | None:
    if isinstance(value, str):
        return value.strip() or None
    if not isinstance(value, dict) or len(value) != 1:
        return None
    key, item = next(iter(value.items()))
    if key == "Fn::Sub" and isinstance(item, str):
        return item.strip() or None
    return None


def _literal_role_arn(value: Any) -> str | None:
    static = _static_string(value)
    if (
        static
        and static.startswith("arn:")
        and ":iam::" in static
        and ":role/" in static
    ):
        return static
    return None


def _role_name_from_arn(role_arn: str | None) -> str | None:
    if not role_arn or ":role/" not in role_arn:
        return None
    return role_arn.split(":role/", 1)[1].strip("/").rsplit("/", 1)[-1]


def _looks_like_cloudformation(path: Path) -> bool:
    try:
        head = path.read_bytes()[:_PEEK_BYTES]
    except (OSError, PermissionError):
        return False
    has_resources = b'"Resources"' in head or b"Resources:" in head
    has_resource_type = b"AWS::IAM::" in head or b"AWS::Serverless::" in head
    return has_resources and has_resource_type


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)
