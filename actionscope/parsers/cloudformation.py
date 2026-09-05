"""CloudFormation and SAM parser for repository-local IAM policy evidence."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Iterator

import yaml

from actionscope.models import PolicyFinding
from actionscope.parsers.policy_json import extract_actions_from_policy

_PEEK_BYTES = 131_072
_MAX_TEMPLATE_BYTES = 8 * 1024 * 1024
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
    text, read_error = _read_template_text(path)
    if read_error:
        return None, read_error
    assert text is not None
    try:
        if path.suffix.lower() == ".json" or text.lstrip().startswith("{"):
            data = json.loads(text)
        else:
            data = yaml.load(text, Loader=CloudFormationLoader)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
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

    roles = {
        logical_id: properties
        for logical_id, _display_name, properties in iter_cloudformation_iam_roles(
            template
        )
    }
    role_names = {
        logical_id: _static_string(properties.get("RoleName"))
        for logical_id, properties in roles.items()
    }
    role_documents = {
        logical_id: _role_inline_policy_documents(properties)
        for logical_id, properties in roles.items()
    }
    role_policy_ids = {
        logical_id: [str(logical_id)] if role_documents[logical_id] else []
        for logical_id in roles
    }
    role_policy_names = {
        logical_id: _role_inline_policy_names(properties)
        for logical_id, properties in roles.items()
    }
    role_unresolved_attachments: dict[str, list[str]] = {
        logical_id: [] for logical_id in roles
    }

    policy_resources: dict[str, tuple[str, dict, dict]] = {}
    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        resource_type = str(resource.get("Type", ""))
        properties = resource.get("Properties") or {}
        if (
            resource_type in {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
            and isinstance(properties, dict)
            and isinstance(properties.get("PolicyDocument"), dict)
        ):
            policy_resources[str(logical_id)] = (
                resource_type,
                properties,
                properties["PolicyDocument"],
            )

    attached_policy_roles: dict[str, set[str]] = {
        logical_id: set() for logical_id in policy_resources
    }
    for role_id, properties in roles.items():
        managed_policy_arns = properties.get("ManagedPolicyArns") or []
        values = (
            managed_policy_arns
            if isinstance(managed_policy_arns, list)
            else [managed_policy_arns]
        )
        for value in values:
            policy_id = _direct_local_policy_reference(value, policy_resources)
            if policy_id is not None:
                attached_policy_roles[policy_id].add(role_id)
            else:
                role_unresolved_attachments[role_id].append(_attachment_display(value))

    standalone_policy_findings: list[PolicyFinding] = []
    for policy_id, (resource_type, properties, document) in policy_resources.items():
        resolved_role_ids, unresolved_targets = _resolve_role_targets(
            properties.get("Roles"),
            role_names,
        )
        policy_name = (
            _static_string(properties.get("PolicyName"))
            or _static_string(properties.get("ManagedPolicyName"))
            or policy_id
        )
        resolved_role_ids.update(attached_policy_roles[policy_id])
        for role_id in resolved_role_ids:
            role_documents[role_id].append(document)
            role_policy_ids[role_id].append(policy_id)
            role_policy_names[role_id].append(policy_name)

        if not resolved_role_ids and not unresolved_targets:
            unresolved_targets = [(None, None)]
        for role_name, role_arn in unresolved_targets:
            standalone_policy_findings.append(
                _finding_from_documents(
                    [document],
                    source_file,
                    role_name=role_name,
                    role_arn=role_arn,
                    policy_name=policy_name,
                    metadata={
                        "cloudformation_logical_id": policy_id,
                        "cloudformation_resource_type": resource_type,
                    },
                )
            )

    findings: list[PolicyFinding] = []

    for logical_id, properties in roles.items():
        documents = role_documents[logical_id]
        unresolved_attachments = list(
            dict.fromkeys(role_unresolved_attachments[logical_id])
        )
        if not documents and not unresolved_attachments:
            continue
        policy_ids = list(dict.fromkeys(role_policy_ids[logical_id]))
        policy_names = list(dict.fromkeys(role_policy_names[logical_id]))
        findings.append(
            _finding_from_documents(
                documents,
                source_file,
                role_name=role_names[logical_id],
                policy_name=(
                    policy_names[0]
                    if len(policy_names) == 1
                    else f"{logical_id}.effective-policies"
                ),
                metadata={
                    "cloudformation_logical_id": logical_id,
                    "cloudformation_resource_type": "AWS::IAM::Role",
                    "cloudformation_policy_logical_ids": policy_ids,
                    "policy_coverage_complete": not unresolved_attachments,
                    "unresolved_policy_attachments": unresolved_attachments,
                },
            )
        )

    findings.extend(standalone_policy_findings)

    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        resource_type = str(resource.get("Type", ""))
        properties = resource.get("Properties") or {}
        if not isinstance(properties, dict):
            continue

        if resource_type in {
            "AWS::IAM::Role",
            "AWS::IAM::Policy",
            "AWS::IAM::ManagedPolicy",
        }:
            continue

        if resource_type.startswith("AWS::Serverless::"):
            # SAM ignores Policies when an explicit execution Role is supplied.
            if properties.get("Role") is not None:
                continue
            documents = _collect_policy_documents(properties.get("Policies"))
            if not documents:
                continue
            findings.append(
                _finding_from_documents(
                    documents,
                    source_file,
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


def _role_inline_policy_names(properties: dict) -> list[str]:
    policies = properties.get("Policies") or []
    if isinstance(policies, dict):
        policies = [policies]
    if not isinstance(policies, list):
        return []
    return [
        _static_string(policy.get("PolicyName")) or "inline-policy"
        for policy in policies
        if isinstance(policy, dict) and isinstance(policy.get("PolicyDocument"), dict)
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


def _resolve_role_targets(
    value: Any,
    role_names: dict[str, str | None],
) -> tuple[set[str], list[tuple[str | None, str | None]]]:
    """Split policy role targets into known template roles and external roles."""
    values = value if isinstance(value, list) else [value]
    resolved: set[str] = set()
    unresolved: list[tuple[str | None, str | None]] = []

    for item in values:
        referenced_roles = _logical_resource_references(item) & role_names.keys()
        if referenced_roles:
            resolved.update(referenced_roles)
            continue

        static = _static_string(item)
        if static is None:
            continue
        matching_role_ids = {
            role_id for role_id, role_name in role_names.items() if role_name == static
        }
        if matching_role_ids:
            resolved.update(matching_role_ids)
            continue
        role_arn = _literal_role_arn(static)
        unresolved.append((_role_name_from_arn(role_arn) or static, role_arn))

    return resolved, unresolved


def _logical_resource_references(value: Any) -> set[str]:
    """Return logical resource IDs referenced through Ref or Fn::GetAtt."""
    if isinstance(value, list):
        return {
            reference
            for item in value
            for reference in _logical_resource_references(item)
        }
    if not isinstance(value, dict):
        return set()

    references: set[str] = set()
    ref = value.get("Ref")
    if isinstance(ref, str):
        references.add(ref)

    get_att = value.get("Fn::GetAtt")
    if isinstance(get_att, list) and get_att and isinstance(get_att[0], str):
        references.add(get_att[0])
    elif isinstance(get_att, str):
        references.add(get_att.split(".", 1)[0])

    for nested in value.values():
        references.update(_logical_resource_references(nested))
    return references


def _direct_local_policy_reference(
    value: Any,
    policy_resources: dict[str, tuple[str, dict, dict]],
) -> str | None:
    """Resolve only an unambiguous reference to a policy in this template."""
    if not isinstance(value, dict) or len(value) != 1:
        return None

    ref = value.get("Ref")
    if (
        isinstance(ref, str)
        and ref in policy_resources
        and policy_resources[ref][0] == "AWS::IAM::ManagedPolicy"
    ):
        return ref

    get_att = value.get("Fn::GetAtt")
    if isinstance(get_att, list) and get_att and isinstance(get_att[0], str):
        policy_id = get_att[0]
    elif isinstance(get_att, str):
        policy_id = get_att.split(".", 1)[0]
    else:
        return None
    if (
        policy_id in policy_resources
        and policy_resources[policy_id][0] == "AWS::IAM::ManagedPolicy"
    ):
        return policy_id
    return None


def _attachment_display(value: Any) -> str:
    """Return stable, readable evidence for an unresolved policy attachment."""
    static = _static_string(value)
    if static is not None:
        return static
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(value)


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
    resource_markers = (b'"Resources"', b"Resources:")
    type_markers = (b"AWS::IAM::", b"AWS::Serverless::")
    carry_size = max(len(marker) for marker in resource_markers + type_markers) - 1
    has_resources = False
    has_resource_type = False
    bytes_read = 0
    carry = b""
    try:
        if path.is_symlink():
            return False
        with path.open("rb") as template_file:
            if not stat.S_ISREG(os.fstat(template_file.fileno()).st_mode):
                return False
            while bytes_read <= _MAX_TEMPLATE_BYTES:
                remaining = _MAX_TEMPLATE_BYTES + 1 - bytes_read
                chunk = template_file.read(min(_PEEK_BYTES, remaining))
                if not chunk:
                    break
                bytes_read += len(chunk)
                window = carry + chunk
                has_resources = has_resources or any(
                    marker in window for marker in resource_markers
                )
                has_resource_type = has_resource_type or any(
                    marker in window for marker in type_markers
                )
                if has_resources and has_resource_type:
                    return True
                carry = window[-carry_size:]
    except (OSError, PermissionError):
        return False

    # Let the bounded parser report a useful coverage error for an oversized
    # file that at least declares a CloudFormation Resources section.
    return bytes_read > _MAX_TEMPLATE_BYTES and has_resources


def _read_template_text(path: Path) -> tuple[str | None, str | None]:
    """Read one regular template file with a strict byte limit."""
    try:
        if path.is_symlink():
            return (
                None,
                f"Could not parse CloudFormation file {path}: not a regular file",
            )
        with path.open("rb") as template_file:
            if not stat.S_ISREG(os.fstat(template_file.fileno()).st_mode):
                return (
                    None,
                    f"Could not parse CloudFormation file {path}: not a regular file",
                )
            payload = template_file.read(_MAX_TEMPLATE_BYTES + 1)
    except (OSError, PermissionError) as exc:
        return None, f"Could not parse CloudFormation file {path}: {exc}"

    if len(payload) > _MAX_TEMPLATE_BYTES:
        return (
            None,
            f"Could not parse CloudFormation file {path}: "
            f"template exceeds {_MAX_TEMPLATE_BYTES} bytes",
        )
    try:
        return payload.decode("utf-8"), None
    except UnicodeDecodeError as exc:
        return None, f"Could not parse CloudFormation file {path}: {exc}"


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)
