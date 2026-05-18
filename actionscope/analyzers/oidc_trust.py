"""OIDC trust policy analyzer.

Analyzes AWS IAM trust policies for GitHub Actions OIDC misconfigurations:
wildcard subject claims, missing conditions, missing audience checks, and
insufficient branch/environment scoping.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import hcl2

from actionscope.models import OidcTrustFinding, RiskLevel

GITHUB_OIDC_ISSUER = "token.actions.githubusercontent.com"
GITHUB_OIDC_PROVIDER_URL = "https://token.actions.githubusercontent.com"


def is_github_oidc_trust(assume_role_policy: dict) -> bool:
    """Return True if the assume-role policy trusts GitHub's OIDC provider."""
    return bool(extract_github_oidc_statements(assume_role_policy))


def extract_github_oidc_statements(assume_role_policy: dict) -> list[dict]:
    """Return statements that trust GitHub's OIDC provider."""
    statements = _statements(assume_role_policy)
    return [
        statement
        for statement in statements
        if isinstance(statement, dict) and _principal_mentions_github(statement)
    ]


def analyze_oidc_trust_conditions(
    statement: dict,
    source_file: str,
    role_name: str,
) -> list[OidcTrustFinding]:
    """Analyze one GitHub OIDC trust statement for common misconfigurations."""
    findings: list[OidcTrustFinding] = []
    condition = statement.get("Condition") or statement.get("condition")
    condition_display = _compact(condition) if condition else "no Condition block found"
    sub_values = _condition_values(condition, ":sub")
    aud_values = _condition_values(condition, ":aud")

    if not sub_values:
        findings.append(
            _finding(
                source_file,
                role_name,
                "missing_sub",
                "Missing GitHub OIDC subject condition",
                RiskLevel.CRITICAL,
                condition_display,
                "Add a token.actions.githubusercontent.com:sub condition scoped "
                "to a specific repository and protected branch or environment.",
            )
        )
    else:
        for sub_value in sub_values:
            normalized = str(sub_value)
            if _is_repo_wildcard_subject(normalized):
                findings.append(
                    _finding(
                        source_file,
                        role_name,
                        "wildcard_repo",
                        "Wildcard repo in GitHub OIDC subject condition",
                        RiskLevel.CRITICAL,
                        normalized,
                        "Scope the subject to a specific repo, for example "
                        "repo:ORG/REPO:ref:refs/heads/main or an environment.",
                    )
                )
            elif _is_repo_without_branch_or_environment(normalized):
                findings.append(
                    _finding(
                        source_file,
                        role_name,
                        "no_branch_scope",
                        "GitHub OIDC subject is not scoped to a branch or environment",
                        RiskLevel.HIGH,
                        normalized,
                        "For deploy roles, scope the subject to a protected branch "
                        "or GitHub environment.",
                    )
                )
            elif _is_non_protected_branch_without_environment(normalized):
                findings.append(
                    _finding(
                        source_file,
                        role_name,
                        "branch_not_protected",
                        "GitHub OIDC subject uses a non-main branch without "
                        "environment scoping",
                        RiskLevel.MEDIUM,
                        normalized,
                        "Use GitHub environment protection rules for deploy roles, "
                        "or restrict to main/master where appropriate.",
                    )
                )

    if not aud_values:
        findings.append(
            _finding(
                source_file,
                role_name,
                "missing_aud",
                "Missing GitHub OIDC audience condition",
                RiskLevel.MEDIUM,
                condition_display,
                "Add token.actions.githubusercontent.com:aud == sts.amazonaws.com.",
            )
        )

    return findings


def analyze_terraform_oidc_trust(
    tf_data: dict,
    source_file: str,
) -> list[OidcTrustFinding]:
    """Find and analyze GitHub OIDC trust policies in parsed Terraform data."""
    findings: list[OidcTrustFinding] = []

    for resource_type, resource_name, body in _iter_blocks(tf_data.get("resource")):
        if resource_type != "aws_iam_role":
            continue
        role_name = _role_name(resource_name, body)
        policy = _parse_policy_value(body.get("assume_role_policy"))
        if policy is None:
            continue
        findings.extend(analyze_json_oidc_trust(policy, source_file, role_name))

    for data_type, data_name, body in _iter_blocks(tf_data.get("data")):
        if data_type != "aws_iam_policy_document":
            continue
        policy = _policy_from_terraform_document(body)
        if is_github_oidc_trust(policy):
            findings.extend(analyze_json_oidc_trust(policy, source_file, data_name))

    return findings


def analyze_json_oidc_trust(
    policy_data: dict,
    source_file: str,
    role_name: str = "unknown",
) -> list[OidcTrustFinding]:
    """Analyze a parsed assume-role trust policy document."""
    findings: list[OidcTrustFinding] = []
    for statement in extract_github_oidc_statements(policy_data):
        findings.extend(
            analyze_oidc_trust_conditions(statement, source_file, role_name)
        )
    return findings


def scan_oidc_trust_policies(
    repo_path: str,
) -> tuple[list[OidcTrustFinding], list[str]]:
    """Scan Terraform and JSON files for GitHub OIDC trust policy issues."""
    repo = Path(repo_path).expanduser()
    findings: list[OidcTrustFinding] = []
    errors: list[str] = []
    if not repo.is_dir():
        return findings, errors

    for tf_file in sorted(repo.rglob("*.tf")):
        if ".terraform" in tf_file.parts:
            continue
        try:
            with tf_file.open("r", encoding="utf-8") as handle:
                data = hcl2.load(handle)
        except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError) as exc:
            errors.append(f"Could not read Terraform file {tf_file}: {exc}")
            continue
        except Exception as exc:
            errors.append(f"Could not parse Terraform file {tf_file}: {exc}")
            continue
        if isinstance(data, dict):
            findings.extend(analyze_terraform_oidc_trust(data, str(tf_file.resolve())))

    for json_file in sorted(repo.rglob("*.json"))[:200]:
        try:
            with json_file.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError) as exc:
            errors.append(f"Could not read JSON trust policy file {json_file}: {exc}")
            continue
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and is_github_oidc_trust(data):
            findings.extend(analyze_json_oidc_trust(data, str(json_file.resolve())))

    return findings, errors


def _finding(
    source_file: str,
    role_name: str,
    issue_id: str,
    description: str,
    risk: RiskLevel,
    evidence: str,
    recommendation: str,
) -> OidcTrustFinding:
    return OidcTrustFinding(
        source_file=source_file,
        role_name=role_name,
        role_arn=None,
        issue_id=issue_id,
        issue_description=description,
        risk_level=risk,
        evidence=evidence,
        recommendation=recommendation,
    )


def _statements(policy: dict) -> list[dict]:
    statements = policy.get("Statement") or policy.get("statement") or []
    if isinstance(statements, dict):
        return [statements]
    if isinstance(statements, list):
        return [statement for statement in statements if isinstance(statement, dict)]
    return []


def _principal_mentions_github(statement: dict) -> bool:
    principal = statement.get("Principal") or statement.get("principal")
    return GITHUB_OIDC_ISSUER in _compact(principal)


def _condition_values(condition: Any, suffix: str) -> list[str]:
    values: list[str] = []
    if not isinstance(condition, dict):
        return values
    for operator_value in condition.values():
        if not isinstance(operator_value, dict):
            continue
        for key, value in operator_value.items():
            if str(key).lower().endswith(suffix):
                values.extend(_string_values(value))
    return values


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int, float))]
    return []


def _is_repo_wildcard_subject(sub_value: str) -> bool:
    return bool(re.match(r"^repo:[^/]+/\*(?::|$)", sub_value))


def _is_repo_without_branch_or_environment(sub_value: str) -> bool:
    return bool(
        re.fullmatch(r"repo:[^/\s]+/[^:\s]+", sub_value)
        and ":environment:" not in sub_value
        and ":ref:" not in sub_value
    )


def _is_non_protected_branch_without_environment(sub_value: str) -> bool:
    if ":environment:" in sub_value:
        return False
    match = re.search(r":ref:refs/heads/([^:\s]+)", sub_value)
    if not match:
        return False
    return match.group(1) not in {"main", "master"}


def _iter_blocks(blocks: Any) -> Any:
    if blocks is None:
        return
    blocks_list = [blocks] if isinstance(blocks, dict) else blocks
    if not isinstance(blocks_list, list):
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


def _role_name(resource_name: str, body: dict) -> str:
    explicit_name = body.get("name")
    if isinstance(explicit_name, str) and "${" not in explicit_name:
        return _clean_string(explicit_name).strip("/").rsplit("/", 1)[-1]
    return resource_name


def _parse_policy_value(value: Any) -> dict | None:
    if isinstance(value, dict):
        return _normalize(value)
    if not isinstance(value, str):
        return None
    clean = value.strip()
    if clean.startswith("${") and clean.endswith("}"):
        clean = clean[2:-1].strip()
    if clean.startswith("jsonencode("):
        inner = _extract_call_arg(clean, "jsonencode")
        if inner is None:
            return None
        try:
            parsed = hcl2.loads(f"policy = {inner}")
        except Exception as exc:
            print(
                f"Warning: could not parse jsonencode trust policy: {exc}",
                file=sys.stderr,
            )
            return None
        policy = parsed.get("policy")
        return _normalize(policy) if isinstance(policy, dict) else None
    try:
        parsed_json = json.loads(clean)
    except json.JSONDecodeError:
        return None
    return parsed_json if isinstance(parsed_json, dict) else None


def _extract_call_arg(value: str, call_name: str) -> str | None:
    marker = f"{call_name}("
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


def _policy_from_terraform_document(body: dict) -> dict:
    statements = []
    raw_statements = body.get("statement") or []
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    for statement in raw_statements if isinstance(raw_statements, list) else []:
        if not isinstance(statement, dict):
            continue
        converted: dict[str, Any] = {
            "Effect": statement.get("effect", "Allow"),
            "Action": statement.get("actions") or statement.get("action"),
        }
        principals = statement.get("principals")
        if isinstance(principals, list) and principals:
            identifiers = (
                principals[0].get("identifiers")
                if isinstance(principals[0], dict)
                else None
            )
            converted["Principal"] = {"Federated": identifiers}
        condition = _terraform_conditions(statement.get("condition"))
        if condition:
            converted["Condition"] = condition
        statements.append(converted)
    return {"Version": "2012-10-17", "Statement": statements}


def _terraform_conditions(raw_conditions: Any) -> dict[str, dict[str, Any]]:
    conditions: dict[str, dict[str, Any]] = {}
    if isinstance(raw_conditions, dict):
        raw_conditions = [raw_conditions]
    if not isinstance(raw_conditions, list):
        return conditions
    for condition in raw_conditions:
        if not isinstance(condition, dict):
            continue
        test = str(condition.get("test", "StringEquals"))
        variable = condition.get("variable")
        values = condition.get("values")
        if variable:
            conditions.setdefault(test, {})[str(variable)] = values
    return conditions


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            _clean_string(key): _normalize(item)
            for key, item in value.items()
            if key != "__is_block__"
        }
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, str):
        return _clean_string(value)
    return value


def _clean_string(value: Any) -> str:
    cleaned = str(value).strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] == '"':
        return cleaned[1:-1]
    return cleaned


def _compact(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True)
    except TypeError:
        return str(value)
