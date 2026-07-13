"""OIDC trust policy analyzer.

Analyzes AWS IAM trust policies for GitHub Actions OIDC misconfigurations:
wildcard subject claims, missing conditions, missing audience checks, and
insufficient branch/environment scoping.
"""

from __future__ import annotations

import json
import re
import sys
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterator

import hcl2

from actionscope.models import OidcTrustFinding, RiskLevel

GITHUB_OIDC_ISSUER = "token.actions.githubusercontent.com"
GITHUB_OIDC_PROVIDER_URL = "https://token.actions.githubusercontent.com"
GITHUB_MULTIVALUED_CLAIMS = {"amr"}


def is_github_oidc_trust(assume_role_policy: dict) -> bool:
    """Return True if the assume-role policy trusts GitHub's OIDC provider."""
    return bool(extract_github_oidc_statements(assume_role_policy))


def extract_github_oidc_statements(assume_role_policy: dict) -> list[dict]:
    """Return statements that trust GitHub's OIDC provider."""
    statements = _statements(assume_role_policy)
    return [
        statement
        for statement in statements
        if isinstance(statement, dict)
        and _principal_mentions_github(statement)
        and _allows_web_identity_assumption(statement)
    ]


def analyze_oidc_trust_conditions(
    statement: dict,
    source_file: str,
    role_name: str,
) -> list[OidcTrustFinding]:
    """Analyze one GitHub OIDC trust statement for common misconfigurations."""
    if not _is_allow_statement(statement):
        return []

    findings: list[OidcTrustFinding] = []
    condition = statement.get("Condition") or statement.get("condition")
    condition_display = _compact(condition) if condition else "no Condition block found"
    sub_values = _condition_values(condition, ":sub")
    aud_values = _condition_values(condition, ":aud")

    unsafe_forallvalues = _unsafe_forallvalues_claims(condition)
    if unsafe_forallvalues:
        corrected = _replace_unsafe_forallvalues(condition)
        findings.append(
            _finding(
                source_file,
                role_name,
                "forallvalues_single_valued_claim",
                "ForAllValues is used with a single-valued GitHub OIDC claim",
                RiskLevel.MEDIUM,
                _compact(unsafe_forallvalues),
                "Use the scalar StringEquals or StringLike operator for these "
                f"claims. Corrected Condition: {_compact(corrected)}",
            )
        )

    if not sub_values:
        findings.append(
            _finding(
                source_file,
                role_name,
                "missing_sub",
                "Missing GitHub OIDC subject condition",
                RiskLevel.CRITICAL,
                condition_display,
                "Add a subject condition scoped to one repository and protected "
                f"branch or environment. Example Condition: {_safe_condition()}",
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
                        "Scope the subject to one repository and protected branch "
                        f"or environment. Example Condition: {_safe_condition()}",
                    )
                )
            elif _is_broad_repo_context_subject(normalized):
                findings.append(
                    _finding(
                        source_file,
                        role_name,
                        "broad_subject",
                        "GitHub OIDC subject uses a wildcard workflow context",
                        RiskLevel.HIGH,
                        normalized,
                        "Replace the wildcard context with a protected branch or "
                        f"environment. Example Condition: {_safe_condition()}",
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
                        f"or environment. Example Condition: {_safe_condition()}",
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
                        "Use a protected GitHub environment for deploy roles, or "
                        "restrict to main/master where appropriate. Example "
                        f"Condition: {_safe_condition()}",
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
                "Constrain the audience to AWS STS. Example Condition: "
                f"{_safe_condition()}",
            )
        )

    return findings


def analyze_terraform_oidc_trust(
    tf_data: dict,
    source_file: str,
) -> list[OidcTrustFinding]:
    """Find and analyze GitHub OIDC trust policies in parsed Terraform data."""
    findings: list[OidcTrustFinding] = []

    for resource_type, resource_name, body in _iter_blocks(
        tf_data.get("resource") or []
    ):
        if resource_type != "aws_iam_role":
            continue
        role_name = _role_name(resource_name, body)
        policy = _parse_policy_value(body.get("assume_role_policy"))
        if policy is None:
            continue
        findings.extend(analyze_json_oidc_trust(policy, source_file, role_name))

    for data_type, data_name, body in _iter_blocks(tf_data.get("data") or []):
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

    for json_file in sorted(repo.rglob("*.json")):
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


def _is_allow_statement(statement: dict) -> bool:
    effect = statement.get("Effect", statement.get("effect", "Allow"))
    return str(effect).strip().lower() == "allow"


def _allows_web_identity_assumption(statement: dict) -> bool:
    if not _is_allow_statement(statement):
        return False
    actions = statement.get("Action") or statement.get("action")
    target = "sts:assumerolewithwebidentity"
    return any(
        fnmatchcase(target, action.lower()) for action in _string_values(actions)
    )


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


def _unsafe_forallvalues_claims(condition: Any) -> dict[str, dict[str, Any]]:
    unsafe: dict[str, dict[str, Any]] = {}
    if not isinstance(condition, dict):
        return unsafe
    for operator, operator_value in condition.items():
        if str(operator).lower() not in {
            "forallvalues:stringequals",
            "forallvalues:stringlike",
        }:
            continue
        if not isinstance(operator_value, dict):
            continue
        for key, value in operator_value.items():
            if _is_single_valued_github_claim(key):
                unsafe.setdefault(str(operator), {})[str(key)] = value
    return unsafe


def _is_single_valued_github_claim(key: Any) -> bool:
    normalized = str(key).strip().lower()
    prefix = f"{GITHUB_OIDC_ISSUER}:"
    if not normalized.startswith(prefix):
        return False
    claim = normalized.removeprefix(prefix)
    return bool(claim) and claim not in GITHUB_MULTIVALUED_CLAIMS


def _replace_unsafe_forallvalues(condition: Any) -> dict[str, dict[str, Any]]:
    corrected: dict[str, dict[str, Any]] = {}
    if not isinstance(condition, dict):
        return corrected

    for operator, operator_value in condition.items():
        operator_name = str(operator)
        if not isinstance(operator_value, dict):
            continue
        is_forall = operator_name.lower() in {
            "forallvalues:stringequals",
            "forallvalues:stringlike",
        }
        for key, value in operator_value.items():
            target_operator = operator_name
            if is_forall and _is_single_valued_github_claim(key):
                target_operator = operator_name.split(":", 1)[1]
            corrected.setdefault(target_operator, {})[str(key)] = value
    return corrected


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int, float))]
    return []


def _is_repo_wildcard_subject(sub_value: str) -> bool:
    repo_scope, _ = _subject_parts(sub_value)
    return repo_scope is not None and any(char in repo_scope for char in "*?")


def _is_broad_repo_context_subject(sub_value: str) -> bool:
    repo_scope, context = _subject_parts(sub_value)
    if not repo_scope or any(char in repo_scope for char in "*?") or not context:
        return False
    normalized = context.lower()
    if normalized in {"*", "?", "**", "ref:*", "ref:refs/*"}:
        return True
    for prefix in ("ref:refs/heads/", "ref:refs/tags/", "environment:"):
        if normalized.startswith(prefix):
            return normalized.removeprefix(prefix) in {"*", "?", "**"}
    return False


def _subject_parts(sub_value: str) -> tuple[str | None, str | None]:
    if not sub_value.lower().startswith("repo:"):
        return None, None
    remainder = sub_value[5:]
    if ":" not in remainder:
        return remainder, None
    repo_scope, context = remainder.split(":", 1)
    return repo_scope, context


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


def _safe_condition(subject: str | None = None) -> str:
    safe_subject = subject or "repo:ORG/REPO:environment:production"
    return _compact(
        {
            "StringEquals": {
                f"{GITHUB_OIDC_ISSUER}:aud": "sts.amazonaws.com",
                f"{GITHUB_OIDC_ISSUER}:sub": safe_subject,
            }
        }
    )


def _iter_blocks(blocks: Any) -> Iterator[tuple[str, str, dict]]:
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
    body = _normalize(body)
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
        principal = _terraform_federated_principal(statement.get("principals"))
        if principal:
            converted["Principal"] = principal
        condition = _terraform_conditions(statement.get("condition"))
        if condition:
            converted["Condition"] = condition
        statements.append(converted)
    return {"Version": "2012-10-17", "Statement": statements}


def _terraform_federated_principal(raw_principals: Any) -> dict[str, Any] | None:
    principals = raw_principals
    if isinstance(principals, dict):
        principals = [principals]
    if not isinstance(principals, list):
        return None

    for principal in principals:
        if not isinstance(principal, dict):
            continue
        principal_type = _clean_string(principal.get("type", ""))
        identifiers = _normalize(principal.get("identifiers"))
        identifiers_list = _string_values(identifiers)
        mentions_github = GITHUB_OIDC_ISSUER in _compact(identifiers)
        if principal_type == "Federated" or mentions_github:
            if not identifiers_list:
                continue
            principal_value: Any = (
                identifiers_list[0]
                if len(identifiers_list) == 1
                else identifiers_list
            )
            return {"Federated": principal_value}

    return None


def _terraform_conditions(raw_conditions: Any) -> dict[str, dict[str, Any]]:
    conditions: dict[str, dict[str, Any]] = {}
    raw_conditions = _normalize(raw_conditions)
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
