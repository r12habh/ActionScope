"""JSON IAM policy parser for loading inline and standalone policy documents."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from actionscope.analyzers.iam_risk import classify_action, get_overall_risk
from actionscope.models import IamAction, PolicyFinding, RiskLevel

DEFAULT_MAX_OTHER_JSON_FILES = 800
COMMON_POLICY_DIRS = (
    "iam",
    "policies",
    ".github",
    "infra",
    "infrastructure",
    "terraform",
)
PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:attachrolepolicy",
    "iam:createpolicyversion",
    "iam:createloginprofile",
    "iam:addusertogroup",
    "iam:updateloginprofile",
    "iam:setdefaultpolicyversion",
}


def find_policy_json_files(
    repo_path: str,
    max_other_files: int = DEFAULT_MAX_OTHER_JSON_FILES,
) -> list[str]:
    """Find JSON files that look like standalone IAM policy documents."""
    repo = Path(repo_path).expanduser()
    if not repo.is_dir():
        return []

    candidates = _apply_cap(repo, _json_candidates(repo), max_other=max_other_files)

    policy_files: list[str] = []
    for candidate in candidates:
        try:
            with candidate.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            if _should_report_parse_error(candidate):
                _warn(f"Could not parse policy JSON file {candidate}: {exc}")
            continue

        if (
            isinstance(data, dict)
            and _has_key_at_any_level(data, "Statement")
            and _has_key_at_any_level(data, "Effect")
            and is_iam_policy(data)
        ):
            policy_files.append(str(candidate.resolve()))

    return policy_files


def is_iam_policy(data: dict) -> bool:
    """Return True when parsed JSON looks like an IAM policy document."""
    statements = data.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return False

    return any(
        isinstance(statement, dict) and "Effect" in statement
        for statement in statements
    )


def parse_policy_json_file(filepath: str) -> dict | None:
    """Parse a single IAM policy JSON file."""
    try:
        with Path(filepath).open("r", encoding="utf-8") as policy_file:
            policy_data = json.load(policy_file)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        _warn(f"Could not parse policy JSON file {filepath}: {exc}")
        return None

    if not isinstance(policy_data, dict) or not is_iam_policy(policy_data):
        return None

    return policy_data


def extract_actions_from_policy(
    policy_data: dict,
    source_file: str,
) -> PolicyFinding:
    """Extract and classify all Allow actions from a parsed IAM policy."""
    actions: list[IamAction] = []
    has_star_action = False
    has_star_resource = False
    has_passrole = False
    has_privilege_escalation = False

    statements_raw = policy_data.get("Statement", [])
    if isinstance(statements_raw, dict):
        statements = [statements_raw]
    elif isinstance(statements_raw, list):
        statements = statements_raw
    else:
        statements = []

    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            _warn(f"Skipping malformed statement {index} in {source_file}")
            continue

        if str(statement.get("Effect", "")).lower() == "deny":
            continue

        if str(statement.get("Effect", "")).lower() != "allow":
            continue

        if "Action" not in statement or "Resource" not in statement:
            _warn(
                f"Skipping statement {index} in {source_file}: "
                "missing Action or Resource"
            )
            continue

        statement_actions = _string_list(statement.get("Action"))
        resources = _string_list(statement.get("Resource"))
        if not statement_actions or not resources:
            _warn(
                f"Skipping statement {index} in {source_file}: "
                "malformed Action or Resource"
            )
            continue

        resource = "*" if "*" in resources else ", ".join(resources)
        classified_actions = [
            classify_action(action, resource=resource)
            for action in statement_actions
        ]
        actions.extend(classified_actions)

        normalized_actions = {action.action.lower() for action in classified_actions}
        has_star_action = has_star_action or "*" in statement_actions
        has_passrole = has_passrole or "iam:passrole" in normalized_actions

        statement_has_star_resource = "*" in resources
        statement_has_write_or_permissions = any(
            _is_write_or_permissions_action(action)
            for action in classified_actions
        )
        if statement_has_star_resource and statement_has_write_or_permissions:
            has_star_resource = True

        if statement_has_star_resource and (
            ("iam:passrole" in normalized_actions)
            or bool(PRIVILEGE_ESCALATION_ACTIONS & normalized_actions)
        ):
            has_privilege_escalation = True

    return PolicyFinding(
        source_file=source_file,
        source_type="json_policy",
        role_arn=None,
        actions=actions,
        has_star_action=has_star_action,
        has_star_resource=has_star_resource,
        has_passrole=has_passrole,
        has_privilege_escalation=has_privilege_escalation,
        overall_risk=get_overall_risk(actions),
    )


def scan_policy_files(
    repo_path: str,
    max_other_files: int = DEFAULT_MAX_OTHER_JSON_FILES,
) -> tuple[list[PolicyFinding], list[str]]:
    """Find, parse, and analyze standalone IAM policy JSON files."""
    findings: list[PolicyFinding] = []
    errors: list[str] = []

    repo = Path(repo_path).expanduser()
    candidates = _apply_cap(
        repo, _json_candidates(repo), max_other=max_other_files
    )

    for policy_file in candidates:
        try:
            with policy_file.open("r", encoding="utf-8") as file:
                policy_data = json.load(file)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            if _should_report_parse_error(policy_file):
                errors.append(
                    f"Could not parse policy JSON file {policy_file}: {exc}"
                )
            continue

        if not isinstance(policy_data, dict) or not is_iam_policy(policy_data):
            continue

        findings.append(
            extract_actions_from_policy(policy_data, str(policy_file.resolve()))
        )

    return findings, errors


def _json_candidates(repo: Path) -> list[Path]:
    """Order JSON candidates for scanning.

    Files under `COMMON_POLICY_DIRS` come first (these are *always* scanned —
    the cap on line-noise JSON files never applies to them). Everything else
    is appended afterward and may be subject to the
    `DEFAULT_MAX_OTHER_JSON_FILES` cap via `_apply_cap`.
    """
    if not repo.is_dir():
        return []

    candidates: list[Path] = []
    seen: set[Path] = set()

    for directory_name in COMMON_POLICY_DIRS:
        directory = repo / directory_name
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*.json")):
            resolved = path.resolve()
            if resolved not in seen:
                candidates.append(path)
                seen.add(resolved)

    for path in sorted(repo.rglob("*.json")):
        resolved = path.resolve()
        if resolved not in seen:
            candidates.append(path)
            seen.add(resolved)

    return candidates


def _apply_cap(
    repo: Path,
    candidates: list[Path],
    max_other: int = DEFAULT_MAX_OTHER_JSON_FILES,
) -> list[Path]:
    """Always keep candidates under `COMMON_POLICY_DIRS`; cap only "other" files.

    Prior to this refactor a single flat cap of 200 applied to all candidates,
    which silently dropped IAM policies in non-standard locations when a repo
    had >200 JSON files (test fixtures, vendored data, schema files, …).
    Now the cap only applies to files outside the well-known policy
    directories, and the warning identifies what was skipped so a user can
    re-scan a narrower path if needed.
    """
    if max_other <= 0:
        return candidates

    common_roots = tuple(
        (repo / name).resolve() for name in COMMON_POLICY_DIRS
    )
    common_files: list[Path] = []
    other_files: list[Path] = []
    for path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            other_files.append(path)
            continue
        in_common_dir = False
        for root in common_roots:
            try:
                resolved.relative_to(root)
                in_common_dir = True
                break
            except ValueError:
                continue
        if in_common_dir:
            common_files.append(path)
        else:
            other_files.append(path)

    if len(other_files) > max_other:
        skipped = len(other_files) - max_other
        common_dirs_str = ", ".join(f"{d}/" for d in COMMON_POLICY_DIRS)
        _warn(
            f"Found {len(candidates)} JSON files; scanning the {len(common_files)} "
            f"in {common_dirs_str} plus the first {max_other} of {len(other_files)} "
            f"others ({skipped} skipped). To scan all of them, pass "
            f"--max-policy-files <N> with a higher limit, or scan a narrower "
            f"sub-path."
        )
        other_files = other_files[:max_other]

    return common_files + other_files


def _should_report_parse_error(path: Path) -> bool:
    """Report malformed JSON only when the path looks policy-related."""
    normalized_parts = {part.lower() for part in path.parts}
    policy_dirs = {"iam", "policies", "policy", "terraform"}
    if normalized_parts & policy_dirs:
        return True

    name = path.name.lower()
    return any(marker in name for marker in ("policy", "iam", "assume-role"))


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]

    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]

    return []


def _is_write_or_permissions_action(action: IamAction) -> bool:
    return action.access_level in {"All", "Write", "Permissions management"} or (
        action.risk_level >= RiskLevel.MEDIUM
    )


def _has_key_at_any_level(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(
            _has_key_at_any_level(child, key)
            for child in value.values()
        )

    if isinstance(value, list):
        return any(_has_key_at_any_level(item, key) for item in value)

    return False


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)
