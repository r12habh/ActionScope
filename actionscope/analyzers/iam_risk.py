"""IAM risk classifier for translating AWS permissions into severity levels."""

from __future__ import annotations

import sys
from typing import Any

try:
    from policy_sentry.querying.actions import get_action_data
except ImportError:  # pragma: no cover - fallback when policy-sentry is absent
    get_action_data = None

try:
    from policy_sentry.querying.actions import get_actions_for_service
except ImportError:  # pragma: no cover - compatibility for older policy-sentry
    get_actions_for_service = None

try:
    from policy_sentry.shared.database import connect_db
except ImportError:  # pragma: no cover - compatibility for newer policy-sentry
    connect_db = None

from actionscope.models import IamAction, RiskLevel

_DB_SESSION: object | None = None
_JSON_BUNDLE_SESSION = object()

ALWAYS_CRITICAL = frozenset(
    {
        "iam:passrole",
        "iam:createpolicyversion",
        "iam:attachrolepolicy",
        "iam:attachuserpolicy",
        "iam:putrolepolicy",
        "iam:updateassumerolepolicy",
        "iam:createaccesskey",
        "iam:createloginprofile",
        "iam:addusertogroup",
        "iam:updateloginprofile",
        "iam:setdefaultpolicyversion",
        "sts:assumerole",
    }
)
ALWAYS_HIGH = frozenset(
    {
        "ec2:terminateinstances",
        "ec2:stopinstances",
        "rds:deletedbinstance",
        "s3:deletebucket",
        "s3:deleteobject",
        "lambda:deletefunction",
        "cloudformation:deletestack",
        "dynamodb:deletetable",
    }
)

_CRITICAL_ACTIONS = {
    "iam:passrole": "iam:PassRole",
    "iam:createpolicyversion": "iam:CreatePolicyVersion",
    "iam:attachrolepolicy": "iam:AttachRolePolicy",
    "iam:attachuserpolicy": "iam:AttachUserPolicy",
    "iam:putrolepolicy": "iam:PutRolePolicy",
    "iam:updateassumerolepolicy": "iam:UpdateAssumeRolePolicy",
    "iam:createloginprofile": "iam:CreateLoginProfile",
    "iam:addusertogroup": "iam:AddUserToGroup",
    "iam:updateloginprofile": "iam:UpdateLoginProfile",
    "iam:setdefaultpolicyversion": "iam:SetDefaultPolicyVersion",
}
_DESTRUCTIVE_KEYWORDS = ("delete", "terminate", "remove", "destroy")


def get_db_session() -> object:
    """Return a cached policy-sentry DB session or offline sentinel."""
    global _DB_SESSION

    if _DB_SESSION is not None:
        return _DB_SESSION

    if connect_db is None:
        _DB_SESSION = _JSON_BUNDLE_SESSION
        return _DB_SESSION

    try:
        _DB_SESSION = connect_db("bundled")
    except Exception as exc:
        _warn(f"Policy-sentry bundled IAM database unavailable: {exc}")
        _DB_SESSION = _JSON_BUNDLE_SESSION

    return _DB_SESSION


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def _heuristic_classify(normalized_action: str, resource: str) -> IamAction | None:
    """Offline risk classification when policy-sentry returns no data."""
    if normalized_action in ALWAYS_CRITICAL:
        return IamAction(
            action=normalized_action,
            access_level="Permissions management",
            risk_level=RiskLevel.CRITICAL,
            description=(
                "Heuristic critical action "
                "(policy-sentry database unavailable)"
            ),
            resource=resource,
        )
    if normalized_action in ALWAYS_HIGH:
        return IamAction(
            action=normalized_action,
            access_level="Write",
            risk_level=RiskLevel.HIGH,
            description=(
                "Heuristic high-risk action "
                "(policy-sentry database unavailable)"
            ),
            resource=resource,
        )
    return None


def classify_action(action: str, resource: str = "*") -> IamAction:
    """
    Classify a single IAM action string.

    The lookup is case-insensitive and uses policy-sentry's bundled IAM data.
    """
    stripped_action = action.strip()
    normalized_action = stripped_action.lower()

    if normalized_action == "*":
        return IamAction(
            action="*",
            access_level="All",
            risk_level=RiskLevel.CRITICAL,
            description="Grants ALL permissions on ALL AWS services",
            resource=resource,
        )

    if not _has_valid_action_format(normalized_action):
        return _invalid_action(stripped_action, resource)

    service_prefix, action_name = normalized_action.split(":", 1)

    if action_name == "*":
        return _classify_service_wildcard(service_prefix, resource)

    if _is_special_critical_action(normalized_action, resource):
        return _critical_action(
            normalized_action,
            service_prefix,
            action_name,
            resource,
        )

    entries = _get_action_entries(service_prefix, action_name)
    if not entries:
        heuristic = _heuristic_classify(normalized_action, resource)
        if heuristic is not None:
            return heuristic
        return IamAction(
            action=normalized_action,
            access_level="Unknown",
            risk_level=RiskLevel.LOW,
            description=(
                "Unknown action — could not verify risk level "
                "(database unavailable)"
            ),
            resource=resource,
        )

    entry = entries[0]
    canonical_action = str(entry.get("action", normalized_action))
    access_level = str(entry.get("access_level", "Unknown"))
    description = str(entry.get("description", "No description available"))
    risk_level = _risk_for_access_level(normalized_action, access_level)

    return IamAction(
        action=canonical_action,
        access_level=access_level,
        risk_level=risk_level,
        description=description,
        resource=resource,
    )


def classify_actions(actions: list[str], resource: str = "*") -> list[IamAction]:
    """Classify a list of actions."""
    return [classify_action(action, resource=resource) for action in actions]


def expand_wildcard_service(service_prefix: str) -> list[str]:
    """Return all IAM actions for a service prefix."""
    normalized_service = service_prefix.strip().lower()
    if not normalized_service:
        return []

    get_db_session()

    try:
        if get_actions_for_service is not None:
            return get_actions_for_service(normalized_service)

        entries = _get_action_entries(normalized_service, "*")
    except RuntimeError as exc:
        _warn(f"Policy-sentry lookup failed for {normalized_service}: {exc}")
        return []
    except Exception:
        return []

    actions: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        action = entry.get("action")
        if not isinstance(action, str) or action.lower() in seen:
            continue
        actions.append(action)
        seen.add(action.lower())
    return actions


def get_overall_risk(actions: list[IamAction]) -> RiskLevel:
    """Return the highest risk level from a list of IamAction objects."""
    return max((action.risk_level for action in actions), default=RiskLevel.INFO)


def format_risk_summary(actions: list[IamAction]) -> dict[RiskLevel, list[str]]:
    """Group action descriptions by risk level."""
    summary: dict[RiskLevel, list[str]] = {}
    for action in actions:
        summary.setdefault(action.risk_level, []).append(action.description)
    return summary


def _has_valid_action_format(action: str) -> bool:
    service_prefix, separator, action_name = action.partition(":")
    return bool(separator and service_prefix and action_name)


def _invalid_action(action: str, resource: str) -> IamAction:
    return IamAction(
        action=action,
        access_level="Unknown",
        risk_level=RiskLevel.LOW,
        description=f"Invalid action format: {action}",
        resource=resource,
    )


def _classify_service_wildcard(service_prefix: str, resource: str) -> IamAction:
    expanded_actions = expand_wildcard_service(service_prefix)
    if not expanded_actions:
        return IamAction(
            action=f"{service_prefix}:*",
            access_level="Unknown",
            risk_level=RiskLevel.LOW,
            description=(
                "Unknown action — could not verify risk level "
                "(database unavailable)"
            ),
            resource=resource,
        )

    expanded_action_names = {action.lower() for action in expanded_actions}
    has_critical_action = any(
        action in expanded_action_names for action in _CRITICAL_ACTIONS
    ) or ("sts:assumerole" in expanded_action_names and resource == "*")
    risk_level = RiskLevel.CRITICAL if has_critical_action else RiskLevel.HIGH

    return IamAction(
        action=f"{service_prefix}:*",
        access_level="All",
        risk_level=risk_level,
        description=f"Grants all {service_prefix} permissions",
        resource=resource,
    )


def _is_special_critical_action(action: str, resource: str) -> bool:
    return action in _CRITICAL_ACTIONS or (
        action == "sts:assumerole" and resource == "*"
    )


def _critical_action(
    action: str, service_prefix: str, action_name: str, resource: str
) -> IamAction:
    entries = _get_action_entries(service_prefix, action_name)
    entry = entries[0] if entries else {}
    canonical_action = str(entry.get("action", _CRITICAL_ACTIONS.get(action, action)))
    access_level = str(
        entry.get(
            "access_level",
            "Write" if action == "sts:assumerole" else "Permissions management",
        )
    )
    description = str(
        entry.get(
            "description",
            "Can enable AWS privilege escalation or broad role assumption",
        )
    )

    return IamAction(
        action=canonical_action,
        access_level=access_level,
        risk_level=RiskLevel.CRITICAL,
        description=description,
        resource=resource,
    )


def _risk_for_access_level(action: str, access_level: str) -> RiskLevel:
    if access_level == "Permissions management":
        return RiskLevel.CRITICAL if action in _CRITICAL_ACTIONS else RiskLevel.HIGH

    if access_level == "Write":
        if any(keyword in action for keyword in _DESTRUCTIVE_KEYWORDS):
            return RiskLevel.HIGH
        return RiskLevel.MEDIUM

    if access_level in {"Tagging", "Read", "List"}:
        return RiskLevel.LOW

    return RiskLevel.LOW


def _get_action_entries(service_prefix: str, action_name: str) -> list[dict[str, Any]]:
    if get_action_data is None:
        return []

    get_db_session()

    try:
        import inspect

        signature = inspect.signature(get_action_data)
        if len(signature.parameters) >= 3:
            action_data = get_action_data(get_db_session(), service_prefix, action_name)
        else:
            action_data = get_action_data(service_prefix, action_name)
    except RuntimeError as exc:
        _warn(
            "Policy-sentry action lookup failed for "
            f"{service_prefix}:{action_name}: {exc}"
        )
        return []
    except Exception:
        return []

    return _flatten_action_data(action_data)


def _flatten_action_data(action_data: Any) -> list[dict[str, Any]]:
    if not action_data:
        return []

    if isinstance(action_data, list):
        return [entry for entry in action_data if isinstance(entry, dict)]

    if not isinstance(action_data, dict):
        return []

    if "access_level" in action_data:
        return [action_data]

    entries: list[dict[str, Any]] = []
    for value in action_data.values():
        if isinstance(value, list):
            entries.extend(entry for entry in value if isinstance(entry, dict))
        elif isinstance(value, dict):
            entries.extend(_flatten_action_data(value))
    return entries
