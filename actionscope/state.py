"""Lightweight scan state persistence for delta/diff reporting."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from actionscope.models import RiskLevel

DEFAULT_STATE_DIR = ".actionscope"
DEFAULT_STATE_FILE = ".actionscope/last_scan.json"


@dataclass
class ScanDelta:
    """Difference between a previous ActionScope state and current scan."""

    previous_overall_risk: str | None
    current_overall_risk: str
    risk_changed: bool
    risk_increased: bool
    risk_decreased: bool
    previous_critical_count: int
    current_critical_count: int
    previous_high_count: int
    current_high_count: int
    new_finding_types: list[str]
    resolved_finding_types: list[str]
    new_compromised_actions: list[str]
    new_oidc_issues: int
    new_injection_issues: int
    new_privesc_paths: int


def save_scan_state(
    result,
    repo_path: str,
    state_file: str = DEFAULT_STATE_FILE,
) -> None:
    """Save a compact scan-result state for future comparison."""
    state_path = Path(state_file)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    payload = _state_payload(result, repo_path)
    tmp_path = state_path.with_name(f"{state_path.name}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp_path, state_path)


def load_scan_state(
    state_file: str = DEFAULT_STATE_FILE,
) -> dict | None:
    """Load previous scan state, returning None when unavailable or invalid."""
    try:
        data = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except (FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def compute_delta(
    previous_state: dict | None,
    current_result,
) -> ScanDelta:
    """Compute the difference between a previous state and current result."""
    current_state = _state_payload(
        current_result,
        getattr(current_result, "scan_path", "."),
    )
    current_risk = str(current_state["overall_risk"])
    if previous_state is None:
        return ScanDelta(
            previous_overall_risk=None,
            current_overall_risk=current_risk,
            risk_changed=False,
            risk_increased=False,
            risk_decreased=False,
            previous_critical_count=0,
            current_critical_count=current_state["finding_counts"]["critical"],
            previous_high_count=0,
            current_high_count=current_state["finding_counts"]["high"],
            new_finding_types=list(current_state["finding_types"]),
            resolved_finding_types=[],
            new_compromised_actions=list(current_state["compromised_actions"]),
            new_oidc_issues=int(current_state["oidc_issue_count"]),
            new_injection_issues=int(current_state["injection_issue_count"]),
            new_privesc_paths=int(current_state["privesc_path_count"]),
        )

    previous_risk = str(previous_state.get("overall_risk", "info"))
    risk_changed = previous_risk != current_risk
    previous_types = set(_list(previous_state.get("finding_types")))
    current_types = set(_list(current_state.get("finding_types")))
    previous_actions = set(_list(previous_state.get("compromised_actions")))
    current_actions = set(_list(current_state.get("compromised_actions")))

    prev_counts = previous_state.get("finding_counts")
    if not isinstance(prev_counts, dict):
        prev_counts = {}

    return ScanDelta(
        previous_overall_risk=previous_risk,
        current_overall_risk=current_risk,
        risk_changed=risk_changed,
        risk_increased=_risk_value(current_risk) > _risk_value(previous_risk),
        risk_decreased=_risk_value(current_risk) < _risk_value(previous_risk),
        previous_critical_count=_to_int(prev_counts.get("critical")),
        current_critical_count=current_state["finding_counts"]["critical"],
        previous_high_count=_to_int(prev_counts.get("high")),
        current_high_count=current_state["finding_counts"]["high"],
        new_finding_types=sorted(current_types - previous_types),
        resolved_finding_types=sorted(previous_types - current_types),
        new_compromised_actions=sorted(current_actions - previous_actions),
        new_oidc_issues=max(
            0,
            int(current_state["oidc_issue_count"])
            - _to_int(previous_state.get("oidc_issue_count")),
        ),
        new_injection_issues=max(
            0,
            int(current_state["injection_issue_count"])
            - _to_int(previous_state.get("injection_issue_count")),
        ),
        new_privesc_paths=max(
            0,
            int(current_state["privesc_path_count"])
            - _to_int(previous_state.get("privesc_path_count")),
        ),
    )


def _state_payload(result, repo_path: str) -> dict[str, Any]:
    finding_types = sorted(_finding_types(result))
    return {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "repo_path": repo_path,
        "overall_risk": _risk_name(getattr(result, "overall_risk", RiskLevel.INFO)),
        "workflow_count": int(getattr(result, "workflow_count", 0)),
        "finding_counts": {
            "critical": _count_risk(result, RiskLevel.CRITICAL),
            "high": _count_risk(result, RiskLevel.HIGH),
            "medium": _count_risk(result, RiskLevel.MEDIUM),
            "low": _count_risk(result, RiskLevel.LOW),
        },
        "finding_types": finding_types,
        "compromised_actions": sorted(
            {
                str(getattr(finding, "action_name", ""))
                for finding in getattr(result, "compromised_action_findings", [])
                if getattr(finding, "action_name", "")
            }
        ),
        "oidc_issue_count": len(getattr(result, "oidc_trust_findings", [])),
        "injection_issue_count": len(
            getattr(result, "script_injection_findings", [])
        )
        + len(getattr(result, "artifact_poisoning_findings", []))
        + len(getattr(result, "ai_agent_injection_findings", [])),
        "privesc_path_count": sum(
            len(getattr(finding, "privesc_paths", []))
            for finding in getattr(result, "policy_findings", [])
        ),
    }


def _finding_types(result) -> set[str]:
    types: set[str] = set()
    for finding in getattr(result, "policy_findings", []):
        for path in getattr(finding, "privesc_paths", []):
            types.add(f"privesc:{getattr(path, 'path_id', 'unknown')}")
    for finding in getattr(result, "oidc_trust_findings", []):
        types.add(f"oidc:{getattr(finding, 'issue_id', 'unknown')}")
    for finding in getattr(result, "script_injection_findings", []):
        types.add(f"script:{getattr(finding, 'untrusted_expression', 'unknown')}")
    for finding in getattr(result, "artifact_poisoning_findings", []):
        types.add(f"artifact:{getattr(finding, 'job_name', 'unknown')}")
    for finding in getattr(result, "ai_agent_injection_findings", []):
        types.add(f"ai:{getattr(finding, 'agent_type', 'unknown')}")
    for finding in getattr(result, "compromised_action_findings", []):
        types.add(f"compromised:{getattr(finding, 'action_name', 'unknown')}")
    for finding in getattr(result, "environment_findings", []):
        types.add(f"environment:{getattr(finding, 'finding_type', 'unknown')}")
    return types


def _count_risk(result, risk: RiskLevel) -> int:
    try:
        return len(result.findings_by_risk(risk))
    except AttributeError:
        return 0


def _risk_name(value: RiskLevel | str) -> str:
    if isinstance(value, RiskLevel):
        return value.name.lower()
    return str(value).lower()


def _risk_value(value: RiskLevel | str) -> int:
    try:
        return RiskLevel(value).value
    except ValueError:
        return RiskLevel.INFO.value


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
