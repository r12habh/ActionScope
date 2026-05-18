"""JSON reporter for machine-readable ActionScope scan results."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from enum import Enum
from typing import Any

from actionscope.models import (
    IamAction,
    PolicyFinding,
    RiskLevel,
    ScanResult,
    WorkflowCredentialBinding,
    get_unmatched_findings,
)


def _risk_level_str(level: RiskLevel) -> str:
    """Serialize risk as lowercase enum name (matches JSON schema examples)."""
    return level.name.lower()


def _serialize_for_json(obj: Any) -> Any:
    """Convert dataclass trees and enums to JSON-serializable structures."""
    if isinstance(obj, Enum):
        # RiskLevel .value is int; schema expects string labels like "critical".
        if isinstance(obj, RiskLevel):
            return _risk_level_str(obj)
        return str(obj.value) if hasattr(obj, "value") else obj.name.lower()
    if isinstance(obj, dict):
        return {k: _serialize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize_for_json(v) for v in obj]
    return obj


def _iam_action_to_dict(action: IamAction) -> dict[str, Any]:
    d = asdict(action)
    d["risk_level"] = _risk_level_str(action.risk_level)
    return d


def _auth_type_for_binding(binding: WorkflowCredentialBinding) -> str:
    src = binding.credential_source
    if src.uses_oidc:
        return "oidc"
    if src.uses_access_keys:
        return "access_keys"
    return "unknown"


def _binding_to_finding_dict(binding: WorkflowCredentialBinding) -> dict[str, Any]:
    src = binding.credential_source
    pf = binding.policy_finding

    out: dict[str, Any] = {
        "workflow_file": src.workflow_file,
        "job_name": src.job_name,
        "role_arn": src.role_arn,
        "auth_type": _auth_type_for_binding(binding),
        "policy_source": binding.policy_source,
        "match_confidence": binding.match_confidence,
        "match_reason": binding.match_reason,
    }

    if pf is not None:
        out["overall_risk"] = _risk_level_str(pf.overall_risk)
        out["has_passrole"] = pf.has_passrole
        out["has_privilege_escalation"] = pf.has_privilege_escalation
        out["actions"] = [_iam_action_to_dict(a) for a in pf.actions]
    else:
        out["overall_risk"] = _risk_level_str(RiskLevel.INFO)
        out["has_passrole"] = False
        out["has_privilege_escalation"] = False
        out["actions"] = []

    return out


def _policy_finding_to_report_dict(finding: PolicyFinding) -> dict[str, Any]:
    d = asdict(finding)
    d["overall_risk"] = _risk_level_str(finding.overall_risk)
    d["actions"] = [_iam_action_to_dict(a) for a in finding.actions]
    return _serialize_for_json(d)


def _summary_dict(result: ScanResult) -> dict[str, Any]:
    policies_found = sum(
        1 for b in result.bindings if b.policy_finding is not None
    )
    policies_not_found = sum(
        1 for b in result.bindings if b.policy_source == "not_found"
    )
    github_token_risks = sum(
        1
        for p in result.github_token_permissions
        if p.risk_level >= RiskLevel.MEDIUM
    )
    return {
        "credential_sources": len(result.credential_sources),
        "policies_found": policies_found,
        "policies_not_found": policies_not_found,
        "github_token_risks": github_token_risks,
        "unpinned_actions": len(result.unpinned_actions),
        "oidc_trust_issues": len(result.oidc_trust_findings),
        "script_injection_risks": len(result.script_injection_findings),
        "artifact_poisoning_risks": len(result.artifact_poisoning_findings),
        "ai_agent_injection_risks": len(result.ai_agent_injection_findings),
    }


def to_json(result: ScanResult, indent: int = 2) -> str:
    """
    Serialize ScanResult to JSON string.

    Uses dataclasses.asdict for policy payloads and lowercase risk labels for enums.
    """
    unmatched = get_unmatched_findings(result.bindings, result.policy_findings)
    payload: dict[str, Any] = {
        "scan_path": result.scan_path,
        "overall_risk": _risk_level_str(result.overall_risk),
        "workflow_count": result.workflow_count,
        "summary": _summary_dict(result),
        "findings": [_binding_to_finding_dict(b) for b in result.bindings],
        "github_token_permissions": [
            _serialize_for_json(asdict(p))
            for p in result.github_token_permissions
        ],
        "unpinned_actions": [
            _serialize_for_json(asdict(finding))
            for finding in result.unpinned_actions
        ],
        "oidc_trust_findings": [
            _serialize_for_json(asdict(finding))
            for finding in result.oidc_trust_findings
        ],
        "script_injection_findings": [
            _serialize_for_json(asdict(finding))
            for finding in result.script_injection_findings
        ],
        "artifact_poisoning_findings": [
            _serialize_for_json(asdict(finding))
            for finding in result.artifact_poisoning_findings
        ],
        "ai_agent_injection_findings": [
            _serialize_for_json(asdict(finding))
            for finding in result.ai_agent_injection_findings
        ],
        "unmatched_policies": [
            _policy_finding_to_report_dict(p) for p in unmatched
        ],
        "errors": list(result.errors),
    }
    return json.dumps(payload, indent=indent)


def write_json(result: ScanResult, output_path: str) -> None:
    """Write JSON to file."""
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(to_json(result))
    except (OSError, UnicodeEncodeError) as exc:
        print(
            f"Warning: could not write JSON output file {output_path}: {exc}",
            file=sys.stderr,
        )
