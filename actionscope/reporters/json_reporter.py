"""JSON reporter for machine-readable ActionScope scan results."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

from actionscope.models import (
    FindingConfidence,
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
        if isinstance(obj, RiskLevel):
            return _risk_level_str(obj)
        if isinstance(obj, FindingConfidence):
            return obj.name.lower()
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
        "risk_status": "known" if pf is not None else "unknown",
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


def _summary_dict(
    result: ScanResult,
    *,
    coverage_gap_count: int | None = None,
) -> dict[str, Any]:
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
        "reusable_workflows": len(result.reusable_workflows),
        "exposure_paths": len(result.exposure_paths),
        "uninspected_reusable_workflows": sum(
            1
            for reference in result.reusable_workflows
            if reference.status not in {"inspected", "cycle"}
        ),
        "oidc_trust_issues": len(result.oidc_trust_findings),
        "script_injection_risks": len(result.script_injection_findings),
        "artifact_poisoning_risks": len(result.artifact_poisoning_findings),
        "ai_agent_injection_risks": len(result.ai_agent_injection_findings),
        "compromised_actions": len(result.compromised_action_findings),
        "environment_issues": len(result.environment_findings),
        "pin_suggestions": len(result.pin_suggestions),
        "suppressed_rules": len(result.applied_suppressions),
        "hard_blocks": len(result.hard_block_findings),
        "coverage_gaps": (
            len(result.coverage_gaps)
            if coverage_gap_count is None
            else coverage_gap_count
        ),
    }


def to_json(result: ScanResult, indent: int = 2) -> str:
    """
    Serialize ScanResult to JSON string.

    Uses dataclasses.asdict for policy payloads and lowercase risk labels for enums.
    """
    unmatched = get_unmatched_findings(result.bindings, result.policy_findings)
    coverage_gaps = list(result.coverage_gaps)
    if not coverage_gaps:
        from actionscope.coverage import build_coverage_gaps

        coverage_gaps = build_coverage_gaps(result)
    coverage_status = "partial" if coverage_gaps else result.coverage_status
    finding_records = list(result.finding_records)
    normalization_failed = any(
        gap.gap_type == "finding_normalization_error"
        for gap in coverage_gaps
    )
    if (
        not finding_records
        and not normalization_failed
        and not result.config_applied
    ):
        from actionscope.findings import build_finding_records

        finding_records = build_finding_records(result)
    payload: dict[str, Any] = {
        "scan_path": result.scan_path,
        "overall_risk": _risk_level_str(result.overall_risk),
        "coverage_status": coverage_status,
        "coverage_gaps": [
            _serialize_for_json(asdict(gap)) for gap in coverage_gaps
        ],
        "workflow_count": result.workflow_count,
        "summary": _summary_dict(
            result,
            coverage_gap_count=len(coverage_gaps),
        ),
        "findings": [_binding_to_finding_dict(b) for b in result.bindings],
        "github_token_permissions": [
            _serialize_for_json(asdict(p))
            for p in result.github_token_permissions
        ],
        "unpinned_actions": [
            _serialize_for_json(asdict(finding))
            for finding in result.unpinned_actions
        ],
        "reusable_workflows": [
            _serialize_for_json(asdict(reference))
            for reference in result.reusable_workflows
        ],
        "exposure_paths": [
            _serialize_for_json(asdict(path)) for path in result.exposure_paths
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
        "compromised_action_findings": [
            _serialize_for_json(asdict(finding))
            for finding in result.compromised_action_findings
        ],
        "environment_findings": [
            _serialize_for_json(asdict(finding))
            for finding in result.environment_findings
        ],
        "finding_records": [
            _serialize_for_json(asdict(record)) for record in finding_records
        ],
        "configuration": {
            "applied": result.config_applied,
            "path": result.config_path,
            "severity_overrides": dict(result.severity_overrides),
            "warnings": list(result.config_warnings),
        },
        "applied_suppressions": [
            _serialize_for_json(asdict(item))
            for item in result.applied_suppressions
        ],
        "hard_block_findings": [
            _serialize_for_json(asdict(item))
            for item in result.hard_block_findings
        ],
        "pin_suggestions": [
            _serialize_for_json(asdict(finding) if is_dataclass(finding) else finding)
            for finding in result.pin_suggestions
        ],
        "delta": _serialize_for_json(
            asdict(result.delta)
            if is_dataclass(getattr(result, "delta", None))
            else getattr(result, "delta", None)
        ),
        "gate": _serialize_for_json(
            asdict(result.gate)
            if is_dataclass(getattr(result, "gate", None))
            else getattr(result, "gate", None)
        ),
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
