"""Normalize heterogeneous detector output for deltas and CI gating."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from actionscope.models import (
    FindingConfidence,
    FindingRecord,
    RiskLevel,
    ScanResult,
    get_unmatched_findings,
)


def build_finding_records(result: ScanResult) -> list[FindingRecord]:
    """Return stable, deduplicated records for all reportable findings."""
    records: list[FindingRecord] = []

    for binding in result.bindings:
        source = binding.credential_source
        finding = binding.policy_finding
        confidence = _match_confidence(binding.match_confidence)
        role = source.role_arn or "(unknown role)"

        if finding is not None and finding.overall_risk > RiskLevel.INFO:
            reportable_actions = [
                action
                for action in finding.actions
                if action.risk_level > RiskLevel.INFO
            ]
            for action in reportable_actions:
                records.append(
                    _record(
                        result,
                        "AS001",
                        action.risk_level,
                        confidence,
                        f"AWS permission: {action.action} on {action.resource}",
                        source.workflow_file,
                        source.job_name,
                        role,
                        action.action.lower(),
                        action.resource,
                    )
                )

            # Some parsers can establish aggregate risk without recovering
            # individual IAM actions. Preserve a gateable record for that
            # degraded case.
            if not reportable_actions:
                records.append(
                    _record(
                        result,
                        "AS001",
                        finding.overall_risk,
                        confidence,
                        f"AWS blast radius detected for {role}",
                        source.workflow_file,
                        source.job_name,
                        role,
                        _relative_path(finding.source_file, result.scan_path),
                    )
                )

            for path in finding.privesc_paths:
                records.append(
                    _record(
                        result,
                        "AS002",
                        path.severity,
                        confidence,
                        f"Privilege escalation path: {path.path_name}",
                        source.workflow_file,
                        source.job_name,
                        role,
                        path.path_id,
                    )
                )

            if finding.has_passrole:
                records.append(
                    _record(
                        result,
                        "AS003",
                        RiskLevel.CRITICAL,
                        confidence,
                        f"iam:PassRole detected for {role}",
                        source.workflow_file,
                        source.job_name,
                        role,
                    )
                )

        if source.uses_access_keys:
            records.append(
                _record(
                    result,
                    "AS005",
                    RiskLevel.MEDIUM,
                    FindingConfidence.HIGH,
                    "Static AWS credentials used",
                    source.workflow_file,
                    source.job_name,
                    role,
                )
            )

    for finding in get_unmatched_findings(
        result.bindings,
        result.policy_findings,
    ):
        role = finding.role_arn or finding.role_name or "(unmatched policy)"
        source_file = _relative_path(finding.source_file, result.scan_path)
        reportable_actions = [
            action
            for action in finding.actions
            if action.risk_level > RiskLevel.INFO
        ]
        for action in reportable_actions:
            records.append(
                _record(
                    result,
                    "AS001",
                    action.risk_level,
                    FindingConfidence.LOW,
                    f"Unmatched AWS permission: {action.action} on {action.resource}",
                    source_file,
                    None,
                    "unmatched_policy",
                    role,
                    action.action.lower(),
                    action.resource,
                    gate_eligible=False,
                )
            )
        if finding.overall_risk > RiskLevel.INFO and not reportable_actions:
            records.append(
                _record(
                    result,
                    "AS001",
                    finding.overall_risk,
                    FindingConfidence.LOW,
                    f"Unmatched IAM policy risk detected for {role}",
                    source_file,
                    None,
                    "unmatched_policy",
                    role,
                    gate_eligible=False,
                )
            )
        for path in finding.privesc_paths:
            records.append(
                _record(
                    result,
                    "AS002",
                    path.severity,
                    FindingConfidence.LOW,
                    f"Unmatched privilege escalation path: {path.path_name}",
                    source_file,
                    None,
                    "unmatched_policy",
                    role,
                    path.path_id,
                    gate_eligible=False,
                )
            )
        if finding.has_passrole:
            records.append(
                _record(
                    result,
                    "AS003",
                    RiskLevel.CRITICAL,
                    FindingConfidence.LOW,
                    f"iam:PassRole detected in unmatched policy for {role}",
                    source_file,
                    None,
                    "unmatched_policy",
                    role,
                    gate_eligible=False,
                )
            )

    for permission in result.github_token_permissions:
        if permission.risk_level <= RiskLevel.INFO:
            continue
        records.append(
            _record(
                result,
                "AS004",
                permission.risk_level,
                FindingConfidence.HIGH,
                f"GITHUB_TOKEN permission: {permission.scope} {permission.access}",
                permission.workflow_file,
                permission.job_name,
                permission.scope,
                permission.access,
            )
        )

    for finding in result.unpinned_actions:
        records.append(
            _record(
                result,
                "AS006",
                RiskLevel.MEDIUM,
                FindingConfidence.HIGH,
                f"Unpinned GitHub Action: {finding.uses}",
                finding.workflow_file,
                finding.job_name,
                finding.uses,
            )
        )

    for finding in result.oidc_trust_findings:
        rule_id = "AS008" if finding.issue_id == "missing_sub" else "AS007"
        records.append(
            _record(
                result,
                rule_id,
                finding.risk_level,
                FindingConfidence.HIGH,
                finding.issue_description,
                finding.source_file,
                None,
                finding.role_name,
                finding.issue_id,
                finding.evidence,
            )
        )

    for finding in result.script_injection_findings:
        records.append(
            _record(
                result,
                "AS009",
                finding.risk_level,
                FindingConfidence.HIGH,
                f"Script injection: {finding.untrusted_expression}",
                finding.workflow_file,
                finding.job_name,
                finding.untrusted_expression,
            )
        )

    for finding in result.artifact_poisoning_findings:
        records.append(
            _record(
                result,
                "AS010",
                finding.risk_level,
                FindingConfidence.MEDIUM,
                "Artifact poisoning risk",
                finding.workflow_file,
                finding.job_name,
                finding.downloads_artifacts,
                finding.executes_artifacts,
                finding.has_secret_access,
            )
        )

    for finding in result.ai_agent_injection_findings:
        rule_id = "AS012" if finding.has_aws_secret_access else "AS011"
        records.append(
            _record(
                result,
                rule_id,
                finding.risk_level,
                FindingConfidence.MEDIUM,
                f"AI agent injection surface: {finding.agent_type}",
                finding.workflow_file,
                finding.job_name,
                finding.agent_action,
                sorted(str(item) for item in finding.untrusted_inputs),
            )
        )

    for finding in result.compromised_action_findings:
        records.append(
            _record(
                result,
                "AS013",
                finding.risk_level,
                FindingConfidence.HIGH,
                f"Known-compromised action: {finding.uses_ref}",
                finding.workflow_file,
                finding.job_name,
                finding.action_name,
                finding.ref,
            )
        )

    for finding in result.environment_findings:
        records.append(
            _record(
                result,
                "AS014",
                finding.risk_level,
                FindingConfidence.HIGH,
                f"GitHub Environment issue: {finding.finding_type}",
                finding.workflow_file,
                finding.job_name,
                finding.finding_type,
                finding.environment_name,
            )
        )

    for reference in result.reusable_workflows:
        if reference.status in {"inspected", "cycle"}:
            continue
        records.append(
            _record(
                result,
                "AS015",
                RiskLevel.LOW,
                FindingConfidence.HIGH,
                f"Reusable workflow was not inspected: {reference.uses}",
                reference.caller_workflow,
                reference.caller_job,
                reference.uses,
                reference.status,
                gate_eligible=False,
            )
        )

    for path in result.exposure_paths:
        confidence = (
            FindingConfidence.HIGH
            if path.action_kind == "known_compromised"
            else FindingConfidence.MEDIUM
        )
        policy_confidence = _match_confidence(path.match_confidence)
        if path.match_confidence not in {"", "none"}:
            confidence = min(confidence, policy_confidence, key=lambda item: item.value)
        records.append(
            _record(
                result,
                "AS016",
                path.risk_level,
                confidence,
                f"Workflow-to-AWS exposure: {path.action_ref}",
                path.workflow_file,
                path.job_name,
                path.action_kind,
                path.action_ref,
                path.role_arn,
            )
        )

    return _deduplicate(records)


def _record(
    result: ScanResult,
    rule_id: str,
    risk_level: RiskLevel,
    confidence: FindingConfidence,
    title: str,
    workflow_file: str | None,
    job_name: str | None,
    *identity: object,
    gate_eligible: bool = True,
) -> FindingRecord:
    normalized_workflow = _relative_path(workflow_file, result.scan_path)
    fingerprint = _fingerprint(
        rule_id,
        normalized_workflow,
        job_name or "",
        *identity,
    )
    return FindingRecord(
        fingerprint=fingerprint,
        rule_id=rule_id,
        risk_level=risk_level,
        confidence=confidence,
        title=title,
        workflow_file=normalized_workflow or None,
        job_name=job_name,
        gate_eligible=gate_eligible,
    )


def _fingerprint(*parts: object) -> str:
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def _relative_path(value: str | None, scan_path: str) -> str:
    if not value:
        return ""
    path = Path(value)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(Path(scan_path).resolve()).as_posix()
    except (OSError, ValueError):
        digest = hashlib.sha256(path.as_posix().encode("utf-8")).hexdigest()[:12]
        return f"_external/{digest}/{path.name}"


def _match_confidence(value: str) -> FindingConfidence:
    try:
        return FindingConfidence(value)
    except ValueError:
        return FindingConfidence.LOW


def _deduplicate(records: list[FindingRecord]) -> list[FindingRecord]:
    by_fingerprint: dict[str, FindingRecord] = {}
    for record in records:
        by_fingerprint.setdefault(record.fingerprint, record)
    return sorted(
        by_fingerprint.values(),
        key=lambda record: (
            -record.risk_level.value,
            record.rule_id,
            record.workflow_file or "",
            record.job_name or "",
            record.fingerprint,
        ),
    )
