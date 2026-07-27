"""Confidence-aware CI gate evaluation for ActionScope findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from actionscope.models import (
    FindingConfidence,
    FindingRecord,
    RiskLevel,
    ScanResult,
)


@dataclass(frozen=True)
class GateDecision:
    """The result of applying a CI gate policy to one scan."""

    status: str
    mode: str
    threshold: str | None
    minimum_confidence: str
    matching_finding_ids: list[str]
    matching_findings: list[FindingRecord]
    reason: str
    exit_code: int


def evaluate_gate(
    result: ScanResult,
    fail_on: str | None,
    *,
    minimum_confidence: str | None = None,
    new_only: bool = False,
    require_baseline: bool = False,
) -> GateDecision:
    """Evaluate a ScanResult without changing or suppressing report output."""
    if not fail_on:
        return _report_only()

    if minimum_confidence is None and not new_only:
        threshold = RiskLevel(fail_on)
        failed = result.overall_risk >= threshold
        return GateDecision(
            status="failed" if failed else "passed",
            mode="all_current",
            threshold=threshold.name.lower(),
            minimum_confidence="legacy",
            matching_finding_ids=[],
            matching_findings=[],
            reason=(
                f"Observed risk {result.overall_risk.name.lower()} "
                f"{'meets' if failed else 'is below'} the "
                f"{threshold.name.lower()} threshold."
            ),
            exit_code=1 if failed else 0,
        )

    records = list(result.finding_records)
    if not records:
        from actionscope.findings import build_finding_records

        records = build_finding_records(result)

    return _evaluate_records(
        records,
        fail_on,
        minimum_confidence=minimum_confidence,
        new_only=new_only,
        delta=result.delta,
        require_baseline=require_baseline,
    )


def evaluate_gate_payload(
    data: dict[str, Any],
    fail_on: str,
    *,
    minimum_confidence: str = "high",
    new_only: bool = False,
    require_baseline: bool = False,
) -> GateDecision:
    """Evaluate a previously saved ActionScope JSON report."""
    raw_records = data.get("finding_records")
    if not isinstance(raw_records, list):
        return _invalid_report(
            "The JSON report has no normalized finding records. "
            "Run a new scan with the current ActionScope version."
        )
    records: list[FindingRecord] = []
    for item in raw_records:
        record = _record_from_dict(item) if isinstance(item, dict) else None
        if record is None:
            return _invalid_report(
                "The JSON report contains an invalid normalized finding record. "
                "Run a new scan before applying a gate."
            )
        records.append(record)
    delta = data.get("delta") if isinstance(data.get("delta"), dict) else None
    return _evaluate_records(
        records,
        fail_on,
        minimum_confidence=minimum_confidence,
        new_only=new_only,
        delta=delta,
        require_baseline=require_baseline,
    )


def format_gate_decision(decision: GateDecision) -> str:
    """Return a concise log message for a gate decision."""
    prefix = {
        "failed": "FAIL",
        "passed": "PASS",
        "not_evaluated": "NOT EVALUATED",
        "report_only": "REPORT ONLY",
    }.get(decision.status, decision.status.upper())
    return f"ActionScope gate: {prefix}. {decision.reason}"


def gate_decision_to_dict(decision: GateDecision) -> dict[str, Any]:
    """Serialize a gate decision for JSON reports."""
    payload = asdict(decision)
    for finding in payload["matching_findings"]:
        risk = finding.get("risk_level")
        confidence = finding.get("confidence")
        if isinstance(risk, RiskLevel):
            finding["risk_level"] = risk.name.lower()
        if isinstance(confidence, FindingConfidence):
            finding["confidence"] = confidence.name.lower()
    return payload


def _evaluate_records(
    records: list[FindingRecord],
    fail_on: str,
    *,
    minimum_confidence: str | None,
    new_only: bool,
    delta: object | dict[str, Any] | None,
    require_baseline: bool,
) -> GateDecision:
    threshold = RiskLevel(fail_on)
    confidence = FindingConfidence(
        minimum_confidence or ("high" if new_only else "low")
    )
    mode = "new_only" if new_only else "all_current"

    if new_only and not _has_exact_baseline(delta):
        reason = (
            "No exact baseline was available, so new-only findings could not "
            "be evaluated."
        )
        return GateDecision(
            status="not_evaluated",
            mode=mode,
            threshold=threshold.name.lower(),
            minimum_confidence=confidence.name.lower(),
            matching_finding_ids=[],
            matching_findings=[],
            reason=reason,
            exit_code=2 if require_baseline else 0,
        )

    candidates = [
        record
        for record in records
        if record.gate_eligible
        and record.risk_level >= threshold
        and record.confidence >= confidence
    ]
    if new_only:
        candidates = [
            record
            for record in candidates
            if _is_newly_gate_eligible(
                record,
                delta,
                threshold=threshold,
                confidence=confidence,
            )
        ]

    failed = bool(candidates)
    scope = "newly eligible " if new_only else ""
    reason = (
        f"{len(candidates)} {scope}finding(s) meet or exceed "
        f"{threshold.name.lower()} severity with at least "
        f"{confidence.name.lower()} confidence."
    )
    return GateDecision(
        status="failed" if failed else "passed",
        mode=mode,
        threshold=threshold.name.lower(),
        minimum_confidence=confidence.name.lower(),
        matching_finding_ids=[record.fingerprint for record in candidates],
        matching_findings=candidates,
        reason=reason,
        exit_code=1 if failed else 0,
    )


def _report_only() -> GateDecision:
    return GateDecision(
        status="report_only",
        mode="report_only",
        threshold=None,
        minimum_confidence="none",
        matching_finding_ids=[],
        matching_findings=[],
        reason="No fail-on threshold was configured.",
        exit_code=0,
    )


def _invalid_report(reason: str) -> GateDecision:
    return GateDecision(
        status="not_evaluated",
        mode="invalid_report",
        threshold=None,
        minimum_confidence="none",
        matching_finding_ids=[],
        matching_findings=[],
        reason=reason,
        exit_code=2,
    )


def _has_exact_baseline(delta: object | dict[str, Any] | None) -> bool:
    if isinstance(delta, dict):
        return bool(
            delta.get("baseline_available") and delta.get("exact_finding_delta")
        )
    return bool(
        delta is not None
        and getattr(delta, "baseline_available", False)
        and getattr(delta, "exact_finding_delta", False)
    )


def _is_newly_gate_eligible(
    record: FindingRecord,
    delta: object | dict[str, Any] | None,
    *,
    threshold: RiskLevel,
    confidence: FindingConfidence,
) -> bool:
    baseline = _baseline_finding_map(delta)
    previous = baseline.get(record.fingerprint)
    if previous is None:
        return True
    try:
        previous_risk = RiskLevel(str(previous.get("risk_level", "info")))
        previous_confidence = FindingConfidence(
            str(previous.get("confidence", "low"))
        )
    except ValueError:
        return True
    return (
        not bool(previous.get("gate_eligible", True))
        or previous_risk < threshold
        or previous_confidence < confidence
    )


def _baseline_finding_map(
    delta: object | dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    if isinstance(delta, dict):
        value = delta.get("baseline_findings", [])
    else:
        value = getattr(delta, "baseline_findings", []) if delta is not None else []
    if not isinstance(value, list):
        return {}
    return {
        str(item["fingerprint"]): item
        for item in value
        if isinstance(item, dict) and item.get("fingerprint")
    }


def _record_from_dict(item: dict[str, Any]) -> FindingRecord | None:
    try:
        return FindingRecord(
            fingerprint=str(item["fingerprint"]),
            rule_id=str(item["rule_id"]),
            risk_level=RiskLevel(str(item["risk_level"])),
            confidence=FindingConfidence(str(item["confidence"])),
            title=str(item.get("title", item["rule_id"])),
            workflow_file=(
                str(item["workflow_file"]) if item.get("workflow_file") else None
            ),
            job_name=str(item["job_name"]) if item.get("job_name") else None,
            gate_eligible=bool(item.get("gate_eligible", True)),
        )
    except (KeyError, TypeError, ValueError):
        return None
