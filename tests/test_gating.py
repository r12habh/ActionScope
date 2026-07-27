"""Tests for confidence-aware ActionScope CI gating."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from actionscope.cli import main
from actionscope.gating import evaluate_gate, evaluate_gate_payload
from actionscope.models import (
    FindingConfidence,
    FindingRecord,
    RiskLevel,
    ScanResult,
)
from actionscope.state import compute_delta, save_scan_state


def _record(
    fingerprint: str,
    *,
    risk: RiskLevel = RiskLevel.HIGH,
    confidence: FindingConfidence = FindingConfidence.HIGH,
) -> FindingRecord:
    return FindingRecord(
        fingerprint=fingerprint,
        rule_id="AS009",
        risk_level=risk,
        confidence=confidence,
        title=f"Finding {fingerprint}",
        workflow_file=".github/workflows/test.yml",
        job_name="test",
    )


def _result(*records: FindingRecord) -> ScanResult:
    result = ScanResult(finding_records=list(records))
    result.overall_risk = max(
        (record.risk_level for record in records),
        default=RiskLevel.INFO,
    )
    return result


def test_no_threshold_is_report_only() -> None:
    decision = evaluate_gate(_result(_record("one")), None)

    assert decision.status == "report_only"
    assert decision.exit_code == 0


def test_legacy_gate_uses_aggregate_risk() -> None:
    result = _result()
    result.overall_risk = RiskLevel.CRITICAL

    decision = evaluate_gate(result, "high")

    assert decision.status == "failed"
    assert decision.mode == "all_current"


def test_minimum_confidence_filters_low_confidence_finding() -> None:
    result = _result(_record("one", confidence=FindingConfidence.LOW))

    decision = evaluate_gate(
        result,
        "high",
        minimum_confidence="high",
    )

    assert decision.status == "passed"


def test_new_only_ignores_existing_critical_finding(tmp_path: Path) -> None:
    baseline_result = _result(_record("existing", risk=RiskLevel.CRITICAL))
    state_file = tmp_path / "baseline.json"
    save_scan_state(baseline_result, "/repo", str(state_file))
    baseline = json.loads(state_file.read_text(encoding="utf-8"))
    current = _result(_record("existing", risk=RiskLevel.CRITICAL))
    current.delta = compute_delta(baseline, current)

    decision = evaluate_gate(
        current,
        "high",
        minimum_confidence="high",
        new_only=True,
    )

    assert decision.status == "passed"


def test_new_only_blocks_new_high_confidence_finding(tmp_path: Path) -> None:
    baseline_result = _result(_record("existing"))
    state_file = tmp_path / "baseline.json"
    save_scan_state(baseline_result, "/repo", str(state_file))
    baseline = json.loads(state_file.read_text(encoding="utf-8"))
    current = _result(_record("existing"), _record("new"))
    current.delta = compute_delta(baseline, current)

    decision = evaluate_gate(
        current,
        "high",
        minimum_confidence="high",
        new_only=True,
    )

    assert decision.status == "failed"
    assert decision.matching_finding_ids == ["new"]


def test_new_only_blocks_finding_that_crosses_severity_threshold(
    tmp_path: Path,
) -> None:
    baseline_result = _result(_record("same", risk=RiskLevel.MEDIUM))
    state_file = tmp_path / "baseline.json"
    save_scan_state(baseline_result, "/repo", str(state_file))
    baseline = json.loads(state_file.read_text(encoding="utf-8"))
    current = _result(_record("same", risk=RiskLevel.HIGH))
    current.delta = compute_delta(baseline, current)

    decision = evaluate_gate(
        current,
        "high",
        minimum_confidence="high",
        new_only=True,
    )

    assert decision.status == "failed"
    assert decision.matching_finding_ids == ["same"]


def test_new_only_blocks_finding_that_crosses_confidence_threshold(
    tmp_path: Path,
) -> None:
    baseline_result = _result(
        _record("same", confidence=FindingConfidence.LOW)
    )
    state_file = tmp_path / "baseline.json"
    save_scan_state(baseline_result, "/repo", str(state_file))
    baseline = json.loads(state_file.read_text(encoding="utf-8"))
    current = _result(_record("same", confidence=FindingConfidence.HIGH))
    current.delta = compute_delta(baseline, current)

    decision = evaluate_gate(
        current,
        "high",
        minimum_confidence="high",
        new_only=True,
    )

    assert decision.status == "failed"


def test_new_only_does_not_block_improved_existing_finding(
    tmp_path: Path,
) -> None:
    baseline_result = _result(_record("same", risk=RiskLevel.CRITICAL))
    state_file = tmp_path / "baseline.json"
    save_scan_state(baseline_result, "/repo", str(state_file))
    baseline = json.loads(state_file.read_text(encoding="utf-8"))
    current = _result(_record("same", risk=RiskLevel.HIGH))
    current.delta = compute_delta(baseline, current)

    decision = evaluate_gate(
        current,
        "high",
        minimum_confidence="high",
        new_only=True,
    )

    assert decision.status == "passed"


def test_new_only_without_baseline_is_not_evaluated() -> None:
    result = _result(_record("new"))
    result.delta = compute_delta(None, result)

    decision = evaluate_gate(
        result,
        "high",
        minimum_confidence="high",
        new_only=True,
    )

    assert decision.status == "not_evaluated"
    assert decision.exit_code == 0


def test_require_baseline_exits_two() -> None:
    result = _result(_record("new"))
    result.delta = compute_delta(None, result)

    decision = evaluate_gate(
        result,
        "high",
        minimum_confidence="high",
        new_only=True,
        require_baseline=True,
    )

    assert decision.exit_code == 2


def test_payload_gate_filters_confidence() -> None:
    data = {
        "finding_records": [
            {
                "fingerprint": "low",
                "rule_id": "AS001",
                "risk_level": "critical",
                "confidence": "low",
                "title": "Low-confidence IAM match",
                "gate_eligible": True,
            }
        ]
    }

    decision = evaluate_gate_payload(
        data,
        "high",
        minimum_confidence="high",
    )

    assert decision.status == "passed"


def test_payload_gate_rejects_legacy_report_without_records() -> None:
    decision = evaluate_gate_payload(
        {"overall_risk": "critical"},
        "high",
    )

    assert decision.status == "not_evaluated"
    assert decision.exit_code == 2
    assert "new scan" in decision.reason


def test_payload_gate_rejects_malformed_record() -> None:
    decision = evaluate_gate_payload(
        {"finding_records": [{"rule_id": "AS001"}]},
        "high",
    )

    assert decision.status == "not_evaluated"
    assert decision.exit_code == 2


def test_gate_command_writes_decision_back(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "finding_records": [
                    {
                        "fingerprint": "critical",
                        "rule_id": "AS013",
                        "risk_level": "critical",
                        "confidence": "high",
                        "title": "Compromised action",
                        "gate_eligible": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main,
        [
            "gate",
            str(report),
            "--fail-on",
            "high",
            "--write-back",
        ],
    )

    assert result.exit_code == 1
    updated = json.loads(report.read_text(encoding="utf-8"))
    assert updated["gate"]["status"] == "failed"


def test_gate_command_requires_new_only_for_required_baseline(
    tmp_path: Path,
) -> None:
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"finding_records": []}), encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "gate",
            str(report),
            "--fail-on",
            "high",
            "--require-baseline",
        ],
    )

    assert result.exit_code == 2
    assert "--require-baseline requires --new-only" in result.output
