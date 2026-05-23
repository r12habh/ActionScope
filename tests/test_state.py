"""Tests for scan state persistence and delta reporting."""

from __future__ import annotations

from pathlib import Path

from actionscope.models import CompromisedActionFinding, RiskLevel, ScanResult
from actionscope.state import compute_delta, load_scan_state, save_scan_state


def _compromised(
    action: str = "actions-cool/issues-helper",
) -> CompromisedActionFinding:
    return CompromisedActionFinding(
        workflow_file=".github/workflows/triage.yml",
        job_name="triage",
        step_name="Issue helper",
        uses_ref=f"{action}@v3",
        action_name=action,
        ref="v3",
        is_sha_pinned=False,
        compromise_date="2026-05-18T19:10:24Z",
        advisory_url="https://example.com/advisory",
        description="compromised",
        risk_level=RiskLevel.CRITICAL,
    )


def _result(risk: RiskLevel = RiskLevel.INFO) -> ScanResult:
    result = ScanResult()
    result.overall_risk = risk
    return result


def test_save_scan_state_creates_file(tmp_path: Path) -> None:
    state_file = tmp_path / "last_scan.json"

    save_scan_state(_result(), "/repo", str(state_file))

    assert state_file.is_file()


def test_load_scan_state_returns_none_for_nonexistent_file(tmp_path: Path) -> None:
    assert load_scan_state(str(tmp_path / "missing.json")) is None


def test_load_scan_state_returns_none_for_invalid_json(tmp_path: Path) -> None:
    state_file = tmp_path / "bad.json"
    state_file.write_text("{not-json", encoding="utf-8")

    assert load_scan_state(str(state_file)) is None


def test_compute_delta_no_previous_has_no_risk_change() -> None:
    delta = compute_delta(None, _result(RiskLevel.HIGH))

    assert delta.previous_overall_risk is None
    assert delta.risk_changed is False


def test_compute_delta_detects_risk_increase() -> None:
    previous = {"overall_risk": "high", "finding_counts": {}}

    delta = compute_delta(previous, _result(RiskLevel.CRITICAL))

    assert delta.risk_increased is True
    assert delta.risk_decreased is False


def test_compute_delta_detects_risk_decrease() -> None:
    previous = {"overall_risk": "critical", "finding_counts": {}}

    delta = compute_delta(previous, _result(RiskLevel.HIGH))

    assert delta.risk_decreased is True
    assert delta.risk_increased is False


def test_compute_delta_detects_new_compromised_actions() -> None:
    result = ScanResult(compromised_action_findings=[_compromised()])

    delta = compute_delta(
        {"overall_risk": "info", "finding_counts": {}, "compromised_actions": []},
        result,
    )

    assert delta.new_compromised_actions == ["actions-cool/issues-helper"]


def test_compute_delta_resolved_finding_types() -> None:
    previous = {
        "overall_risk": "high",
        "finding_counts": {},
        "finding_types": ["compromised:actions-cool/issues-helper"],
    }

    delta = compute_delta(previous, _result(RiskLevel.INFO))

    assert delta.resolved_finding_types == ["compromised:actions-cool/issues-helper"]


def test_compute_delta_handles_malformed_previous_state() -> None:
    previous = {
        "overall_risk": "high",
        "finding_counts": "bad",
        "oidc_issue_count": None,
    }

    delta = compute_delta(previous, _result(RiskLevel.HIGH))

    assert delta.previous_critical_count == 0
    assert delta.previous_high_count == 0
    assert isinstance(delta.risk_changed, bool)


def test_save_load_round_trip(tmp_path: Path) -> None:
    state_file = tmp_path / "last_scan.json"

    save_scan_state(_result(RiskLevel.MEDIUM), "/repo", str(state_file))
    loaded = load_scan_state(str(state_file))

    assert loaded is not None
    assert loaded["overall_risk"] == "medium"


def test_state_file_written_atomically_without_tmp_leftover(tmp_path: Path) -> None:
    state_file = tmp_path / "last_scan.json"

    save_scan_state(_result(), "/repo", str(state_file))

    assert not (tmp_path / "last_scan.json.tmp").exists()
