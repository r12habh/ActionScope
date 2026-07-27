"""Tests for scan state persistence and delta reporting."""

from __future__ import annotations

import json
from pathlib import Path

from actionscope.findings import build_finding_records
from actionscope.models import (
    CompromisedActionFinding,
    CoverageGap,
    ExposurePath,
    RiskLevel,
    ScanResult,
)
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


def test_compute_delta_tracks_new_exposure_path() -> None:
    path = ExposurePath(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        action_kind="unpinned",
        action_ref="third-party/deploy@v1",
        action_step="Deploy helper",
        credential_step="Configure AWS credentials",
        role_arn="arn:aws:iam::123456789012:role/deploy",
        auth_type="oidc",
        policy_source="not_found",
        policy_source_file=None,
        match_confidence="none",
    )

    delta = compute_delta(
        {"overall_risk": "info", "finding_counts": {}, "finding_types": []},
        ScanResult(exposure_paths=[path]),
    )

    assert delta.new_finding_types == [
        "exposure:unpinned:third-party/deploy@v1"
    ]


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
    assert loaded["schema_version"] == 2
    assert loaded["overall_risk"] == "medium"


def test_compute_delta_tracks_exact_finding_ids(tmp_path: Path) -> None:
    baseline = ScanResult(compromised_action_findings=[_compromised()])
    state_file = tmp_path / "baseline.json"
    save_scan_state(baseline, "/repo", str(state_file))
    previous = load_scan_state(str(state_file))
    assert previous is not None

    current = ScanResult(
        compromised_action_findings=[
            _compromised(),
            _compromised("tj-actions/changed-files"),
        ]
    )
    delta = compute_delta(previous, current)

    assert delta.baseline_available is True
    assert delta.exact_finding_delta is True
    assert len(delta.new_finding_ids) == 1
    assert len(delta.new_findings) == 1
    assert len(delta.baseline_findings) == 1
    assert delta.baseline_findings[0]["fingerprint"]
    assert "tj-actions/changed-files" in delta.new_findings[0].title


def test_compute_delta_tracks_resolved_finding_ids(tmp_path: Path) -> None:
    baseline = ScanResult(
        compromised_action_findings=[
            _compromised(),
            _compromised("tj-actions/changed-files"),
        ]
    )
    state_file = tmp_path / "baseline.json"
    save_scan_state(baseline, "/repo", str(state_file))
    previous = load_scan_state(str(state_file))
    assert previous is not None
    previous_ids = {
        str(item["fingerprint"])
        for item in previous["findings"]
        if isinstance(item, dict)
    }

    current = ScanResult(compromised_action_findings=[_compromised()])
    delta = compute_delta(previous, current)

    current_ids = {
        record.fingerprint for record in build_finding_records(current)
    }
    assert len(delta.resolved_finding_ids) == 1
    assert set(delta.resolved_finding_ids) == previous_ids - current_ids


def test_state_does_not_store_raw_role_arn(tmp_path: Path) -> None:
    path = ExposurePath(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        action_kind="unpinned",
        action_ref="third-party/deploy@v1",
        action_step="Deploy",
        credential_step="Configure AWS",
        role_arn="arn:aws:iam::123456789012:role/secret-deploy-role",
        auth_type="oidc",
        policy_source="not_found",
        policy_source_file=None,
        match_confidence="none",
    )
    state_file = tmp_path / "baseline.json"

    save_scan_state(ScanResult(exposure_paths=[path]), "/repo", str(state_file))

    assert "arn:aws:iam" not in state_file.read_text(encoding="utf-8")


def test_state_does_not_store_absolute_checkout_path(tmp_path: Path) -> None:
    state_file = tmp_path / "baseline.json"

    save_scan_state(
        _result(),
        "/Users/example/private-repo",
        str(state_file),
    )

    payload = json.loads(state_file.read_text(encoding="utf-8"))
    assert payload["repo_path"] == "."
    assert "/Users/example" not in state_file.read_text(encoding="utf-8")


def test_normalization_failure_state_is_not_an_exact_baseline(
    tmp_path: Path,
) -> None:
    state_file = tmp_path / "baseline.json"
    result = ScanResult(
        coverage_status="partial",
        coverage_gaps=[
            CoverageGap(
                gap_type="finding_normalization_error",
                description="normalizer failed",
            )
        ],
    )

    save_scan_state(result, "/repo", str(state_file))
    previous = load_scan_state(str(state_file))
    assert previous is not None
    delta = compute_delta(previous, ScanResult())

    assert previous["findings_valid"] is False
    assert delta.exact_finding_delta is False


def test_compute_delta_preserves_current_normalization_failure(
    monkeypatch,
) -> None:
    result = ScanResult(
        coverage_status="partial",
        coverage_gaps=[
            CoverageGap(
                gap_type="finding_normalization_error",
                description="normalizer failed",
            )
        ],
    )

    def fail_if_retried(_result):
        raise AssertionError("normalization should not be retried")

    monkeypatch.setattr(
        "actionscope.findings.build_finding_records",
        fail_if_retried,
    )
    delta = compute_delta(
        {
            "schema_version": 2,
            "findings_valid": True,
            "overall_risk": "info",
            "finding_counts": {},
            "findings": [],
        },
        result,
    )

    assert delta.exact_finding_delta is False
    assert delta.new_finding_ids == []
    assert delta.new_findings == []


def test_state_file_written_atomically_without_tmp_leftover(tmp_path: Path) -> None:
    state_file = tmp_path / "last_scan.json"

    save_scan_state(_result(), "/repo", str(state_file))

    assert not (tmp_path / "last_scan.json.tmp").exists()
