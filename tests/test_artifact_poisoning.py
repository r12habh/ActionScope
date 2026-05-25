"""Tests for workflow_run artifact poisoning detection."""

from pathlib import Path
from shutil import copyfile

from actionscope.analyzers.artifact_poisoning import (
    analyze_artifact_poisoning,
    downloads_artifact_in_workflow,
    executes_after_download,
    scan_for_artifact_poisoning,
    uses_workflow_run_trigger,
    workflow_accesses_secrets,
)
from actionscope.models import RiskLevel
from actionscope.parsers.workflow import parse_workflow_file

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "workflows"


def _fixture() -> dict:
    data = parse_workflow_file(str(FIXTURE_DIR / "artifact_poisoning.yml"))
    assert data is not None
    return data


def test_uses_workflow_run_trigger_returns_true() -> None:
    assert uses_workflow_run_trigger(_fixture())


def test_downloads_artifact_detects_download_action() -> None:
    assert downloads_artifact_in_workflow(_fixture())


def test_executes_after_download_detects_chmod_pattern() -> None:
    assert executes_after_download(_fixture())


def test_workflow_accesses_secrets_returns_true() -> None:
    assert workflow_accesses_secrets(_fixture())


def test_fixture_workflow_produces_critical_finding() -> None:
    findings = analyze_artifact_poisoning(_fixture(), "artifact_poisoning.yml")

    assert findings[0].risk_level is RiskLevel.CRITICAL


def test_dawidd6_download_artifact_execution_is_detected() -> None:
    data = {
        "on": {"workflow_run": {"workflows": ["Build"], "types": ["completed"]}},
        "jobs": {
            "deploy": {
                "steps": [
                    {"uses": "dawidd6/action-download-artifact@v3"},
                    {"run": "bash deploy.sh"},
                    {
                        "run": "echo ${{ secrets.DEPLOY_TOKEN }}",
                    },
                ]
            }
        },
    }

    findings = analyze_artifact_poisoning(data, "deploy.yml")

    assert downloads_artifact_in_workflow(data) is True
    assert executes_after_download(data) is True
    assert findings[0].job_name == "deploy"
    assert findings[0].risk_level is RiskLevel.CRITICAL
    assert findings[0].downloads_artifacts is True
    assert findings[0].executes_artifacts is True
    assert findings[0].has_secret_access is True


def test_workflow_with_download_but_no_execution_is_medium() -> None:
    data = {
        "on": {"workflow_run": {}},
        "jobs": {
            "publish": {
                "steps": [{"uses": "actions/download-artifact@v4"}]
            }
        },
    }

    findings = analyze_artifact_poisoning(data, "artifact.yml")

    assert findings[0].risk_level is RiskLevel.MEDIUM


def test_non_workflow_run_workflow_produces_no_findings() -> None:
    data = {"on": "push", "jobs": {"test": {"steps": []}}}

    assert analyze_artifact_poisoning(data, "ci.yml") == []


def test_missing_secrets_reduces_critical_to_high() -> None:
    data = {
        "on": {"workflow_run": {}},
        "jobs": {
            "publish": {
                "steps": [
                    {"uses": "actions/download-artifact@v4"},
                    {"run": "chmod +x ./dist/deploy.sh"},
                ]
            }
        },
    }

    findings = analyze_artifact_poisoning(data, "artifact.yml")

    assert findings[0].risk_level is RiskLevel.HIGH


def test_artifact_poisoning_finding_fields_populated() -> None:
    finding = analyze_artifact_poisoning(_fixture(), "artifact_poisoning.yml")[0]

    assert finding.workflow_file
    assert finding.job_name == "publish"
    assert finding.description
    assert finding.recommendation


def test_scan_for_artifact_poisoning_works_on_fixture_dir(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    copyfile(
        FIXTURE_DIR / "artifact_poisoning.yml",
        workflow_dir / "artifact_poisoning.yml",
    )

    findings, errors = scan_for_artifact_poisoning(str(tmp_path))

    assert errors == []
    assert len(findings) == 1


def test_non_mapping_jobs_do_not_crash_artifact_scan() -> None:
    data = {"on": {"workflow_run": {}}, "jobs": None}

    assert downloads_artifact_in_workflow(data) is False
    assert analyze_artifact_poisoning(data, "artifact.yml") == []
