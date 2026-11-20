"""End-to-end coverage tests against the coverage_repo fixture.

The coverage_repo fixture is a small synthetic repo designed to trigger every
detector in ActionScope at least once. These tests pin down the expected set of
findings so a future change that silently disables a detector, mis-filters
results, or regresses the risk-aggregation logic surfaces as a hard test
failure rather than a quietly under-reported scan.

Each detector has its own targeted test instead of one giant snapshot, so the
failure message points directly at the broken detector.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from actionscope.cli import main

FIXTURE = str(Path(__file__).resolve().parent / "fixtures" / "coverage_repo")
MEDIUM_ONLY_FIXTURE = str(
    Path(__file__).resolve().parent / "fixtures" / "medium_only_repo"
)


@pytest.fixture(scope="module")
def scan_json() -> dict:
    """Run one scan and share the parsed JSON across the tests in this module."""
    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", FIXTURE, "--output-format", "json", "--no-color"]
    )
    assert result.exit_code == 0, (
        "scan should succeed (exit 0) without --fail-on; got %d. Output: %s"
        % (result.exit_code, result.output[:500])
    )
    return json.loads(result.stdout)


def test_overall_risk_is_critical(scan_json: dict) -> None:
    """Aggregate risk must be CRITICAL — the compromised action drives it."""
    assert scan_json["overall_risk"] == "critical"


def test_workflow_count_matches_fixture(scan_json: dict) -> None:
    """Detects all six workflow files in the fixture."""
    assert scan_json["workflow_count"] == 6


def test_two_aws_credential_sources_detected(scan_json: dict) -> None:
    """deploy.yml + ai-review.yml each configure AWS credentials."""
    assert scan_json["summary"]["credential_sources"] == 2


def test_compromised_action_detected_with_advisory(scan_json: dict) -> None:
    """actions-cool/issues-helper@v3 must be flagged with an advisory URL."""
    findings = scan_json["compromised_action_findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["action_name"] == "actions-cool/issues-helper"
    assert finding["risk_level"] == "critical"
    assert finding["advisory_url"].startswith("http")


def test_oidc_trust_issue_detected(scan_json: dict) -> None:
    """The Terraform OIDC trust policy uses ref:refs/heads/* — must be flagged."""
    findings = scan_json["oidc_trust_findings"]
    assert len(findings) == 1
    assert ":ref:" in str(findings[0].get("evidence", "")).lower()


def test_script_injection_in_pr_handler_detected(scan_json: dict) -> None:
    """pr-handler.yml interpolates github.event.pull_request.title directly."""
    findings = scan_json["script_injection_findings"]
    assert len(findings) == 1
    assert "pr-handler" in findings[0]["workflow_file"]


def test_artifact_poisoning_workflow_run_detected(scan_json: dict) -> None:
    """artifact-publish.yml runs a downloaded artifact under workflow_run."""
    findings = scan_json["artifact_poisoning_findings"]
    assert len(findings) == 1
    assert "artifact-publish" in findings[0]["workflow_file"]


def test_ai_agent_with_write_perms_detected(scan_json: dict) -> None:
    """ai-review.yml uses Claude Code with write perms in a PR context."""
    findings = scan_json["ai_agent_injection_findings"]
    assert len(findings) == 1
    assert "ai-review" in findings[0]["workflow_file"]


def test_environment_finding_for_deploy_job(scan_json: dict) -> None:
    """The deploy-style job without proper trust-policy scoping is reported.

    Regression guard for risk_engine.py: an earlier version filtered
    environment findings to >= HIGH, which silently dropped MEDIUM findings out
    of overall_risk. Locking the count and risk level catches that class of bug.
    """
    findings = scan_json["environment_findings"]
    assert len(findings) == 1
    assert findings[0]["job_name"] == "deploy"
    assert {f["risk_level"] for f in findings} == {"medium"}


def test_unpinned_actions_detected(scan_json: dict) -> None:
    """Six unpinned external action references across the fixture workflows."""
    assert scan_json["summary"]["unpinned_actions"] == 6
    assert any(
        finding["uses"] == "actions/checkout@v4"
        for finding in scan_json["unpinned_actions"]
    )


def test_safe_workflow_is_not_in_unpinned_findings(scan_json: dict) -> None:
    """safe.yml uses a full-SHA pin — must not appear in unpinned findings."""
    unpinned_refs = [f["uses"] for f in scan_json["unpinned_actions"]]
    safe_sha = "b4ffde65f46336ab88eb53be808477a3936bae11"
    assert not any(safe_sha in u for u in unpinned_refs)


def test_role_correlation_finds_terraform_policy(scan_json: dict) -> None:
    """The deployer role ARN must correlate with iam.tf's inline policy."""
    findings = [
        f for f in scan_json.get("findings", [])
        if "deployer-role" in (f.get("role_arn") or "")
    ]
    assert findings, "deployer-role finding missing from scan output"
    assert any(f.get("policy_source") == "terraform" for f in findings), (
        "deployer-role must be matched against the terraform/iam.tf source"
    )


def test_role_correlation_finds_json_policy(scan_json: dict) -> None:
    """ai-review-role must correlate to the JSON policy file."""
    findings = [
        f for f in scan_json.get("findings", [])
        if "ai-review-role" in (f.get("role_arn") or "")
    ]
    assert findings, "ai-review-role finding missing from scan output"
    assert any(f.get("policy_source") == "json" for f in findings), (
        "ai-review-role must be matched against the JSON policy source"
    )


def test_passrole_privesc_detected_in_terraform_policy(scan_json: dict) -> None:
    """iam.tf grants iam:PassRole on *; must produce a HIGH/CRITICAL finding."""
    has_passrole = any(
        finding.get("has_passrole")
        for finding in scan_json.get("findings", [])
    )
    assert has_passrole, "iam:PassRole privesc path not detected on deployer-role"


def test_github_token_write_permissions_flagged(scan_json: dict) -> None:
    """pr-handler.yml + ai-review.yml have write-capable token perms."""
    assert scan_json["summary"]["github_token_risks"] >= 2


def test_sarif_output_matches_critical_risk(tmp_path: Path) -> None:
    """SARIF output must include rules and emit at least one error-level result."""
    runner = CliRunner()
    sarif_path = tmp_path / "results.sarif"
    result = runner.invoke(
        main,
        [
            "scan", FIXTURE,
            "--output-format", "sarif",
            "--output-file", str(sarif_path),
            "--no-color",
        ],
    )
    assert result.exit_code in (0, 1)
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    results = data["runs"][0]["results"]
    assert any(r.get("level") == "error" for r in results), (
        "no error-level SARIF result for the compromised action"
    )


def test_markdown_output_mentions_all_detectors(tmp_path: Path) -> None:
    """Markdown report should mention each detector by section heading.

    Regression guard for the markdown reporter dropping a detector when one of
    its sections is conditionally rendered and the condition gets broken.
    """
    runner = CliRunner()
    out_path = tmp_path / "report.md"
    result = runner.invoke(
        main,
        [
            "scan", FIXTURE,
            "--output-format", "markdown",
            "--output-file", str(out_path),
            "--no-color",
        ],
    )
    assert result.exit_code in (0, 1)
    text = out_path.read_text(encoding="utf-8").lower()
    for needle in (
        "compromised",
        "oidc",
        "injection",
        "ai agent",
        "environment",
        "unpinned",
    ):
        assert needle in text, f"markdown report missing section for '{needle}'"


def test_fail_on_medium_triggered_by_environment_findings_alone() -> None:
    """`--fail-on medium` must fail when MEDIUM env findings are the *only* signal.

    Uses the medium_only_repo fixture which is constructed to produce exactly
    one MEDIUM environment finding and nothing else (no compromised actions,
    no privesc paths, no script injection, no unpinned actions). If the
    risk_engine HIGH-filter bug came back, overall_risk would drop to INFO,
    `--fail-on medium` would exit 0, and this assertion would fail —
    catching exactly the regression class.
    """
    runner = CliRunner()
    json_result = runner.invoke(
        main,
        [
            "scan", MEDIUM_ONLY_FIXTURE,
            "--output-format", "json", "--no-color",
        ],
    )
    data = json.loads(json_result.stdout)

    # Lock down isolation: only the environment detector fires.
    assert data["overall_risk"] == "medium"
    assert data["summary"]["environment_issues"] == 1
    for noisy in (
        "compromised_actions",
        "oidc_trust_issues",
        "script_injection_risks",
        "artifact_poisoning_risks",
        "ai_agent_injection_risks",
        "unpinned_actions",
        "github_token_risks",
    ):
        assert data["summary"][noisy] == 0, (
            f"medium_only_repo unexpectedly produced {noisy}={data['summary'][noisy]};"
            f" this test relies on environment findings being the only signal"
        )

    # The actual regression guard: --fail-on medium must trip on MEDIUM alone.
    fail_result = runner.invoke(
        main,
        ["scan", MEDIUM_ONLY_FIXTURE, "--fail-on", "medium", "--output-format", "json"],
    )
    assert fail_result.exit_code == 1


def test_json_output_is_stable_across_runs() -> None:
    """Two consecutive scans must produce the same finding counts."""
    runner = CliRunner()

    def counts() -> dict:
        result = runner.invoke(
            main, ["scan", FIXTURE, "--output-format", "json", "--no-color"]
        )
        data = json.loads(result.stdout)
        return {
            "overall_risk": data["overall_risk"],
            "summary": data["summary"],
        }

    assert counts() == counts()
