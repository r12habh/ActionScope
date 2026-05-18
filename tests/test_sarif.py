"""Tests for SARIF output."""

from __future__ import annotations

import json
from pathlib import Path

from actionscope.models import (
    AiAgentInjectionFinding,
    ArtifactPoisoningFinding,
    AwsCredentialSource,
    GitHubTokenPermission,
    IamAction,
    OidcTrustFinding,
    PolicyFinding,
    RiskLevel,
    ScanResult,
    ScriptInjectionFinding,
    UnpinnedActionFinding,
    WorkflowCredentialBinding,
)
from actionscope.reporters.sarif import to_sarif, write_sarif


def _credential_source(uses_access_keys: bool = False) -> AwsCredentialSource:
    return AwsCredentialSource(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        step_name="Configure AWS credentials",
        role_arn="arn:aws:iam::123456789012:role/github-deploy-role",
        uses_access_keys=uses_access_keys,
        uses_oidc=not uses_access_keys,
        aws_region="us-east-1",
    )


def _policy_finding(risk: RiskLevel = RiskLevel.CRITICAL) -> PolicyFinding:
    return PolicyFinding(
        source_file="terraform/iam.tf",
        source_type="terraform",
        role_arn=None,
        actions=[
            IamAction(
                action="iam:PassRole",
                access_level="Permissions management",
                risk_level=RiskLevel.CRITICAL,
                description="Can pass roles",
                resource="*",
            )
        ],
        has_passrole=True,
        overall_risk=risk,
    )


def _result(
    risk: RiskLevel = RiskLevel.CRITICAL,
    uses_access_keys: bool = False,
) -> ScanResult:
    credential = _credential_source(uses_access_keys=uses_access_keys)
    policy = _policy_finding(risk)
    binding = WorkflowCredentialBinding(
        credential_source=credential,
        policy_finding=policy,
        policy_source="terraform",
    )
    result = ScanResult(
        scan_path="/repo",
        workflow_count=1,
        credential_sources=[credential],
        policy_findings=[policy],
        bindings=[binding],
    )
    result.overall_risk = risk
    return result


def _sarif_data(result: ScanResult) -> dict:
    return json.loads(to_sarif(result))


def _results(data: dict) -> list[dict]:
    return data["runs"][0]["results"]


def _rules(data: dict) -> list[dict]:
    return data["runs"][0]["tool"]["driver"]["rules"]


def test_to_sarif_returns_valid_json() -> None:
    data = _sarif_data(_result())

    assert data["runs"][0]["tool"]["driver"]["name"] == "ActionScope"


def test_sarif_output_contains_required_schema_key() -> None:
    data = _sarif_data(_result())

    assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"


def test_sarif_schema_version_is_210() -> None:
    data = _sarif_data(_result())

    assert data["version"] == "2.1.0"


def test_passrole_finding_produces_as003_result() -> None:
    data = _sarif_data(_result())

    assert "AS003" in {result["ruleId"] for result in _results(data)}


def test_static_key_usage_produces_as005_result() -> None:
    data = _sarif_data(_result(uses_access_keys=True))

    assert "AS005" in {result["ruleId"] for result in _results(data)}


def test_critical_overall_risk_maps_to_error_level() -> None:
    data = _sarif_data(_result(RiskLevel.CRITICAL))
    as001 = next(result for result in _results(data) if result["ruleId"] == "AS001")

    assert as001["level"] == "error"


def test_medium_overall_risk_maps_to_warning_level() -> None:
    data = _sarif_data(_result(RiskLevel.MEDIUM))
    as001 = next(result for result in _results(data) if result["ruleId"] == "AS001")

    assert as001["level"] == "warning"


def test_empty_scan_result_produces_valid_sarif_with_zero_results() -> None:
    data = _sarif_data(ScanResult())

    assert data["version"] == "2.1.0"
    assert _results(data) == []


def test_write_sarif_creates_file(tmp_path: Path) -> None:
    output_path = tmp_path / "actionscope.sarif"

    write_sarif(_result(), str(output_path))

    assert output_path.is_file()
    assert json.loads(output_path.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_sarif_results_have_correct_location_uri_base_id() -> None:
    data = _sarif_data(_result())
    location = _results(data)[0]["locations"][0]["physicalLocation"]

    assert location["artifactLocation"]["uriBaseId"] == "%SRCROOT%"


def test_all_rule_ids_are_present_in_rules_list() -> None:
    data = _sarif_data(_result())

    assert {rule["id"] for rule in _rules(data)} == {
        "AS001",
        "AS002",
        "AS003",
        "AS004",
        "AS005",
        "AS006",
        "AS007",
        "AS008",
        "AS009",
        "AS010",
        "AS011",
        "AS012",
    }


def test_security_severity_is_string_not_number() -> None:
    data = _sarif_data(_result())
    result = next(result for result in _results(data) if result["ruleId"] == "AS001")

    assert isinstance(result["properties"]["security-severity"], str)


def test_unpinned_action_produces_as006_result() -> None:
    result = ScanResult(
        unpinned_actions=[
            UnpinnedActionFinding(
                workflow_file=".github/workflows/deploy.yml",
                job_name="deploy",
                step_name="Checkout",
                uses="actions/checkout@v4",
                pin_type="tag",
            )
        ]
    )
    data = _sarif_data(result)

    assert "AS006" in {result["ruleId"] for result in _results(data)}


def test_github_token_permission_produces_as004_result() -> None:
    result = ScanResult(
        github_token_permissions=[
            GitHubTokenPermission(
                workflow_file=".github/workflows/release.yml",
                job_name="release",
                scope="pull-requests",
                access="write",
                risk_level=RiskLevel.HIGH,
            )
        ]
    )
    data = _sarif_data(result)

    assert "AS004" in {result["ruleId"] for result in _results(data)}


def test_v020_detector_findings_produce_sarif_results() -> None:
    result = ScanResult(
        oidc_trust_findings=[
            OidcTrustFinding(
                source_file="terraform/oidc.tf",
                role_name="deploy",
                role_arn=None,
                issue_id="missing_sub",
                issue_description="Missing sub",
                risk_level=RiskLevel.CRITICAL,
                evidence="{}",
                recommendation="Add sub",
            )
        ],
        script_injection_findings=[
            ScriptInjectionFinding(
                workflow_file=".github/workflows/ci.yml",
                job_name="test",
                step_name="Run",
                run_snippet="echo",
                untrusted_expression="${{ github.head_ref }}",
                injection_method="direct",
                risk_level=RiskLevel.HIGH,
                description="Direct injection",
                recommendation="Use env",
            )
        ],
        artifact_poisoning_findings=[
            ArtifactPoisoningFinding(
                workflow_file=".github/workflows/release.yml",
                job_name="publish",
                risk_level=RiskLevel.HIGH,
                has_workflow_run_trigger=True,
                downloads_artifacts=True,
                executes_artifacts=True,
                has_secret_access=False,
                description="Artifact execution",
                recommendation="Verify artifact",
            )
        ],
        ai_agent_injection_findings=[
            AiAgentInjectionFinding(
                workflow_file=".github/workflows/ai.yml",
                job_name="review",
                step_name="Claude",
                agent_type="claude_code",
                agent_action="anthropics/claude-code-action@v1",
                has_api_key_secret=True,
                has_aws_secret_access=True,
                has_write_permissions=True,
                untrusted_trigger=True,
                untrusted_inputs=["github.event.pull_request.body"],
                risk_level=RiskLevel.CRITICAL,
                description="AI risk",
                recommendation="Gate execution",
            )
        ],
    )

    data = _sarif_data(result)

    assert {"AS008", "AS009", "AS010", "AS012"} <= {
        result["ruleId"] for result in _results(data)
    }
