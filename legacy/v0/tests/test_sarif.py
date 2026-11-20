"""Tests for SARIF output."""

from __future__ import annotations

import json
from pathlib import Path

from actionscope.models import (
    AiAgentInjectionFinding,
    ArtifactPoisoningFinding,
    AwsCredentialSource,
    CompromisedActionFinding,
    EnvironmentFinding,
    ExposurePath,
    GitHubTokenPermission,
    IamAction,
    OidcTrustFinding,
    PolicyFinding,
    ReusableWorkflowReference,
    RiskLevel,
    ScanResult,
    ScriptInjectionFinding,
    UnpinnedActionFinding,
    WorkflowCredentialBinding,
)
from actionscope.reporters.json_reporter import to_json
from actionscope.reporters.sarif import to_sarif, to_sarif_from_dict, write_sarif


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


def test_sarif_results_use_repo_relative_locations(tmp_path: Path) -> None:
    workflow_file = tmp_path / ".github" / "workflows" / "deploy.yml"
    workflow_file.parent.mkdir(parents=True)
    workflow_file.write_text("name: deploy\n", encoding="utf-8")
    credential = AwsCredentialSource(
        workflow_file=str(workflow_file),
        job_name="deploy",
        step_name="Configure AWS credentials",
        role_arn="arn:aws:iam::123456789012:role/github-deploy-role",
        uses_access_keys=False,
        uses_oidc=True,
        aws_region="us-east-1",
    )
    permission = GitHubTokenPermission(
        workflow_file=str(workflow_file),
        job_name="deploy",
        scope="contents",
        access="write",
        risk_level=RiskLevel.HIGH,
    )
    result = ScanResult(
        scan_path=str(tmp_path),
        workflow_count=1,
        credential_sources=[credential],
        github_token_permissions=[permission],
    )

    data = _sarif_data(result)
    location = _results(data)[0]["locations"][0]["physicalLocation"]

    assert location["artifactLocation"]["uri"] == ".github/workflows/deploy.yml"


def test_sarif_location_falls_back_when_path_is_outside_repo(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / "outside.yml"
    outside.write_text("name: outside\n", encoding="utf-8")
    result = ScanResult(
        scan_path=str(tmp_path),
        github_token_permissions=[
            GitHubTokenPermission(
                workflow_file=str(outside),
                job_name="deploy",
                scope="contents",
                access="write",
                risk_level=RiskLevel.HIGH,
            )
        ],
    )

    data = _sarif_data(result)
    location = _results(data)[0]["locations"][0]["physicalLocation"]

    assert location["artifactLocation"]["uri"] == outside.as_posix()


def test_sarif_location_allows_empty_path() -> None:
    data = json.loads(
        to_sarif_from_dict(
            {
                "scan_path": "/repo",
                "github_token_permissions": [
                    {
                        "workflow_file": "",
                        "scope": "contents",
                        "access": "write",
                        "risk_level": "high",
                    }
                ],
            }
        )
    )

    location = _results(data)[0]["locations"][0]["physicalLocation"]

    assert location["artifactLocation"]["uri"] == ""


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
        "AS013",
        "AS014",
        "AS015",
        "AS016",
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


def test_exposure_path_produces_as016_with_policy_related_location() -> None:
    path = ExposurePath(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        action_kind="unpinned",
        action_ref="third-party/deploy@v1",
        action_step="Deploy helper",
        credential_step="Configure AWS credentials",
        role_arn="arn:aws:iam::123456789012:role/deploy",
        auth_type="oidc",
        policy_source="terraform",
        policy_source_file="terraform/deploy.tf",
        match_confidence="high",
        reachable_actions=["iam:PassRole"],
        risk_level=RiskLevel.CRITICAL,
    )
    result = ScanResult(scan_path="/repo", exposure_paths=[path])

    direct = _sarif_data(result)
    saved = json.loads(to_sarif_from_dict(json.loads(to_json(result))))

    for data in (direct, saved):
        finding = next(
            item for item in _results(data) if item["ruleId"] == "AS016"
        )
        assert finding["level"] == "error"
        assert "third-party/deploy@v1" in finding["message"]["text"]
        assert "iam:PassRole" in finding["message"]["text"]
        assert "terraform (high confidence)" in finding["message"]["text"]
        assert finding["relatedLocations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"] == "terraform/deploy.tf"


def test_reusable_workflow_exposure_path_maps_to_root_caller() -> None:
    target = "acme/platform/.github/workflows/deploy.yml@v1"
    result = ScanResult(
        scan_path="/repo",
        reusable_workflows=[
            ReusableWorkflowReference(
                caller_workflow=".github/workflows/caller.yml",
                caller_job="release",
                uses=target,
                target_workflow=target,
                repository="acme/platform",
                ref="v1",
                pin_type="tag",
                is_local=False,
                status="inspected",
                depth=1,
            )
        ],
        exposure_paths=[
            ExposurePath(
                workflow_file=target,
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
                risk_level=RiskLevel.HIGH,
            )
        ],
    )

    finding = next(
        item
        for item in _results(_sarif_data(result))
        if item["ruleId"] == "AS016"
    )

    assert finding["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] == ".github/workflows/caller.yml"
    assert "originates from reusable workflow" in finding["message"]["text"]


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


def test_oidc_wildcard_finding_produces_as007_result() -> None:
    result = ScanResult(
        oidc_trust_findings=[
            OidcTrustFinding(
                source_file="terraform/oidc.tf",
                role_name="deploy",
                role_arn=None,
                issue_id="wildcard_repo",
                issue_description="Wildcard subject",
                risk_level=RiskLevel.CRITICAL,
                evidence="repo:acme-corp/*",
                recommendation="Scope down",
            )
        ],
    )
    data = _sarif_data(result)

    assert "AS007" in {result["ruleId"] for result in _results(data)}
    assert "Recommendation: Scope down" in _results(data)[0]["message"]["text"]


def test_ai_agent_without_aws_credentials_produces_as011_result() -> None:
    result = ScanResult(
        ai_agent_injection_findings=[
            AiAgentInjectionFinding(
                workflow_file=".github/workflows/ai.yml",
                job_name="review",
                step_name="Claude",
                agent_type="claude_code",
                agent_action="anthropics/claude-code-action@v1",
                has_api_key_secret=True,
                has_aws_secret_access=False,
                has_write_permissions=True,
                untrusted_trigger=True,
                untrusted_inputs=["github.event.pull_request.body"],
                risk_level=RiskLevel.HIGH,
                description="AI risk",
                recommendation="Gate execution",
            )
        ],
    )
    data = _sarif_data(result)

    assert "AS011" in {result["ruleId"] for result in _results(data)}


def test_compromised_action_produces_as013_result() -> None:
    result = ScanResult(
        compromised_action_findings=[
            CompromisedActionFinding(
                workflow_file=".github/workflows/triage.yml",
                job_name="triage",
                step_name="Issue helper",
                uses_ref="actions-cool/issues-helper@v3",
                action_name="actions-cool/issues-helper",
                ref="v3",
                is_sha_pinned=False,
                compromise_date="2026-05-18T19:10:24Z",
                advisory_url="https://example.com/advisory",
                description="compromised",
                risk_level=RiskLevel.CRITICAL,
            )
        ]
    )
    data = _sarif_data(result)

    assert "AS013" in {result["ruleId"] for result in _results(data)}


def test_environment_finding_produces_as014_result() -> None:
    result = ScanResult(
        environment_findings=[
            EnvironmentFinding(
                workflow_file=".github/workflows/deploy.yml",
                job_name="deploy",
                environment_name=None,
                has_aws_credentials=True,
                role_arn="arn:aws:iam::123456789012:role/github-deploy-role",
                finding_type="deploy_without_environment",
                risk_level=RiskLevel.MEDIUM,
                description="missing environment",
                recommendation="add environment",
            )
        ]
    )
    data = _sarif_data(result)

    assert "AS014" in {result["ruleId"] for result in _results(data)}


def test_compromised_action_from_dict_produces_as013_result() -> None:
    data = json.loads(
        to_sarif_from_dict(
            {
                "compromised_action_findings": [
                    {
                        "workflow_file": ".github/workflows/triage.yml",
                        "uses_ref": "actions-cool/issues-helper@v3",
                        "description": "compromised",
                        "advisory_url": "https://example.com/advisory",
                        "risk_level": "critical",
                    }
                ]
            }
        )
    )
    assert "AS013" in {result["ruleId"] for result in _results(data)}


def test_environment_finding_from_dict_produces_as014_result() -> None:
    data = json.loads(
        to_sarif_from_dict(
            {
                "environment_findings": [
                    {
                        "workflow_file": ".github/workflows/deploy.yml",
                        "risk_level": "medium",
                        "description": "missing environment",
                    }
                ]
            }
        )
    )
    assert "AS014" in {result["ruleId"] for result in _results(data)}


def test_uninspected_reusable_workflow_produces_as015_result() -> None:
    result = ScanResult(
        reusable_workflows=[
            ReusableWorkflowReference(
                caller_workflow=".github/workflows/caller.yml",
                caller_job="deploy",
                uses="acme/platform/.github/workflows/deploy.yml@v1",
                target_workflow=(
                    "acme/platform/.github/workflows/deploy.yml@v1"
                ),
                repository="acme/platform",
                ref="v1",
                pin_type="tag",
                is_local=False,
                status="no_token",
                depth=1,
                error="pass --github-token",
            )
        ]
    )

    data = _sarif_data(result)
    finding = next(item for item in _results(data) if item["ruleId"] == "AS015")

    assert finding["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] == ".github/workflows/caller.yml"


def test_external_reusable_finding_points_to_caller_with_provenance() -> None:
    external = "acme/platform/.github/workflows/deploy.yml@v1"
    result = ScanResult(
        scan_path="/repo",
        reusable_workflows=[
            ReusableWorkflowReference(
                caller_workflow="/repo/.github/workflows/caller.yml",
                caller_job="deploy",
                uses=external,
                target_workflow=external,
                repository="acme/platform",
                ref="v1",
                pin_type="tag",
                is_local=False,
                status="inspected",
                depth=1,
            )
        ],
        script_injection_findings=[
            ScriptInjectionFinding(
                workflow_file=external,
                job_name="deploy",
                step_name="run",
                run_snippet="echo unsafe",
                untrusted_expression="${{ github.event.issue.body }}",
                injection_method="direct",
                risk_level=RiskLevel.MEDIUM,
                description="script injection",
                recommendation="use env",
            )
        ],
    )

    data = _sarif_data(result)
    finding = next(item for item in _results(data) if item["ruleId"] == "AS009")

    assert finding["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] == ".github/workflows/caller.yml"
    assert "originates from reusable workflow" in finding["message"]["text"]


def test_shared_external_finding_points_to_every_root_caller() -> None:
    external = "acme/platform/.github/workflows/deploy.yml@v1"
    references = [
        ReusableWorkflowReference(
            caller_workflow=f"/repo/.github/workflows/{name}",
            caller_job="deploy",
            uses=external,
            target_workflow=external,
            repository="acme/platform",
            ref="v1",
            pin_type="tag",
            is_local=False,
            status="inspected",
            depth=1,
            root_workflow=f"/repo/.github/workflows/{name}",
        )
        for name in ("caller-a.yml", "caller-b.yml")
    ]
    result = ScanResult(
        scan_path="/repo",
        reusable_workflows=references,
        script_injection_findings=[
            ScriptInjectionFinding(
                workflow_file=external,
                job_name="deploy",
                step_name="run",
                run_snippet="echo unsafe",
                untrusted_expression="${{ github.event.issue.body }}",
                injection_method="direct",
                risk_level=RiskLevel.MEDIUM,
                description="script injection",
                recommendation="use env",
            )
        ],
    )

    direct = _sarif_data(result)
    saved = json.loads(to_sarif_from_dict(json.loads(to_json(result))))

    for data in (direct, saved):
        findings = [
            item for item in _results(data) if item["ruleId"] == "AS009"
        ]
        uris = {
            finding["locations"][0]["physicalLocation"]["artifactLocation"][
                "uri"
            ]
            for finding in findings
        }
        assert len(findings) == 2
        assert uris == {
            ".github/workflows/caller-a.yml",
            ".github/workflows/caller-b.yml",
        }


def test_nested_external_finding_points_to_top_level_caller() -> None:
    parent = "acme/platform/.github/workflows/parent.yml@v1"
    child = "acme/platform/.github/workflows/child.yml@v1"
    result = ScanResult(
        scan_path="/repo",
        reusable_workflows=[
            ReusableWorkflowReference(
                caller_workflow="/repo/.github/workflows/caller.yml",
                caller_job="parent",
                uses=parent,
                target_workflow=parent,
                repository="acme/platform",
                ref="v1",
                pin_type="tag",
                is_local=False,
                status="inspected",
                depth=1,
            ),
            ReusableWorkflowReference(
                caller_workflow=parent,
                caller_job="child",
                uses="./.github/workflows/child.yml",
                target_workflow=child,
                repository="acme/platform",
                ref="v1",
                pin_type="local",
                is_local=True,
                status="inspected",
                depth=2,
            ),
        ],
        script_injection_findings=[
            ScriptInjectionFinding(
                workflow_file=child,
                job_name="deploy",
                step_name="run",
                run_snippet="echo unsafe",
                untrusted_expression="${{ github.event.issue.body }}",
                injection_method="direct",
                risk_level=RiskLevel.MEDIUM,
                description="script injection",
                recommendation="use env",
            )
        ],
    )

    direct = _sarif_data(result)
    direct_finding = next(
        item for item in _results(direct) if item["ruleId"] == "AS009"
    )
    saved = json.loads(to_sarif_from_dict(json.loads(to_json(result))))
    saved_finding = next(
        item for item in _results(saved) if item["ruleId"] == "AS009"
    )

    for finding in (direct_finding, saved_finding):
        assert finding["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"] == ".github/workflows/caller.yml"
        assert "child.yml" in finding["message"]["text"]


def test_uninspected_reusable_workflow_from_dict_produces_as015() -> None:
    data = json.loads(
        to_sarif_from_dict(
            {
                "scan_path": "/repo",
                "reusable_workflows": [
                    {
                        "caller_workflow": "/repo/.github/workflows/caller.yml",
                        "uses": "acme/platform/.github/workflows/deploy.yml@v1",
                        "status": "no_token",
                        "error": "pass --github-token",
                    }
                ],
            }
        )
    )

    assert "AS015" in {result["ruleId"] for result in _results(data)}
