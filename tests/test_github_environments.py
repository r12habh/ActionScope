"""Tests for GitHub Environment OIDC hardening analysis."""

from __future__ import annotations

from pathlib import Path

from actionscope.analyzers.github_environments import (
    analyze_environment_usage,
    extract_job_environments,
    is_deploy_job,
    scan_environment_usage,
)
from actionscope.models import AwsCredentialSource, OidcTrustFinding, RiskLevel


def _credential(job_name: str = "deploy") -> AwsCredentialSource:
    return AwsCredentialSource(
        workflow_file="deploy.yml",
        job_name=job_name,
        step_name="Configure AWS",
        role_arn="arn:aws:iam::123456789012:role/github-deploy-role",
        uses_access_keys=False,
        uses_oidc=True,
        aws_region="us-east-1",
    )


def _trust(evidence: str) -> OidcTrustFinding:
    return OidcTrustFinding(
        source_file="terraform/iam.tf",
        role_name="github-deploy-role",
        role_arn=None,
        issue_id="missing_aud",
        issue_description="Missing aud",
        risk_level=RiskLevel.MEDIUM,
        evidence=evidence,
        recommendation="Add aud",
    )


def test_extract_job_environments_handles_string_form() -> None:
    workflow = {"jobs": {"deploy": {"environment": "production"}}}

    assert extract_job_environments(workflow)[0]["environment"] == "production"


def test_extract_job_environments_handles_dict_form() -> None:
    workflow = {
        "jobs": {
            "deploy": {
                "environment": {
                    "name": "production",
                    "url": "https://example.com",
                }
            }
        }
    }

    env = extract_job_environments(workflow)[0]

    assert env["environment"] == "production"
    assert env["environment_url"] == "https://example.com"


def test_extract_job_environments_returns_none_without_environment() -> None:
    workflow = {"jobs": {"test": {"steps": []}}}

    assert extract_job_environments(workflow)[0]["environment"] is None


def test_is_deploy_job_true_for_deploy_name() -> None:
    assert is_deploy_job({"__job_name": "deploy"}, []) is True


def test_is_deploy_job_true_for_aws_credentials() -> None:
    assert is_deploy_job({"__job_name": "build"}, [_credential("build")]) is True


def test_is_deploy_job_false_for_test_only_job() -> None:
    assert (
        is_deploy_job({"__job_name": "test", "steps": [{"run": "pytest"}]}, [])
        is False
    )


def test_deploy_job_without_environment_produces_medium_finding() -> None:
    workflow = {"jobs": {"deploy": {"steps": [{"run": "terraform apply"}]}}}

    findings = analyze_environment_usage(workflow, "deploy.yml", [_credential()], [])

    assert findings[0].finding_type == "deploy_without_environment"
    assert findings[0].risk_level is RiskLevel.MEDIUM


def test_environment_with_ref_trust_policy_produces_medium_finding() -> None:
    workflow = {
        "jobs": {"deploy": {"environment": "production", "steps": []}},
    }

    findings = analyze_environment_usage(
        workflow,
        "deploy.yml",
        [_credential()],
        [_trust("repo:acme/app:ref:refs/heads/main")],
    )

    assert findings[0].finding_type == "environment_not_in_trust_policy"
    assert findings[0].risk_level is RiskLevel.MEDIUM


def test_environment_trust_policy_using_environment_produces_no_finding() -> None:
    workflow = {
        "jobs": {"deploy": {"environment": "production", "steps": []}},
    }

    findings = analyze_environment_usage(
        workflow,
        "deploy.yml",
        [_credential()],
        [_trust("repo:acme/app:environment:production")],
    )

    assert findings == []


def test_scan_environment_usage_empty_for_non_deploy_workflow(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: pytest\n",
        encoding="utf-8",
    )

    findings, errors = scan_environment_usage(str(tmp_path), [], [])

    assert findings == []
    assert errors == []


def test_environment_finding_recommendation_is_non_empty() -> None:
    workflow = {"jobs": {"deploy": {"steps": [{"run": "terraform apply"}]}}}

    findings = analyze_environment_usage(workflow, "deploy.yml", [_credential()], [])

    assert findings[0].recommendation


def test_multiple_jobs_are_analyzed_independently() -> None:
    workflow = {
        "jobs": {
            "deploy": {"steps": [{"run": "terraform apply"}]},
            "release": {"steps": [{"run": "aws s3 sync dist s3://bucket"}]},
        }
    }

    findings = analyze_environment_usage(
        workflow,
        "deploy.yml",
        [_credential("deploy"), _credential("release")],
        [],
    )

    assert {finding.job_name for finding in findings} == {"deploy", "release"}


def test_trust_finding_only_affects_matching_role_job() -> None:
    """A trust finding for role A must not generate a finding for job B using role B."""
    deploy_arn = "arn:aws:iam::123456789012:role/deploy-role"
    release_arn = "arn:aws:iam::123456789012:role/release-role"

    workflow = {
        "jobs": {
            "deploy": {
                "environment": "production",
                "steps": [{"run": "terraform apply"}],
            },
            "release": {
                "environment": "production",
                "steps": [{"run": "aws s3 sync dist s3://bucket"}],
            },
        }
    }
    credentials = [
        AwsCredentialSource(
            workflow_file="deploy.yml",
            job_name="deploy",
            step_name="Configure AWS",
            role_arn=deploy_arn,
            uses_access_keys=False,
            uses_oidc=True,
            aws_region="us-east-1",
        ),
        AwsCredentialSource(
            workflow_file="deploy.yml",
            job_name="release",
            step_name="Configure AWS",
            role_arn=release_arn,
            uses_access_keys=False,
            uses_oidc=True,
            aws_region="us-east-1",
        ),
    ]
    trust_findings = [
        OidcTrustFinding(
            source_file="terraform/iam.tf",
            role_name="deploy-role",
            role_arn=deploy_arn,
            issue_id="ref_scoped",
            issue_description="Branch-scoped trust",
            risk_level=RiskLevel.MEDIUM,
            evidence="condition: StringLike, :ref:refs/heads/main",
            recommendation="Use environment scope",
        )
    ]

    findings = analyze_environment_usage(
        workflow,
        "deploy.yml",
        credentials,
        trust_findings,
    )

    job_names = {f.job_name for f in findings}
    assert "deploy" in job_names
    assert "release" not in job_names
