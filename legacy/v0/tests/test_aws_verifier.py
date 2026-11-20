"""Tests for live AWS IAM verification using moto mocks."""

from __future__ import annotations

import json

import boto3
from moto import mock_aws

from actionscope.models import AwsCredentialSource, RiskLevel
from actionscope.verifiers.aws_verifier import (
    check_boto3_available,
    extract_role_name_from_arn,
    fetch_role_policies,
    is_dynamic_reference,
    verify_all_credential_sources,
    verify_credential_source,
)


def credential_source(role_arn: str | None) -> AwsCredentialSource:
    return AwsCredentialSource(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        step_name="Configure AWS credentials",
        role_arn=role_arn,
        uses_access_keys=False,
        uses_oidc=True,
        aws_region="us-east-1",
    )


@mock_aws
class TestFetchRolePolicies:
    def setup_method(self, _method: object) -> None:
        """Create test IAM resources using moto."""
        self.iam = boto3.client("iam", region_name="us-east-1")

        role = self.iam.create_role(
            RoleName="github-deploy-role",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Federated": "token.actions.githubusercontent.com"
                            },
                            "Action": "sts:AssumeRoleWithWebIdentity",
                        }
                    ],
                }
            ),
        )
        self.role_arn = role["Role"]["Arn"]

        policy = self.iam.create_policy(
            PolicyName="DeployPolicy",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["iam:PassRole", "s3:GetObject"],
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )
        self.policy_arn = policy["Policy"]["Arn"]
        self.iam.attach_role_policy(
            RoleName="github-deploy-role",
            PolicyArn=self.policy_arn,
        )

    def test_fetch_role_policies_returns_statements(self) -> None:
        result = fetch_role_policies("github-deploy-role", self.iam)

        assert result["role_name"] == "github-deploy-role"
        assert result["role_arn"] == self.role_arn
        assert len(result["all_statements"]) == 1
        assert result["all_statements"][0]["Action"] == [
            "iam:PassRole",
            "s3:GetObject",
        ]
        assert result["managed_policies"][0]["policy_name"] == "DeployPolicy"
        assert result["managed_policies"][0]["policy_arn"] == self.policy_arn
        assert result["managed_policies"][0]["document"]["Version"] == "2012-10-17"

    def test_fetch_role_policies_role_not_found(self) -> None:
        result = fetch_role_policies("missing-role", self.iam)

        assert result["error"] == "role_not_found"
        assert result["role_name"] == "missing-role"

    def test_fetch_role_policies_returns_inline_policies(self) -> None:
        self.iam.put_role_policy(
            RoleName="github-deploy-role",
            PolicyName="InlineDeployPolicy",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": {
                        "Effect": "Allow",
                        "Action": "s3:DeleteBucket",
                        "Resource": "*",
                    },
                }
            ),
        )

        result = fetch_role_policies("github-deploy-role", self.iam)

        assert result["inline_policies"][0]["policy_name"] == "InlineDeployPolicy"
        assert len(result["all_statements"]) == 2

    def test_verify_credential_source_detects_passrole(self) -> None:
        finding = verify_credential_source(
            credential_source(self.role_arn),
            self.iam,
        )

        assert finding is not None
        assert finding.source_type == "aws_verified"
        assert finding.role_arn == self.role_arn
        assert finding.metadata["aws_verification_status"] == "success"
        assert finding.has_passrole is True
        assert finding.overall_risk is RiskLevel.CRITICAL

    def test_verify_credential_source_dynamic_returns_none(self) -> None:
        finding = verify_credential_source(
            credential_source("${{ secrets.ROLE_ARN }}"),
            self.iam,
        )

        assert finding is None

    def test_verify_credential_source_none_role_returns_none(self) -> None:
        assert verify_credential_source(credential_source(None), self.iam) is None

    def test_verify_credential_source_role_not_found_returns_info(self) -> None:
        missing_arn = "arn:aws:iam::123456789012:role/missing-role"

        finding = verify_credential_source(
            credential_source(missing_arn),
            self.iam,
        )

        assert finding is not None
        assert finding.source_type == "aws_verified"
        assert finding.overall_risk is RiskLevel.INFO
        assert finding.metadata["aws_verification_status"] == "error"
        assert finding.metadata["aws_verification_error"] == "role_not_found"
        assert "role_not_found" in finding.actions[0].description

    def test_is_dynamic_reference_true_for_expressions(self) -> None:
        assert is_dynamic_reference("${{ secrets.DEPLOY_ROLE }}")
        assert is_dynamic_reference("${{ vars.ROLE_ARN }}")
        assert is_dynamic_reference("${{ env.AWS_ROLE }}")

    def test_is_dynamic_reference_false_for_real_arn(self) -> None:
        assert not is_dynamic_reference(self.role_arn)

    def test_extract_role_name_from_arn(self) -> None:
        assert extract_role_name_from_arn(self.role_arn) == "github-deploy-role"
        assert (
            extract_role_name_from_arn(
                "arn:aws:iam::123456789012:role/path/to/role-name"
            )
            == "role-name"
        )
        assert extract_role_name_from_arn("not-an-arn") is None

    def test_check_boto3_available_does_not_raise(self) -> None:
        check_boto3_available()

    def test_verify_all_credential_sources_collects_findings(self) -> None:
        findings, errors = verify_all_credential_sources(
            [credential_source(self.role_arn)]
        )

        assert errors == []
        assert len(findings) == 1
        assert findings[0].source_type == "aws_verified"
