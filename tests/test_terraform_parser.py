"""Tests for the Terraform IAM parser."""

from pathlib import Path

from actionscope.models import RiskLevel
from actionscope.parsers.terraform import (
    extract_iam_policies_from_terraform,
    find_terraform_files,
    parse_terraform_file,
    scan_terraform_files,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "terraform"


def parse_fixture(name: str) -> dict:
    """Parse a Terraform fixture and return its HCL data."""
    tf_data = parse_terraform_file(str(FIXTURE_DIR / name))
    assert tf_data is not None
    return tf_data


def test_find_terraform_files_finds_tf_files_and_excludes_terraform_dir(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.tf").write_text("resource \"x\" \"y\" {}\n", encoding="utf-8")
    hidden_dir = tmp_path / ".terraform" / "modules"
    hidden_dir.mkdir(parents=True)
    (hidden_dir / "ignored.tf").write_text(
        "resource \"x\" \"z\" {}\n",
        encoding="utf-8",
    )
    (tmp_path / ".terraform.lock.hcl").write_text("# lock\n", encoding="utf-8")

    files = find_terraform_files(str(tmp_path))

    assert [Path(file).name for file in files] == ["main.tf"]
    assert Path(files[0]).is_absolute()


def test_parse_terraform_file_returns_none_for_invalid_hcl(tmp_path: Path) -> None:
    invalid_file = tmp_path / "broken.tf"
    invalid_file.write_text(
        "resource \"aws_iam_policy\" \"broken\" {\n",
        encoding="utf-8",
    )

    assert parse_terraform_file(str(invalid_file)) is None


def test_iam_with_passrole_produces_has_passrole_true() -> None:
    findings = extract_iam_policies_from_terraform(
        parse_fixture("iam_with_passrole.tf"),
        "iam_with_passrole.tf",
    )

    assert findings[0].has_passrole is True


def test_iam_with_passrole_sets_privilege_escalation() -> None:
    findings = extract_iam_policies_from_terraform(
        parse_fixture("iam_with_passrole.tf"),
        "iam_with_passrole.tf",
    )

    assert findings[0].has_privilege_escalation is True


def test_policy_document_produces_low_overall_risk() -> None:
    findings = extract_iam_policies_from_terraform(
        parse_fixture("policy_document.tf"),
        "policy_document.tf",
    )

    assert findings[0].overall_risk is RiskLevel.LOW


def test_admin_role_produces_critical_overall_risk() -> None:
    findings = extract_iam_policies_from_terraform(
        parse_fixture("admin_role.tf"),
        "admin_role.tf",
    )

    assert findings[0].overall_risk is RiskLevel.CRITICAL


def test_no_iam_produces_empty_policy_finding_list() -> None:
    findings = extract_iam_policies_from_terraform(
        parse_fixture("no_iam.tf"),
        "no_iam.tf",
    )

    assert findings == []


def test_policy_document_statement_blocks_parsed_correctly() -> None:
    findings = extract_iam_policies_from_terraform(
        parse_fixture("policy_document.tf"),
        "policy_document.tf",
    )

    assert [action.action for action in findings[0].actions] == [
        "s3:GetObject",
        "s3:ListBucket",
    ]


def test_variable_interpolation_in_resource_treated_as_star() -> None:
    tf_data = {
        "data": [
            {
                "aws_iam_policy_document": {
                    "variable_resource": {
                        "statement": [
                            {
                                "effect": "Allow",
                                "actions": ["s3:PutObject"],
                                "resources": ["${var.bucket_arn}"],
                            }
                        ]
                    }
                }
            }
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "variable.tf")

    assert findings[0].actions[0].resource == "*"
    assert findings[0].has_star_resource is True


def test_source_type_is_terraform_for_all_findings() -> None:
    findings, errors = scan_terraform_files(str(FIXTURE_DIR))

    assert errors == []
    assert {finding.source_type for finding in findings} == {"terraform"}


def test_scan_terraform_files_works_end_to_end_on_fixtures_dir() -> None:
    findings, errors = scan_terraform_files(str(FIXTURE_DIR))

    assert len(findings) == 4
    assert errors == []
    assert {finding.overall_risk for finding in findings} == {
        RiskLevel.CRITICAL,
        RiskLevel.MEDIUM,
        RiskLevel.LOW,
    }


def test_aws_iam_role_policy_resource_extracts_all_actions() -> None:
    findings = extract_iam_policies_from_terraform(
        parse_fixture("iam_with_passrole.tf"),
        "iam_with_passrole.tf",
    )

    assert [action.action for action in findings[0].actions] == [
        "iam:PassRole",
        "ec2:DescribeInstances",
    ]


def test_not_actions_statement_is_skipped(capsys) -> None:
    tf_data = {
        "data": [
            {
                "aws_iam_policy_document": {
                    "complex": {
                        "statement": [
                            {
                                "effect": "Allow",
                                "not_actions": ["iam:DeleteUser"],
                                "resources": ["*"],
                            }
                        ]
                    }
                }
            }
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "complex.tf")

    assert findings[0].overall_risk is RiskLevel.INFO
    assert "not_actions" in capsys.readouterr().err


def test_unresolvable_policy_reference_returns_info_finding() -> None:
    tf_data = {
        "resource": [
            {
                "aws_iam_policy": {
                    "from_file": {
                        "policy": "${file(\"policy.json\")}",
                    }
                }
            }
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "unresolved.tf")

    assert len(findings) == 1
    assert findings[0].actions == []
    assert findings[0].overall_risk is RiskLevel.INFO


def test_file_policy_reference_is_resolved() -> None:
    findings = extract_iam_policies_from_terraform(
        parse_fixture("role_attachment.tf"),
        str(FIXTURE_DIR / "role_attachment.tf"),
    )

    policy = next(f for f in findings if f.policy_name == "GitHubDeployPolicy")
    assert [action.action for action in policy.actions] == ["s3:PutObject"]
    assert policy.overall_risk is RiskLevel.MEDIUM


def test_role_policy_attachment_sets_role_name() -> None:
    findings, errors = scan_terraform_files(str(FIXTURE_DIR))

    assert errors == []
    attached = next(f for f in findings if f.policy_name == "GitHubDeployPolicy")
    assert attached.role_name == "github-deploy-role"
    assert attached.metadata["terraform_attachment"] == (
        "aws_iam_role_policy_attachment.deploy"
    )


def test_scan_terraform_files_reports_parse_errors(tmp_path: Path) -> None:
    (tmp_path / "broken.tf").write_text("resource \"broken\" {\n", encoding="utf-8")

    findings, errors = scan_terraform_files(str(tmp_path))

    assert findings == []
    assert len(errors) == 1
