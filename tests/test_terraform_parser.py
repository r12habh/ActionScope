"""Tests for the Terraform IAM parser."""

from pathlib import Path

from actionscope.models import RiskLevel
from actionscope.parsers.terraform import (
    extract_iam_policies_from_terraform,
    find_terraform_files,
    parse_terraform_file,
    scan_terraform_files,
)
from actionscope.parsers.terraform_refs import parse_resource_reference

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


def test_not_actions_statement_is_classified_conservatively() -> None:
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

    assert findings[0].overall_risk is RiskLevel.CRITICAL
    assert findings[0].has_star_action
    assert findings[0].has_privilege_escalation


def test_not_resources_statement_is_classified_conservatively() -> None:
    tf_data = {
        "data": [
            {
                "aws_iam_policy_document": {
                    "complex": {
                        "statement": [
                            {
                                "effect": "Allow",
                                "actions": ["s3:PutObject"],
                                "not_resources": ["arn:aws:s3:::audit/*"],
                            }
                        ]
                    }
                }
            }
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "complex.tf")

    assert findings[0].overall_risk is RiskLevel.MEDIUM
    assert findings[0].has_star_resource


def test_not_action_or_not_resource_wildcard_allow_statement_is_noop() -> None:
    tf_data = {
        "data": [
            {
                "aws_iam_policy_document": {
                    "noop": {
                        "statement": [
                            {
                                "effect": "Allow",
                                "not_actions": ["*"],
                                "resources": ["*"],
                            },
                            {
                                "effect": "Allow",
                                "actions": ["iam:PassRole"],
                                "not_resources": ["*"],
                            },
                        ]
                    }
                }
            }
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "noop.tf")

    assert findings[0].actions == []
    assert findings[0].overall_risk is RiskLevel.INFO
    assert findings[0].has_star_action is False
    assert findings[0].has_star_resource is False
    assert findings[0].has_privilege_escalation is False


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


def test_managed_policy_attached_to_multiple_roles_is_preserved_per_role() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
            }
        ],
    }
    tf_data = {
        "resource": [
            {
                "aws_iam_role": {
                    "dev": {"name": "dev-role", "assume_role_policy": "{}"},
                    "prod": {"name": "prod-role", "assume_role_policy": "{}"},
                }
            },
            {
                "aws_iam_policy": {
                    "shared": {"name": "SharedPolicy", "policy": policy}
                }
            },
            {
                "aws_iam_role_policy_attachment": {
                    "dev": {
                        "role": "${aws_iam_role.dev.name}",
                        "policy_arn": "${aws_iam_policy.shared.arn}",
                    },
                    "prod": {
                        "role": "${aws_iam_role.prod.name}",
                        "policy_arn": "${aws_iam_policy.shared.arn}",
                    },
                }
            },
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "shared.tf")

    assert {finding.role_name for finding in findings} == {"dev-role", "prod-role"}
    assert all(finding.has_passrole for finding in findings)
    assert {
        finding.metadata["terraform_attachment"] for finding in findings
    } == {
        "aws_iam_role_policy_attachment.dev",
        "aws_iam_role_policy_attachment.prod",
    }


def test_indexed_managed_policy_reference_retains_role_relationship() -> None:
    tf_data = {
        "resource": [
            {
                "aws_iam_role": {
                    "deploy": {
                        "name": "github-deploy-role",
                        "assume_role_policy": "{}",
                    }
                }
            },
            {
                "aws_iam_policy": {
                    "deploy": {
                        "name": "DeployPolicy",
                        "policy": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "iam:PassRole",
                                    "Resource": "*",
                                }
                            ]
                        },
                    }
                }
            },
            {
                "aws_iam_role_policy_attachment": {
                    "deploy": {
                        "role": "${aws_iam_role.deploy[each.key].name}",
                        "policy_arn": "${aws_iam_policy.deploy[each.key].arn}",
                    }
                }
            },
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "indexed.tf")

    assert len(findings) == 1
    assert findings[0].role_name == "github-deploy-role"
    assert findings[0].has_passrole is True
    assert findings[0].metadata["terraform_role_reference"] == (
        "${aws_iam_role.deploy[each.key].name}"
    )


def test_role_managed_policy_arns_retains_role_relationship() -> None:
    tf_data = {
        "resource": [
            {
                "aws_iam_role": {
                    "deploy": {
                        "name": "github-deploy-role",
                        "assume_role_policy": "{}",
                        "managed_policy_arns": ["${aws_iam_policy.admin.arn}"],
                    }
                }
            },
            {
                "aws_iam_policy": {
                    "admin": {
                        "policy": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "iam:PassRole",
                                    "Resource": "*",
                                }
                            ]
                        }
                    }
                }
            },
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "role.tf")

    assert len(findings) == 1
    assert findings[0].role_name == "github-deploy-role"
    assert findings[0].has_passrole is True


def test_external_managed_policy_arn_marks_role_coverage_partial() -> None:
    tf_data = {
        "resource": [
            {
                "aws_iam_role": {
                    "deploy": {
                        "name": "github-deploy-role",
                        "assume_role_policy": "{}",
                        "managed_policy_arns": [
                            "arn:aws:iam::aws:policy/AdministratorAccess"
                        ],
                    }
                }
            }
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "role.tf")

    assert len(findings) == 1
    assert findings[0].role_name == "github-deploy-role"
    assert findings[0].metadata["policy_coverage_complete"] is False
    assert findings[0].metadata["unresolved_policy_attachments"] == [
        "arn:aws:iam::aws:policy/AdministratorAccess"
    ]
    assert findings[0].metadata["coverage_gap_type"] == (
        "unresolved_terraform_policy_attachment"
    )


def test_generic_policy_attachment_retains_each_role_relationship() -> None:
    tf_data = {
        "resource": [
            {
                "aws_iam_role": {
                    "dev": {"name": "dev-role", "assume_role_policy": "{}"},
                    "prod": {"name": "prod-role", "assume_role_policy": "{}"},
                }
            },
            {
                "aws_iam_policy": {
                    "shared": {
                        "policy": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "iam:PassRole",
                                    "Resource": "*",
                                }
                            ]
                        }
                    }
                }
            },
            {
                "aws_iam_policy_attachment": {
                    "shared": {
                        "roles": [
                            "${aws_iam_role.dev.name}",
                            "${aws_iam_role.prod.name}",
                        ],
                        "policy_arn": "${aws_iam_policy.shared.arn}",
                    }
                }
            },
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "attachments.tf")

    assert {finding.role_name for finding in findings} == {"dev-role", "prod-role"}
    assert all(finding.overall_risk is RiskLevel.CRITICAL for finding in findings)


def test_indexed_role_references_resolve_to_the_role_declaration() -> None:
    tf_data = {
        "resource": [
            {
                "aws_iam_role": {
                    "deploy": {
                        "name": "github-deploy-role",
                        "assume_role_policy": "{}",
                    }
                }
            },
            {
                "aws_iam_role_policy": {
                    "inline": {
                        "role": "${aws_iam_role.deploy[count.index].name}",
                        "policy": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                }
                            ]
                        },
                    }
                }
            },
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "indexed.tf")

    assert findings[0].role_name == "github-deploy-role"


def test_resource_reference_parser_preserves_index_traversals() -> None:
    cases = {
        "aws_iam_role.deploy[count.index].name": (
            "aws_iam_role.deploy",
            "aws_iam_role.deploy[count.index]",
        ),
        "${aws_iam_role.deploy[each.key].arn}": (
            "aws_iam_role.deploy",
            "aws_iam_role.deploy[each.key]",
        ),
        '${aws_iam_role.deploy["prod.us"].name}': (
            "aws_iam_role.deploy",
            'aws_iam_role.deploy["prod.us"]',
        ),
    }

    for value, expected in cases.items():
        parsed = parse_resource_reference(value, "aws_iam_role")
        assert parsed is not None
        assert (parsed.declaration_address, parsed.instance_address) == expected


def test_role_without_explicit_name_does_not_use_resource_label() -> None:
    tf_data = {
        "resource": [
            {
                "aws_iam_role": {
                    "generated": {
                        "assume_role_policy": "{}",
                    }
                }
            },
            {
                "aws_iam_policy": {
                    "deploy": {
                        "name": "DeployPolicy",
                        "policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:PutObject",
                                    "Resource": "*",
                                }
                            ],
                        },
                    }
                }
            },
            {
                "aws_iam_role_policy_attachment": {
                    "attach": {
                        "role": "${aws_iam_role.generated.name}",
                        "policy_arn": "${aws_iam_policy.deploy.arn}",
                    }
                }
            },
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "generated.tf")
    deploy = next(f for f in findings if f.policy_name == "DeployPolicy")

    assert deploy.role_name is None


def test_literal_role_arn_preserved_for_non_standard_partition() -> None:
    tf_data = {
        "resource": [
            {
                "aws_iam_role_policy": {
                    "govcloud": {
                        "role": "arn:aws-us-gov:iam::123456789012:role/deploy",
                        "policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                }
                            ],
                        },
                    }
                }
            }
        ]
    }

    findings = extract_iam_policies_from_terraform(tf_data, "govcloud.tf")

    assert findings[0].role_arn == "arn:aws-us-gov:iam::123456789012:role/deploy"


def test_scan_terraform_files_reports_parse_errors(tmp_path: Path) -> None:
    (tmp_path / "broken.tf").write_text("resource \"broken\" {\n", encoding="utf-8")

    findings, errors = scan_terraform_files(str(tmp_path))

    assert findings == []
    assert len(errors) == 1
