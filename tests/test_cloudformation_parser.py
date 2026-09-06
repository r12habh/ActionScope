"""Tests for CloudFormation and SAM IAM evidence extraction."""

import json
from pathlib import Path

from click.testing import CliRunner

import actionscope.parsers.cloudformation as cloudformation
from actionscope.analyzers.oidc_trust import scan_oidc_trust_policies
from actionscope.analyzers.risk_engine import build_bindings
from actionscope.cli import main
from actionscope.coverage import build_coverage_gaps
from actionscope.models import AwsCredentialSource, RiskLevel, ScanResult
from actionscope.parsers.cloudformation import (
    extract_iam_policies_from_cloudformation,
    find_cloudformation_files,
    is_cloudformation_template,
    parse_cloudformation_file,
    scan_cloudformation_files,
)
from actionscope.reporters.json_reporter import to_json

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "cloudformation_repo"
TEMPLATE = FIXTURE_REPO / "infrastructure" / "template.yml"


def _credential(role_name: str) -> AwsCredentialSource:
    return AwsCredentialSource(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        step_name="Configure AWS credentials",
        role_arn=f"arn:aws:iam::123456789012:role/{role_name}",
        uses_access_keys=False,
        uses_oidc=True,
        aws_region="us-east-1",
        role_reference_kind="literal_arn",
    )


def test_find_cloudformation_files_only_returns_template_candidates() -> None:
    files = find_cloudformation_files(str(FIXTURE_REPO))

    assert files == [str(TEMPLATE.resolve())]


def test_parse_cloudformation_file_preserves_intrinsic_functions() -> None:
    template = parse_cloudformation_file(str(TEMPLATE))

    assert template is not None
    federated = template["Resources"]["DeployRole"]["Properties"][
        "AssumeRolePolicyDocument"
    ]["Statement"][0]["Principal"]["Federated"]
    assert federated == {
        "Fn::Sub": (
            "arn:aws:iam::${AWS::AccountId}:oidc-provider/"
            "token.actions.githubusercontent.com"
        )
    }


def test_is_cloudformation_template_rejects_ordinary_yaml() -> None:
    assert not is_cloudformation_template({"Resources": {"Bucket": {}}})


def test_role_inline_policy_is_linked_to_explicit_role_name() -> None:
    template = parse_cloudformation_file(str(TEMPLATE))
    assert template is not None

    findings = extract_iam_policies_from_cloudformation(template, str(TEMPLATE))
    deploy = next(
        finding for finding in findings if finding.role_name == "github-deploy-role"
    )

    assert deploy.source_type == "cloudformation"
    assert {action.action for action in deploy.actions} == {
        "ec2:TerminateInstances",
        "s3:PutObject",
    }
    assert deploy.overall_risk is RiskLevel.HIGH


def test_iam_policy_ref_resolves_attached_role_name() -> None:
    template = parse_cloudformation_file(str(TEMPLATE))
    assert template is not None

    findings = extract_iam_policies_from_cloudformation(template, str(TEMPLATE))
    audit = next(
        finding for finding in findings if finding.role_name == "github-audit-role"
    )

    assert [action.action for action in audit.actions] == ["cloudtrail:LookupEvents"]
    assert audit.policy_name == "audit-policy"


def test_sam_policies_are_ignored_when_explicit_role_is_supplied() -> None:
    template = parse_cloudformation_file(str(TEMPLATE))
    assert template is not None

    findings = extract_iam_policies_from_cloudformation(template, str(TEMPLATE))

    assert not any(
        finding.role_name == "github-worker-role" for finding in findings
    )
    assert not any(
        action.action == "sqs:SendMessage"
        for finding in findings
        for action in finding.actions
    )


def test_sam_policies_are_extracted_for_generated_execution_role() -> None:
    template = {
        "Resources": {
            "WorkerFunction": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "Handler": "app.handler",
                    "Policies": [
                        {
                            "Statement": {
                                "Effect": "Allow",
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                            }
                        }
                    ],
                },
            }
        }
    }

    findings = extract_iam_policies_from_cloudformation(template, "template.yml")

    assert len(findings) == 1
    assert findings[0].role_name is None
    assert [action.action for action in findings[0].actions] == [
        "sqs:SendMessage"
    ]
    assert findings[0].actions[0].resource == "<dynamic:Fn::GetAtt>"


def test_sam_policy_templates_are_reported_as_partial_coverage() -> None:
    template = {
        "Resources": {
            "WorkerFunction": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "Handler": "app.handler",
                    "Policies": [
                        "AWSLambdaBasicExecutionRole",
                        {"S3ReadPolicy": {"BucketName": {"Ref": "Bucket"}}},
                    ],
                },
            }
        }
    }

    findings = extract_iam_policies_from_cloudformation(template, "template.yml")
    gaps = build_coverage_gaps(ScanResult(policy_findings=findings))

    assert len(findings) == 1
    assert findings[0].actions == []
    assert findings[0].metadata["policy_coverage_complete"] is False
    assert findings[0].metadata["unresolved_policy_attachments"] == [
        "AWSLambdaBasicExecutionRole",
        '{"S3ReadPolicy":{"BucketName":{"Ref":"Bucket"}}}',
    ]
    assert [gap.gap_type for gap in gaps] == ["unsupported_sam_policy"]


def test_conditional_sam_policy_is_not_flattened_into_active_permissions() -> None:
    template = {
        "Resources": {
            "WorkerFunction": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "Handler": "app.handler",
                    "Policies": [
                        {
                            "Fn::If": [
                                "UseAdminPolicy",
                                {
                                    "Statement": {
                                        "Effect": "Allow",
                                        "Action": "*",
                                        "Resource": "*",
                                    }
                                },
                                {"Ref": "AWS::NoValue"},
                            ]
                        }
                    ],
                },
            }
        }
    }

    findings = extract_iam_policies_from_cloudformation(template, "template.yml")

    assert len(findings) == 1
    assert findings[0].actions == []
    assert findings[0].overall_risk is RiskLevel.INFO
    assert findings[0].metadata["policy_coverage_complete"] is False
    assert "Fn::If" in findings[0].metadata["unresolved_policy_attachments"][0]


def test_unknown_dynamic_resource_is_not_treated_as_wildcard() -> None:
    template = {
        "Resources": {
            "DeployRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "deploy-role",
                    "Policies": [
                        {
                            "PolicyDocument": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "s3:PutObject",
                                    "Resource": {"Fn::GetAtt": ["Bucket", "Arn"]},
                                }
                            }
                        }
                    ],
                },
            }
        }
    }

    finding = extract_iam_policies_from_cloudformation(template, "template.yml")[0]

    assert finding.actions[0].resource == "<dynamic:Fn::GetAtt>"
    assert not finding.has_star_resource


def test_role_aggregates_inline_and_attached_policy_documents() -> None:
    template = {
        "Resources": {
            "DeployRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "deploy-role",
                    "Policies": [
                        {
                            "PolicyDocument": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::builds/*",
                                }
                            }
                        }
                    ],
                },
            },
            "EscalationPolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "Roles": [{"Ref": "DeployRole"}],
                    "PolicyDocument": {
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "iam:PassRole",
                            "Resource": "*",
                        }
                    },
                },
            },
        }
    }

    findings = extract_iam_policies_from_cloudformation(template, "template.yml")

    assert len(findings) == 1
    assert {action.action for action in findings[0].actions} == {
        "iam:PassRole",
        "s3:GetObject",
    }
    assert findings[0].has_passrole
    assert findings[0].overall_risk is RiskLevel.CRITICAL


def test_static_join_role_name_preserves_workflow_correlation() -> None:
    template = {
        "Resources": {
            "DeployRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Fn::Join": ["", ["deploy", "-role"]]},
                    "Policies": [
                        {
                            "PolicyDocument": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "iam:PassRole",
                                    "Resource": "*",
                                }
                            }
                        }
                    ],
                },
            }
        }
    }

    findings = extract_iam_policies_from_cloudformation(template, "template.yml")
    binding = build_bindings([_credential("deploy-role")], findings, ".")[0]

    assert binding.policy_finding is not None
    assert binding.match_confidence == "high"
    assert binding.policy_finding.role_name == "deploy-role"
    assert binding.policy_finding.overall_risk is RiskLevel.CRITICAL


def test_dynamic_role_name_is_reported_as_partial_coverage() -> None:
    template = {
        "Resources": {
            "DeployRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Fn::Sub": "${Stage}-deploy-role"},
                    "Policies": [
                        {
                            "PolicyDocument": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                }
                            }
                        }
                    ],
                },
            }
        }
    }

    finding = extract_iam_policies_from_cloudformation(template, "template.yml")[0]

    assert finding.role_name is None
    assert finding.metadata["policy_coverage_complete"] is False
    assert finding.metadata["coverage_gap_type"] == (
        "unresolved_cloudformation_role_name"
    )
    assert "Stage" in finding.metadata["unresolved_policy_attachments"][0]


def test_conditional_policy_resource_is_partial_not_unconditionally_attached() -> None:
    template = {
        "Resources": {
            "DeployRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "deploy-role",
                    "Policies": [
                        {
                            "PolicyDocument": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::builds/*",
                                }
                            }
                        }
                    ],
                },
            },
            "ConditionalAdmin": {
                "Type": "AWS::IAM::Policy",
                "Condition": "EnableAdmin",
                "Properties": {
                    "PolicyName": "conditional-admin",
                    "Roles": [{"Ref": "DeployRole"}],
                    "PolicyDocument": {
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "iam:PassRole",
                            "Resource": "*",
                        }
                    },
                },
            },
        }
    }

    findings = extract_iam_policies_from_cloudformation(template, "template.yml")
    binding = build_bindings([_credential("deploy-role")], findings, ".")[0]

    assert binding.policy_finding is not None
    assert [action.action for action in binding.policy_finding.actions] == [
        "s3:GetObject"
    ]
    assert binding.policy_finding.overall_risk is RiskLevel.LOW
    assert binding.policy_finding.metadata["policy_coverage_complete"] is False
    assert "EnableAdmin" in binding.policy_finding.metadata[
        "unresolved_policy_attachments"
    ][0]
    standalone = next(finding for finding in findings if finding.role_name is None)
    assert standalone.metadata["coverage_gap_type"] == (
        "conditional_cloudformation_policy_resource"
    )


def test_conditional_inline_role_policy_marks_coverage_partial() -> None:
    template = {
        "Resources": {
            "DeployRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "deploy-role",
                    "Policies": [
                        {
                            "PolicyName": "read-builds",
                            "PolicyDocument": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::builds/*",
                                }
                            },
                        },
                        {
                            "Fn::If": [
                                "EnableAdmin",
                                {
                                    "PolicyName": "admin",
                                    "PolicyDocument": {
                                        "Statement": {
                                            "Effect": "Allow",
                                            "Action": "*",
                                            "Resource": "*",
                                        }
                                    },
                                },
                                {"Ref": "AWS::NoValue"},
                            ]
                        },
                    ],
                },
            }
        }
    }

    finding = extract_iam_policies_from_cloudformation(template, "template.yml")[0]

    assert [action.action for action in finding.actions] == ["s3:GetObject"]
    assert finding.overall_risk is RiskLevel.LOW
    assert finding.metadata["policy_coverage_complete"] is False
    assert "Fn::If" in finding.metadata["unresolved_policy_attachments"][0]


def test_conditional_role_attachment_is_partial_not_granted_to_every_role() -> None:
    template = {
        "Resources": {
            "RoleA": {
                "Type": "AWS::IAM::Role",
                "Properties": {"RoleName": "role-a"},
            },
            "RoleB": {
                "Type": "AWS::IAM::Role",
                "Properties": {"RoleName": "role-b"},
            },
            "ConditionalPolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": "conditional-admin",
                    "Roles": {
                        "Fn::If": [
                            "AttachToA",
                            {"Ref": "RoleA"},
                            {"Ref": "RoleB"},
                        ]
                    },
                    "PolicyDocument": {
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "iam:PassRole",
                            "Resource": "*",
                        }
                    },
                },
            },
        }
    }

    findings = extract_iam_policies_from_cloudformation(template, "template.yml")

    assert {finding.role_name for finding in findings} == {"role-a", "role-b"}
    assert all(finding.actions == [] for finding in findings)
    assert all(
        finding.metadata["policy_coverage_complete"] is False
        for finding in findings
    )
    assert all(
        "conditional-admin has a conditional role target"
        in finding.metadata["unresolved_policy_attachments"][0]
        for finding in findings
    )


def test_unresolved_role_target_marks_local_roles_partial() -> None:
    template = {
        "Resources": {
            "DeployRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "deploy-role",
                    "Policies": [
                        {
                            "PolicyDocument": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::builds/*",
                                }
                            }
                        }
                    ],
                },
            },
            "ParameterAttachedPolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": "parameter-admin",
                    "Roles": [{"Ref": "RoleNameParameter"}],
                    "PolicyDocument": {
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "iam:PassRole",
                            "Resource": "*",
                        }
                    },
                },
            },
        }
    }

    findings = extract_iam_policies_from_cloudformation(template, "template.yml")
    binding = build_bindings([_credential("deploy-role")], findings, ".")[0]

    assert binding.policy_finding is not None
    assert [action.action for action in binding.policy_finding.actions] == [
        "s3:GetObject"
    ]
    assert binding.policy_finding.metadata["policy_coverage_complete"] is False
    assert "RoleNameParameter" in binding.policy_finding.metadata[
        "unresolved_policy_attachments"
    ][0]


def test_role_side_managed_policy_ref_is_resolved() -> None:
    template = {
        "Resources": {
            "DeployRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "deploy-role",
                    "ManagedPolicyArns": [{"Ref": "EscalationPolicy"}],
                },
            },
            "EscalationPolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": "deploy-escalation",
                    "PolicyDocument": {
                        "Statement": {
                            "Effect": "Allow",
                            "Action": "iam:CreatePolicyVersion",
                            "Resource": "*",
                        }
                    },
                },
            },
        }
    }

    findings = extract_iam_policies_from_cloudformation(template, "template.yml")

    assert len(findings) == 1
    assert findings[0].role_name == "deploy-role"
    assert [action.action for action in findings[0].actions] == [
        "iam:CreatePolicyVersion"
    ]
    assert findings[0].overall_risk is RiskLevel.CRITICAL
    assert findings[0].metadata["cloudformation_policy_logical_ids"] == [
        "EscalationPolicy"
    ]
    assert findings[0].metadata["policy_coverage_complete"] is True
    assert findings[0].metadata["unresolved_policy_attachments"] == []


def test_external_managed_policy_attachment_marks_role_coverage_partial() -> None:
    external_policy = "arn:aws:iam::aws:policy/AdministratorAccess"
    template = {
        "Resources": {
            "DeployRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "deploy-role",
                    "ManagedPolicyArns": [external_policy],
                    "Policies": [
                        {
                            "PolicyDocument": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::builds/*",
                                }
                            }
                        }
                    ],
                },
            }
        }
    }

    findings = extract_iam_policies_from_cloudformation(template, "template.yml")
    binding = build_bindings([_credential("deploy-role")], findings, ".")[0]
    result = ScanResult(
        credential_sources=[binding.credential_source],
        policy_findings=findings,
        bindings=[binding],
    )

    assert binding.policy_finding is not None
    assert [action.action for action in binding.policy_finding.actions] == [
        "s3:GetObject"
    ]
    assert binding.policy_finding.metadata["policy_coverage_complete"] is False
    assert binding.policy_finding.metadata["unresolved_policy_attachments"] == [
        external_policy
    ]
    assert [gap.gap_type for gap in build_coverage_gaps(result)] == [
        "unresolved_managed_policy_attachment"
    ]
    report = json.loads(to_json(result))
    assert report["coverage_status"] == "partial"
    assert report["findings"][0]["risk_status"] == "partial"
    assert report["summary"]["policies_partial"] == 1


def test_external_only_managed_policy_still_creates_partial_role_binding() -> None:
    template = {
        "Resources": {
            "DeployRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "deploy-role",
                    "ManagedPolicyArns": [
                        {"Ref": "ExternalManagedPolicyArn"}
                    ],
                },
            }
        }
    }

    findings = extract_iam_policies_from_cloudformation(template, "template.yml")
    binding = build_bindings([_credential("deploy-role")], findings, ".")[0]

    assert len(findings) == 1
    assert binding.policy_source == "cloudformation"
    assert binding.match_confidence == "high"
    assert binding.policy_finding is not None
    assert binding.policy_finding.actions == []
    assert binding.policy_finding.metadata["policy_coverage_complete"] is False
    assert binding.policy_finding.metadata["unresolved_policy_attachments"] == [
        '{"Ref":"ExternalManagedPolicyArn"}'
    ]


def test_dynamic_policy_action_marks_binding_coverage_partial() -> None:
    template = {
        "Resources": {
            "DeployRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "deploy-role",
                    "Policies": [
                        {
                            "PolicyDocument": {
                                "Statement": {
                                    "Effect": "Allow",
                                    "Action": {"Fn::Sub": "${Service}:*"},
                                    "Resource": "*",
                                }
                            }
                        }
                    ],
                },
            }
        }
    }

    findings = extract_iam_policies_from_cloudformation(template, "template.yml")
    binding = build_bindings([_credential("deploy-role")], findings, ".")[0]
    result = ScanResult(bindings=[binding])

    assert binding.policy_finding is not None
    assert binding.policy_finding.metadata["policy_coverage_complete"] is False
    assert binding.policy_finding.metadata["uninspectable_policy_elements"] == [
        "document 1 statement 1 Action"
    ]
    assert [gap.gap_type for gap in build_coverage_gaps(result)] == [
        "uninspectable_policy_content"
    ]
    report = json.loads(to_json(result))
    assert report["findings"][0]["risk_status"] == "partial"
    assert report["findings"][0]["uninspectable_policy_elements"] == [
        "document 1 statement 1 Action"
    ]


def test_not_action_and_not_resource_are_classified_conservatively() -> None:
    template = {
        "Resources": {
            "BroadRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "broad-role",
                    "Policies": [
                        {
                            "PolicyDocument": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "NotAction": "iam:DeleteUser",
                                        "Resource": "*",
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": "s3:PutObject",
                                        "NotResource": "arn:aws:s3:::audit/*",
                                    },
                                ]
                            }
                        }
                    ],
                },
            }
        }
    }

    finding = extract_iam_policies_from_cloudformation(template, "template.yml")[0]

    assert finding.has_star_action
    assert finding.has_star_resource
    assert finding.overall_risk is RiskLevel.CRITICAL


def test_scan_rejects_oversized_template(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(cloudformation, "_MAX_TEMPLATE_BYTES", 128)
    template = tmp_path / "template.yml"
    template.write_text(
        "Resources:\n"
        "  Role:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      RoleName: oversized\n"
        + ("# padding\n" * 20),
        encoding="utf-8",
    )

    findings, errors = scan_cloudformation_files(str(tmp_path))

    assert findings == []
    assert len(errors) == 1
    assert "template exceeds 128 bytes" in errors[0]


def test_scan_finds_iam_resource_after_initial_peek(tmp_path: Path) -> None:
    template = tmp_path / "template.yml"
    template.write_text(
        "Resources:\n"
        + ("#" + (" padding" * 20_000) + "\n")
        + "  LateRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      RoleName: late-role\n"
        "      Policies:\n"
        "        - PolicyDocument:\n"
        "            Statement:\n"
        "              Effect: Allow\n"
        "              Action: s3:GetObject\n"
        "              Resource: '*'\n",
        encoding="utf-8",
    )

    assert template.stat().st_size > cloudformation._PEEK_BYTES
    findings, errors = scan_cloudformation_files(str(tmp_path))

    assert errors == []
    assert len(findings) == 1
    assert findings[0].role_name == "late-role"


def test_scan_finds_single_quoted_resources_key(tmp_path: Path) -> None:
    template = tmp_path / "template.yml"
    template.write_text(
        "'Resources':\n"
        "  DeployRole:\n"
        "    Type: AWS::IAM::Role\n"
        "    Properties:\n"
        "      RoleName: deploy-role\n"
        "      Policies:\n"
        "        - PolicyDocument:\n"
        "            Statement:\n"
        "              Effect: Allow\n"
        "              Action: s3:GetObject\n"
        "              Resource: '*'\n",
        encoding="utf-8",
    )

    findings, errors = scan_cloudformation_files(str(tmp_path))

    assert errors == []
    assert len(findings) == 1
    assert findings[0].role_name == "deploy-role"


def test_scan_cloudformation_files_returns_findings_without_errors() -> None:
    findings, errors = scan_cloudformation_files(str(FIXTURE_REPO))

    assert errors == []
    assert len(findings) == 2


def test_scan_ignores_serverless_framework_wrapper(tmp_path: Path) -> None:
    (tmp_path / "serverless.yml").write_text(
        """
service: example
resources:
  Resources:
    DeployRole:
      Type: AWS::IAM::Role
""",
        encoding="utf-8",
    )

    findings, errors = scan_cloudformation_files(str(tmp_path))

    assert findings == []
    assert errors == []


def test_scan_reports_malformed_template_once(tmp_path: Path) -> None:
    (tmp_path / "template.yml").write_text(
        """
Resources:
  Broken:
    Type: AWS::IAM::Role
    Properties: [
""",
        encoding="utf-8",
    )

    findings, errors = scan_cloudformation_files(str(tmp_path))

    assert findings == []
    assert len(errors) == 1
    assert "Could not parse CloudFormation file" in errors[0]


def test_json_cloudformation_template_is_parsed(tmp_path: Path) -> None:
    template_file = tmp_path / "template.json"
    template_file.write_text(
        json.dumps(
            {
                "Resources": {
                    "DeployRole": {
                        "Type": "AWS::IAM::Role",
                        "Properties": {
                            "RoleName": "json-deploy-role",
                            "Policies": [
                                {
                                    "PolicyName": "deploy",
                                    "PolicyDocument": {
                                        "Statement": [
                                            {
                                                "Effect": "Allow",
                                                "Action": "s3:PutObject",
                                                "Resource": "*",
                                            }
                                        ]
                                    },
                                }
                            ],
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    findings, errors = scan_cloudformation_files(str(tmp_path))

    assert errors == []
    assert len(findings) == 1
    assert findings[0].role_name == "json-deploy-role"
    assert [action.action for action in findings[0].actions] == ["s3:PutObject"]


def test_cloudformation_role_matches_workflow_binding_with_high_confidence() -> None:
    findings, _errors = scan_cloudformation_files(str(FIXTURE_REPO))

    binding = build_bindings(
        [_credential("github-deploy-role")],
        findings,
        str(FIXTURE_REPO),
    )[0]

    assert binding.policy_source == "cloudformation"
    assert binding.match_confidence == "high"
    assert binding.match_reason == "CloudFormation/SAM role relationship match"
    assert binding.policy_finding is not None
    assert binding.policy_finding.role_name == "github-deploy-role"


def test_cloudformation_github_oidc_trust_is_analyzed() -> None:
    findings, errors = scan_oidc_trust_policies(str(FIXTURE_REPO))

    assert errors == []
    wildcard = next(
        finding for finding in findings if finding.issue_id == "wildcard_repo"
    )
    assert wildcard.role_name == "github-deploy-role"
    assert wildcard.risk_level is RiskLevel.CRITICAL


def test_cli_correlates_cloudformation_policy_with_workflow() -> None:
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(FIXTURE_REPO),
            "--output-format",
            "json",
            "--offline",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    deploy = next(
        finding for finding in payload["findings"] if finding["job_name"] == "deploy"
    )
    assert deploy["policy_source"] == "cloudformation"
    assert deploy["match_confidence"] == "high"
    assert deploy["role_reference_kind"] == "literal_arn"
    assert {action["action"] for action in deploy["actions"]} == {
        "ec2:TerminateInstances",
        "s3:PutObject",
    }
