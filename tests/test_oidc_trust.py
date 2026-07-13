"""Tests for the GitHub Actions OIDC trust policy analyzer."""

from pathlib import Path
from shutil import copyfile

import hcl2

from actionscope.analyzers.oidc_trust import (
    analyze_json_oidc_trust,
    analyze_oidc_trust_conditions,
    analyze_terraform_oidc_trust,
    extract_github_oidc_statements,
    is_github_oidc_trust,
    scan_oidc_trust_policies,
)
from actionscope.models import RiskLevel

FIXTURE = Path(__file__).parent / "fixtures" / "terraform" / "oidc_trust.tf"


def _load_fixture() -> dict:
    with FIXTURE.open(encoding="utf-8") as handle:
        return hcl2.load(handle)


def _trust_policy(sub: str | None = None, aud: bool = True) -> dict:
    condition: dict = {"StringEquals": {}}
    if aud:
        condition["StringEquals"][
            "token.actions.githubusercontent.com:aud"
        ] = "sts.amazonaws.com"
    if sub is not None:
        condition.setdefault("StringLike", {})[
            "token.actions.githubusercontent.com:sub"
        ] = sub
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": (
                        "arn:aws:iam::123456789012:oidc-provider/"
                        "token.actions.githubusercontent.com"
                    )
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": condition,
            }
        ],
    }


def test_is_github_oidc_trust_true_for_github_principal() -> None:
    assert is_github_oidc_trust(_trust_policy("repo:acme/app:ref:refs/heads/main"))


def test_is_github_oidc_trust_false_for_non_oidc_role() -> None:
    assert not is_github_oidc_trust(
        {
            "Statement": [
                {
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
    )


def test_wildcard_org_subject_detected_as_critical() -> None:
    findings = analyze_json_oidc_trust(_trust_policy("repo:acme-corp/*"), "iam.tf")

    assert any(
        f.issue_id == "wildcard_repo" and f.risk_level is RiskLevel.CRITICAL
        for f in findings
    )


def test_missing_sub_condition_detected_as_critical() -> None:
    findings = analyze_json_oidc_trust(_trust_policy(None), "iam.tf")

    assert any(
        f.issue_id == "missing_sub" and f.risk_level is RiskLevel.CRITICAL
        for f in findings
    )


def test_no_branch_scope_detected_as_high() -> None:
    findings = analyze_json_oidc_trust(_trust_policy("repo:acme-corp/app"), "iam.tf")

    assert any(
        f.issue_id == "no_branch_scope" and f.risk_level is RiskLevel.HIGH
        for f in findings
    )


def test_clean_role_produces_no_findings() -> None:
    findings = analyze_json_oidc_trust(
        _trust_policy("repo:acme-corp/app:ref:refs/heads/main"),
        "iam.tf",
    )

    assert findings == []


def test_analyze_terraform_oidc_trust_finds_issues_in_fixture() -> None:
    findings = analyze_terraform_oidc_trust(_load_fixture(), str(FIXTURE))

    assert {finding.issue_id for finding in findings} >= {
        "wildcard_repo",
        "missing_sub",
        "no_branch_scope",
        "missing_aud",
        "forallvalues_single_valued_claim",
    }


def test_scan_oidc_trust_policies_returns_findings(tmp_path: Path) -> None:
    tf_dir = tmp_path / "terraform"
    tf_dir.mkdir()
    copyfile(FIXTURE, tf_dir / "oidc_trust.tf")

    findings, errors = scan_oidc_trust_policies(str(tmp_path))

    assert errors == []
    assert findings


def test_oidc_trust_finding_risk_level_is_critical_for_wildcard() -> None:
    findings = analyze_json_oidc_trust(_trust_policy("repo:acme-corp/*"), "iam.tf")
    wildcard = next(f for f in findings if f.issue_id == "wildcard_repo")

    assert wildcard.risk_level is RiskLevel.CRITICAL


def test_recommendation_is_non_empty_for_all_findings() -> None:
    findings = analyze_terraform_oidc_trust(_load_fixture(), str(FIXTURE))

    assert all(f.recommendation for f in findings)


def test_missing_aud_condition_detected_as_medium() -> None:
    findings = analyze_json_oidc_trust(
        _trust_policy("repo:acme/app:environment:prod", aud=False),
        "iam.tf",
    )

    assert any(
        f.issue_id == "missing_aud" and f.risk_level is RiskLevel.MEDIUM
        for f in findings
    )


def test_evidence_field_shows_actual_sub_value() -> None:
    findings = analyze_json_oidc_trust(_trust_policy("repo:acme-corp/*"), "iam.tf")

    assert "repo:acme-corp/*" in findings[0].evidence


def test_jsonencode_terraform_block_parsed_correctly() -> None:
    findings = analyze_terraform_oidc_trust(_load_fixture(), str(FIXTURE))

    assert any(f.role_name == "wildcard-org-role" for f in findings)
    assert any(f.role_name == "forallvalues-sub-role" for f in findings)


def test_environment_condition_not_flagged_as_no_branch_scope() -> None:
    findings = analyze_json_oidc_trust(
        _trust_policy("repo:acme/app:environment:prod"),
        "iam.tf",
    )

    assert not any(f.issue_id == "no_branch_scope" for f in findings)


def test_multiple_roles_in_same_file_each_produce_findings() -> None:
    findings = analyze_terraform_oidc_trust(_load_fixture(), str(FIXTURE))
    roles = {finding.role_name for finding in findings}

    assert {"wildcard-org-role", "missing-sub-role", "no-branch-role"} <= roles


def test_analyze_single_statement_api() -> None:
    statement = _trust_policy("repo:acme-corp/*")["Statement"][0]

    findings = analyze_oidc_trust_conditions(statement, "iam.tf", "role")

    assert findings[0].role_name == "role"


def test_policy_document_data_source_conditions_are_unquoted() -> None:
    tf_data = hcl2.loads(
        """
data "aws_iam_policy_document" "trust" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type = "Federated"
      identifiers = [
        "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      ]
    }
    condition {
      test = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = ["repo:acme-corp/app:ref:refs/heads/main"]
    }
    condition {
      test = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values = ["sts.amazonaws.com"]
    }
  }
}
"""
    )

    findings = analyze_terraform_oidc_trust(tf_data, "iam.tf")

    assert findings == []


def test_policy_document_data_source_detects_wildcard_subject() -> None:
    tf_data = hcl2.loads(
        """
data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type = "Federated"
      identifiers = ["token.actions.githubusercontent.com"]
    }
    condition {
      test = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = ["repo:acme-corp/*"]
    }
    condition {
      test = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values = ["sts.amazonaws.com"]
    }
  }
}
"""
    )

    findings = analyze_terraform_oidc_trust(tf_data, "iam.tf")

    assert [finding.issue_id for finding in findings] == ["wildcard_repo"]


def test_policy_document_detects_later_github_federated_principal() -> None:
    tf_data = hcl2.loads(
        """
data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }
    principals {
      type = "Federated"
      identifiers = [
        "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      ]
    }
    condition {
      test = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = ["repo:acme-corp/*"]
    }
    condition {
      test = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values = ["sts.amazonaws.com"]
    }
  }
}
"""
    )

    findings = analyze_terraform_oidc_trust(tf_data, "iam.tf")

    assert [finding.issue_id for finding in findings] == ["wildcard_repo"]


def test_terraform_without_resource_section_does_not_crash() -> None:
    tf_data = hcl2.loads(
        """
data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type = "Federated"
      identifiers = ["token.actions.githubusercontent.com"]
    }
  }
}
"""
    )

    findings = analyze_terraform_oidc_trust(tf_data, "iam.tf")

    assert [finding.issue_id for finding in findings] == [
        "missing_sub",
        "missing_aud",
    ]


def test_forallvalues_stringlike_on_sub_is_reported() -> None:
    policy = _trust_policy("repo:acme/app:ref:refs/heads/main")
    condition = policy["Statement"][0]["Condition"]
    condition["ForAllValues:StringLike"] = condition.pop("StringLike")

    findings = analyze_json_oidc_trust(policy, "iam.tf")
    finding = next(
        item
        for item in findings
        if item.issue_id == "forallvalues_single_valued_claim"
    )

    assert finding.risk_level is RiskLevel.MEDIUM
    assert "ForAllValues:StringLike" in finding.evidence
    assert "ForAllValues" not in finding.recommendation
    assert '"StringLike"' in finding.recommendation


def test_forallvalues_stringequals_on_aud_is_reported() -> None:
    policy = _trust_policy("repo:acme/app:environment:production")
    condition = policy["Statement"][0]["Condition"]
    condition["ForAllValues:StringEquals"] = condition.pop("StringEquals")

    findings = analyze_json_oidc_trust(policy, "iam.tf")

    assert any(
        finding.issue_id == "forallvalues_single_valued_claim"
        and "token.actions.githubusercontent.com:aud" in finding.evidence
        for finding in findings
    )


def test_forallvalues_on_multivalued_amr_is_not_reported() -> None:
    policy = _trust_policy("repo:acme/app:ref:refs/heads/main")
    policy["Statement"][0]["Condition"]["ForAllValues:StringEquals"] = {
        "token.actions.githubusercontent.com:amr": ["authenticated"]
    }

    findings = analyze_json_oidc_trust(policy, "iam.tf")

    assert not any(
        finding.issue_id == "forallvalues_single_valued_claim"
        for finding in findings
    )


def test_deny_statement_is_not_treated_as_oidc_trust() -> None:
    policy = _trust_policy("repo:acme/*")
    policy["Statement"][0]["Effect"] = "Deny"

    assert not is_github_oidc_trust(policy)
    assert analyze_json_oidc_trust(policy, "iam.tf") == []


def test_non_web_identity_action_is_not_treated_as_oidc_trust() -> None:
    policy = _trust_policy("repo:acme/*")
    policy["Statement"][0]["Action"] = "sts:AssumeRole"

    assert not is_github_oidc_trust(policy)
    assert analyze_json_oidc_trust(policy, "iam.tf") == []


def test_notaction_that_keeps_web_identity_is_analyzed() -> None:
    for key in ("NotAction", "notAction"):
        policy = _trust_policy("repo:acme/*")
        statement = policy["Statement"][0]
        statement.pop("Action")
        statement[key] = "sts:AssumeRole"

        extracted = extract_github_oidc_statements(policy)
        findings = analyze_json_oidc_trust(policy, "iam.tf")

        assert extracted == [statement]
        assert any(finding.issue_id == "wildcard_repo" for finding in findings)


def test_notaction_that_excludes_web_identity_is_not_analyzed() -> None:
    policy = _trust_policy("repo:acme/*")
    statement = policy["Statement"][0]
    statement.pop("Action")
    statement["NotAction"] = ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"]

    assert extract_github_oidc_statements(policy) == []
    assert analyze_json_oidc_trust(policy, "iam.tf") == []


def test_repo_star_subject_is_critical() -> None:
    findings = analyze_json_oidc_trust(_trust_policy("repo:*"), "iam.tf")

    assert any(
        finding.issue_id == "wildcard_repo"
        and finding.risk_level is RiskLevel.CRITICAL
        for finding in findings
    )


def test_wildcard_owner_subject_is_critical() -> None:
    findings = analyze_json_oidc_trust(
        _trust_policy("repo:*/app:ref:refs/heads/main"),
        "iam.tf",
    )

    assert any(finding.issue_id == "wildcard_repo" for finding in findings)


def test_repo_wide_context_wildcard_is_high() -> None:
    findings = analyze_json_oidc_trust(_trust_policy("repo:acme/app:*"), "iam.tf")

    assert any(
        finding.issue_id == "broad_subject"
        and finding.risk_level is RiskLevel.HIGH
        for finding in findings
    )


def test_branch_wildcard_is_high() -> None:
    findings = analyze_json_oidc_trust(
        _trust_policy("repo:acme/app:ref:refs/heads/*"),
        "iam.tf",
    )

    assert [finding.issue_id for finding in findings] == ["broad_subject"]


def test_environment_wildcard_is_high() -> None:
    findings = analyze_json_oidc_trust(
        _trust_policy("repo:acme/app:environment:*"),
        "iam.tf",
    )

    assert [finding.issue_id for finding in findings] == ["broad_subject"]


def test_partial_environment_wildcard_is_high() -> None:
    findings = analyze_json_oidc_trust(
        _trust_policy("repo:acme/app:environment:prod-*"),
        "iam.tf",
    )

    assert [finding.issue_id for finding in findings] == ["broad_subject"]


def test_constrained_release_tag_wildcard_is_not_reported() -> None:
    findings = analyze_json_oidc_trust(
        _trust_policy("repo:acme/app:ref:refs/tags/v*"),
        "iam.tf",
    )

    assert findings == []


def test_terraform_forallvalues_condition_is_reported() -> None:
    tf_data = hcl2.loads(
        """
data "aws_iam_policy_document" "trust" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type = "Federated"
      identifiers = ["token.actions.githubusercontent.com"]
    }
    condition {
      test = "ForAllValues:StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = ["repo:acme/app:ref:refs/heads/main"]
    }
    condition {
      test = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values = ["sts.amazonaws.com"]
    }
  }
}
"""
    )

    findings = analyze_terraform_oidc_trust(tf_data, "iam.tf")

    assert [finding.issue_id for finding in findings] == [
        "forallvalues_single_valued_claim"
    ]


def test_oidc_findings_include_condition_block_remediation() -> None:
    findings = analyze_json_oidc_trust(_trust_policy("repo:acme/*"), "iam.tf")

    assert all("Condition:" in finding.recommendation for finding in findings)
