"""Tests for the IAM risk classifier."""

import pytest

from actionscope.analyzers import iam_risk
from actionscope.analyzers.iam_risk import (
    classify_action,
    classify_actions,
    expand_wildcard_service,
    format_risk_summary,
    get_db_session,
    get_overall_risk,
)
from actionscope.models import IamAction, RiskLevel


def test_iam_passrole_classified_as_critical() -> None:
    result = classify_action("iam:PassRole")

    assert result.risk_level is RiskLevel.CRITICAL


def test_iam_create_policy_version_classified_as_critical() -> None:
    result = classify_action("iam:CreatePolicyVersion")

    assert result.risk_level is RiskLevel.CRITICAL


def test_s3_delete_bucket_classified_as_high() -> None:
    result = classify_action("s3:DeleteBucket")

    assert result.risk_level is RiskLevel.HIGH


def test_s3_get_object_classified_as_low() -> None:
    result = classify_action("s3:GetObject")

    assert result.risk_level is RiskLevel.LOW


def test_s3_wildcard_classified_as_high() -> None:
    result = classify_action("s3:*")
    expanded_actions = expand_wildcard_service("s3")

    assert result.risk_level is RiskLevel.HIGH
    assert result.description == "Grants all s3 permissions"
    assert "s3:GetObject" in expanded_actions
    assert "s3:DeleteBucket" in expanded_actions


def test_iam_wildcard_classified_as_critical() -> None:
    result = classify_action("iam:*")

    assert result.risk_level is RiskLevel.CRITICAL


def test_star_action_classified_as_critical() -> None:
    result = classify_action("*")

    assert result.risk_level is RiskLevel.CRITICAL
    assert result.description == "Grants ALL permissions on ALL AWS services"


def test_unknown_action_returns_low_with_unknown_description() -> None:
    result = classify_action("s3:DefinitelyNotAnAction")

    assert result.risk_level is RiskLevel.LOW
    assert "Unknown action" in result.description


def test_mixed_case_action_normalizes_for_lookup() -> None:
    result = classify_action("S3:DELETEBUCKET")

    assert result.action == "s3:DeleteBucket"
    assert result.risk_level is RiskLevel.HIGH


def test_get_overall_risk_returns_critical_when_any_action_is_critical() -> None:
    actions = [
        IamAction("s3:GetObject", "Read", RiskLevel.LOW, "Read object", "*"),
        IamAction(
            "iam:PassRole",
            "Permissions management",
            RiskLevel.CRITICAL,
            "Pass role",
            "*",
        ),
    ]

    assert get_overall_risk(actions) is RiskLevel.CRITICAL


def test_format_risk_summary_groups_by_risk_level() -> None:
    actions = [
        IamAction("s3:GetObject", "Read", RiskLevel.LOW, "Read object", "*"),
        IamAction("s3:DeleteBucket", "Write", RiskLevel.HIGH, "Delete bucket", "*"),
        IamAction(
            "ec2:TerminateInstances",
            "Write",
            RiskLevel.HIGH,
            "Terminate instances",
            "*",
        ),
    ]

    summary = format_risk_summary(actions)

    assert summary == {
        RiskLevel.LOW: ["Read object"],
        RiskLevel.HIGH: ["Delete bucket", "Terminate instances"],
    }


def test_empty_actions_list_returns_info_from_get_overall_risk() -> None:
    assert get_overall_risk([]) is RiskLevel.INFO


def test_iam_put_role_policy_classified_as_critical() -> None:
    result = classify_action("iam:PutRolePolicy")

    assert result.risk_level is RiskLevel.CRITICAL


def test_iam_create_login_profile_classified_as_critical() -> None:
    result = classify_action("iam:CreateLoginProfile")

    assert result.risk_level is RiskLevel.CRITICAL


def test_iam_add_user_to_group_classified_as_critical() -> None:
    result = classify_action("iam:AddUserToGroup")

    assert result.risk_level is RiskLevel.CRITICAL


def test_iam_update_login_profile_classified_as_critical() -> None:
    result = classify_action("iam:UpdateLoginProfile")

    assert result.risk_level is RiskLevel.CRITICAL


def test_iam_set_default_policy_version_classified_as_critical() -> None:
    result = classify_action("iam:SetDefaultPolicyVersion")

    assert result.risk_level is RiskLevel.CRITICAL


def test_glue_create_dev_endpoint_classified_as_critical() -> None:
    result = classify_action("glue:CreateDevEndpoint")

    assert result.risk_level is RiskLevel.CRITICAL


def test_ec2_terminate_instances_classified_as_high() -> None:
    result = classify_action("ec2:TerminateInstances")

    assert result.risk_level is RiskLevel.HIGH


def test_s3_list_bucket_classified_as_low() -> None:
    result = classify_action("s3:ListBucket")

    assert result.risk_level is RiskLevel.LOW


def test_sts_assume_role_on_star_resource_classified_as_critical() -> None:
    result = classify_action("sts:AssumeRole", resource="*")

    assert result.risk_level is RiskLevel.CRITICAL


def test_classify_actions_passes_resource_and_strips_whitespace() -> None:
    results = classify_actions(
        [" s3:GetObject "],
        resource="arn:aws:s3:::example-bucket/*",
    )

    assert results[0].action == "s3:GetObject"
    assert results[0].resource == "arn:aws:s3:::example-bucket/*"


def test_invalid_action_format_returns_low() -> None:
    result = classify_action("not-an-action")

    assert result.risk_level is RiskLevel.LOW
    assert result.description == "Invalid action format: not-an-action"


def test_get_db_session_caches_connect_db(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    session = object()

    def fake_connect_db(name: str) -> object:
        calls.append(name)
        return session

    monkeypatch.setattr(iam_risk, "_DB_SESSION", None)
    monkeypatch.setattr(iam_risk, "connect_db", fake_connect_db)

    assert get_db_session() is session
    assert get_db_session() is session
    assert calls == ["bundled"]


def test_get_db_session_failure_uses_offline_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_connect_db(name: str) -> object:
        raise ValueError(f"boom: {name}")

    monkeypatch.setattr(iam_risk, "_DB_SESSION", None)
    monkeypatch.setattr(iam_risk, "connect_db", fake_connect_db)

    s1 = get_db_session()
    s2 = get_db_session()
    assert s1 is s2
    assert s1 is iam_risk._JSON_BUNDLE_SESSION
