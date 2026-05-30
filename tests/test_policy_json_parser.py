"""Tests for the JSON IAM policy parser."""

from pathlib import Path

from actionscope.models import RiskLevel
from actionscope.parsers.policy_json import (
    extract_actions_from_policy,
    find_policy_json_files,
    is_iam_policy,
    parse_policy_json_file,
    scan_policy_files,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "policies"


def parse_fixture(name: str) -> dict:
    """Parse a policy fixture and return its data."""
    policy = parse_policy_json_file(str(FIXTURE_DIR / name))
    assert policy is not None
    return policy


def test_is_iam_policy_returns_true_for_valid_policy_structure() -> None:
    assert is_iam_policy(
        {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject"}]}
    )


def test_is_iam_policy_returns_false_for_random_json() -> None:
    assert not is_iam_policy({"name": "not a policy"})


def test_passrole_wildcard_sets_passrole_and_privilege_escalation() -> None:
    finding = extract_actions_from_policy(
        parse_fixture("passrole_wildcard.json"),
        "passrole_wildcard.json",
    )

    assert finding.has_passrole is True
    assert finding.has_privilege_escalation is True


def test_admin_policy_produces_critical_overall_risk() -> None:
    finding = extract_actions_from_policy(
        parse_fixture("admin_policy.json"),
        "admin_policy.json",
    )

    assert finding.overall_risk is RiskLevel.CRITICAL
    assert finding.has_star_action is True


def test_s3_readonly_policy_produces_low_overall_risk() -> None:
    finding = extract_actions_from_policy(
        parse_fixture("s3_readonly.json"),
        "s3_readonly.json",
    )

    assert finding.overall_risk is RiskLevel.LOW


def test_mixed_policy_has_high_and_low_actions() -> None:
    finding = extract_actions_from_policy(
        parse_fixture("mixed_policy.json"),
        "mixed_policy.json",
    )

    assert {action.risk_level for action in finding.actions} == {
        RiskLevel.HIGH,
        RiskLevel.LOW,
    }


def test_deny_statements_are_not_counted_toward_risk() -> None:
    finding = extract_actions_from_policy(
        parse_fixture("mixed_policy.json"),
        "mixed_policy.json",
    )

    assert finding.has_passrole is False
    assert all(action.action != "iam:PassRole" for action in finding.actions)


def test_action_as_string_is_handled_correctly() -> None:
    finding = extract_actions_from_policy(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::example-bucket/*",
                }
            ]
        },
        "inline.json",
    )

    assert len(finding.actions) == 1
    assert finding.actions[0].action == "s3:GetObject"


def test_star_action_produces_critical_risk() -> None:
    finding = extract_actions_from_policy(
        parse_fixture("admin_policy.json"),
        "admin_policy.json",
    )

    assert finding.actions[0].action == "*"
    assert finding.actions[0].risk_level is RiskLevel.CRITICAL


def test_star_resource_with_write_actions_sets_has_star_resource() -> None:
    finding = extract_actions_from_policy(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:PutObject",
                    "Resource": "*",
                }
            ]
        },
        "inline.json",
    )

    assert finding.has_star_resource is True


def test_not_a_policy_returns_none_from_parse_policy_json_file() -> None:
    assert parse_policy_json_file(str(FIXTURE_DIR / "not_a_policy.json")) is None


def test_scan_policy_files_returns_errors_for_unparseable_files(
    tmp_path: Path,
) -> None:
    (tmp_path / "broken_policy.json").write_text("{", encoding="utf-8")

    findings, errors = scan_policy_files(str(tmp_path))

    assert findings == []
    assert len(errors) == 1


def test_scan_policy_files_ignores_unparseable_non_policy_json(
    tmp_path: Path,
) -> None:
    devcontainer_dir = tmp_path / ".devcontainer"
    devcontainer_dir.mkdir()
    (devcontainer_dir / "devcontainer.json").write_text(
        "// JSONC comments are valid for devcontainer files\n{}",
        encoding="utf-8",
    )

    findings, errors = scan_policy_files(str(tmp_path))

    assert findings == []
    assert errors == []


def test_scan_policy_files_reports_unparseable_json_in_iam_dir(
    tmp_path: Path,
) -> None:
    iam_dir = tmp_path / "iam"
    iam_dir.mkdir()
    (iam_dir / "broken.json").write_text("{", encoding="utf-8")

    findings, errors = scan_policy_files(str(tmp_path))

    assert findings == []
    assert len(errors) == 1


def test_empty_statement_list_returns_info_overall_risk() -> None:
    finding = extract_actions_from_policy({"Statement": []}, "empty.json")

    assert finding.overall_risk is RiskLevel.INFO
    assert finding.actions == []


def test_policy_with_only_deny_statements_returns_info_overall_risk() -> None:
    finding = extract_actions_from_policy(
        {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "iam:PassRole",
                    "Resource": "*",
                }
            ]
        },
        "deny.json",
    )

    assert finding.overall_risk is RiskLevel.INFO
    assert finding.has_passrole is False


def test_find_policy_json_files_returns_only_policy_fixtures() -> None:
    files = find_policy_json_files(str(FIXTURE_DIR))

    assert {Path(file).name for file in files} == {
        "admin_policy.json",
        "mixed_policy.json",
        "passrole_wildcard.json",
        "s3_readonly.json",
    }
    assert all(Path(file).is_absolute() for file in files)


def test_terraform_outputs_json_is_ignored() -> None:
    assert parse_policy_json_file(str(FIXTURE_DIR / "terraform_outputs.json")) is None


def test_scan_policy_files_finds_policies_and_ignores_non_policy_json() -> None:
    findings, errors = scan_policy_files(str(FIXTURE_DIR))

    assert {Path(finding.source_file).name for finding in findings} == {
        "admin_policy.json",
        "mixed_policy.json",
        "passrole_wildcard.json",
        "s3_readonly.json",
    }
    assert errors == []


def test_malformed_allow_statement_is_skipped_with_warning(capsys) -> None:
    finding = extract_actions_from_policy(
        {"Statement": [{"Effect": "Allow", "Action": "s3:PutObject"}]},
        "malformed.json",
    )

    assert finding.overall_risk is RiskLevel.INFO
    assert "missing Action or Resource" in capsys.readouterr().err
