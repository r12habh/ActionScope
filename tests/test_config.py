"""Tests for repository-local ActionScope risk policy configuration."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from click.testing import CliRunner

from actionscope.cli import main
from actionscope.config import (
    ActionScopeConfig,
    ConfigError,
    CustomPrivescPath,
    RuleSuppression,
    add_custom_privesc_paths,
    apply_action_overrides,
    apply_result_configuration,
    load_config,
    recompute_policy_risk,
    write_starter_config,
)
from actionscope.gating import evaluate_gate
from actionscope.models import (
    CoverageGap,
    FindingConfidence,
    FindingRecord,
    IamAction,
    PolicyFinding,
    RiskLevel,
    ScanResult,
)
from actionscope.reporters.sarif import to_sarif_from_dict


def _write_config(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def _action(name: str, risk: RiskLevel = RiskLevel.MEDIUM) -> IamAction:
    return IamAction(
        action=name,
        access_level="Write",
        risk_level=risk,
        description="test action",
        resource="*",
    )


def _record(rule_id: str, risk: RiskLevel) -> FindingRecord:
    return FindingRecord(
        fingerprint=f"fingerprint-{rule_id}",
        rule_id=rule_id,
        risk_level=risk,
        confidence=FindingConfidence.HIGH,
        title=f"Finding for {rule_id}",
    )


def test_load_config_returns_empty_policy_when_default_file_is_absent(
    tmp_path: Path,
) -> None:
    config = load_config(str(tmp_path))

    assert config.source_path is None
    assert config.critical_actions == ()


def test_load_config_finds_repo_policy_when_scanning_one_workflow(
    tmp_path: Path,
) -> None:
    (tmp_path / ".git").mkdir()
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("on: push\njobs: {}\n", encoding="utf-8")
    _write_config(
        tmp_path / ".actionscope.yml",
        "version: 1\nhard_blocks: [iam:CreateUser]\n",
    )

    config = load_config(str(workflow))

    assert config.hard_blocks == ("iam:createuser",)


def test_load_config_parses_all_supported_policy_sections(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path / ".actionscope.yml",
        """
version: 1
critical_actions: [kms:Decrypt]
accepted_risks: [cloudwatch:PutMetricData]
hard_blocks: [iam:CreateUser]
custom_privesc_paths:
  - id: custom_path
    name: Custom path
    required_actions: [s3:GetObject, kms:Decrypt]
    description: Reads and decrypts protected data.
    severity: high
severity_overrides:
  AS014: low
deploy_job_patterns: [ship-*]
non_deploy_job_patterns: ['*plan*']
suppress:
  - rule: AS006
    reason: Renovate updates this reference daily.
    expires: 2099-12-31
""",
    )

    config = load_config(str(tmp_path), config_path)

    assert config.critical_actions == ("kms:decrypt",)
    assert config.accepted_risks == ("cloudwatch:putmetricdata",)
    assert config.hard_blocks == ("iam:createuser",)
    assert config.custom_privesc_paths[0].path_id == "custom_path"
    assert config.severity_overrides == {"AS014": RiskLevel.LOW}
    assert config.deploy_job_patterns == ("ship-*",)
    assert config.non_deploy_job_patterns == ("*plan*",)
    assert config.active_suppressions[0].rule_id == "AS006"


@pytest.mark.parametrize(
    "body, expected",
    [
        ("version: 2\n", "version must be 1"),
        ("version: 1\nunknown: true\n", "unknown key"),
        (
            "version: 1\nsuppress:\n"
            "  - rule: AS006\n"
            "    reason: test\n"
            "    expires: soon\n",
            "YYYY-MM-DD",
        ),
        ("version: 1\nhard_blocks: [not-an-action]\n", "invalid IAM action"),
    ],
)
def test_load_config_rejects_invalid_configuration(
    tmp_path: Path,
    body: str,
    expected: str,
) -> None:
    config_path = _write_config(tmp_path / ".actionscope.yml", body)

    with pytest.raises(ConfigError, match=expected):
        load_config(str(tmp_path), config_path)


def test_expired_suppression_is_not_active_and_emits_warning(
    tmp_path: Path,
) -> None:
    config_path = _write_config(
        tmp_path / ".actionscope.yml",
        """
version: 1
suppress:
  - rule: AS006
    reason: Temporary migration exception.
    expires: 2000-01-01
""",
    )

    config = load_config(str(tmp_path), config_path)

    assert config.active_suppressions == ()
    assert "expired" in config.warnings[0]


def test_write_starter_config_round_trips_through_validator(tmp_path: Path) -> None:
    output = write_starter_config(tmp_path / ".actionscope.yml")

    config = load_config(str(tmp_path), output)

    assert config.source_path == str(output)
    assert config.hard_blocks == ()
    assert config.suppressions == ()


def test_write_starter_config_refuses_to_replace_existing_file(
    tmp_path: Path,
) -> None:
    output = tmp_path / ".actionscope.yml"
    output.write_text("version: 1\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="already exists"):
        write_starter_config(output)


def test_action_override_precedence_is_hard_block_then_critical_then_accepted(
) -> None:
    finding = PolicyFinding(
        source_file="iam.json",
        source_type="json_policy",
        role_arn=None,
        actions=[
            _action("iam:CreateUser", RiskLevel.LOW),
            _action("kms:Decrypt", RiskLevel.MEDIUM),
            _action("cloudwatch:PutMetricData", RiskLevel.MEDIUM),
        ],
    )
    config = ActionScopeConfig(
        source_path=".actionscope.yml",
        critical_actions=("kms:decrypt",),
        accepted_risks=("cloudwatch:putmetricdata", "iam:createuser"),
        hard_blocks=("iam:createuser",),
    )

    hard_blocks = apply_action_overrides(finding, config)
    recompute_policy_risk(finding)

    assert [action.risk_level for action in finding.actions] == [
        RiskLevel.CRITICAL,
        RiskLevel.CRITICAL,
        RiskLevel.LOW,
    ]
    assert hard_blocks[0].action == "iam:CreateUser"
    assert finding.overall_risk is RiskLevel.CRITICAL


def test_custom_privesc_path_is_added_when_all_actions_match() -> None:
    finding = PolicyFinding(
        source_file="iam.json",
        source_type="json_policy",
        role_arn=None,
        actions=[_action("s3:GetObject"), _action("kms:Decrypt")],
    )
    config = ActionScopeConfig(
        source_path=".actionscope.yml",
        custom_privesc_paths=(
            CustomPrivescPath(
                path_id="decrypt_s3",
                name="Decrypt S3 data",
                required_actions=("s3:getobject", "kms:decrypt"),
                description="Can read and decrypt protected objects.",
                severity=RiskLevel.HIGH,
                example_attack="Read encrypted objects and decrypt them.",
            ),
        ),
    )

    add_custom_privesc_paths(finding, config)
    recompute_policy_risk(finding)

    assert finding.privesc_paths[0].path_id == "decrypt_s3"
    assert finding.has_privilege_escalation is True
    assert finding.overall_risk is RiskLevel.HIGH


def test_result_configuration_suppresses_rule_and_overrides_severity() -> None:
    config = ActionScopeConfig(
        source_path=".actionscope.yml",
        suppressions=(
            RuleSuppression(
                rule_id="AS006",
                reason="Automated pin updates are enabled.",
                expires=date(2099, 12, 31),
            ),
        ),
        severity_overrides={"AS014": RiskLevel.LOW},
    )
    result = ScanResult(
        finding_records=[
            _record("AS006", RiskLevel.MEDIUM),
            _record("AS014", RiskLevel.MEDIUM),
        ]
    )

    apply_result_configuration(result, config)

    assert [record.rule_id for record in result.finding_records] == ["AS014"]
    assert result.finding_records[0].risk_level is RiskLevel.LOW
    assert result.applied_suppressions[0].finding_count == 1
    assert result.overall_risk is RiskLevel.LOW


def test_configuration_does_not_hide_normalization_failure() -> None:
    config = ActionScopeConfig(
        source_path=".actionscope.yml",
        suppressions=(
            RuleSuppression(
                rule_id="AS006",
                reason="Temporary exception.",
                expires=date(2099, 12, 31),
            ),
        ),
    )
    result = ScanResult(overall_risk=RiskLevel.HIGH)
    result.overall_risk = RiskLevel.HIGH
    result.coverage_status = "partial"
    result.coverage_gaps = [
        CoverageGap(
            gap_type="finding_normalization_error",
            description="normalizer failed",
        )
    ]

    apply_result_configuration(result, config)
    decision = evaluate_gate(
        result,
        "high",
        minimum_confidence="high",
    )

    assert result.overall_risk is RiskLevel.HIGH
    assert result.applied_suppressions == []
    assert decision.status == "not_evaluated"
    assert decision.exit_code == 2


def test_cli_config_init_creates_valid_starter_file(tmp_path: Path) -> None:
    output = tmp_path / "policy.yml"

    result = CliRunner().invoke(
        main,
        ["config", "init", "--output", str(output)],
    )

    assert result.exit_code == 0
    assert output.exists()
    assert load_config(str(tmp_path), output).source_path == str(output)


def test_cli_hard_block_fails_without_fail_on(
    cli_repo_critical: Path,
) -> None:
    _write_config(
        cli_repo_critical / ".actionscope.yml",
        "version: 1\nhard_blocks: [iam:PassRole]\n",
    )

    result = CliRunner().invoke(
        main,
        ["scan", str(cli_repo_critical), "--output-format", "json"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["gate"]["mode"] == "hard_block"
    assert payload["hard_block_findings"][0]["action"].lower() == "iam:passrole"


def test_cli_suppression_prevents_gate_and_sarif_alert(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        """
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
        encoding="utf-8",
    )
    _write_config(
        tmp_path / ".actionscope.yml",
        """
version: 1
suppress:
  - rule: AS006
    reason: Renovate updates action pins daily.
    expires: 2099-12-31
""",
    )

    gate_result = CliRunner().invoke(
        main,
        [
            "scan",
            str(tmp_path),
            "--fail-on",
            "medium",
            "--min-confidence",
            "high",
        ],
    )
    json_result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--output-format", "json"],
    )
    sarif_result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--output-format", "sarif"],
    )

    assert gate_result.exit_code == 0
    assert "Suppressed from CI gates and SARIF" in gate_result.output
    payload = json.loads(json_result.stdout)
    assert payload["finding_records"] == []
    report_path = tmp_path / "scan.json"
    report_path.write_text(json_result.stdout, encoding="utf-8")
    saved_gate = CliRunner().invoke(
        main,
        [
            "gate",
            str(report_path),
            "--fail-on",
            "medium",
            "--min-confidence",
            "high",
        ],
    )
    assert saved_gate.exit_code == 0
    sarif = json.loads(sarif_result.stdout)
    assert all(
        finding["ruleId"] != "AS006"
        for finding in sarif["runs"][0]["results"]
    )


def test_cli_explicit_missing_config_fails_cleanly(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--config", str(tmp_path / "missing.yml")],
    )

    assert result.exit_code != 0
    assert "configuration file does not exist" in result.output


def test_saved_json_sarif_renderer_honors_suppressions() -> None:
    payload = {
        "scan_path": ".",
        "unpinned_actions": [
            {
                "uses": "actions/checkout@v4",
                "workflow_file": ".github/workflows/ci.yml",
                "job_name": "test",
                "pin_type": "tag",
            }
        ],
        "configuration": {
            "applied": True,
            "severity_overrides": {},
        },
        "applied_suppressions": [
            {
                "rule_id": "AS006",
                "reason": "Automated pinning is enabled.",
                "expires": "2099-12-31",
                "finding_count": 1,
            }
        ],
    }

    sarif = json.loads(to_sarif_from_dict(payload))

    assert sarif["runs"][0]["results"] == []
