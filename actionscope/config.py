"""Repository-local risk policy configuration for ActionScope."""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from actionscope.analyzers.privesc_detector import PrivescFinding
from actionscope.models import (
    AppliedSuppression,
    FindingRecord,
    HardBlockFinding,
    PolicyFinding,
    RiskLevel,
    ScanResult,
)

CONFIG_FILENAME = ".actionscope.yml"
VALID_RULE_IDS = frozenset(f"AS{number:03d}" for number in range(1, 17))
_ACTION_PATTERN = re.compile(
    r"^(?:\*|[a-z0-9][a-z0-9-]*):(?:\*|[a-z0-9_*?]+)$",
    re.IGNORECASE,
)
_PATH_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_TOP_LEVEL_KEYS = frozenset(
    {
        "version",
        "critical_actions",
        "accepted_risks",
        "hard_blocks",
        "custom_privesc_paths",
        "suppress",
        "severity_overrides",
        "deploy_job_patterns",
        "non_deploy_job_patterns",
    }
)


class ConfigError(ValueError):
    """Raised when an ActionScope configuration file is invalid."""


@dataclass(frozen=True)
class RuleSuppression:
    """A time-bounded suppression for one SARIF rule."""

    rule_id: str
    reason: str
    expires: date

    def is_active(self, today: date | None = None) -> bool:
        """Return True through the configured expiry date, inclusive."""
        return self.expires >= (today or date.today())


@dataclass(frozen=True)
class CustomPrivescPath:
    """A repository-defined IAM privilege-escalation action combination."""

    path_id: str
    name: str
    required_actions: tuple[str, ...]
    description: str
    severity: RiskLevel
    example_attack: str


@dataclass(frozen=True)
class ActionScopeConfig:
    """Validated repository-local ActionScope policy."""

    source_path: str | None = None
    critical_actions: tuple[str, ...] = ()
    accepted_risks: tuple[str, ...] = ()
    hard_blocks: tuple[str, ...] = ()
    custom_privesc_paths: tuple[CustomPrivescPath, ...] = ()
    suppressions: tuple[RuleSuppression, ...] = ()
    severity_overrides: dict[str, RiskLevel] = field(default_factory=dict)
    deploy_job_patterns: tuple[str, ...] = ()
    non_deploy_job_patterns: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def active_suppressions(self) -> tuple[RuleSuppression, ...]:
        """Return suppressions whose expiry date has not passed."""
        return tuple(item for item in self.suppressions if item.is_active())


STARTER_CONFIG = """# ActionScope repository risk policy
version: 1

# Elevate permissions that are critical for this repository.
critical_actions: []
#  - kms:Decrypt
#  - secretsmanager:GetSecretValue

# Keep accepted permissions visible, but lower their effective severity.
accepted_risks: []
#  - cloudwatch:PutMetricData

# Always fail the scan when any matching permission is observed.
hard_blocks: []
#  - iam:CreateAccessKey
#  - iam:CreateUser

# Add repository-specific action combinations.
custom_privesc_paths: []
#  - id: custom_data_exfiltration
#    name: Bedrock and S3 data exfiltration
#    required_actions:
#      - bedrock:InvokeModel
#      - s3:GetObject
#    description: Can send data read from S3 to a model endpoint.
#    severity: high
#    example_attack: Read sensitive S3 objects and include them in model prompts.

# Override a detector rule severity. Rule IDs are documented in docs/sarif.md.
severity_overrides: {}
#  AS014: low

# Calibrate GitHub Environment deploy-job detection for this repository.
deploy_job_patterns: []
#  - deploy*
#  - release*
non_deploy_job_patterns: []
#  - '*plan*'

# Suppressions are time-bounded and remain visible in human-readable reports.
suppress: []
#  - rule: AS005
#    reason: Legacy vendor key is rotated weekly while OIDC migration is underway.
#    expires: 2026-12-31
"""


def load_config(
    repo_path: str,
    config_path: str | os.PathLike[str] | None = None,
) -> ActionScopeConfig:
    """Load and validate a repository config, or return an empty policy."""
    path = _resolve_config_path(repo_path, config_path)
    if not path.exists():
        if config_path is not None:
            raise ConfigError(f"configuration file does not exist: {path}")
        return ActionScopeConfig()
    if not path.is_file():
        raise ConfigError(f"configuration path is not a file: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"could not read {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top-level configuration must be a mapping")
    unknown = sorted(set(raw) - _TOP_LEVEL_KEYS)
    if unknown:
        raise ConfigError(f"{path}: unknown key(s): {', '.join(unknown)}")
    if raw.get("version") != 1:
        raise ConfigError(f"{path}: version must be 1")

    critical_actions = _action_list(raw, "critical_actions", path)
    accepted_risks = _action_list(raw, "accepted_risks", path)
    hard_blocks = _action_list(raw, "hard_blocks", path)
    custom_paths = _custom_paths(raw.get("custom_privesc_paths"), path)
    suppressions, warnings = _suppressions(raw.get("suppress"), path)
    severity_overrides = _severity_overrides(
        raw.get("severity_overrides"), path
    )
    deploy_patterns = _string_list(raw, "deploy_job_patterns", path)
    non_deploy_patterns = _string_list(
        raw,
        "non_deploy_job_patterns",
        path,
    )

    return ActionScopeConfig(
        source_path=str(path),
        critical_actions=critical_actions,
        accepted_risks=accepted_risks,
        hard_blocks=hard_blocks,
        custom_privesc_paths=custom_paths,
        suppressions=suppressions,
        severity_overrides=severity_overrides,
        deploy_job_patterns=deploy_patterns,
        non_deploy_job_patterns=non_deploy_patterns,
        warnings=warnings,
    )


def write_starter_config(
    output_path: str | os.PathLike[str] = CONFIG_FILENAME,
    *,
    force: bool = False,
) -> Path:
    """Create a starter configuration atomically."""
    path = Path(output_path).expanduser().resolve()
    if path.exists() and not force:
        raise ConfigError(f"configuration file already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(STARTER_CONFIG, encoding="utf-8")
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise ConfigError(f"could not write {path}: {exc}") from exc
    return path


def apply_action_overrides(
    finding: PolicyFinding,
    config: ActionScopeConfig,
) -> list[HardBlockFinding]:
    """Apply IAM action severity policy and return hard-block matches."""
    hard_blocks: list[HardBlockFinding] = []
    for action in finding.actions:
        normalized = action.action.lower()
        if _matches_any(normalized, config.hard_blocks):
            action.risk_level = RiskLevel.CRITICAL
            hard_blocks.append(
                HardBlockFinding(
                    action=action.action,
                    resource=action.resource,
                    source_file=finding.source_file,
                    role_arn=finding.role_arn,
                    role_name=finding.role_name,
                )
            )
        elif _matches_any(normalized, config.critical_actions):
            action.risk_level = RiskLevel.CRITICAL
        elif _matches_any(normalized, config.accepted_risks):
            action.risk_level = RiskLevel.LOW
    return hard_blocks


def add_custom_privesc_paths(
    finding: PolicyFinding,
    config: ActionScopeConfig,
) -> None:
    """Append matching repository-defined escalation paths to a policy."""
    existing_ids = {
        str(getattr(path, "path_id", "")) for path in finding.privesc_paths
    }
    actions = [action.action.lower() for action in finding.actions]
    for path in config.custom_privesc_paths:
        if path.path_id in existing_ids:
            continue
        matched = [
            next(
                (
                    action
                    for action in actions
                    if fnmatch.fnmatchcase(action, requirement)
                ),
                None,
            )
            for requirement in path.required_actions
        ]
        if any(action is None for action in matched):
            continue
        finding.privesc_paths.append(
            PrivescFinding(
                path_id=path.path_id,
                path_name=path.name,
                description=path.description,
                example_attack=path.example_attack,
                severity=path.severity,
                matched_actions=[str(action) for action in matched],
                source_file=finding.source_file,
            )
        )
        existing_ids.add(path.path_id)


def recompute_policy_risk(finding: PolicyFinding) -> None:
    """Recompute aggregate policy risk after repository overrides."""
    risks = [action.risk_level for action in finding.actions]
    risks.extend(
        path.severity
        for path in finding.privesc_paths
        if isinstance(getattr(path, "severity", None), RiskLevel)
    )
    if risks:
        finding.overall_risk = max(risks)
    finding.has_privilege_escalation = bool(finding.privesc_paths)


def apply_result_configuration(
    result: ScanResult,
    config: ActionScopeConfig,
) -> ScanResult:
    """Apply severity overrides and suppressions to normalized findings."""
    result.config_applied = config.source_path is not None
    result.config_path = _display_config_path(config.source_path, result.scan_path)
    result.config_warnings = list(config.warnings)
    result.severity_overrides = {
        rule_id: risk.name.lower()
        for rule_id, risk in sorted(config.severity_overrides.items())
    }
    if not result.config_applied:
        return result
    if any(
        gap.gap_type == "finding_normalization_error"
        for gap in result.coverage_gaps
    ):
        result.config_warnings.append(
            "Suppressions were not applied because finding normalization failed."
        )
        return result

    active_suppressions = {
        item.rule_id: item for item in config.active_suppressions
    }
    suppression_counts = {rule_id: 0 for rule_id in active_suppressions}
    active_records: list[FindingRecord] = []
    for record in result.finding_records:
        override = config.severity_overrides.get(record.rule_id)
        configured_record = (
            replace(record, risk_level=override)
            if override and record.rule_id != "AS001"
            else record
        )
        if configured_record.rule_id in active_suppressions:
            suppression_counts[configured_record.rule_id] += 1
            continue
        active_records.append(configured_record)

    result.finding_records = active_records
    result.applied_suppressions = [
        AppliedSuppression(
            rule_id=suppression.rule_id,
            reason=suppression.reason,
            expires=suppression.expires.isoformat(),
            finding_count=suppression_counts[suppression.rule_id],
        )
        for suppression in config.active_suppressions
    ]
    effective_risks = [record.risk_level for record in active_records]
    if result.hard_block_findings:
        effective_risks.append(RiskLevel.CRITICAL)
    result.overall_risk = max(effective_risks, default=RiskLevel.INFO)
    return result


def apply_severity_overrides_to_findings(
    result: ScanResult,
    config: ActionScopeConfig,
) -> None:
    """Keep detector detail output aligned with configured rule severities."""
    overrides = config.severity_overrides
    if not overrides:
        return

    if "AS001" in overrides:
        for finding in result.policy_findings:
            for action in finding.actions:
                normalized = action.action.lower()
                if _matches_any(normalized, config.hard_blocks):
                    action.risk_level = RiskLevel.CRITICAL
                elif _matches_any(normalized, config.critical_actions):
                    action.risk_level = RiskLevel.CRITICAL
                elif _matches_any(normalized, config.accepted_risks):
                    action.risk_level = RiskLevel.LOW
                else:
                    action.risk_level = overrides["AS001"]
    if "AS002" in overrides:
        for finding in result.policy_findings:
            for path in finding.privesc_paths:
                path.severity = overrides["AS002"]

    _set_risk(result.github_token_permissions, overrides.get("AS004"))
    for finding in result.oidc_trust_findings:
        rule_id = "AS008" if finding.issue_id == "missing_sub" else "AS007"
        if rule_id in overrides:
            finding.risk_level = overrides[rule_id]
    _set_risk(result.script_injection_findings, overrides.get("AS009"))
    _set_risk(result.artifact_poisoning_findings, overrides.get("AS010"))
    for finding in result.ai_agent_injection_findings:
        rule_id = "AS012" if finding.has_aws_secret_access else "AS011"
        if rule_id in overrides:
            finding.risk_level = overrides[rule_id]
    _set_risk(result.compromised_action_findings, overrides.get("AS013"))
    _set_risk(result.environment_findings, overrides.get("AS014"))
    _set_risk(result.exposure_paths, overrides.get("AS016"))
    for finding in result.policy_findings:
        recompute_policy_risk(finding)


def suppressed_rule_ids(result: ScanResult) -> set[str]:
    """Return rule IDs suppressed from gates and machine-readable alerts."""
    return {item.rule_id for item in result.applied_suppressions}


def _resolve_config_path(
    repo_path: str,
    config_path: str | os.PathLike[str] | None,
) -> Path:
    if config_path is None:
        scan_path = Path(repo_path).resolve()
        if scan_path.is_file():
            for parent in (scan_path.parent, *scan_path.parents):
                if (parent / ".git").exists():
                    return parent / CONFIG_FILENAME
            return scan_path.parent / CONFIG_FILENAME
        return scan_path / CONFIG_FILENAME
    path = Path(config_path).expanduser()
    return path.resolve()


def _display_config_path(source_path: str | None, scan_path: str) -> str | None:
    if source_path is None:
        return None
    path = Path(source_path)
    try:
        return path.resolve().relative_to(Path(scan_path).resolve()).as_posix()
    except (OSError, ValueError):
        return path.name


def _action_list(raw: dict[str, Any], key: str, path: Path) -> tuple[str, ...]:
    values = _string_list(raw, key, path)
    normalized: list[str] = []
    for value in values:
        lowered = value.lower()
        if not _ACTION_PATTERN.fullmatch(lowered):
            raise ConfigError(
                f"{path}: {key} contains invalid IAM action pattern {value!r}"
            )
        if lowered not in normalized:
            normalized.append(lowered)
    return tuple(normalized)


def _string_list(
    raw: dict[str, Any],
    key: str,
    path: Path,
) -> tuple[str, ...]:
    value = raw.get(key, [])
    if value is None:
        return ()
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ConfigError(f"{path}: {key} must be a list of non-empty strings")
    return tuple(dict.fromkeys(item.strip() for item in value))


def _custom_paths(value: object, path: Path) -> tuple[CustomPrivescPath, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError(f"{path}: custom_privesc_paths must be a list")
    parsed: list[CustomPrivescPath] = []
    seen: set[str] = set()
    allowed = {
        "id",
        "name",
        "required_actions",
        "description",
        "severity",
        "example_attack",
    }
    for index, item in enumerate(value):
        label = f"{path}: custom_privesc_paths[{index}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{label} must be a mapping")
        unknown = sorted(set(item) - allowed)
        if unknown:
            raise ConfigError(f"{label} has unknown key(s): {', '.join(unknown)}")
        path_id = _required_string(item, "id", label).lower()
        if not _PATH_ID_PATTERN.fullmatch(path_id):
            raise ConfigError(f"{label}.id must use lowercase letters, digits, _ or -")
        if path_id in seen:
            raise ConfigError(f"{label}.id duplicates {path_id!r}")
        seen.add(path_id)
        requirements = _required_action_values(item, label)
        severity = _risk_level(item.get("severity"), f"{label}.severity")
        parsed.append(
            CustomPrivescPath(
                path_id=path_id,
                name=_required_string(item, "name", label),
                required_actions=requirements,
                description=_required_string(item, "description", label),
                severity=severity,
                example_attack=str(
                    item.get("example_attack")
                    or (
                        "Combine the configured IAM actions to exceed the "
                        "intended role scope."
                    )
                ).strip(),
            )
        )
    return tuple(parsed)


def _required_action_values(
    item: dict[str, Any],
    label: str,
) -> tuple[str, ...]:
    value = item.get("required_actions")
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{label}.required_actions must be a non-empty list")
    normalized: list[str] = []
    for action in value:
        if not isinstance(action, str) or not _ACTION_PATTERN.fullmatch(action):
            raise ConfigError(
                f"{label}.required_actions contains invalid pattern {action!r}"
            )
        lowered = action.lower()
        if lowered not in normalized:
            normalized.append(lowered)
    return tuple(normalized)


def _suppressions(
    value: object,
    path: Path,
) -> tuple[tuple[RuleSuppression, ...], tuple[str, ...]]:
    if value is None:
        return (), ()
    if not isinstance(value, list):
        raise ConfigError(f"{path}: suppress must be a list")
    parsed: list[RuleSuppression] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        label = f"{path}: suppress[{index}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{label} must be a mapping")
        unknown = sorted(set(item) - {"rule", "reason", "expires"})
        if unknown:
            raise ConfigError(f"{label} has unknown key(s): {', '.join(unknown)}")
        rule_id = _required_string(item, "rule", label).upper()
        if rule_id not in VALID_RULE_IDS:
            raise ConfigError(f"{label}.rule is not a known rule ID: {rule_id}")
        if rule_id in seen:
            raise ConfigError(f"{label}.rule duplicates {rule_id}")
        seen.add(rule_id)
        expiry = _expiry_date(item.get("expires"), f"{label}.expires")
        suppression = RuleSuppression(
            rule_id=rule_id,
            reason=_required_string(item, "reason", label),
            expires=expiry,
        )
        parsed.append(suppression)
        if not suppression.is_active():
            warnings.append(
                f"Suppression {rule_id} expired on {expiry.isoformat()} and "
                "was not applied."
            )
    return tuple(parsed), tuple(warnings)


def _severity_overrides(value: object, path: Path) -> dict[str, RiskLevel]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{path}: severity_overrides must be a mapping")
    parsed: dict[str, RiskLevel] = {}
    for key, raw_risk in value.items():
        rule_id = str(key).upper()
        if rule_id not in VALID_RULE_IDS:
            raise ConfigError(
                f"{path}: severity_overrides has unknown rule ID {rule_id}"
            )
        parsed[rule_id] = _risk_level(
            raw_risk,
            f"{path}: severity_overrides.{rule_id}",
        )
    return parsed


def _risk_level(value: object, label: str) -> RiskLevel:
    if not isinstance(value, str):
        raise ConfigError(f"{label} must be critical, high, medium, low, or info")
    try:
        return RiskLevel(value.strip().lower())
    except ValueError as exc:
        raise ConfigError(
            f"{label} must be critical, high, medium, low, or info"
        ) from exc


def _expiry_date(value: object, label: str) -> date:
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise ConfigError(f"{label} must use YYYY-MM-DD") from exc
    raise ConfigError(f"{label} is required and must use YYYY-MM-DD")


def _required_string(item: dict[str, Any], key: str, label: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label}.{key} must be a non-empty string")
    return value.strip()


def _matches_any(action: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(action, pattern) for pattern in patterns)


def _set_risk(findings: list, risk: RiskLevel | None) -> None:
    if risk is None:
        return
    for finding in findings:
        finding.risk_level = risk
