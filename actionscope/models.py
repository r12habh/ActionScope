"""Dataclass models for ActionScope scan inputs, findings, and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(Enum):
    """Ordered risk levels used throughout ActionScope findings."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def _missing_(cls, value: object) -> "RiskLevel | None":
        if isinstance(value, str):
            normalized = value.lower()
            for member in cls:
                if member.name.lower() == normalized:
                    return member
        return None

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.value < other.value

    def __le__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.value <= other.value

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.value > other.value

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.value >= other.value


VALID_POLICY_SOURCE_TYPES = frozenset(
    {
        "workflow",
        "terraform",
        "json_policy",
        "aws_verified",
    }
)


@dataclass
class IamAction:
    """An AWS IAM action discovered in a workflow or policy document."""

    action: str
    access_level: str
    risk_level: RiskLevel
    description: str
    resource: str


@dataclass
class AwsCredentialSource:
    """A source of AWS credentials configured inside a GitHub Actions workflow."""

    workflow_file: str
    job_name: str
    step_name: str
    role_arn: Optional[str]
    uses_access_keys: bool
    uses_oidc: bool
    aws_region: Optional[str]


@dataclass
class GitHubTokenPermission:
    """A workflow-level or job-level GITHUB_TOKEN permission."""

    workflow_file: str
    job_name: str
    scope: str
    access: str
    risk_level: RiskLevel


@dataclass
class UnpinnedActionFinding:
    """A GitHub Actions step that references an external action without a SHA."""

    workflow_file: str
    job_name: str
    step_name: str
    uses: str
    pin_type: str


@dataclass
class PolicyFinding:
    """IAM policy analysis results from a supported policy source."""

    source_file: str
    source_type: str
    role_arn: Optional[str]
    actions: list[IamAction] = field(default_factory=list)
    has_star_action: bool = False
    has_star_resource: bool = False
    has_passrole: bool = False
    has_privilege_escalation: bool = False
    overall_risk: RiskLevel = RiskLevel.INFO
    privesc_paths: list = field(default_factory=list)


@dataclass
class WorkflowCredentialBinding:
    """Links a workflow's AwsCredentialSource to its PolicyFinding."""

    credential_source: AwsCredentialSource
    policy_finding: Optional[PolicyFinding]
    policy_source: str


@dataclass
class ScanResult:
    """Aggregate result for a single ActionScope scan."""

    scan_path: str = "."
    workflow_count: int = 0
    credential_sources: list[AwsCredentialSource] = field(default_factory=list)
    github_token_permissions: list[GitHubTokenPermission] = field(
        default_factory=list
    )
    unpinned_actions: list[UnpinnedActionFinding] = field(default_factory=list)
    policy_findings: list[PolicyFinding] = field(default_factory=list)
    bindings: list[WorkflowCredentialBinding] = field(default_factory=list)
    overall_risk: RiskLevel = RiskLevel.INFO
    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Compute the scan risk from bindings and GITHUB_TOKEN permissions."""
        binding_risks = [
            binding.policy_finding.overall_risk
            for binding in self.bindings
            if binding.policy_finding is not None
        ]
        token_risks = [
            permission.risk_level for permission in self.github_token_permissions
        ]
        self.overall_risk = max(binding_risks + token_risks, default=RiskLevel.INFO)

    def has_critical_findings(self) -> bool:
        """Return True when any finding reaches critical severity."""
        return bool(self.findings_by_risk(RiskLevel.CRITICAL))

    def findings_by_risk(self, level: RiskLevel) -> list:
        """Return policy and GitHub token findings matching a risk level."""
        findings: list[object] = []
        seen_policy_ids: set[int] = set()

        for finding in self.policy_findings:
            if finding.overall_risk == level:
                findings.append(finding)
                seen_policy_ids.add(id(finding))

        for binding in self.bindings:
            finding = binding.policy_finding
            if (
                finding is not None
                and finding.overall_risk == level
                and id(finding) not in seen_policy_ids
            ):
                findings.append(finding)
                seen_policy_ids.add(id(finding))

        findings.extend(
            permission
            for permission in self.github_token_permissions
            if permission.risk_level == level
        )
        return findings


def get_unmatched_findings(
    bindings: list[WorkflowCredentialBinding],
    all_findings: list[PolicyFinding],
) -> list[PolicyFinding]:
    """Return policy findings that are not referenced by any binding."""
    matched_ids = {
        id(binding.policy_finding)
        for binding in bindings
        if binding.policy_finding is not None
    }

    return [
        finding
        for finding in all_findings
        if id(finding) not in matched_ids
    ]
