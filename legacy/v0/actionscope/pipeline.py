"""Static scan pipeline shared by the ``scan`` and ``corpus`` commands.

The pipeline is split in two so callers can insert steps between evidence
collection and correlation (``scan --aws-verify`` replaces policy findings with
live IAM evidence there).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from actionscope.analyzers.reusable_workflows import (
    ReusableWorkflowScan,
    scan_reusable_workflows,
)
from actionscope.analyzers.risk_engine import (
    build_scan_result,
    finalize_scan_metadata,
)
from actionscope.config import ActionScopeConfig
from actionscope.models import (
    AwsCredentialSource,
    GitHubTokenPermission,
    PolicyFinding,
    ScanResult,
    UnpinnedActionFinding,
)
from actionscope.parsers.cloudformation import scan_cloudformation_files
from actionscope.parsers.policy_json import scan_policy_files
from actionscope.parsers.terraform import scan_terraform_files
from actionscope.parsers.workflow import scan_workflows


@dataclass
class StaticEvidence:
    """Workflow and repository-local IAM evidence collected for one path."""

    credential_sources: list[AwsCredentialSource] = field(default_factory=list)
    github_token_permissions: list[GitHubTokenPermission] = field(
        default_factory=list
    )
    unpinned_actions: list[UnpinnedActionFinding] = field(default_factory=list)
    policy_findings: list[PolicyFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    reusable_scan: ReusableWorkflowScan = field(
        default_factory=ReusableWorkflowScan
    )


def collect_static_evidence(
    repo_path: str,
    *,
    github_token: str | None = None,
    offline: bool = False,
    max_policy_files: int | None = None,
) -> StaticEvidence:
    """Run every static parser over ``repo_path``.

    Each parser is isolated: a failure in one is recorded as an error and the
    remaining parsers still run.
    """
    try:
        (
            credential_sources,
            github_token_perms,
            unpinned_actions,
            workflow_errors,
        ) = scan_workflows(repo_path)
    except Exception as exc:
        credential_sources, github_token_perms, unpinned_actions = [], [], []
        workflow_errors = [f"Fatal error scanning workflows: {exc}"]

    try:
        reusable_scan = scan_reusable_workflows(
            repo_path,
            github_token=None if offline else github_token,
            offline=offline,
        )
    except Exception as exc:
        reusable_scan = ReusableWorkflowScan(
            errors=[f"Fatal error scanning reusable workflows: {exc}"]
        )

    credential_sources.extend(reusable_scan.credential_sources)
    github_token_perms.extend(reusable_scan.github_token_permissions)
    unpinned_actions.extend(reusable_scan.unpinned_actions)
    workflow_errors.extend(reusable_scan.errors)

    try:
        # None means "use scan_policy_files' built-in default cap".
        if max_policy_files is None:
            json_findings, json_errors = scan_policy_files(repo_path)
        else:
            json_findings, json_errors = scan_policy_files(
                repo_path, max_other_files=max_policy_files
            )
    except Exception as exc:
        json_findings, json_errors = [], [str(exc)]

    try:
        tf_findings, tf_errors = scan_terraform_files(repo_path)
    except Exception as exc:
        tf_findings, tf_errors = [], [str(exc)]

    try:
        cloudformation_findings, cloudformation_errors = (
            scan_cloudformation_files(repo_path)
        )
    except Exception as exc:
        cloudformation_findings, cloudformation_errors = [], [str(exc)]

    return StaticEvidence(
        credential_sources=credential_sources,
        github_token_permissions=github_token_perms,
        unpinned_actions=unpinned_actions,
        policy_findings=json_findings + tf_findings + cloudformation_findings,
        errors=workflow_errors + json_errors + tf_errors + cloudformation_errors,
        reusable_scan=reusable_scan,
    )


def correlate_evidence(
    repo_path: str,
    evidence: StaticEvidence,
    *,
    offline: bool = False,
    config: ActionScopeConfig | None = None,
) -> ScanResult:
    """Correlate collected evidence into a finalized :class:`ScanResult`."""
    try:
        return build_scan_result(
            repo_path=repo_path,
            credential_sources=evidence.credential_sources,
            github_token_perms=evidence.github_token_permissions,
            policy_findings=evidence.policy_findings,
            unpinned_actions=evidence.unpinned_actions,
            errors=evidence.errors,
            reusable_scan=evidence.reusable_scan,
            offline=offline,
            config=config,
        )
    except Exception as exc:
        result = ScanResult(
            scan_path=repo_path,
            workflow_count=0,
            credential_sources=evidence.credential_sources,
            github_token_permissions=evidence.github_token_permissions,
            unpinned_actions=evidence.unpinned_actions,
            policy_findings=evidence.policy_findings,
            errors=evidence.errors
            + [f"Could not correlate scan results: {exc}"],
        )
        finalize_scan_metadata(result, config=config)
        return result
