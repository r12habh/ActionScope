"""Correlate workflow supply-chain findings with reachable AWS credentials."""

from __future__ import annotations

from actionscope.models import (
    CompromisedActionFinding,
    ExposurePath,
    RiskLevel,
    UnpinnedActionFinding,
    WorkflowCredentialBinding,
)

MAX_REACHABLE_ACTIONS = 5


def build_exposure_paths(
    bindings: list[WorkflowCredentialBinding],
    unpinned_actions: list[UnpinnedActionFinding],
    compromised_actions: list[CompromisedActionFinding],
) -> list[ExposurePath]:
    """Connect risky actions to AWS credentials configured in the same job."""
    paths: list[ExposurePath] = []
    seen: set[tuple[str, str, str, str, str | None]] = set()
    compromised_steps = {
        (
            finding.workflow_file,
            finding.job_name,
            finding.step_name,
            finding.uses_ref,
        )
        for finding in compromised_actions
    }

    for finding in compromised_actions:
        for binding in _matching_bindings(
            bindings,
            finding.workflow_file,
            finding.job_name,
        ):
            _append_path(
                paths,
                seen,
                binding,
                action_kind="known_compromised",
                action_ref=finding.uses_ref,
                action_step=finding.step_name,
                source_risk=finding.risk_level,
            )

    for finding in unpinned_actions:
        duplicate_key = (
            finding.workflow_file,
            finding.job_name,
            finding.step_name,
            finding.uses,
        )
        if duplicate_key in compromised_steps:
            continue
        for binding in _matching_bindings(
            bindings,
            finding.workflow_file,
            finding.job_name,
        ):
            _append_path(
                paths,
                seen,
                binding,
                action_kind="unpinned",
                action_ref=finding.uses,
                action_step=finding.step_name,
                source_risk=RiskLevel.HIGH,
            )

    return paths


def _matching_bindings(
    bindings: list[WorkflowCredentialBinding],
    workflow_file: str,
    job_name: str,
) -> list[WorkflowCredentialBinding]:
    return [
        binding
        for binding in bindings
        if binding.credential_source.workflow_file == workflow_file
        and binding.credential_source.job_name == job_name
    ]


def _append_path(
    paths: list[ExposurePath],
    seen: set[tuple[str, str, str, str, str | None]],
    binding: WorkflowCredentialBinding,
    *,
    action_kind: str,
    action_ref: str,
    action_step: str,
    source_risk: RiskLevel,
) -> None:
    source = binding.credential_source
    key = (
        source.workflow_file,
        source.job_name,
        action_kind,
        action_ref,
        source.role_arn,
    )
    if key in seen:
        return
    seen.add(key)

    policy = binding.policy_finding
    policy_risk = policy.overall_risk if policy else RiskLevel.INFO
    auth_type = (
        "oidc"
        if source.uses_oidc
        else "access_keys"
        if source.uses_access_keys
        else "unknown"
    )
    paths.append(
        ExposurePath(
            workflow_file=source.workflow_file,
            job_name=source.job_name,
            action_kind=action_kind,
            action_ref=action_ref,
            action_step=action_step,
            credential_step=source.step_name,
            role_arn=source.role_arn,
            auth_type=auth_type,
            policy_source=binding.policy_source,
            policy_source_file=(
                policy.source_file
                if policy and binding.policy_source != "aws_verified"
                else None
            ),
            match_confidence=binding.match_confidence,
            reachable_actions=_top_reachable_actions(binding),
            has_privilege_escalation=(
                policy.has_privilege_escalation if policy else False
            ),
            risk_level=max(source_risk, policy_risk),
        )
    )


def _top_reachable_actions(
    binding: WorkflowCredentialBinding,
) -> list[str]:
    policy = binding.policy_finding
    if policy is None:
        return []

    ordered = sorted(
        (
            action
            for action in policy.actions
            if action.risk_level >= RiskLevel.HIGH
        ),
        key=lambda action: (-action.risk_level.value, action.action.lower()),
    )
    unique: list[str] = []
    for action in ordered:
        if action.action not in unique:
            unique.append(action.action)
        if len(unique) == MAX_REACHABLE_ACTIONS:
            break
    return unique
