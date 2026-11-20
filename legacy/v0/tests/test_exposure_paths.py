"""Tests for same-job supply-chain to AWS exposure correlation."""

from __future__ import annotations

from actionscope.analyzers.exposure_paths import build_exposure_paths
from actionscope.analyzers.risk_engine import build_scan_result
from actionscope.models import (
    AwsCredentialSource,
    CompromisedActionFinding,
    IamAction,
    PolicyFinding,
    RiskLevel,
    UnpinnedActionFinding,
    WorkflowCredentialBinding,
)

WORKFLOW = ".github/workflows/deploy.yml"
ROLE_ARN = "arn:aws:iam::123456789012:role/github-deploy"


def _credential(job_name: str = "deploy") -> AwsCredentialSource:
    return AwsCredentialSource(
        workflow_file=WORKFLOW,
        job_name=job_name,
        step_name="Configure AWS credentials",
        role_arn=ROLE_ARN,
        uses_access_keys=False,
        uses_oidc=True,
        aws_region="us-east-1",
    )


def _policy(risk: RiskLevel = RiskLevel.CRITICAL) -> PolicyFinding:
    return PolicyFinding(
        source_file="terraform/deploy-role.tf",
        source_type="terraform",
        role_arn=ROLE_ARN,
        actions=[
            IamAction(
                action="iam:PassRole",
                access_level="Permissions management",
                risk_level=RiskLevel.CRITICAL,
                description="Pass a role",
                resource="*",
            ),
            IamAction(
                action="s3:PutObject",
                access_level="Write",
                risk_level=RiskLevel.HIGH,
                description="Write objects",
                resource="*",
            ),
            IamAction(
                action="s3:GetObject",
                access_level="Read",
                risk_level=RiskLevel.LOW,
                description="Read objects",
                resource="*",
            ),
        ],
        has_passrole=True,
        has_privilege_escalation=True,
        overall_risk=risk,
    )


def _binding(
    job_name: str = "deploy",
    policy: PolicyFinding | None = None,
) -> WorkflowCredentialBinding:
    return WorkflowCredentialBinding(
        credential_source=_credential(job_name),
        policy_finding=policy,
        policy_source="terraform" if policy else "not_found",
        match_confidence="high" if policy else "none",
        match_reason="exact role ARN match" if policy else "no matching policy",
    )


def _unpinned(job_name: str = "deploy") -> UnpinnedActionFinding:
    return UnpinnedActionFinding(
        workflow_file=WORKFLOW,
        job_name=job_name,
        step_name="Deploy helper",
        uses="third-party/deploy-action@v1",
        pin_type="tag",
    )


def _compromised() -> CompromisedActionFinding:
    return CompromisedActionFinding(
        workflow_file=WORKFLOW,
        job_name="deploy",
        step_name="Deploy helper",
        uses_ref="third-party/deploy-action@v1",
        action_name="third-party/deploy-action",
        ref="v1",
        is_sha_pinned=False,
        compromise_date="2026-05-18",
        advisory_url="https://example.com/advisory",
        description="Documented compromise",
        risk_level=RiskLevel.CRITICAL,
    )


def test_unpinned_action_and_aws_binding_produce_exposure_path() -> None:
    paths = build_exposure_paths([_binding(policy=_policy())], [_unpinned()], [])

    assert len(paths) == 1
    assert paths[0].action_kind == "unpinned"
    assert paths[0].role_arn == ROLE_ARN
    assert paths[0].risk_level is RiskLevel.CRITICAL
    assert paths[0].reachable_actions == ["iam:PassRole", "s3:PutObject"]
    assert paths[0].has_privilege_escalation is True


def test_findings_in_different_jobs_do_not_form_path() -> None:
    paths = build_exposure_paths(
        [_binding(job_name="deploy", policy=_policy())],
        [_unpinned(job_name="test")],
        [],
    )

    assert paths == []


def test_unpinned_action_without_aws_binding_does_not_form_path() -> None:
    assert build_exposure_paths([], [_unpinned()], []) == []


def test_compromised_action_takes_precedence_over_unpinned_duplicate() -> None:
    paths = build_exposure_paths(
        [_binding(policy=_policy())],
        [_unpinned()],
        [_compromised()],
    )

    assert len(paths) == 1
    assert paths[0].action_kind == "known_compromised"
    assert paths[0].risk_level is RiskLevel.CRITICAL


def test_missing_policy_keeps_unknown_blast_radius_explicit() -> None:
    paths = build_exposure_paths([_binding()], [_unpinned()], [])

    assert len(paths) == 1
    assert paths[0].policy_source == "not_found"
    assert paths[0].policy_source_file is None
    assert paths[0].reachable_actions == []
    assert paths[0].risk_level is RiskLevel.HIGH


def test_aws_verified_policy_has_no_local_related_location() -> None:
    policy = _policy()
    policy.source_type = "aws_verified"
    binding = WorkflowCredentialBinding(
        credential_source=_credential(),
        policy_finding=policy,
        policy_source="aws_verified",
        match_confidence="high",
    )

    path = build_exposure_paths([binding], [_unpinned()], [])[0]

    assert path.policy_source == "aws_verified"
    assert path.policy_source_file is None
    assert path.reachable_actions == ["iam:PassRole", "s3:PutObject"]


def test_reachable_actions_are_limited_and_sorted_by_risk() -> None:
    policy = _policy()
    policy.actions.extend(
        IamAction(
            action=f"service:HighAction{index}",
            access_level="Write",
            risk_level=RiskLevel.HIGH,
            description="High impact",
            resource="*",
        )
        for index in range(10)
    )

    path = build_exposure_paths([_binding(policy=policy)], [_unpinned()], [])[0]

    assert len(path.reachable_actions) == 5
    assert path.reachable_actions[0] == "iam:PassRole"


def test_external_reusable_workflow_findings_correlate_by_exact_source() -> None:
    source = _credential()
    source.workflow_file = "acme/platform/.github/workflows/deploy.yml@v1"
    binding = WorkflowCredentialBinding(source, _policy(), "terraform")
    finding = _unpinned()
    finding.workflow_file = source.workflow_file

    paths = build_exposure_paths([binding], [finding], [])

    assert len(paths) == 1
    assert paths[0].workflow_file == source.workflow_file


def test_build_scan_result_populates_exposure_paths(monkeypatch, tmp_path) -> None:
    from actionscope.analyzers import risk_engine

    monkeypatch.setattr(
        risk_engine,
        "_safe_scan_compromised_actions",
        lambda _repo_path: ([_compromised()], []),
    )

    result = build_scan_result(
        str(tmp_path),
        [_credential()],
        [],
        [_policy()],
        [_unpinned()],
    )

    assert len(result.exposure_paths) == 1
    assert result.exposure_paths[0].action_kind == "known_compromised"
    assert result.overall_risk is RiskLevel.CRITICAL
