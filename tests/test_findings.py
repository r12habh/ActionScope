"""Tests for normalized finding records and coverage metadata."""

from __future__ import annotations

from pathlib import Path

from actionscope.coverage import build_coverage_gaps
from actionscope.findings import build_finding_records
from actionscope.models import (
    AwsCredentialSource,
    CompromisedActionFinding,
    FindingConfidence,
    IamAction,
    PolicyFinding,
    ReusableWorkflowReference,
    RiskLevel,
    ScanResult,
    WorkflowCredentialBinding,
)


def _compromised(
    *,
    job_name: str = "triage",
    step_name: str = "Run helper",
    description: str = "Known compromise",
) -> CompromisedActionFinding:
    return CompromisedActionFinding(
        workflow_file=".github/workflows/triage.yml",
        job_name=job_name,
        step_name=step_name,
        uses_ref="actions-cool/issues-helper@v3",
        action_name="actions-cool/issues-helper",
        ref="v3",
        is_sha_pinned=False,
        compromise_date="2026-05-18T19:10:24Z",
        advisory_url="https://example.com/advisory",
        description=description,
        risk_level=RiskLevel.CRITICAL,
    )


def _binding(
    *,
    policy: PolicyFinding | None,
    source: str,
    confidence: str = "none",
) -> WorkflowCredentialBinding:
    credential = AwsCredentialSource(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        step_name="Configure AWS",
        role_arn="arn:aws:iam::123456789012:role/deploy",
        uses_access_keys=False,
        uses_oidc=True,
        aws_region="us-east-1",
    )
    return WorkflowCredentialBinding(
        credential_source=credential,
        policy_finding=policy,
        policy_source=source,
        match_confidence=confidence,
    )


def test_compromised_action_record_is_high_confidence() -> None:
    result = ScanResult(compromised_action_findings=[_compromised()])

    records = build_finding_records(result)

    assert len(records) == 1
    assert records[0].rule_id == "AS013"
    assert records[0].confidence is FindingConfidence.HIGH
    assert records[0].risk_level is RiskLevel.CRITICAL


def test_fingerprint_ignores_description_changes() -> None:
    first = build_finding_records(
        ScanResult(compromised_action_findings=[_compromised(description="one")])
    )
    second = build_finding_records(
        ScanResult(compromised_action_findings=[_compromised(description="two")])
    )

    assert first[0].fingerprint == second[0].fingerprint


def test_fingerprint_distinguishes_jobs() -> None:
    result = ScanResult(
        compromised_action_findings=[
            _compromised(job_name="triage"),
            _compromised(job_name="release"),
        ]
    )

    records = build_finding_records(result)

    assert len({record.fingerprint for record in records}) == 2


def test_fingerprint_ignores_cosmetic_step_name_changes() -> None:
    first = build_finding_records(
        ScanResult(
            compromised_action_findings=[
                _compromised(step_name="Run helper")
            ]
        )
    )
    second = build_finding_records(
        ScanResult(
            compromised_action_findings=[
                _compromised(step_name="Triage incoming issues")
            ]
        )
    )

    assert first[0].fingerprint == second[0].fingerprint


def test_policy_record_uses_binding_match_confidence() -> None:
    policy = PolicyFinding(
        source_file="terraform/deploy.tf",
        source_type="terraform",
        role_arn="arn:aws:iam::123456789012:role/deploy",
        overall_risk=RiskLevel.HIGH,
    )
    result = ScanResult(
        bindings=[
            _binding(
                policy=policy,
                source="terraform",
                confidence="low",
            )
        ]
    )

    records = build_finding_records(result)

    assert records[0].rule_id == "AS001"
    assert records[0].confidence is FindingConfidence.LOW


def test_policy_fingerprint_is_stable_across_checkout_roots(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first" / "repo"
    second_root = tmp_path / "second" / "repo"
    first_policy = PolicyFinding(
        source_file=str(first_root / "infra" / "iam.tf"),
        source_type="terraform",
        role_arn="arn:aws:iam::123456789012:role/deploy",
        overall_risk=RiskLevel.HIGH,
    )
    second_policy = PolicyFinding(
        source_file=str(second_root / "infra" / "iam.tf"),
        source_type="terraform",
        role_arn="arn:aws:iam::123456789012:role/deploy",
        overall_risk=RiskLevel.HIGH,
    )

    first = ScanResult(
        scan_path=str(first_root),
        bindings=[
            _binding(
                policy=first_policy,
                source="terraform",
                confidence="high",
            )
        ],
    )
    second = ScanResult(
        scan_path=str(second_root),
        bindings=[
            _binding(
                policy=second_policy,
                source="terraform",
                confidence="high",
            )
        ],
    )

    assert (
        build_finding_records(first)[0].fingerprint
        == build_finding_records(second)[0].fingerprint
    )


def test_iam_permissions_have_granular_fingerprints() -> None:
    policy = PolicyFinding(
        source_file="terraform/deploy.tf",
        source_type="terraform",
        role_arn="arn:aws:iam::123456789012:role/deploy",
        actions=[
            IamAction(
                action="s3:GetObject",
                access_level="Read",
                risk_level=RiskLevel.LOW,
                description="Read an object",
                resource="arn:aws:s3:::example/*",
            ),
            IamAction(
                action="ec2:TerminateInstances",
                access_level="Write",
                risk_level=RiskLevel.HIGH,
                description="Terminate instances",
                resource="*",
            ),
        ],
        overall_risk=RiskLevel.HIGH,
    )
    result = ScanResult(
        bindings=[
            _binding(
                policy=policy,
                source="terraform",
                confidence="high",
            )
        ]
    )

    records = [
        record
        for record in build_finding_records(result)
        if record.rule_id == "AS001"
    ]

    assert len(records) == 2
    assert len({record.fingerprint for record in records}) == 2
    assert {record.risk_level for record in records} == {
        RiskLevel.LOW,
        RiskLevel.HIGH,
    }


def test_unresolved_policy_creates_coverage_gap_not_finding() -> None:
    result = ScanResult(bindings=[_binding(policy=None, source="not_found")])

    gaps = build_coverage_gaps(result)
    records = build_finding_records(result)

    assert [gap.gap_type for gap in gaps] == ["unresolved_role_policy"]
    assert records == []


def test_analyzer_error_marks_coverage_partial() -> None:
    result = ScanResult(errors=["Scan incomplete: parser failed"])

    gaps = build_coverage_gaps(result)

    assert gaps[0].gap_type == "analyzer_error"


def test_empty_analyzer_error_does_not_break_coverage() -> None:
    gaps = build_coverage_gaps(ScanResult(errors=[""]))

    assert len(gaps) == 1
    assert gaps[0].gap_type == "analyzer_error"
    assert gaps[0].description == "Analyzer reported an unspecified error."


def test_unmatched_policy_is_normalized_at_low_confidence() -> None:
    policy = PolicyFinding(
        source_file="terraform/unmatched.tf",
        source_type="terraform",
        role_arn="arn:aws:iam::123456789012:role/unmatched",
        actions=[
            IamAction(
                action="iam:CreateAccessKey",
                access_level="Permissions management",
                risk_level=RiskLevel.CRITICAL,
                description="Create an access key",
                resource="*",
            )
        ],
        overall_risk=RiskLevel.CRITICAL,
    )

    records = build_finding_records(ScanResult(policy_findings=[policy]))

    assert len(records) == 1
    assert records[0].rule_id == "AS001"
    assert records[0].confidence is FindingConfidence.LOW


def test_uninspected_reusable_workflow_is_not_gate_eligible() -> None:
    reference = ReusableWorkflowReference(
        caller_workflow=".github/workflows/caller.yml",
        caller_job="scan",
        uses="external/repo/.github/workflows/reuse.yml@v1",
        target_workflow=".github/workflows/reuse.yml",
        repository="external/repo",
        ref="v1",
        pin_type="tag",
        is_local=False,
        status="no_token",
        depth=1,
    )
    result = ScanResult(reusable_workflows=[reference])

    records = build_finding_records(result)
    gaps = build_coverage_gaps(result)

    assert records[0].rule_id == "AS015"
    assert records[0].gate_eligible is False
    assert gaps[0].gap_type == "uninspected_reusable_workflow"


def test_out_of_tree_paths_do_not_collide_or_leak_absolute_paths(
    tmp_path: Path,
) -> None:
    first = PolicyFinding(
        source_file=str(tmp_path / "one" / "iam.tf"),
        source_type="terraform",
        role_arn=None,
        overall_risk=RiskLevel.HIGH,
    )
    second = PolicyFinding(
        source_file=str(tmp_path / "two" / "iam.tf"),
        source_type="terraform",
        role_arn=None,
        overall_risk=RiskLevel.HIGH,
    )
    result = ScanResult(
        scan_path=str(tmp_path / "repo"),
        policy_findings=[first, second],
    )

    records = build_finding_records(result)

    assert len(records) == 2
    assert len({record.fingerprint for record in records}) == 2
    assert all(
        record.workflow_file
        and record.workflow_file.startswith("_external/")
        for record in records
    )
    assert all(str(tmp_path) not in (record.workflow_file or "") for record in records)
