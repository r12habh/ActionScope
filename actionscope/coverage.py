"""Describe where a scan could not fully resolve available evidence."""

from __future__ import annotations

from actionscope.models import CoverageGap, ScanResult


def build_coverage_gaps(result: ScanResult) -> list[CoverageGap]:
    """Return deduplicated reasons why the scan has partial coverage."""
    gaps: list[CoverageGap] = []

    for binding in result.bindings:
        source = binding.credential_source
        if binding.policy_source == "not_found":
            gaps.append(
                CoverageGap(
                    gap_type="unresolved_role_policy",
                    description=(
                        "The workflow role was found, but its IAM policy was not "
                        "available in a supported in-repository source."
                    ),
                    workflow_file=source.workflow_file,
                    job_name=source.job_name,
                )
            )
        elif binding.policy_source == "dynamic_reference":
            gaps.append(
                CoverageGap(
                    gap_type="dynamic_role_reference",
                    description=(
                        "The workflow role uses an expression that cannot be "
                        "resolved statically."
                    ),
                    workflow_file=source.workflow_file,
                    job_name=source.job_name,
                )
            )
        elif binding.policy_source == "no_role":
            gaps.append(
                CoverageGap(
                    gap_type="credential_scope_unknown",
                    description=(
                        "AWS credentials were configured without a role that "
                        "ActionScope could correlate to a policy."
                    ),
                    workflow_file=source.workflow_file,
                    job_name=source.job_name,
                )
            )

    for reference in result.reusable_workflows:
        if reference.status in {"inspected", "cycle"}:
            continue
        gaps.append(
            CoverageGap(
                gap_type="uninspected_reusable_workflow",
                description=(
                    f"Reusable workflow '{reference.uses}' was not inspected "
                    f"({reference.status.replace('_', ' ')})."
                ),
                workflow_file=reference.caller_workflow,
                job_name=reference.caller_job,
            )
        )

    for error in result.errors:
        text = str(error).strip()
        gaps.append(
            CoverageGap(
                gap_type="analyzer_error",
                description=(
                    text.splitlines()[0]
                    if text
                    else "Analyzer reported an unspecified error."
                ),
            )
        )

    unique: dict[tuple[str, str, str, str], CoverageGap] = {}
    for gap in gaps:
        key = (
            gap.gap_type,
            gap.workflow_file or "",
            gap.job_name or "",
            gap.description,
        )
        unique.setdefault(key, gap)
    return list(unique.values())
