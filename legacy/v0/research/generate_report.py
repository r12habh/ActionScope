#!/usr/bin/env python3
"""Generate public research reports from ActionScope workflow findings."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def generate_markdown_report(findings_data: dict[str, Any]) -> str:
    """Generate a Markdown report from scanner findings data."""
    stats = calculate_statistics(findings_data)
    generated_at = _metadata_value(findings_data, "scanned_at") or _metadata_value(
        findings_data,
        "generated_at",
    )

    return (
        "# ActionScope Research: GitHub Actions AWS Workflow Security\n\n"
        "## Methodology\n\n"
        "We selected public GitHub repositories with GitHub Code Search using "
        "the query `aws-actions/configure-aws-credentials "
        "path:.github/workflows`. For each repository, we downloaded public "
        "workflow YAML files under `.github/workflows/` and measured only "
        "workflow-level configuration patterns.\n\n"
        "We analyzed workflow YAML files only. No AWS accounts were accessed. "
        "No AWS APIs were called for external repositories. IAM policy content "
        "is private and cannot be seen from outside unless the repository "
        "publishes Terraform or JSON policy files.\n\n"
        f"Collected: `{generated_at or 'unknown'}`\n\n"
        "## Key Statistics\n\n"
        f"- Total repos analyzed: **{stats['repo_count']}**\n"
        f"- Total workflow files analyzed: **{stats['workflow_count']}**\n\n"
        "### Auth Method Breakdown\n\n"
        f"- **{stats['pct_oidc']:.1f}%** use OIDC (recommended)\n"
        f"- **{stats['pct_access_keys']:.1f}%** use static access keys "
        "(not recommended)\n"
        f"- **{stats['pct_dynamic_role']:.1f}%** have role ARN as dynamic "
        "reference (cannot verify statically)\n"
        f"- **{stats['pct_hardcoded_role']:.1f}%** have role ARN hardcoded "
        "(visible in public workflow)\n\n"
        "### GITHUB_TOKEN Permissions\n\n"
        f"- **{stats['pct_write_all']:.1f}%** use write-all permissions "
        "(overly broad)\n"
        f"- **{stats['pct_pr_write']:.1f}%** have `pull-requests: write`\n"
        f"- **{stats['pct_contents_write']:.1f}%** have `contents: write`\n\n"
        "### Dangerous Patterns\n\n"
        f"- **{stats['pct_prt']:.1f}%** use `pull_request_target` trigger\n"
        f"- **{stats['pct_dangerous_prt']:.1f}%** use `pull_request_target` "
        "WITH write permissions (dangerous combo)\n"
        "  - Note: this is the pattern exploited in the April 2026 prt-scan "
        "campaign\n"
        f"- **{stats['pct_unpinned']:.1f}%** use unpinned actions "
        "(floating version tags, not SHA-pinned)\n\n"
        "## What ActionScope Adds\n\n"
        "These workflow-level findings show what's visible from outside. For "
        "users scanning their own repos, ActionScope also maps the effective "
        "AWS blast radius by correlating workflow role ARNs with IAM policies "
        "from Terraform, JSON files, or live AWS verification.\n\n"
        "[ActionScope](https://github.com/r12habh/ActionScope)\n"
    )


def write_csv_summary(findings_data: dict[str, Any], output_path: str | Path) -> None:
    """Write anonymized per-workflow CSV summary."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "repo_hash",
                "workflow_file",
                "uses_oidc",
                "uses_access_keys",
                "has_write_all",
                "has_pr_write",
                "uses_prt",
                "dangerous_prt_combo",
                "uses_unpinned_actions",
            ],
        )
        writer.writeheader()
        for finding in _valid_findings(findings_data):
            writer.writerow(
                {
                    "repo_hash": finding.get("repo_hash", ""),
                    "workflow_file": _workflow_file(finding),
                    "uses_oidc": bool(finding.get("uses_oidc")),
                    "uses_access_keys": bool(finding.get("uses_access_keys")),
                    "has_write_all": bool(finding.get("has_write_all")),
                    "has_pr_write": bool(finding.get("has_pr_write")),
                    "uses_prt": bool(_uses_prt(finding)),
                    "dangerous_prt_combo": bool(
                        finding.get("dangerous_prt_combo")
                    ),
                    "uses_unpinned_actions": bool(_uses_unpinned(finding)),
                }
            )


def calculate_statistics(findings_data: dict[str, Any]) -> dict[str, float | int]:
    """Calculate repository-level statistics from findings data."""
    valid = _valid_findings(findings_data)
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in valid:
        by_repo[str(finding.get("repo_hash") or finding.get("repo_full_name"))].append(
            finding
        )

    repo_count = len(by_repo)

    def pct(flag: str) -> float:
        if repo_count == 0:
            return 0.0
        matched = sum(
            any(_flag_value(finding, flag) for finding in findings)
            for findings in by_repo.values()
        )
        return (matched / repo_count) * 100

    return {
        "repo_count": repo_count,
        "workflow_count": len(valid),
        "pct_oidc": pct("uses_oidc"),
        "pct_access_keys": pct("uses_access_keys"),
        "pct_dynamic_role": pct("role_arn_is_dynamic"),
        "pct_hardcoded_role": pct("has_role_arn"),
        "pct_write_all": pct("has_write_all"),
        "pct_pr_write": pct("has_pr_write"),
        "pct_contents_write": pct("has_contents_write"),
        "pct_prt": pct("uses_pull_request_target"),
        "pct_dangerous_prt": pct("dangerous_prt_combo"),
        "pct_unpinned": pct("uses_unpinned_actions"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate Markdown and CSV reports from findings JSON."
    )
    parser.add_argument("--input", default="research/findings.json")
    parser.add_argument("--output", default="research/FINDINGS.md")
    parser.add_argument("--csv", default="research/findings_summary.csv")
    args = parser.parse_args()

    findings_data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    report = generate_markdown_report(findings_data)
    Path(args.output).write_text(report, encoding="utf-8")
    write_csv_summary(findings_data, args.csv)
    print(f"Markdown report written to {args.output}")
    print(f"CSV summary written to {args.csv}")


def _valid_findings(findings_data: dict[str, Any]) -> list[dict[str, Any]]:
    findings = findings_data.get("findings", [])
    if not isinstance(findings, list):
        return []
    return [
        finding
        for finding in findings
        if isinstance(finding, dict) and not finding.get("error")
    ]


def _metadata_value(findings_data: dict[str, Any], key: str) -> Any:
    metadata = findings_data.get("metadata")
    if isinstance(metadata, dict) and metadata.get(key):
        return metadata[key]
    return findings_data.get(key)


def _flag_value(finding: dict[str, Any], flag: str) -> bool:
    if flag == "uses_pull_request_target":
        return _uses_prt(finding)
    if flag == "uses_unpinned_actions":
        return _uses_unpinned(finding)
    return bool(finding.get(flag))


def _workflow_file(finding: dict[str, Any]) -> str:
    return str(
        finding.get("workflow_filename")
        or finding.get("workflow_path")
        or finding.get("file")
        or ""
    )


def _uses_prt(finding: dict[str, Any]) -> bool:
    return bool(
        finding.get("uses_pull_request_target")
        or finding.get("uses_prt")
    )


def _uses_unpinned(finding: dict[str, Any]) -> bool:
    return bool(
        finding.get("uses_unpinned_actions")
        or finding.get("has_unpinned_actions")
    )


if __name__ == "__main__":
    main()
