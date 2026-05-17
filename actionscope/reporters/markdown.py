"""Markdown reporter for pull request comments and saved reports."""

from __future__ import annotations

import sys
from pathlib import Path

from actionscope.models import (
    AwsCredentialSource,
    GitHubTokenPermission,
    IamAction,
    PolicyFinding,
    RiskLevel,
    ScanResult,
    UnpinnedActionFinding,
    WorkflowCredentialBinding,
)

RISK_ROW_LABELS = {
    RiskLevel.CRITICAL: "🔴 Critical",
    RiskLevel.HIGH: "🟠 High",
    RiskLevel.MEDIUM: "🟡 Medium",
    RiskLevel.LOW: "🟢 Low",
    RiskLevel.INFO: "ℹ️ INFO",
}

RISK_DISPLAY = {
    RiskLevel.CRITICAL: "🔴 CRITICAL",
    RiskLevel.HIGH: "🟠 HIGH",
    RiskLevel.MEDIUM: "🟡 MEDIUM",
    RiskLevel.LOW: "🟢 LOW",
    RiskLevel.INFO: "ℹ️ INFO",
}


def _workflow_basename(path: str) -> str:
    return Path(path).name


def _auth_display(source: AwsCredentialSource) -> str:
    if source.uses_oidc:
        return "OIDC ✓"
    if source.uses_access_keys:
        return "Static Keys ⚠️"
    return "unknown"


def _critical_concern_lines(finding: PolicyFinding) -> list[str]:
    lines: list[str] = []
    for action in finding.actions:
        if action.action == "iam:PassRole":
            res = action.resource or "*"
            lines.append(
                f"- ⚠️ `{action.action}` on `{res}` — privilege escalation path exists"
            )
        elif action.action == "ec2:TerminateInstances":
            lines.append(
                f"- ⚠️ `{action.action}` — can terminate production instances"
            )
    if finding.has_privilege_escalation and not any(
        a.action == "iam:PassRole" for a in finding.actions
    ):
        lines.append(
            "- ⚠️ Policy enables IAM privilege escalation paths"
        )
    return lines


def _iam_action_row(action: IamAction) -> str:
    risk = RISK_DISPLAY.get(action.risk_level, action.risk_level.name)
    al = action.access_level.replace("|", "\\|")
    return (
        f"| `{action.action}` | {al} | {risk} |"
    )


def _token_workflow_cell(permission: GitHubTokenPermission) -> str:
    wf = _workflow_basename(permission.workflow_file)
    if permission.job_name:
        return f"{wf} (job: {permission.job_name})"
    return f"{wf} (workflow level)"


def _token_table_row(permission: GitHubTokenPermission) -> str:
    scope = permission.scope.replace("|", "\\|")
    access = permission.access.replace("|", "\\|")
    risk = RISK_DISPLAY[permission.risk_level]
    wf = _token_workflow_cell(permission)
    return f"| `{scope}` | {access} | {wf} | {risk} |"


def _binding_section(binding: WorkflowCredentialBinding) -> str:
    src = binding.credential_source
    wf_name = _workflow_basename(src.workflow_file)
    job_label = src.job_name or "(default)"

    lines: list[str] = [
        f"#### `{wf_name}` → `{job_label}` job",
        "",
        "| Field | Value |",
        "|-------|-------|",
    ]

    if src.role_arn:
        role_cell = f"`{src.role_arn}`"
    else:
        role_cell = "`(none)`"

    lines.append(f"| AWS Role | {role_cell} |")
    lines.append(f"| Auth Type | {_auth_display(src)} |")
    lines.append(f"| Policy Source | {binding.policy_source} |")

    if binding.policy_source == "not_found":
        lines.append(
            "| Note | Policy not found in repo. Run with `--aws-verify` flag "
            "to fetch live AWS permissions. |"
        )

    if binding.policy_finding is not None:
        pf = binding.policy_finding
        lines.append(
            f"| Risk | {RISK_DISPLAY[pf.overall_risk]} |",
        )
        lines.append("")

        concerns = _critical_concern_lines(pf)
        if concerns:
            lines.append("**Critical Concerns:**")
            lines.extend(concerns)
            lines.append("")

        if pf.privesc_paths:
            lines.append("**Privilege Escalation Paths:**")
            for path in pf.privesc_paths:
                lines.append(
                    f"- 🔴 **{path.path_name}** — {path.description}"
                )
            lines.append("")

        lines.append("<details>")
        lines.append("<summary>All IAM Actions (click to expand)</summary>")
        lines.append("")
        lines.append("| Action | Access Level | Risk |")
        lines.append("|--------|-------------|------|")
        if pf.actions:
            for a in sorted(pf.actions, key=lambda x: (-x.risk_level.value, x.action)):
                lines.append(_iam_action_row(a))
        else:
            lines.append("| _No actions in policy_ | | |")
        lines.append("")
        lines.append("</details>")
    else:
        lines.append(f"| Risk | {RISK_DISPLAY[RiskLevel.INFO]} |")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>All IAM Actions (click to expand)</summary>")
        lines.append("")
        lines.append("| Action | Access Level | Risk |")
        lines.append("|--------|-------------|------|")
        lines.append("| _No policy matched_ | | |")
        lines.append("")
        lines.append("</details>")

    lines.append("")
    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def _github_token_section(result: ScanResult) -> str:
    if not result.github_token_permissions:
        return ""

    lines = [
        "### GITHUB_TOKEN Permissions",
        "",
        "| Scope | Access | Workflow | Risk |",
        "|-------|--------|----------|------|",
    ]
    for p in result.github_token_permissions:
        lines.append(_token_table_row(p))
    lines.extend(["", "---", ""])
    return "\n".join(lines)


def _pin_type_label(pin_type: str) -> str:
    return {
        "tag": "version tag",
        "branch": "branch",
        "unresolvable": "missing ref",
    }.get(pin_type, pin_type)


def _unpinned_section(findings: list[UnpinnedActionFinding]) -> str:
    if not findings:
        return ""

    lines = [
        "### Unpinned Actions (95.5% of AWS repos have this issue)",
        "",
        "| Action | Workflow | Job | Type |",
        "|--------|----------|-----|------|",
    ]
    for finding in findings:
        workflow = _workflow_basename(finding.workflow_file)
        action = finding.uses.replace("|", "\\|")
        job = finding.job_name.replace("|", "\\|")
        pin_type = _pin_type_label(finding.pin_type)
        lines.append(f"| `{action}` | {workflow} | {job} | {pin_type} |")

    lines.extend(
        [
            "",
            "> ⚠️ Version tags are mutable. Pin to SHA to prevent "
            "supply-chain attacks.",
            "> Reference: the March 2025 tj-actions/changed-files compromise.",
            "",
            "---",
            "",
        ]
    )
    return "\n".join(lines)


def _summary_table(result: ScanResult) -> str:
    # Count IAM actions by risk across all policy findings in the scan
    counts: dict[RiskLevel, int] = {lvl: 0 for lvl in RiskLevel}
    for pf in result.policy_findings:
        for a in pf.actions:
            counts[a.risk_level] += 1

    rows = [
        "| Risk Level | Count |",
        "|-----------|-------|",
        f"| {RISK_ROW_LABELS[RiskLevel.CRITICAL]} | {counts[RiskLevel.CRITICAL]} |",
        f"| {RISK_ROW_LABELS[RiskLevel.HIGH]} | {counts[RiskLevel.HIGH]} |",
        f"| {RISK_ROW_LABELS[RiskLevel.MEDIUM]} | {counts[RiskLevel.MEDIUM]} |",
        f"| {RISK_ROW_LABELS[RiskLevel.LOW]} | {counts[RiskLevel.LOW]} |",
    ]
    return "\n".join(rows)


def to_markdown(result: ScanResult) -> str:
    """
    Generate a Markdown report suitable for GitHub PR comments.
    """
    cred_count = len(result.credential_sources)
    overall = RISK_DISPLAY.get(result.overall_risk, result.overall_risk.name)

    header = (
        "## 🔍 ActionScope — Blast Radius Report\n\n"
        f"**Overall Risk:** {overall} | **Workflows:** {result.workflow_count} "
        f"| **Credential Sources:** {cred_count}\n\n"
        "---\n\n"
    )

    findings_body = "### Workflow Findings\n\n"
    if result.bindings:
        sections = [_binding_section(b) for b in result.bindings]
        findings_body += "".join(sections)
    else:
        findings_body += "_No workflow credential bindings._\n\n---\n\n"

    token_part = _github_token_section(result)
    unpinned_part = _unpinned_section(result.unpinned_actions)

    summary = (
        "### Summary\n\n"
        f"{_summary_table(result)}\n\n"
        "> Generated by [ActionScope](https://github.com/r12habh/ActionScope)\n"
    )

    return header + findings_body + token_part + unpinned_part + summary


def to_markdown_from_dict(data: dict) -> str:
    """Generate Markdown directly from a saved ActionScope JSON payload."""
    overall = str(data.get("overall_risk", "info")).lower()
    risk_display = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🟢 LOW",
        "info": "ℹ️ INFO",
    }.get(overall, overall.upper())
    summary_data = data.get("summary", {})
    credential_count = summary_data.get("credential_sources", 0)

    lines = [
        "## 🔍 ActionScope — Blast Radius Report",
        "",
        f"**Overall Risk:** {risk_display} | "
        f"**Workflows:** {data.get('workflow_count', 0)} | "
        f"**Credential Sources:** {credential_count}",
        "",
        "---",
        "",
        "### Workflow Findings",
        "",
    ]

    findings = data.get("findings", [])
    if findings:
        for finding in findings:
            workflow = _workflow_basename(str(finding.get("workflow_file", "")))
            job = str(finding.get("job_name") or "(default)")
            role = finding.get("role_arn") or "(none)"
            auth_type = str(finding.get("auth_type", "unknown"))
            policy_source = str(finding.get("policy_source", "unknown"))
            finding_risk = str(finding.get("overall_risk", "info")).lower()
            finding_risk_display = {
                "critical": "🔴 CRITICAL",
                "high": "🟠 HIGH",
                "medium": "🟡 MEDIUM",
                "low": "🟢 LOW",
                "info": "ℹ️ INFO",
            }.get(finding_risk, finding_risk.upper())

            lines.extend(
                [
                    f"#### `{workflow}` → `{job}` job",
                    "",
                    "| Field | Value |",
                    "|-------|-------|",
                    f"| AWS Role | `{role}` |",
                    f"| Auth Type | {auth_type} |",
                    f"| Policy Source | {policy_source} |",
                    f"| Risk | {finding_risk_display} |",
                    "",
                ]
            )

            if policy_source == "not_found":
                lines.extend(
                    [
                        "> Policy not found in repo. Run with `--aws-verify` "
                        "flag to fetch live AWS permissions.",
                        "",
                    ]
                )

            actions = finding.get("actions", [])
            lines.extend(
                [
                    "<details>",
                    "<summary>All IAM Actions (click to expand)</summary>",
                    "",
                    "| Action | Access Level | Risk |",
                    "|--------|-------------|------|",
                ]
            )
            if actions:
                for action in actions:
                    risk = str(action.get("risk_level", "info")).lower()
                    action_risk = {
                        "critical": "🔴 CRITICAL",
                        "high": "🟠 HIGH",
                        "medium": "🟡 MEDIUM",
                        "low": "🟢 LOW",
                        "info": "ℹ️ INFO",
                    }.get(risk, risk.upper())
                    lines.append(
                        f"| `{action.get('action', '')}` | "
                        f"{action.get('access_level', '')} | {action_risk} |"
                    )
            else:
                lines.append("| _No actions in policy_ | | |")
            lines.extend(["", "</details>", "", "---", ""])
    else:
        lines.extend(["_No workflow credential bindings._", "", "---", ""])

    token_permissions = data.get("github_token_permissions", [])
    if token_permissions:
        lines.extend(
            [
                "### GITHUB_TOKEN Permissions",
                "",
                "| Scope | Access | Workflow | Risk |",
                "|-------|--------|----------|------|",
            ]
        )
        for permission in token_permissions:
            risk = str(permission.get("risk_level", "info")).lower()
            token_risk = {
                "critical": "🔴 CRITICAL",
                "high": "🟠 HIGH",
                "medium": "🟡 MEDIUM",
                "low": "🟢 LOW",
                "info": "ℹ️ INFO",
            }.get(risk, risk.upper())
            workflow = _workflow_basename(str(permission.get("workflow_file", "")))
            job = permission.get("job_name") or "workflow level"
            lines.append(
                f"| `{permission.get('scope', '')}` | "
                f"{permission.get('access', '')} | {workflow} ({job}) | "
                f"{token_risk} |"
            )
        lines.extend(["", "---", ""])

    unpinned = data.get("unpinned_actions", [])
    if unpinned:
        lines.extend(
            [
                "### Unpinned Actions (95.5% of AWS repos have this issue)",
                "",
                "| Action | Workflow | Job | Type |",
                "|--------|----------|-----|------|",
            ]
        )
        for finding in unpinned:
            workflow = _workflow_basename(str(finding.get("workflow_file", "")))
            lines.append(
                f"| `{finding.get('uses', '')}` | {workflow} | "
                f"{finding.get('job_name', '')} | "
                f"{_pin_type_label(str(finding.get('pin_type', '')))} |"
            )
        lines.extend(
            [
                "",
                "> ⚠️ Version tags are mutable. Pin to SHA to prevent "
                "supply-chain attacks.",
                "> Reference: the March 2025 tj-actions/changed-files compromise.",
                "",
                "---",
                "",
            ]
        )

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        for action in finding.get("actions", []):
            risk = str(action.get("risk_level", "info")).lower()
            if risk in counts:
                counts[risk] += 1

    lines.extend(
        [
            "### Summary",
            "",
            "| Risk Level | Count |",
            "|-----------|-------|",
            f"| 🔴 Critical | {counts['critical']} |",
            f"| 🟠 High | {counts['high']} |",
            f"| 🟡 Medium | {counts['medium']} |",
            f"| 🟢 Low | {counts['low']} |",
            "",
            "> Generated by [ActionScope](https://github.com/r12habh/ActionScope)",
        ]
    )
    return "\n".join(lines)


def write_markdown(result: ScanResult, output_path: str) -> None:
    """Write Markdown to file."""
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(to_markdown(result))
    except (OSError, UnicodeEncodeError) as exc:
        print(
            f"Warning: could not write Markdown output file {output_path}: {exc}",
            file=sys.stderr,
        )
