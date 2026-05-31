"""Markdown reporter for pull request comments and saved reports."""

from __future__ import annotations

import sys
from pathlib import Path

from actionscope.models import (
    AiAgentInjectionFinding,
    ArtifactPoisoningFinding,
    AwsCredentialSource,
    CompromisedActionFinding,
    EnvironmentFinding,
    GitHubTokenPermission,
    IamAction,
    OidcTrustFinding,
    PolicyFinding,
    RiskLevel,
    ScanResult,
    ScriptInjectionFinding,
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


def _md_cell(value: object) -> str:
    text = str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")


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
    al = _md_cell(action.access_level)
    return (
        f"| `{_md_cell(action.action)}` | {al} | {risk} |"
    )


def _token_workflow_cell(permission: GitHubTokenPermission) -> str:
    wf = _workflow_basename(permission.workflow_file)
    if permission.job_name:
        return f"{wf} (job: {permission.job_name})"
    return f"{wf} (workflow level)"


def _token_table_row(permission: GitHubTokenPermission) -> str:
    scope = _md_cell(permission.scope)
    access = _md_cell(permission.access)
    risk = RISK_DISPLAY[permission.risk_level]
    wf = _md_cell(_token_workflow_cell(permission))
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
    lines.append(f"| Match Confidence | {binding.match_confidence} |")

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
        "short_sha": "short SHA",
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
        workflow = _md_cell(_workflow_basename(finding.workflow_file))
        action = _md_cell(finding.uses)
        job = _md_cell(finding.job_name)
        pin_type = _md_cell(_pin_type_label(finding.pin_type))
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


def _oidc_trust_section(findings: list[OidcTrustFinding]) -> str:
    if not findings:
        return ""
    lines = [
        "### OIDC Trust Issues",
        "",
        "| Role | Issue | Risk | Evidence |",
        "|------|-------|------|----------|",
    ]
    for finding in findings:
        role = _md_cell(finding.role_name)
        issue = _md_cell(finding.issue_description)
        evidence = _md_cell(finding.evidence)
        lines.append(
            f"| `{role}` | {issue} | "
            f"{RISK_DISPLAY[finding.risk_level]} | `{evidence}` |"
        )
    lines.extend(["", "---", ""])
    return "\n".join(lines)


def _script_injection_section(findings: list[ScriptInjectionFinding]) -> str:
    if not findings:
        return ""
    lines = [
        "### Script Injection Risks",
        "",
        "| Expression | Workflow | Job | Risk |",
        "|------------|----------|-----|------|",
    ]
    for finding in findings:
        workflow = _md_cell(_workflow_basename(finding.workflow_file))
        expression = _md_cell(finding.untrusted_expression)
        job = _md_cell(finding.job_name)
        lines.append(
            f"| `{expression}` | {workflow} | {job} | "
            f"{RISK_DISPLAY[finding.risk_level]} |"
        )
    lines.extend(
        [
            "",
            "> ⚠️ Direct GitHub context interpolation in `run:` can execute "
            "attacker-controlled shell content. Set values through `env:` first.",
            "",
            "---",
            "",
        ]
    )
    return "\n".join(lines)


def _artifact_poisoning_section(findings: list[ArtifactPoisoningFinding]) -> str:
    if not findings:
        return ""
    lines = [
        "### Artifact Poisoning Risks",
        "",
        "| Workflow | Job | Executes Artifact | Secrets | Risk |",
        "|----------|-----|-------------------|---------|------|",
    ]
    for finding in findings:
        workflow = _md_cell(_workflow_basename(finding.workflow_file))
        job = _md_cell(finding.job_name)
        lines.append(
            f"| {workflow} | {job} | {finding.executes_artifacts} | "
            f"{finding.has_secret_access} | {RISK_DISPLAY[finding.risk_level]} |"
        )
    lines.extend(["", "---", ""])
    return "\n".join(lines)


def _ai_agent_section(findings: list[AiAgentInjectionFinding]) -> str:
    if not findings:
        return ""
    lines = [
        "### AI Agent Prompt Injection Surfaces",
        "",
        "| Agent | Workflow | Untrusted Trigger | Write Access | AWS Access | Risk |",
        "|-------|----------|-------------------|--------------|------------|------|",
    ]
    for finding in findings:
        workflow = _md_cell(_workflow_basename(finding.workflow_file))
        agent_type = _md_cell(finding.agent_type)
        lines.append(
            f"| `{agent_type}` | {workflow} | {finding.untrusted_trigger} | "
            f"{finding.has_write_permissions} | {finding.has_aws_secret_access} | "
            f"{RISK_DISPLAY[finding.risk_level]} |"
        )
    lines.extend(
        [
            "",
            "> Reference: AI agents that read PR or issue content can be prompt "
            "injected into exfiltrating secrets or modifying code.",
            "",
            "---",
            "",
        ]
    )
    return "\n".join(lines)


def _compromised_actions_section(findings: list[CompromisedActionFinding]) -> str:
    if not findings:
        return ""
    lines = [
        "### ⛔ COMPROMISED ACTIONS (Immediate Action Required)",
        "",
    ]
    for finding in findings:
        workflow = _md_cell(_workflow_basename(finding.workflow_file))
        lines.extend(
            [
                "> ⛔ **COMPROMISED ACTION DETECTED**",
                f"> `{workflow}` uses `{_md_cell(finding.uses_ref)}`",
                (
                    f"> Compromised on {finding.compromise_date}. "
                    "Mutable tags may execute credential-stealing code."
                ),
                "> **Remove this action or pin to a verified SHA immediately.**",
                f"> Advisory: {finding.advisory_url}",
                ">",
            ]
        )
    lines.extend(["", "---", ""])
    return "\n".join(lines)


def _environment_section(findings: list[EnvironmentFinding]) -> str:
    if not findings:
        return ""
    lines = [
        "### GitHub Environment Issues",
        "",
        "| Workflow | Job | Environment | Issue | Risk |",
        "|----------|-----|-------------|-------|------|",
    ]
    for finding in findings:
        workflow = _md_cell(_workflow_basename(finding.workflow_file))
        environment = _md_cell(finding.environment_name or "(none)")
        issue = _md_cell(finding.finding_type.replace("_", " "))
        lines.append(
            f"| {workflow} | {_md_cell(finding.job_name)} | {environment} | "
            f"{issue} | {RISK_DISPLAY[finding.risk_level]} |"
        )
    lines.extend(["", "---", ""])
    return "\n".join(lines)


def _pin_suggestions_section(suggestions: list) -> str:
    if not suggestions:
        return ""
    lines = [
        "### Pin Suggestions",
        "",
        "```yaml",
        "# Replace unpinned actions with SHA-pinned equivalents:",
    ]
    for pin in suggestions:
        original = _pin_value(pin, "original_ref")
        pinned = _pin_value(pin, "pinned_ref")
        error = _pin_value(pin, "error")
        lines.append(f"# {original}")
        if error:
            lines.append(f"# unresolved: {error}")
        else:
            lines.append(f"uses: {pinned}")
    lines.extend(
        [
            "```",
            "",
            "> SHA shown is current as of scan time. Verify via "
            "`git ls-remote https://github.com/ACTION_OWNER/ACTION_REPO "
            "refs/tags/TAG`.",
            "",
            "---",
            "",
        ]
    )
    return "\n".join(lines)


def _pin_value(pin: object, key: str) -> object:
    if isinstance(pin, dict):
        return pin.get(key)
    return getattr(pin, key, None)


def _delta_section(delta: object | None) -> str:
    if delta is None:
        return ""
    previous = getattr(delta, "previous_overall_risk", None) or "(none)"
    current = getattr(delta, "current_overall_risk", "info")
    if getattr(delta, "risk_increased", False):
        change = "⬆️ Increased"
    elif getattr(delta, "risk_decreased", False):
        change = "⬇️ Decreased"
    elif getattr(delta, "risk_changed", False):
        change = "Changed"
    else:
        change = "No comparison"
    previous_critical = getattr(delta, "previous_critical_count", 0)
    current_critical = getattr(delta, "current_critical_count", 0)
    previous_high = getattr(delta, "previous_high_count", 0)
    current_high = getattr(delta, "current_high_count", 0)
    lines = [
        "### 📊 Delta Since Last Scan",
        "",
        "| Metric | Previous | Current | Change |",
        "|--------|----------|---------|--------|",
        (
            f"| Overall Risk | {str(previous).upper()} | "
            f"{str(current).upper()} | {change} |"
        ),
        (
            f"| Critical Findings | {previous_critical} | {current_critical} | "
            f"{_signed_delta(current_critical, previous_critical)} |"
        ),
        (
            f"| High Findings | {previous_high} | {current_high} | "
            f"{_signed_delta(current_high, previous_high)} |"
        ),
    ]
    new_actions = getattr(delta, "new_compromised_actions", [])
    if new_actions:
        lines.extend(
            [
                "",
                "⛔ **New compromised actions since last scan:** "
                + ", ".join(f"`{_md_cell(action)}`" for action in new_actions),
            ]
        )
    resolved = getattr(delta, "resolved_finding_types", [])
    if resolved:
        lines.extend(
            [
                "",
                "✅ **Resolved since last scan:** "
                + ", ".join(f"`{_md_cell(item)}`" for item in resolved),
            ]
        )
    lines.extend(["", "---", ""])
    return "\n".join(lines)


def _signed_delta(current: int, previous: int) -> str:
    diff = current - previous
    if diff > 0:
        return f"+{diff}"
    if diff < 0:
        return str(diff)
    return "No change"


def _summary_table(result: ScanResult) -> str:
    counts: dict[RiskLevel, int] = {
        level: len(result.findings_by_risk(level)) for level in RiskLevel
    }

    rows = [
        "| Risk Level | Count |",
        "|-----------|-------|",
        f"| {RISK_ROW_LABELS[RiskLevel.CRITICAL]} | {counts[RiskLevel.CRITICAL]} |",
        f"| {RISK_ROW_LABELS[RiskLevel.HIGH]} | {counts[RiskLevel.HIGH]} |",
        f"| {RISK_ROW_LABELS[RiskLevel.MEDIUM]} | {counts[RiskLevel.MEDIUM]} |",
        f"| {RISK_ROW_LABELS[RiskLevel.LOW]} | {counts[RiskLevel.LOW]} |",
    ]
    return "\n".join(rows)


def to_markdown(result: ScanResult, delta: object | None = None) -> str:
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

    compromised_part = _compromised_actions_section(
        result.compromised_action_findings
    )
    delta_part = _delta_section(delta)
    findings_body = "### Workflow Findings\n\n"
    if result.bindings:
        sections = [_binding_section(b) for b in result.bindings]
        findings_body += "".join(sections)
    else:
        findings_body += "_No workflow credential bindings._\n\n---\n\n"

    token_part = _github_token_section(result)
    unpinned_part = _unpinned_section(result.unpinned_actions)
    oidc_part = _oidc_trust_section(result.oidc_trust_findings)
    environment_part = _environment_section(result.environment_findings)
    script_part = _script_injection_section(result.script_injection_findings)
    artifact_part = _artifact_poisoning_section(result.artifact_poisoning_findings)
    ai_part = _ai_agent_section(result.ai_agent_injection_findings)
    pin_part = _pin_suggestions_section(result.pin_suggestions)

    summary = (
        "### Summary\n\n"
        f"{_summary_table(result)}\n\n"
        "> Generated by [ActionScope](https://github.com/r12habh/ActionScope)\n"
    )

    return (
        header
        + compromised_part
        + delta_part
        + findings_body
        + token_part
        + oidc_part
        + environment_part
        + script_part
        + artifact_part
        + ai_part
        + unpinned_part
        + pin_part
        + summary
    )


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

    compromised = data.get("compromised_action_findings", [])
    if compromised:
        prefix = [
            "### ⛔ COMPROMISED ACTIONS (Immediate Action Required)",
            "",
        ]
        for finding in compromised:
            workflow = _md_cell(
                _workflow_basename(str(finding.get("workflow_file", "")))
            )
            prefix.extend(
                [
                    "> ⛔ **COMPROMISED ACTION DETECTED**",
                    f"> `{workflow}` uses `{_md_cell(finding.get('uses_ref', ''))}`",
                    (
                        f"> Compromised on {finding.get('compromise_date', '')}. "
                        "Mutable tags may execute credential-stealing code."
                    ),
                    "> **Remove this action or pin to a verified SHA immediately.**",
                    f"> Advisory: {finding.get('advisory_url', '')}",
                    ">",
                ]
            )
        prefix.extend(["", "---", ""])
        lines = lines[:6] + prefix + lines[6:]

    delta_data = data.get("delta")
    if isinstance(delta_data, dict):
        delta_lines = [
            "### 📊 Delta Since Last Scan",
            "",
            "| Metric | Previous | Current | Change |",
            "|--------|----------|---------|--------|",
        ]
        previous = delta_data.get("previous_overall_risk") or "(none)"
        current = delta_data.get("current_overall_risk", "info")
        if delta_data.get("risk_increased"):
            change = "⬆️ Increased"
        elif delta_data.get("risk_decreased"):
            change = "⬇️ Decreased"
        elif delta_data.get("risk_changed"):
            change = "Changed"
        else:
            change = "No comparison"
        previous_critical = int(delta_data.get("previous_critical_count", 0))
        current_critical = int(delta_data.get("current_critical_count", 0))
        previous_high = int(delta_data.get("previous_high_count", 0))
        current_high = int(delta_data.get("current_high_count", 0))
        delta_lines.append(
            f"| Overall Risk | {str(previous).upper()} | "
            f"{str(current).upper()} | {change} |"
        )
        delta_lines.append(
            f"| Critical Findings | {previous_critical} | {current_critical} | "
            f"{_signed_delta(current_critical, previous_critical)} |"
        )
        delta_lines.append(
            f"| High Findings | {previous_high} | {current_high} | "
            f"{_signed_delta(current_high, previous_high)} |"
        )
        new_actions = delta_data.get("new_compromised_actions") or []
        if new_actions:
            delta_lines.extend(
                [
                    "",
                    "⛔ **New compromised actions since last scan:** "
                    + ", ".join(f"`{_md_cell(action)}`" for action in new_actions),
                ]
            )
        delta_lines.extend(["", "---", ""])
        lines = lines[:6] + delta_lines + lines[6:]

    findings = data.get("findings", [])
    if findings:
        for finding in findings:
            workflow = _md_cell(
                _workflow_basename(str(finding.get("workflow_file", "")))
            )
            job = _md_cell(str(finding.get("job_name") or "(default)"))
            role = _md_cell(finding.get("role_arn") or "(none)")
            auth_type = _md_cell(finding.get("auth_type", "unknown"))
            policy_source = _md_cell(finding.get("policy_source", "unknown"))
            match_confidence = _md_cell(finding.get("match_confidence", "none"))
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
                    f"| Match Confidence | {match_confidence} |",
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
                        f"| `{_md_cell(action.get('action', ''))}` | "
                        f"{_md_cell(action.get('access_level', ''))} | "
                        f"{action_risk} |"
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
            workflow = _md_cell(
                _workflow_basename(str(permission.get("workflow_file", "")))
            )
            job = _md_cell(permission.get("job_name") or "workflow level")
            lines.append(
                f"| `{_md_cell(permission.get('scope', ''))}` | "
                f"{_md_cell(permission.get('access', ''))} | {workflow} ({job}) | "
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
            workflow = _md_cell(
                _workflow_basename(str(finding.get("workflow_file", "")))
            )
            lines.append(
                f"| `{_md_cell(finding.get('uses', ''))}` | {workflow} | "
                f"{_md_cell(finding.get('job_name', ''))} | "
                f"{_md_cell(_pin_type_label(str(finding.get('pin_type', ''))))} |"
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

    pin_suggestions = data.get("pin_suggestions", [])
    if pin_suggestions:
        lines.extend(
            [
                "### Pin Suggestions",
                "",
                "```yaml",
                "# Replace unpinned actions with SHA-pinned equivalents:",
            ]
        )
        for pin in pin_suggestions:
            lines.append(f"# {pin.get('original_ref', '')}")
            if pin.get("error"):
                lines.append(f"# unresolved: {pin.get('error')}")
            else:
                lines.append(f"uses: {pin.get('pinned_ref', '')}")
        lines.extend(
            [
                "```",
                "",
                "> SHA shown is current as of scan time. Verify before committing.",
                "",
                "---",
                "",
            ]
        )

    for key, title in (
        ("oidc_trust_findings", "OIDC Trust Issues"),
        ("environment_findings", "GitHub Environment Issues"),
        ("script_injection_findings", "Script Injection Risks"),
        ("artifact_poisoning_findings", "Artifact Poisoning Risks"),
        ("ai_agent_injection_findings", "AI Agent Prompt Injection Surfaces"),
    ):
        detector_findings = data.get(key, [])
        if detector_findings:
            lines.extend(
                [
                    f"### {title}",
                    "",
                    "| Finding | Workflow/Source | Risk |",
                    "|---------|-----------------|------|",
                ]
            )
            for finding in detector_findings:
                risk = str(finding.get("risk_level", "info")).lower()
                risk_label = {
                    "critical": "🔴 CRITICAL",
                    "high": "🟠 HIGH",
                    "medium": "🟡 MEDIUM",
                    "low": "🟢 LOW",
                    "info": "ℹ️ INFO",
                }.get(risk, risk.upper())
                title_text = (
                    finding.get("issue_description")
                    or finding.get("description")
                    or finding.get("finding_type")
                    or finding.get("agent_type")
                    or "finding"
                )
                location = (
                    finding.get("workflow_file")
                    or finding.get("source_file")
                    or ""
                )
                lines.append(
                    f"| {_md_cell(title_text)} | `{_md_cell(location)}` | "
                    f"{risk_label} |"
                )
            lines.extend(["", "---", ""])

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        risk = str(finding.get("overall_risk", "info")).lower()
        if risk in counts:
            counts[risk] += 1
    for permission in token_permissions:
        risk = str(permission.get("risk_level", "info")).lower()
        if risk in counts:
            counts[risk] += 1
    for key in (
        "oidc_trust_findings",
        "environment_findings",
        "script_injection_findings",
        "artifact_poisoning_findings",
        "ai_agent_injection_findings",
        "compromised_action_findings",
    ):
        for finding in data.get(key, []):
            risk = str(finding.get("risk_level", "info")).lower()
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


def write_markdown(
    result: ScanResult,
    output_path: str,
    delta: object | None = None,
) -> None:
    """Write Markdown to file."""
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(to_markdown(result, delta=delta))
    except (OSError, UnicodeEncodeError) as exc:
        print(
            f"Warning: could not write Markdown output file {output_path}: {exc}",
            file=sys.stderr,
        )
