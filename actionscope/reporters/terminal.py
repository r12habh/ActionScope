"""Rich terminal reporter for human-readable ActionScope scan results."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from actionscope.models import (
    AiAgentInjectionFinding,
    ArtifactPoisoningFinding,
    AwsCredentialSource,
    CompromisedActionFinding,
    EnvironmentFinding,
    GitHubTokenPermission,
    OidcTrustFinding,
    PolicyFinding,
    RiskLevel,
    ScanResult,
    ScriptInjectionFinding,
    UnpinnedActionFinding,
    WorkflowCredentialBinding,
    get_unmatched_findings,
)

RISK_COLORS = {
    RiskLevel.CRITICAL: "bold red",
    RiskLevel.HIGH: "red",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.LOW: "green",
    RiskLevel.INFO: "dim",
}

RISK_ICONS = {
    RiskLevel.CRITICAL: "🔴",
    RiskLevel.HIGH: "🟠",
    RiskLevel.MEDIUM: "🟡",
    RiskLevel.LOW: "🟢",
    RiskLevel.INFO: "ℹ️ ",
}

_TOKEN_SCOPE_HINTS: dict[str, str] = {
    "contents": "Can push code to repo",
    "pull-requests": "Prompt injection risk",
    "actions": "Can modify workflows",
    "packages": "Can publish or tamper with packages",
    "id-token": "OIDC token minting for cloud access",
    "deployments": "Can create deployments",
    "security-events": "Can write security events",
}


def _risk_short(level: RiskLevel) -> str:
    return {
        RiskLevel.CRITICAL: "CRIT",
        RiskLevel.HIGH: "HIGH",
        RiskLevel.MEDIUM: "MED",
        RiskLevel.LOW: "LOW",
        RiskLevel.INFO: "INFO",
    }[level]


def _workflow_basename(path: str) -> str:
    return Path(path).name


def _format_auth_line(source: AwsCredentialSource) -> str:
    if source.uses_oidc:
        return "Auth: OIDC ✓"
    if source.uses_access_keys:
        return "Auth: Static Keys ⚠️"
    return "Auth: (not detected)"


def _token_permission_hint(permission: GitHubTokenPermission) -> str:
    key = permission.scope.lower()
    return _TOKEN_SCOPE_HINTS.get(
        key,
        "Elevated repository access",
    )


def _critical_concerns(finding: PolicyFinding) -> list[str]:
    messages: list[str] = []
    seen: set[str] = set()

    def add(msg: str) -> None:
        if msg not in seen:
            seen.add(msg)
            messages.append(msg)

    if finding.has_passrole or any(
        a.action == "iam:PassRole" for a in finding.actions
    ):
        add("iam:PassRole on * creates a privilege escalation path")

    if any(a.action == "ec2:TerminateInstances" for a in finding.actions):
        add("This workflow can terminate EC2 instances")

    if finding.has_privilege_escalation:
        add("Policy enables IAM privilege escalation paths")

    return messages


def _iam_action_risk_counts(
    policy_findings: list[PolicyFinding],
) -> dict[RiskLevel, int]:
    counts: dict[RiskLevel, int] = {level: 0 for level in RiskLevel}
    for finding in policy_findings:
        for action in finding.actions:
            counts[action.risk_level] += 1
    return counts


def render_scan_result(
    result: ScanResult,
    console: Optional[Console] = None,
    delta: object | None = None,
) -> None:
    """
    Render the complete ScanResult to the terminal.

    Output structure (in order):

    A. Header panel
    B. One section per WorkflowCredentialBinding
    C. GITHUB_TOKEN permissions (non-low risk)
    D. Unmatched IAM policies
    E. Summary panel
    F. Warnings for result.errors

    Use console = Console() if not passed in.
    Do not raise — catch all rendering errors.
    """
    try:
        _render_scan_result_impl(result, console, delta=delta)
    except Exception as exc:
        render_error(f"Could not render ActionScope report: {exc}", console)


def _render_scan_result_impl(
    result: ScanResult,
    console: Optional[Console] = None,
    delta: object | None = None,
) -> None:
    c = console if console is not None else Console()
    delta_lines = _delta_header_lines(delta)

    header_body = Text.assemble(
        ("ActionScope — Blast Radius Report\n", "bold"),
        (f"Path: {result.scan_path}\n", ""),
        (
            f"Workflows: {result.workflow_count} | "
            f"Credential Sources: {len(result.credential_sources)}\n",
            "",
        ),
        (
            "Overall Risk: "
            f"{RISK_ICONS[result.overall_risk]} {result.overall_risk.name}",
            RISK_COLORS[result.overall_risk],
        ),
        *delta_lines,
    )
    c.print()
    c.print(
        Panel(
            header_body,
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    c.print()

    _render_compromised_actions_section(c, result.compromised_action_findings)

    for binding in result.bindings:
        _render_binding(c, binding)

    _render_oidc_trust_section(c, result.oidc_trust_findings)
    _render_environment_section(c, result.environment_findings)
    _render_script_injection_section(c, result.script_injection_findings)
    _render_artifact_poisoning_section(c, result.artifact_poisoning_findings)
    _render_ai_agent_section(c, result.ai_agent_injection_findings)
    _render_unpinned_actions_section(c, result.unpinned_actions)
    _render_pin_suggestions_section(c, result.pin_suggestions)

    _render_github_token_section(c, result)

    unmatched = get_unmatched_findings(result.bindings, result.policy_findings)
    _render_unmatched_policies(c, unmatched)

    _render_summary_panel(c, result, delta=delta)

    if result.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        c.print()
        c.print(
            "[dim]💡 Run actionscope scan . --aws-verify "
            "to verify live AWS permissions[/]"
        )

    if result.errors:
        c.print()
        c.print("[yellow]⚠️  Warnings:[/]")
        for err in result.errors:
            c.print(f"  [dim]- {err}[/]")


def _render_binding(c: Console, binding: WorkflowCredentialBinding) -> None:
    src = binding.credential_source
    wf = _workflow_basename(src.workflow_file)
    role_arn = src.role_arn or "(none)"

    c.print(
        f"[bold]Workflow:[/] {wf} [dim]→[/] [bold]Job:[/] {src.job_name} "
        f"[dim]→[/] [bold]Step:[/] {src.step_name}"
    )
    c.print(f"[bold]AWS Role:[/] {role_arn}")
    if binding.policy_source == "aws_verified":
        c.print("[green]✅ Verified via AWS API (live)[/]")
    if binding.policy_finding is not None:
        confidence = binding.match_confidence or "unknown"
        c.print(f"[bold]Policy Match:[/] {binding.policy_source} ({confidence})")
    c.print(_format_auth_line(src))

    if binding.policy_finding is not None and binding.policy_finding.actions:
        _render_actions_table(c, binding.policy_finding)
        _render_privesc_paths(c, binding.policy_finding)
    elif binding.policy_finding is not None:
        c.print()
        c.print(
            "[dim]No IAM actions extracted from this policy (empty or unparseable).[/]"
        )

    if binding.policy_finding is not None:
        concerns = _critical_concerns(binding.policy_finding)
        if concerns:
            c.print()
            c.print("[bold]Critical concerns (if any):[/]")
            for msg in concerns:
                c.print(f"  [yellow]⚠️[/]  {msg}")

    if binding.policy_source == "not_found" and src.role_arn:
        c.print()
        c.print(
            f"[dim]ℹ️  Policy not found in repo for role: {src.role_arn}[/]"
        )
        c.print(
            "[dim]💡  Run with --aws-verify to fetch live policies from AWS[/]"
        )

    if binding.policy_source == "dynamic_reference" and src.role_arn:
        c.print()
        c.print(
            f"[dim]ℹ️  Role ARN is a dynamic reference: {src.role_arn}[/]"
        )
        c.print(
            "[dim]💡  Provide Terraform or policy JSON in repo for static analysis[/]"
        )

    c.print()


def _render_actions_table(c: Console, finding: PolicyFinding) -> None:
    actions = sorted(
        finding.actions,
        key=lambda a: (-a.risk_level.value, a.action),
    )
    table = Table(box=box.SQUARE, show_header=True, header_style="bold")
    table.add_column("Action", no_wrap=False)
    table.add_column("Access", no_wrap=True)
    table.add_column("Risk", no_wrap=True)

    for action in actions:
        risk_txt = Text(
            f"{RISK_ICONS[action.risk_level]} {_risk_short(action.risk_level)}",
            style=RISK_COLORS[action.risk_level],
        )
        table.add_row(action.action, action.access_level, risk_txt)

    c.print()
    c.print(table)


def _render_privesc_paths(c: Console, finding: PolicyFinding) -> None:
    if not finding.privesc_paths:
        return

    c.print()
    c.print("[bold red]🔴 Privilege Escalation Paths Detected:[/]")
    for path in finding.privesc_paths:
        c.print(f"  [red]↳[/] {path.path_name}: {path.description}")


def _render_github_token_section(c: Console, result: ScanResult) -> None:
    notable = [
        p for p in result.github_token_permissions if p.risk_level > RiskLevel.LOW
    ]
    if not notable:
        return

    c.print()
    c.rule("[bold]GITHUB_TOKEN Permissions[/]", style="dim")
    c.print()

    for permission in notable:
        icon = RISK_ICONS[permission.risk_level]
        wf = _workflow_basename(permission.workflow_file)
        scope_line = f"{permission.scope}: {permission.access}"
        if permission.job_name:
            loc = f"{wf} — job: {permission.job_name}"
        else:
            loc = f"{wf} — workflow level"
        hint = _token_permission_hint(permission)
        c.print(
            f"{icon} [bold]{scope_line}[/] [dim]({loc})[/] — {hint}"
        )


def _render_compromised_actions_section(
    c: Console,
    findings: list[CompromisedActionFinding],
) -> None:
    if not findings:
        return

    c.print()
    c.rule(
        f"[bold red]⛔ KNOWN COMPROMISED ACTIONS ({len(findings)} found)[/]",
        style="red",
    )
    c.print()
    for finding in findings:
        wf = _workflow_basename(finding.workflow_file)
        c.print(f"[bold red]⛔ {finding.risk_level.name}: {finding.uses_ref}[/]")
        c.print(f"   Workflow: {wf} → {finding.job_name} → {finding.step_name}")
        c.print(
            f"   Status: Compromised {finding.compromise_date} — documented "
            "supply-chain compromise"
        )
        c.print(
            "   Impact: Mutable tags may run credential-stealing code in this job"
        )
        c.print("   Fix: Remove this action OR pin to a verified pre-compromise SHA")
        c.print(f"   Advisory: {finding.advisory_url}")


def _render_oidc_trust_section(
    c: Console,
    findings: list[OidcTrustFinding],
) -> None:
    if not findings:
        return

    c.print()
    c.rule(f"[bold]OIDC Trust Policy Issues ({len(findings)} found)[/]", style="dim")
    c.print()
    for finding in findings:
        icon = RISK_ICONS[finding.risk_level]
        c.print(
            f"{icon} [bold]{finding.risk_level.name}:[/] "
            f"{finding.issue_description}"
        )
        c.print(
            f"   Role: {finding.role_name} "
            f"([dim]{_workflow_basename(finding.source_file)}[/])"
        )
        c.print(f"   Condition: {finding.evidence}")
        c.print(f"   Risk: {finding.risk_level.name}")
        c.print(f"   Fix: {finding.recommendation}")


def _render_environment_section(
    c: Console,
    findings: list[EnvironmentFinding],
) -> None:
    if not findings:
        return

    c.print()
    c.rule(f"[bold]GitHub Environment Issues ({len(findings)} found)[/]", style="dim")
    c.print()
    for finding in findings:
        icon = RISK_ICONS[finding.risk_level]
        wf = _workflow_basename(finding.workflow_file)
        c.print(
            f"{icon} [bold]{finding.risk_level.name}:[/] {wf} → "
            f"{finding.job_name} — {finding.finding_type.replace('_', ' ')}"
        )
        if finding.role_arn:
            c.print(f"   AWS Role: {finding.role_arn}")
        if finding.environment_name:
            c.print(f"   Environment: {finding.environment_name}")
        c.print(f"   Risk: {finding.description}")
        c.print(f"   Fix: {finding.recommendation}")


def _render_script_injection_section(
    c: Console,
    findings: list[ScriptInjectionFinding],
) -> None:
    if not findings:
        return

    c.print()
    c.rule(f"[bold]Script Injection Risks ({len(findings)} found)[/]", style="dim")
    c.print()
    for finding in findings:
        icon = RISK_ICONS[finding.risk_level]
        wf = _workflow_basename(finding.workflow_file)
        c.print(
            f"{icon} [bold]{finding.risk_level.name}:[/] Direct script injection "
            f"in {wf} → {finding.job_name} → {finding.step_name}"
        )
        c.print(f"   Expression: {finding.untrusted_expression}")
        c.print("   Method: Direct interpolation in run: block")
        c.print(f"   Risk: {finding.description}")
        c.print(f"   Fix: {finding.recommendation}")


def _render_artifact_poisoning_section(
    c: Console,
    findings: list[ArtifactPoisoningFinding],
) -> None:
    if not findings:
        return

    c.print()
    c.rule(f"[bold]Artifact Poisoning Risks ({len(findings)} found)[/]", style="dim")
    c.print()
    for finding in findings:
        icon = RISK_ICONS[finding.risk_level]
        wf = _workflow_basename(finding.workflow_file)
        c.print(
            f"{icon} [bold]{finding.risk_level.name}:[/] workflow_run artifact "
            f"execution in {wf} → {finding.job_name}"
        )
        c.print(f"   Risk: {finding.description}")
        c.print(f"   Fix: {finding.recommendation}")


def _render_ai_agent_section(
    c: Console,
    findings: list[AiAgentInjectionFinding],
) -> None:
    if not findings:
        return

    c.print()
    c.rule(
        f"[bold]AI Agent Prompt Injection Surfaces ({len(findings)} found)[/]",
        style="dim",
    )
    c.print()
    for finding in findings:
        icon = RISK_ICONS[finding.risk_level]
        wf = _workflow_basename(finding.workflow_file)
        c.print(
            f"{icon} [bold]{finding.risk_level.name}:[/] AI Agent Prompt "
            f"Injection Surface — {wf} → {finding.step_name}"
        )
        c.print(
            f"   {finding.agent_type} is configured with "
            f"{_agent_permission_label(finding)} "
            f"and trigger risk={finding.untrusted_trigger}."
        )
        if finding.untrusted_inputs:
            c.print(f"   Inputs: {', '.join(finding.untrusted_inputs)}")
        c.print(f"   Fix: {finding.recommendation}")


def _render_unpinned_actions_section(
    c: Console,
    findings: list[UnpinnedActionFinding],
) -> None:
    if not findings:
        return

    c.print()
    c.rule(f"[bold]Unpinned Actions ({len(findings)} found)[/]", style="dim")
    c.print()

    displayed = findings[:10]
    for finding in displayed:
        wf = _workflow_basename(finding.workflow_file)
        pin_label = {
            "tag": "version tag",
            "branch": "branch",
            "short_sha": "Short SHA",
            "unresolvable": "missing ref",
        }.get(finding.pin_type, finding.pin_type)
        c.print(
            f"🟡 [bold]{wf}[/] [dim]→[/] {finding.job_name} "
            f"[dim]→[/] {finding.step_name}"
        )
        c.print(f"   {finding.uses} ({pin_label} — not SHA-pinned)")
        if finding.pin_type == "short_sha":
            c.print(
                "   [yellow]A short SHA is still mutable or ambiguous. Only a "
                "full 40-character commit SHA is immutable.[/]"
            )

    remaining = len(findings) - len(displayed)
    if remaining > 0:
        c.print(f"[dim]... and {remaining} more[/]")

    c.print()
    c.print(
        "[dim]ℹ️  SHA-pinned actions prevent supply-chain attacks like the "
        "March 2025 tj-actions compromise (23,000+ repos affected).[/]"
    )
    c.print(
        "[dim]💡  Use https://github.com/mheap/pin-github-action to automate "
        "pinning.[/]"
    )


def _render_pin_suggestions_section(c: Console, suggestions: list) -> None:
    if not suggestions:
        return

    c.print()
    c.rule("[bold]Pin Suggestions (resolved via GitHub API)[/]", style="dim")
    c.print()
    for pin in suggestions:
        original = _pin_value(pin, "original_ref")
        pinned = _pin_value(pin, "pinned_ref")
        error = _pin_value(pin, "error")
        c.print(f"  {original}")
        if error:
            c.print(f"  [yellow]→ unresolved: {error}[/]")
        else:
            c.print(f"  [green]→ {pinned}[/]")
        c.print()
    c.print(
        "[dim]SHA shown is current as of scan time. Verify with git ls-remote "
        "before committing the replacement.[/]"
    )


def _pin_value(pin: object, key: str) -> object:
    if isinstance(pin, dict):
        return pin.get(key)
    return getattr(pin, key, None)


def _agent_permission_label(finding: AiAgentInjectionFinding) -> str:
    if finding.has_write_permissions:
        return "write permissions"
    return "limited permissions"


def _render_unmatched_policies(c: Console, findings: list[PolicyFinding]) -> None:
    if not findings:
        return

    c.print()
    c.print("[bold]IAM Policies Found (not linked to a workflow):[/]")
    c.rule(style="dim")
    c.print()

    for finding in findings:
        icon = RISK_ICONS[finding.overall_risk]
        summary = _unmatched_summary(finding)
        c.print(
            Text.assemble(
                (f"{icon} ", ""),
                (finding.source_file, "bold"),
                (" — ", ""),
                (finding.overall_risk.name, RISK_COLORS[finding.overall_risk]),
                (" — ", ""),
                (summary, ""),
            )
        )


def _unmatched_summary(finding: PolicyFinding) -> str:
    if finding.has_passrole:
        return "includes iam:PassRole"
    if finding.actions:
        return f"includes {finding.actions[0].action}"
    return "policy analyzed"


def _render_summary_panel(
    c: Console,
    result: ScanResult,
    delta: object | None = None,
) -> None:
    policies_analyzed = len(result.policy_findings)
    policies_not_found = sum(
        1 for b in result.bindings if b.policy_source == "not_found"
    )
    counts = _iam_action_risk_counts(result.policy_findings)

    risk_line = (
        f"Critical: {counts[RiskLevel.CRITICAL]} | "
        f"High: {counts[RiskLevel.HIGH]} | "
        f"Medium: {counts[RiskLevel.MEDIUM]} | "
        f"Low: {counts[RiskLevel.LOW]}"
    )
    if counts[RiskLevel.INFO]:
        risk_line += f" | Info: {counts[RiskLevel.INFO]}"

    workflow_injection_count = (
        len(result.script_injection_findings)
        + len(result.artifact_poisoning_findings)
        + len(result.ai_agent_injection_findings)
    )

    summary_lines = Text.assemble(
        ("Summary\n", "bold"),
        (f"Workflows scanned: {result.workflow_count}\n", ""),
        (f"AWS credential sources: {len(result.credential_sources)}\n", ""),
        (f"Policies analyzed: {policies_analyzed}\n", ""),
        (f"Policies not found: {policies_not_found}\n", ""),
        (f"OIDC trust issues: {len(result.oidc_trust_findings)}\n", ""),
        (
            f"Known-compromised actions: "
            f"{len(result.compromised_action_findings)}\n",
            "",
        ),
        (f"Environment issues: {len(result.environment_findings)}\n", ""),
        (
            f"Workflow injection risks: {workflow_injection_count}\n",
            "",
        ),
        ("\n", ""),
        (risk_line, ""),
    )
    if result.compromised_action_findings:
        summary_lines.append(
            "\n⛔ IMMEDIATE ACTION REQUIRED: "
            f"{len(result.compromised_action_findings)} workflow(s) use "
            "known-compromised actions.",
            style="bold red",
        )
    if delta is not None and getattr(delta, "new_compromised_actions", []):
        summary_lines.append(
            "\n⛔ NEW: "
            f"{len(getattr(delta, 'new_compromised_actions', []))} "
            "newly-known-compromised action(s) detected since last scan.",
            style="bold red",
        )

    c.print()
    c.print(Panel(summary_lines, box=box.ROUNDED, padding=(0, 2)))


def _delta_header_lines(delta: object | None) -> tuple:
    if delta is None:
        return tuple()
    if not getattr(delta, "risk_changed", False):
        return tuple()
    def _risk_label(value: object) -> str:
        if hasattr(value, "name"):
            return value.name
        return str(value).upper()

    previous = _risk_label(getattr(delta, "previous_overall_risk", "unknown"))
    current = _risk_label(getattr(delta, "current_overall_risk", "unknown"))
    if getattr(delta, "risk_increased", False):
        direction = "⬆️  (risk increased)"
        style = "bold red"
    elif getattr(delta, "risk_decreased", False):
        direction = "⬇️  (risk decreased — good)"
        style = "green"
    else:
        direction = ""
        style = ""
    return (("\n", ""), (f"Risk Change: {previous} → {current} {direction}", style))


def render_no_aws_found(console: Optional[Console] = None) -> None:
    """Render a message when no AWS credential sources are found."""
    try:
        c = console if console is not None else Console()
        body = Text.assemble(
            ("ActionScope — No AWS Access Found\n\n", "bold"),
            (
                "No GitHub Actions workflows were found that configure "
                "AWS credentials.\n\n",
                "",
            ),
            (
                "This repo may not use AWS, or credentials may be configured outside "
                "of workflows.",
                "dim",
            ),
        )
        c.print(
            Panel(
                body,
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )
    except Exception:
        return


def render_error(message: str, console: Optional[Console] = None) -> None:
    """Render a fatal error message in red."""
    try:
        c = console if console is not None else Console()
        c.print(f"[bold red]{message}[/]")
    except Exception:
        return


def render_from_dict(data: dict, console: Optional[Console] = None) -> None:
    """Render a saved ActionScope JSON payload without re-scanning."""
    try:
        c = console if console is not None else Console()
        risk = str(data.get("overall_risk", "info")).lower()
        risk_label = risk.upper()
        summary = data.get("summary", {})
        body = Text.assemble(
            ("ActionScope — Blast Radius Report\n", "bold"),
            (f"Path: {data.get('scan_path', '(unknown)')}\n", ""),
            (
                f"Workflows: {data.get('workflow_count', 0)} | "
                f"Credential Sources: {summary.get('credential_sources', 0)}\n",
                "",
            ),
            (f"Overall Risk: {risk_label}", ""),
        )
        c.print(Panel(body, box=box.ROUNDED, padding=(0, 2)))

        compromised = data.get("compromised_action_findings", [])
        if compromised:
            c.print()
            c.rule(
                f"[bold red]⛔ KNOWN COMPROMISED ACTIONS "
                f"({len(compromised)} found)[/]"
            )
            for finding in compromised:
                c.print(
                    f"⛔ {finding.get('risk_level', 'critical').upper()}: "
                    f"{finding.get('uses_ref', '')}"
                )
                c.print(f"   Advisory: {finding.get('advisory_url', '')}")

        findings = data.get("findings", [])
        for finding in findings:
            c.print()
            c.print(
                f"[bold]Workflow:[/] "
                f"{_workflow_basename(str(finding.get('workflow_file', '')))} "
                f"[dim]→[/] [bold]Job:[/] {finding.get('job_name', '')}"
            )
            c.print(f"[bold]AWS Role:[/] {finding.get('role_arn') or '(none)'}")
            c.print(f"[bold]Policy Source:[/] {finding.get('policy_source')}")
            if finding.get("match_confidence"):
                c.print(
                    f"[bold]Match Confidence:[/] "
                    f"{finding.get('match_confidence')}"
                )
            actions = finding.get("actions", [])
            if actions:
                table = Table(box=box.SQUARE, show_header=True)
                table.add_column("Action")
                table.add_column("Access")
                table.add_column("Risk")
                for action in actions:
                    table.add_row(
                        str(action.get("action", "")),
                        str(action.get("access_level", "")),
                        str(action.get("risk_level", "")).upper(),
                    )
                c.print(table)

        unpinned = data.get("unpinned_actions", [])
        if unpinned:
            c.print()
            c.rule(f"[bold]Unpinned Actions ({len(unpinned)} found)[/]")
            for finding in unpinned[:10]:
                c.print(
                    f"🟡 {_workflow_basename(str(finding.get('workflow_file', '')))} "
                    f"→ {finding.get('job_name', '')} → "
                    f"{finding.get('step_name', '')}"
                )
                c.print(
                    f"   {finding.get('uses', '')} "
                    f"({finding.get('pin_type', '')} — not SHA-pinned)"
                )
        pin_suggestions = data.get("pin_suggestions", [])
        if pin_suggestions:
            c.print()
            c.rule("[bold]Pin Suggestions (resolved via GitHub API)[/]")
            for pin in pin_suggestions:
                c.print(f"  {pin.get('original_ref', '')}")
                if pin.get("error"):
                    c.print(f"  → unresolved: {pin.get('error')}")
                else:
                    c.print(f"  → {pin.get('pinned_ref', '')}")
        for key, title in (
            ("oidc_trust_findings", "OIDC Trust Policy Issues"),
            ("environment_findings", "GitHub Environment Issues"),
            ("script_injection_findings", "Script Injection Risks"),
            ("artifact_poisoning_findings", "Artifact Poisoning Risks"),
            ("ai_agent_injection_findings", "AI Agent Prompt Injection Surfaces"),
        ):
            items = data.get(key, [])
            if items:
                c.print()
                c.rule(f"[bold]{title} ({len(items)} found)[/]")
                for item in items[:10]:
                    c.print(
                        f"{str(item.get('risk_level', 'info')).upper()}: "
                        f"{item.get('issue_description') or item.get('description')}"
                    )
    except Exception as exc:
        render_error(f"Could not render ActionScope JSON report: {exc}", console)
