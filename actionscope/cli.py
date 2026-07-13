"""Click command-line entrypoint for running ActionScope scans."""

from __future__ import annotations

import os
import sys

import click
from rich.console import Console

from actionscope import __version__
from actionscope.analyzers.reusable_workflows import (
    ReusableWorkflowScan,
    scan_reusable_workflows,
)
from actionscope.analyzers.risk_engine import build_scan_result
from actionscope.models import PolicyFinding, RiskLevel, ScanResult
from actionscope.parsers.policy_json import scan_policy_files
from actionscope.parsers.terraform import scan_terraform_files
from actionscope.parsers.workflow import (
    find_workflow_files,
    parse_workflow_file,
    scan_workflows,
)
from actionscope.reporters.json_reporter import to_json, write_json
from actionscope.reporters.markdown import to_markdown, write_markdown
from actionscope.reporters.terminal import render_no_aws_found, render_scan_result


@click.group()
@click.version_option(
    __version__,
    "--version",
    prog_name="ActionScope",
    message="%(prog)s v%(version)s",
)
def main() -> None:
    """ActionScope — Map the AWS blast radius of your GitHub Actions
    workflows and AI agent configs."""
    pass


@main.command("version", hidden=True)
def version_command() -> None:
    """Print ActionScope version."""
    click.echo(f"ActionScope v{__version__}")


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--output-format",
    "-f",
    default="terminal",
    type=click.Choice(["terminal", "json", "markdown", "sarif"]),
    help="Output format",
)
@click.option(
    "--output-file",
    "-o",
    default=None,
    help="Write output to file",
)
@click.option(
    "--fail-on",
    default=None,
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Exit with code 1 if risk >= this level",
)
@click.option(
    "--aws-verify",
    is_flag=True,
    default=False,
    help="Verify permissions via live AWS API calls (requires boto3)",
)
@click.option("--no-color", is_flag=True, default=False)
@click.option("--quiet", "-q", is_flag=True, default=False)
@click.option(
    "--save-state",
    is_flag=True,
    default=False,
    help="Save scan state to .actionscope/last_scan.json",
)
@click.option(
    "--load-state",
    is_flag=True,
    default=False,
    help="Load previous scan state and compute a delta",
)
@click.option(
    "--state-file",
    default=".actionscope/last_scan.json",
    help="Path to the ActionScope scan state file",
)
@click.option(
    "--resolve-pins",
    is_flag=True,
    default=False,
    help="Resolve unpinned action tags to current SHA via GitHub API",
)
@click.option(
    "--github-token",
    default=None,
    envvar="GITHUB_TOKEN",
    help="GitHub token for pin resolution and external reusable workflows",
)
@click.option(
    "--max-policy-files",
    type=int,
    default=None,
    help=(
        "Maximum number of JSON files OUTSIDE common policy directories "
        "(iam/, policies/, .github/, infra/, infrastructure/, terraform/) to "
        "scan for IAM policies. Common-dir files are always scanned in full. "
        "Default 800. Set to 0 to scan unlimited."
    ),
)
def scan(
    path: str,
    output_format: str,
    output_file: str | None,
    fail_on: str | None,
    aws_verify: bool,
    no_color: bool,
    quiet: bool,
    save_state: bool,
    load_state: bool,
    state_file: str,
    resolve_pins: bool,
    github_token: str | None,
    max_policy_files: int | None,
) -> None:
    """Scan a repository for AWS blast radius in GitHub Actions workflows."""

    repo_path = os.path.abspath(path)
    console = Console(no_color=no_color)
    status_console = (
        console
        if output_format == "terminal"
        else Console(no_color=no_color, stderr=True)
    )

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
            github_token=github_token,
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
        # Click sets max_policy_files=None when the user does not pass the
        # flag; in that case, scan_policy_files uses its built-in default.
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

    all_policy_findings = json_findings + tf_findings
    all_errors = workflow_errors + json_errors + tf_errors

    if aws_verify:
        try:
            from actionscope.verifiers.aws_verifier import (
                check_boto3_available,
                extract_role_name_from_arn,
                verify_all_credential_sources,
            )

            check_boto3_available()
            status_console.print("[dim]Running AWS verification...[/dim]")
            aws_findings, aws_errors = verify_all_credential_sources(
                credential_sources
            )
            verified_role_names = {
                role_name.lower()
                for finding in aws_findings
                if finding.role_arn
                for role_name in [extract_role_name_from_arn(finding.role_arn)]
                if role_name
            }
            verified_role_arns = {
                finding.role_arn for finding in aws_findings if finding.role_arn
            }
            static_only = [
                finding
                for finding in all_policy_findings
                if not _finding_matches_verified_role(
                    finding,
                    verified_role_arns,
                    verified_role_names,
                )
            ]
            all_policy_findings = static_only + aws_findings
            all_errors.extend(aws_errors)
        except RuntimeError as exc:
            status_console.print(f"[red]AWS verification failed: {exc}[/red]")
            all_errors.append(f"AWS verification failed: {exc}")

    try:
        result = build_scan_result(
            repo_path=repo_path,
            credential_sources=credential_sources,
            github_token_perms=github_token_perms,
            policy_findings=all_policy_findings,
            unpinned_actions=unpinned_actions,
            errors=all_errors,
            reusable_scan=reusable_scan,
        )
    except Exception as exc:
        result = ScanResult(
            scan_path=repo_path,
            workflow_count=0,
            credential_sources=credential_sources,
            github_token_permissions=github_token_perms,
            unpinned_actions=unpinned_actions,
            policy_findings=all_policy_findings,
            errors=all_errors + [f"Could not correlate scan results: {exc}"],
        )

    if resolve_pins:
        status_console.print("[dim]Resolving action pins via GitHub API...[/dim]")
        result.pin_suggestions = _resolve_pin_suggestions(
            repo_path,
            github_token,
        )

    delta = None
    if load_state:
        from actionscope.state import compute_delta, load_scan_state

        delta = compute_delta(load_scan_state(state_file), result)
        result.delta = delta

    # Step 5: Handle a truly empty scan. Repos can have useful non-credential
    # findings such as OIDC trust-policy issues or script injection risks.
    if (
        not credential_sources
        and not _has_reportable_findings(result)
        and not result.errors
    ):
        if output_format == "terminal":
            if not quiet:
                render_no_aws_found(console)
            if output_file:
                write_markdown(result, output_file, delta=delta)
        elif output_format == "json":
            output = to_json(result)
            if output_file:
                write_json(result, output_file)
            else:
                print(output)
        elif output_format == "markdown":
            md = to_markdown(result, delta=delta)
            if output_file:
                write_markdown(result, output_file, delta=delta)
            else:
                print(md)
        elif output_format == "sarif":
            from actionscope.reporters.sarif import to_sarif, write_sarif

            output = to_sarif(result)
            if output_file:
                write_sarif(result, output_file)
                if not quiet:
                    status_console.print(
                        f"[dim]SARIF report written to {output_file}[/dim]"
                    )
            else:
                print(output)
        if save_state:
            _save_state(result, repo_path, state_file, status_console, quiet)
        _exit_with_fail_on(result, fail_on)

    # Step 6: Render output
    if output_format == "terminal":
        if not quiet:
            render_scan_result(result, console, delta=delta)
        if output_file:
            write_markdown(result, output_file, delta=delta)
    elif output_format == "json":
        output = to_json(result)
        if output_file:
            write_json(result, output_file)
        else:
            print(output)
    elif output_format == "markdown":
        md = to_markdown(result, delta=delta)
        if output_file:
            write_markdown(result, output_file, delta=delta)
        else:
            print(md)
    elif output_format == "sarif":
        from actionscope.reporters.sarif import to_sarif, write_sarif

        output = to_sarif(result)
        if output_file:
            write_sarif(result, output_file)
            if not quiet:
                status_console.print(
                    f"[dim]SARIF report written to {output_file}[/dim]"
                )
        else:
            print(output)

    if save_state:
        _save_state(result, repo_path, state_file, status_console, quiet)

    _exit_with_fail_on(result, fail_on)


@main.command()
@click.argument("json_file", required=False, type=click.Path(exists=True))
@click.option(
    "--from-json",
    "from_json",
    type=click.Path(exists=True),
    default=None,
    help="Saved ActionScope JSON scan result to render",
)
@click.option(
    "--format",
    "-f",
    "fmt",
    default="markdown",
    type=click.Choice(["markdown", "terminal", "json", "sarif"]),
    help="Output format",
)
def report(json_file: str | None, from_json: str | None, fmt: str) -> None:
    """Render a previously saved ActionScope JSON scan result."""
    import json as json_lib

    source = from_json or json_file
    if source is None:
        click.echo("Error: provide JSON_FILE or --from-json", err=True)
        sys.exit(2)

    try:
        with open(source, encoding="utf-8") as f:
            data = json_lib.load(f)
    except Exception as exc:
        click.echo(f"Error reading {source}: {exc}", err=True)
        sys.exit(2)

    if fmt == "json":
        click.echo(json_lib.dumps(data, indent=2))
    elif fmt == "markdown":
        from actionscope.reporters.markdown import to_markdown_from_dict

        click.echo(to_markdown_from_dict(data))
    elif fmt == "terminal":
        from actionscope.reporters.terminal import render_from_dict

        render_from_dict(data, Console())
    elif fmt == "sarif":
        from actionscope.reporters.sarif import to_sarif_from_dict

        click.echo(to_sarif_from_dict(data))


def _exit_with_fail_on(result: ScanResult, fail_on: str | None) -> None:
    if fail_on:
        fail_risk = RiskLevel(fail_on)
        if result.overall_risk >= fail_risk:
            sys.exit(1)
    sys.exit(0)


def _has_reportable_findings(result: ScanResult) -> bool:
    return any(
        (
            result.github_token_permissions,
            result.unpinned_actions,
            result.compromised_action_findings,
            result.environment_findings,
            result.policy_findings,
            result.oidc_trust_findings,
            result.script_injection_findings,
            result.artifact_poisoning_findings,
            result.ai_agent_injection_findings,
            result.reusable_workflows,
            result.errors,
        )
    )


def _resolve_pin_suggestions(
    repo_path: str,
    github_token: str | None,
) -> list:
    from actionscope.resolvers.pin_resolver import resolve_pins_for_workflow

    suggestions = []
    seen: set[str] = set()
    for workflow_file in find_workflow_files(repo_path):
        workflow_data = parse_workflow_file(workflow_file)
        if not isinstance(workflow_data, dict):
            continue
        for pin in resolve_pins_for_workflow(
            workflow_data,
            workflow_file,
            github_token=github_token,
        ):
            if pin.original_ref in seen:
                continue
            seen.add(pin.original_ref)
            suggestions.append(pin)
    return suggestions


def _save_state(
    result: ScanResult,
    repo_path: str,
    state_file: str,
    status_console: Console,
    quiet: bool,
) -> None:
    from actionscope.state import save_scan_state

    try:
        save_scan_state(result, repo_path, state_file)
    except (PermissionError, OSError) as exc:
        status_console.print(
            f"[yellow]Warning: could not save state to {state_file}: {exc}[/yellow]"
        )
        return
    if not quiet:
        status_console.print(f"[dim]State saved to {state_file}[/dim]")


def _finding_matches_verified_role(
    finding: PolicyFinding,
    verified_role_arns: set[str],
    verified_role_names: set[str],
) -> bool:
    if finding.role_arn in verified_role_arns:
        return True

    if finding.role_name and finding.role_name.lower() in verified_role_names:
        return True

    if finding.role_arn:
        role_tail = finding.role_arn.strip("/").rsplit("/", 1)[-1].lower()
        if role_tail in verified_role_names:
            return True

    source_file = finding.source_file.lower()
    if any(role_name in source_file for role_name in verified_role_names):
        return True

    try:
        with open(finding.source_file, encoding="utf-8") as source:
            source_text = source.read().lower()
    except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError) as exc:
        print(
            f"Warning: could not read policy finding source {finding.source_file}: "
            f"{exc}",
            file=sys.stderr,
        )
        return False

    return any(role_name in source_text for role_name in verified_role_names)
