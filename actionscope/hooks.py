"""Offline workflow pinning gate for local and pre-commit use."""

from __future__ import annotations

import click

from actionscope.parsers.workflow import (
    classify_action_ref,
    find_unpinned_action_uses,
    find_workflow_files,
    parse_workflow_file,
)


@click.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def main(path: str) -> None:
    """Check workflow action and reusable-workflow pins without network access."""
    failures = 0
    invalid = False
    for workflow_file in find_workflow_files(path):
        data = parse_workflow_file(workflow_file)
        if data is None:
            click.echo(f"Could not parse workflow: {workflow_file}", err=True)
            invalid = True
            continue
        findings = find_unpinned_action_uses(data, workflow_file)
        jobs = data.get("jobs") or {}
        if isinstance(jobs, dict):
            for name, job in jobs.items():
                uses = job.get("uses") if isinstance(job, dict) else None
                if isinstance(uses, str) and classify_action_ref(uses.strip()) not in (
                    "sha", "local"
                ):
                    findings.append({"job_name": name, "uses": uses.strip()})
        for finding in findings:
            uses = finding["uses"]
            if uses.startswith("$/"):
                continue
            failures += 1
            click.echo(
                f"{workflow_file}: {finding['job_name']}: unpinned {uses}", err=True
            )
    if invalid:
        raise click.exceptions.Exit(2)
    if failures:
        click.echo(
            "Pin external actions to full commit SHAs; use scan --resolve-pins "
            "to look up current tags, then review the suggestions.", err=True
        )
        raise click.exceptions.Exit(1)
