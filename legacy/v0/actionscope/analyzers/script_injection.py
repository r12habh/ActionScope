"""Script injection detector for GitHub Actions workflows.

Detects direct interpolation of attacker-controlled GitHub Actions context
values into ``run:`` shell commands.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

from actionscope.models import RiskLevel, ScriptInjectionFinding

UNTRUSTED_CONTEXTS = [
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.head_ref",
    "github.event.pull_request.head.label",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.pages",
    "github.event.commits",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.pusher.email",
    "github.event.pusher.name",
    "github.event.discussion.title",
    "github.event.discussion.body",
]

INJECTION_PATTERN = re.compile(
    r"\$\{\{[^}]*("
    + "|".join(re.escape(ctx) for ctx in UNTRUSTED_CONTEXTS)
    + r")[^}]*\}\}",
    re.IGNORECASE,
)


class _WorkflowLoader(yaml.SafeLoader):
    """YAML loader that keeps GitHub's ``on`` key as a string."""


_WorkflowLoader.yaml_implicit_resolvers = {
    key: [
        (tag, regexp)
        for tag, regexp in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def find_untrusted_expressions_in_text(text: str) -> list[str]:
    """Return unique untrusted GitHub context expressions found in text."""
    seen: set[str] = set()
    expressions: list[str] = []
    for match in INJECTION_PATTERN.finditer(text or ""):
        expression = match.group(0)
        if expression not in seen:
            seen.add(expression)
            expressions.append(expression)
    return expressions


def is_run_step(step: dict) -> bool:
    """Return True if the step has a string run command."""
    return isinstance(step.get("run"), str)


def is_via_env(step: dict, expression: str) -> bool:
    """Return True when an untrusted expression is first assigned via env."""
    env_block = step.get("env")
    run_block = step.get("run")
    if not isinstance(env_block, dict) or not isinstance(run_block, str):
        return False
    if expression in run_block:
        return False
    return any(
        isinstance(value, str) and expression in value
        for value in env_block.values()
    )


def analyze_step_for_injection(
    step: dict,
    job_name: str,
    workflow_file: str,
    trigger_context: str = "other",
) -> list[ScriptInjectionFinding]:
    """Check a single step for direct script injection vulnerabilities."""
    if not is_run_step(step):
        return []

    run_block = str(step.get("run", ""))
    findings: list[ScriptInjectionFinding] = []
    for expression in find_untrusted_expressions_in_text(run_block):
        if is_via_env(step, expression):
            continue
        risk = _risk_for_trigger(trigger_context)
        findings.append(
            ScriptInjectionFinding(
                workflow_file=workflow_file,
                job_name=job_name,
                step_name=str(step.get("name") or "run"),
                run_snippet=_snippet(run_block),
                untrusted_expression=expression,
                injection_method="direct",
                risk_level=risk,
                description=(
                    "Attacker-controlled GitHub event data is interpolated "
                    "directly into a shell command."
                ),
                recommendation=(
                    "Assign the value to an environment variable first and "
                    "reference the quoted variable from the run block."
                ),
            )
        )
    return findings


def scan_workflow_for_injections(
    workflow_data: dict,
    workflow_file: str,
) -> list[ScriptInjectionFinding]:
    """Scan all jobs and steps in a workflow for script injection."""
    trigger_context = _trigger_context(workflow_data.get("on"))
    jobs = workflow_data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return []

    findings: list[ScriptInjectionFinding] = []
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for step in steps:
            if isinstance(step, dict):
                findings.extend(
                    analyze_step_for_injection(
                        step,
                        str(job_name),
                        workflow_file,
                        trigger_context=trigger_context,
                    )
                )
    return findings


def scan_workflows_for_injection(
    repo_path: str,
) -> tuple[list[ScriptInjectionFinding], list[str]]:
    """Find workflow YAML files and scan them for script injection."""
    findings: list[ScriptInjectionFinding] = []
    errors: list[str] = []
    workflow_dir = Path(repo_path).expanduser() / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return findings, errors

    for workflow_file in sorted(
        list(workflow_dir.rglob("*.yml")) + list(workflow_dir.rglob("*.yaml"))
    ):
        try:
            with workflow_file.open("r", encoding="utf-8") as handle:
                workflow_data = yaml.load(handle, Loader=_WorkflowLoader)
        except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError) as exc:
            errors.append(f"Could not read workflow file {workflow_file}: {exc}")
            continue
        except yaml.YAMLError as exc:
            errors.append(f"Could not parse workflow file {workflow_file}: {exc}")
            continue
        if isinstance(workflow_data, dict):
            findings.extend(
                scan_workflow_for_injections(
                    workflow_data,
                    str(workflow_file.resolve()),
                )
            )
    return findings, errors


def _trigger_context(on_block: Any) -> str:
    triggers = _trigger_names(on_block)
    if {"pull_request_target", "workflow_run"} & triggers:
        return "high_risk"
    if "pull_request" in triggers:
        return "pull_request"
    if "push" in triggers:
        return "push"
    return "other"


def _trigger_names(on_block: Any) -> set[str]:
    if isinstance(on_block, str):
        return {on_block}
    if isinstance(on_block, list):
        return {str(item) for item in on_block}
    if isinstance(on_block, dict):
        return {str(key) for key in on_block}
    return set()


def _risk_for_trigger(trigger_context: str) -> RiskLevel:
    if trigger_context == "high_risk":
        return RiskLevel.CRITICAL
    if trigger_context in {"pull_request", "push"}:
        return RiskLevel.HIGH
    return RiskLevel.MEDIUM


def _snippet(run_block: str) -> str:
    cleaned = " ".join(run_block.split())
    return cleaned[:200]


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)
