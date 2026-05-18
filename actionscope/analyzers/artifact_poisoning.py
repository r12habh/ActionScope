"""Artifact poisoning detector.

Detects the ``workflow_run`` + artifact download + execution pattern that can
allow untrusted build artifacts to run in a privileged workflow context.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from actionscope.models import ArtifactPoisoningFinding, RiskLevel

EXECUTION_PATTERNS = [
    r"chmod\s+\+x",
    r"python\s+[\w./-]+\.py",
    r"bash\s+[\w./-]+\.sh",
    r"node\s+[\w./-]+\.js",
    r"\./[\w./-]+",
    r"sh\s+-c",
    r"npm\s+run\s+",
    r"make\s+",
]

_EXECUTION_RE = re.compile("|".join(EXECUTION_PATTERNS), re.IGNORECASE)
_SECRET_RE = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*}}", re.IGNORECASE)


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


def uses_workflow_run_trigger(workflow_data: dict) -> bool:
    """Return True if the workflow triggers on workflow_run."""
    return "workflow_run" in _trigger_names(workflow_data.get("on"))


def downloads_artifact_in_workflow(workflow_data: dict) -> bool:
    """Return True if any step downloads workflow artifacts."""
    return any(
        _is_download_artifact_step(step)
        for _job, step in _iter_steps(workflow_data)
    )


def executes_after_download(workflow_data: dict) -> bool:
    """Return True if a job appears to execute content after artifact download."""
    jobs = workflow_data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return False

    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        seen_download = False
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            if _is_download_artifact_step(step):
                seen_download = True
                continue
            run_block = step.get("run")
            if (
                seen_download
                and isinstance(run_block, str)
                and _EXECUTION_RE.search(run_block)
            ):
                return True
    return False


def workflow_accesses_secrets(workflow_data: dict) -> bool:
    """Return True if the workflow references non-GITHUB_TOKEN secrets."""
    for match in _SECRET_RE.finditer(_stringify(workflow_data)):
        if match.group(1).upper() != "GITHUB_TOKEN":
            return True
    return False


def analyze_artifact_poisoning(
    workflow_data: dict,
    workflow_file: str,
) -> list[ArtifactPoisoningFinding]:
    """Analyze a workflow for artifact poisoning risk."""
    if not uses_workflow_run_trigger(workflow_data):
        return []

    downloads = downloads_artifact_in_workflow(workflow_data)
    executes = executes_after_download(workflow_data)
    secrets = workflow_accesses_secrets(workflow_data)
    if not downloads:
        return []

    if executes and secrets:
        risk = RiskLevel.CRITICAL
    elif executes:
        risk = RiskLevel.HIGH
    else:
        risk = RiskLevel.MEDIUM

    return [
        ArtifactPoisoningFinding(
            workflow_file=workflow_file,
            job_name=job_name,
            risk_level=risk,
            has_workflow_run_trigger=True,
            downloads_artifacts=downloads,
            executes_artifacts=executes,
            has_secret_access=secrets,
            description=(
                "workflow_run workflow downloads artifacts and may execute "
                "content produced by a less-privileged workflow."
            ),
            recommendation=(
                "Verify artifact integrity before execution or pass only data, "
                "not executable code, between workflows."
            ),
        )
        for job_name in _jobs_with_downloads(workflow_data)
    ]


def scan_for_artifact_poisoning(
    repo_path: str,
) -> tuple[list[ArtifactPoisoningFinding], list[str]]:
    """Scan workflow files for artifact poisoning risk."""
    findings: list[ArtifactPoisoningFinding] = []
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
                analyze_artifact_poisoning(workflow_data, str(workflow_file.resolve()))
            )
    return findings, errors


def _is_download_artifact_step(step: dict) -> bool:
    uses = step.get("uses")
    return isinstance(uses, str) and uses.lower().strip().startswith(
        (
            "actions/download-artifact",
            "dawidd6/action-download-artifact",
        )
    )


def _iter_steps(workflow_data: dict) -> Any:
    jobs = workflow_data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for step in steps:
            if isinstance(step, dict):
                yield str(job_name), step


def _jobs_with_downloads(workflow_data: dict) -> list[str]:
    jobs: list[str] = []
    for job_name, step in _iter_steps(workflow_data):
        if _is_download_artifact_step(step) and job_name not in jobs:
            jobs.append(job_name)
    return jobs or [""]


def _trigger_names(on_block: Any) -> set[str]:
    if isinstance(on_block, str):
        return {on_block}
    if isinstance(on_block, list):
        return {str(item) for item in on_block}
    if isinstance(on_block, dict):
        return {str(key) for key in on_block}
    return set()


def _stringify(value: Any) -> str:
    if isinstance(value, dict):
        return "\n".join(_stringify(item) for item in value.values())
    if isinstance(value, list):
        return "\n".join(_stringify(item) for item in value)
    return str(value)
