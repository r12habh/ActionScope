"""GitHub Environments OIDC security analyzer.

Detects deploy jobs that assume AWS roles without GitHub Environment
protection and jobs whose environment usage does not line up with IAM OIDC
trust-policy scoping.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from actionscope.models import (
    AwsCredentialSource,
    EnvironmentFinding,
    OidcTrustFinding,
    RiskLevel,
)
from actionscope.parsers.workflow import (
    GitHubWorkflowLoader,
    extract_aws_credential_sources,
)

DEPLOY_JOB_NAME_HINTS = ("deploy", "release", "publish", "prod", "production")
DEPLOY_CREDENTIAL_HINTS = ("deploy", "release", "publish")
DEPLOY_STEP_HINTS = (
    "terraform apply",
    "aws s3 sync",
    "aws cloudformation deploy",
    "sam deploy",
    "serverless deploy",
    "kubectl apply",
    "helm upgrade",
)
DEPLOY_ACTION_HINTS = (
    "aws-actions/aws-cloudformation-github-deploy",
    "aws-actions/amazon-ecs-deploy-task-definition",
)


def extract_job_environments(workflow_data: dict) -> list[dict]:
    """Extract environment declarations from each job in a workflow."""
    environments: list[dict] = []
    jobs = workflow_data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return environments

    for job_name, job in jobs.items():
        environment = None
        environment_url = None
        if isinstance(job, dict):
            raw_environment = job.get("environment")
            if isinstance(raw_environment, str):
                environment = raw_environment
            elif isinstance(raw_environment, dict):
                name = raw_environment.get("name")
                url = raw_environment.get("url")
                environment = str(name) if name is not None else None
                environment_url = str(url) if url is not None else None
        environments.append(
            {
                "job_name": str(job_name),
                "environment": environment,
                "environment_url": environment_url,
            }
        )

    return environments


def is_deploy_job(
    job_data: dict,
    credential_sources: list,
) -> bool:
    """Return True if a job appears to deploy production infrastructure."""
    job_name = str(job_data.get("__job_name") or "").lower()
    if job_name and any(hint in job_name for hint in DEPLOY_JOB_NAME_HINTS):
        return True

    for step in _steps(job_data):
        run_block = step.get("run")
        if isinstance(run_block, str):
            lowered = run_block.lower()
            if any(hint in lowered for hint in DEPLOY_STEP_HINTS):
                return True
        uses = step.get("uses")
        if isinstance(uses, str) and any(
            hint in uses.lower() for hint in DEPLOY_ACTION_HINTS
        ):
            return True

    for source in credential_sources:
        if getattr(source, "job_name", None) != job_data.get("__job_name"):
            continue
        source_text = " ".join(
            str(part or "").lower()
            for part in (
                getattr(source, "role_arn", ""),
                getattr(source, "step_name", ""),
            )
        )
        if any(hint in source_text for hint in DEPLOY_CREDENTIAL_HINTS):
            return True

    return False


def analyze_environment_usage(
    workflow_data: dict,
    workflow_file: str,
    credential_sources: list,
    oidc_trust_findings: list,
) -> list[EnvironmentFinding]:
    """Analyze workflow environment declarations for AWS deploy jobs."""
    jobs = workflow_data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return []

    findings: list[EnvironmentFinding] = []
    environment_by_job = {
        item["job_name"]: item["environment"]
        for item in extract_job_environments(workflow_data)
    }

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_name_str = str(job_name)
        sources = _matching_sources(workflow_file, job_name_str, credential_sources)
        if not sources:
            continue
        job_with_name = dict(job)
        job_with_name["__job_name"] = job_name_str
        if not is_deploy_job(job_with_name, credential_sources):
            continue

        environment = environment_by_job.get(job_name_str)
        role_arn = _first_role_arn(sources)
        if not environment:
            findings.append(
                EnvironmentFinding(
                    workflow_file=workflow_file,
                    job_name=job_name_str,
                    environment_name=None,
                    has_aws_credentials=True,
                    role_arn=role_arn,
                    finding_type="deploy_without_environment",
                    risk_level=RiskLevel.MEDIUM,
                    description=(
                        "AWS deploy job does not declare a GitHub Environment, "
                        "so environment protection rules cannot gate role access."
                    ),
                    recommendation=(
                        "Add environment: production to this job and configure "
                        "required reviewers in GitHub Settings -> Environments."
                    ),
                )
            )
            continue

        if _trust_uses_environment(oidc_trust_findings, environment, role_arn):
            continue
        if _trust_uses_ref(oidc_trust_findings, role_arn):
            findings.append(
                EnvironmentFinding(
                    workflow_file=workflow_file,
                    job_name=job_name_str,
                    environment_name=environment,
                    has_aws_credentials=True,
                    role_arn=role_arn,
                    finding_type="environment_not_in_trust_policy",
                    risk_level=RiskLevel.MEDIUM,
                    description=(
                        f"Workflow uses environment '{environment}', but the "
                        "related OIDC trust evidence is branch scoped rather "
                        "than environment scoped."
                    ),
                    recommendation=(
                        "Update the IAM trust policy subject to use "
                        f":environment:{environment} instead of :ref: scoping."
                    ),
                )
            )

    return findings


def scan_environment_usage(
    repo_path: str,
    credential_sources: list,
    oidc_trust_findings: list,
) -> tuple[list[EnvironmentFinding], list[str]]:
    """Scan workflow files for GitHub Environment hardening opportunities."""
    findings: list[EnvironmentFinding] = []
    errors: list[str] = []
    for workflow_file in _workflow_files(repo_path):
        try:
            with workflow_file.open("r", encoding="utf-8") as handle:
                workflow_data = yaml.load(handle, Loader=GitHubWorkflowLoader)
        except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError) as exc:
            errors.append(f"Could not read workflow file {workflow_file}: {exc}")
            continue
        except yaml.YAMLError as exc:
            errors.append(f"Could not parse workflow file {workflow_file}: {exc}")
            continue
        if not isinstance(workflow_data, dict):
            continue
        workflow_sources = _sources_for_workflow(
            str(workflow_file.resolve()),
            workflow_data,
            credential_sources,
        )
        findings.extend(
            analyze_environment_usage(
                workflow_data,
                str(workflow_file.resolve()),
                workflow_sources,
                oidc_trust_findings,
            )
        )
    return findings, errors


def _matching_sources(
    workflow_file: str,
    job_name: str,
    credential_sources: list,
) -> list[AwsCredentialSource]:
    return [
        source
        for source in credential_sources
        if getattr(source, "job_name", None) == job_name
        and getattr(source, "workflow_file", None) == workflow_file
    ]


def _sources_for_workflow(
    workflow_file: str,
    workflow_data: dict,
    credential_sources: list,
) -> list[AwsCredentialSource]:
    sources = [
        source
        for source in credential_sources
        if getattr(source, "workflow_file", None) == workflow_file
    ]
    if sources:
        return sources
    return extract_aws_credential_sources(workflow_data, workflow_file)


def _first_role_arn(sources: list[AwsCredentialSource]) -> str | None:
    for source in sources:
        if source.role_arn:
            return source.role_arn
    return None


def _trust_uses_environment(
    oidc_trust_findings: list[OidcTrustFinding],
    environment: str,
    role_arn: str | None,
) -> bool:
    target = f":environment:{environment}".lower()
    return any(
        _finding_matches_role(finding, role_arn)
        and target in str(finding.evidence).lower()
        for finding in oidc_trust_findings
    )


def _trust_uses_ref(
    oidc_trust_findings: list[OidcTrustFinding],
    role_arn: str | None,
) -> bool:
    return any(
        _finding_matches_role(finding, role_arn)
        and ":ref:refs/heads/" in str(finding.evidence).lower()
        for finding in oidc_trust_findings
    )


def _finding_matches_role(finding: OidcTrustFinding, role_arn: str | None) -> bool:
    if not role_arn:
        return False
    if finding.role_arn:
        return finding.role_arn == role_arn
    if finding.role_name:
        return f":role/{finding.role_name}" in role_arn
    return False


def _steps(job_data: dict) -> list[dict]:
    steps = job_data.get("steps") or []
    if not isinstance(steps, list):
        return []
    return [step for step in steps if isinstance(step, dict)]


def _workflow_files(repo_path: str) -> list[Path]:
    path = Path(repo_path).expanduser()
    if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}:
        return [path]
    workflow_dir = path / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    return sorted(workflow_dir.rglob("*.yml")) + sorted(workflow_dir.rglob("*.yaml"))
