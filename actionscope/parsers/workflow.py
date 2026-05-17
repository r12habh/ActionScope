"""GitHub Actions workflow YAML parser for discovering jobs and permissions."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

from actionscope.analyzers.github_token import analyze_workflow_permissions
from actionscope.models import (
    AwsCredentialSource,
    GitHubTokenPermission,
    UnpinnedActionFinding,
)

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


class GitHubWorkflowLoader(yaml.SafeLoader):
    """PyYAML loader that treats GitHub's ``on`` key as a string."""


GitHubWorkflowLoader.yaml_implicit_resolvers = {
    key: [
        (tag, regexp)
        for tag, regexp in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def find_workflow_files(repo_path: str) -> list[str]:
    """Find GitHub Actions workflow YAML files under a repository path."""
    workflow_dir = Path(repo_path).expanduser() / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []

    files = [
        path.resolve()
        for pattern in ("*.yml", "*.yaml")
        for path in workflow_dir.rglob(pattern)
        if path.is_file()
    ]
    return [str(path) for path in sorted(files)]


def parse_workflow_file(filepath: str) -> dict | None:
    """Parse a GitHub Actions workflow YAML file."""
    try:
        with Path(filepath).open("r", encoding="utf-8") as workflow_file:
            workflow_data = yaml.load(workflow_file, Loader=GitHubWorkflowLoader)
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as exc:
        _warn(f"Could not parse workflow file {filepath}: {exc}")
        return None

    if not workflow_data:
        _warn(f"Could not parse workflow file {filepath}: file is empty")
        return None

    if not isinstance(workflow_data, dict):
        _warn(f"Could not parse workflow file {filepath}: YAML root is not a mapping")
        return None

    if "on" not in workflow_data and "jobs" not in workflow_data:
        _warn(
            f"Could not parse workflow file {filepath}: "
            "missing GitHub Actions 'on' or 'jobs' key"
        )
        return None

    return workflow_data


def extract_aws_credential_sources(
    workflow_data: dict,
    workflow_file: str,
) -> list[AwsCredentialSource]:
    """Extract aws-actions/configure-aws-credentials usage from workflow data."""
    jobs = workflow_data.get("jobs")
    if jobs is None:
        return []
    if not isinstance(jobs, dict):
        return []

    credential_sources: list[AwsCredentialSource] = []
    workflow_has_oidc = _permissions_have_id_token_write(
        workflow_data.get("permissions")
    )

    for job_name, job_data in jobs.items():
        if not isinstance(job_data, dict):
            continue

        steps = job_data.get("steps", [])
        if not isinstance(steps, list):
            continue

        job_has_oidc = _permissions_have_id_token_write(job_data.get("permissions"))

        for step in steps:
            if not isinstance(step, dict):
                continue

            uses = step.get("uses")
            if not _is_configure_aws_credentials_action(uses):
                continue

            with_block = step.get("with", {})
            if not isinstance(with_block, dict):
                with_block = {}

            env_vars = extract_env_var_references(step)
            role_arn = _optional_string(with_block.get("role-to-assume"))

            credential_sources.append(
                AwsCredentialSource(
                    workflow_file=workflow_file,
                    job_name=str(job_name),
                    step_name=str(step.get("name") or uses),
                    role_arn=role_arn,
                    uses_access_keys=(
                        "aws-access-key-id" in with_block
                        or "AWS_ACCESS_KEY_ID" in env_vars
                    ),
                    uses_oidc=bool(role_arn and (workflow_has_oidc or job_has_oidc)),
                    aws_region=_optional_string(with_block.get("aws-region")),
                )
            )

    return credential_sources


def extract_env_var_references(step: dict) -> dict[str, str]:
    """Extract environment variable references from a workflow step."""
    env_block = step.get("env", {})
    if not isinstance(env_block, dict):
        return {}

    return {str(name): str(value) for name, value in env_block.items()}


def is_pinned_to_sha(uses_ref: str) -> bool:
    """
    Return True if a ``uses`` reference is pinned to a full commit SHA.

    Local actions are considered pinned because they are part of the checked-out
    repository. Docker actions are considered pinned only when they use an image
    digest.
    """
    if uses_ref.startswith(("./", "../")):
        return True
    if uses_ref.startswith("docker://"):
        return "@sha256:" in uses_ref
    if "@" not in uses_ref:
        return False

    ref = uses_ref.rsplit("@", 1)[1]
    return bool(SHA_PATTERN.fullmatch(ref))


def classify_action_ref(uses_ref: str) -> str:
    """
    Classify how an action reference is pinned.

    Returns one of: ``sha``, ``tag``, ``branch``, ``local``, or
    ``unresolvable``.
    """
    if uses_ref.startswith(("./", "../")):
        return "local"
    if uses_ref.startswith("docker://"):
        return "sha" if "@sha256:" in uses_ref else "tag"
    if "@" not in uses_ref:
        return "unresolvable"

    ref = uses_ref.rsplit("@", 1)[1]
    if SHA_PATTERN.fullmatch(ref):
        return "sha"
    if ref.startswith("v") or "." in ref:
        return "tag"
    return "branch"


def find_unpinned_action_uses(
    workflow_data: dict,
    workflow_file: str,
) -> list[dict]:
    """Find external action references that are not pinned to a commit SHA."""
    unpinned: list[dict] = []
    jobs = workflow_data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return unpinned

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue

        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue

            uses = step.get("uses")
            if not isinstance(uses, str):
                continue

            uses = uses.strip()
            pin_type = classify_action_ref(uses)
            if pin_type in ("sha", "local"):
                continue

            unpinned.append(
                {
                    "uses": uses,
                    "job_name": str(job_name),
                    "step_name": str(step.get("name", uses)),
                    "pin_type": pin_type,
                    "workflow_file": workflow_file,
                }
            )

    return unpinned


def scan_workflows(
    repo_path: str,
) -> tuple[
    list[AwsCredentialSource],
    list[GitHubTokenPermission],
    list[UnpinnedActionFinding],
    list[str],
]:
    """Scan GitHub Actions workflows for AWS credential and token findings."""
    credential_sources: list[AwsCredentialSource] = []
    token_permissions: list[GitHubTokenPermission] = []
    unpinned_actions: list[UnpinnedActionFinding] = []
    errors: list[str] = []

    for workflow_file in find_workflow_files(repo_path):
        workflow_data = parse_workflow_file(workflow_file)
        if workflow_data is None:
            errors.append(f"Could not parse workflow file: {workflow_file}")
            continue

        credential_sources.extend(
            extract_aws_credential_sources(workflow_data, workflow_file)
        )
        token_permissions.extend(
            analyze_workflow_permissions(workflow_data, workflow_file)
        )
        unpinned_actions.extend(
            UnpinnedActionFinding(**finding)
            for finding in find_unpinned_action_uses(workflow_data, workflow_file)
        )

    return credential_sources, token_permissions, unpinned_actions, errors


def _permissions_have_id_token_write(permissions: Any) -> bool:
    if isinstance(permissions, str):
        return permissions.strip().lower() == "write-all"

    if not isinstance(permissions, dict):
        return False

    id_token_access = permissions.get("id-token")
    return isinstance(id_token_access, str) and id_token_access.lower() == "write"


def _is_configure_aws_credentials_action(uses: Any) -> bool:
    if not isinstance(uses, str):
        return False
    return uses.strip().lower().startswith("aws-actions/configure-aws-credentials")


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)
