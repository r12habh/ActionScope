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
IAM_ROLE_ARN_PATTERN = re.compile(r"^arn:[^:]+:iam::\d{12}:role/.+")
AWS_STATIC_CREDENTIAL_ENV_KEYS = frozenset(
    {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}
)


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
    path = Path(repo_path).expanduser()
    if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}:
        return [str(path.resolve())]

    workflow_dir = path / ".github" / "workflows"
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
    """Extract AWS credential sources from one workflow."""
    jobs = workflow_data.get("jobs")
    if jobs is None:
        return []
    if not isinstance(jobs, dict):
        return []

    credential_sources: list[AwsCredentialSource] = []
    workflow_env = _environment_mapping(workflow_data.get("env"))
    workflow_has_oidc = _permissions_have_id_token_write(
        workflow_data.get("permissions")
    )

    for job_name, job_data in jobs.items():
        if not isinstance(job_data, dict):
            continue

        inherited_env = {
            **workflow_env,
            **_environment_mapping(job_data.get("env")),
        }
        job_has_oidc = _permissions_have_id_token_write(job_data.get("permissions"))
        job_sources: list[AwsCredentialSource] = []

        for step in _job_steps(job_data):
            source = _credential_source_from_step(
                step,
                workflow_file,
                str(job_name),
                workflow_has_oidc or job_has_oidc,
                inherited_env=inherited_env,
            )
            if source is not None:
                job_sources.append(source)

        if not any(source.uses_access_keys for source in job_sources):
            environment_source = _credential_source_from_environment(
                job_data,
                workflow_file,
                str(job_name),
                inherited_env,
            )
            if environment_source is not None:
                job_sources.append(environment_source)

        credential_sources.extend(job_sources)

    return credential_sources


def extract_delegated_credential_sources(
    workflow_data: dict,
    workflow_file: str,
    repo_path: str,
) -> tuple[list[AwsCredentialSource], list[str]]:
    """Detect AWS credential setup delegated to local composite actions."""
    jobs = workflow_data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return [], []

    credential_sources: list[AwsCredentialSource] = []
    warnings: list[str] = []
    workflow_env = _environment_mapping(workflow_data.get("env"))
    workflow_has_oidc = _permissions_have_id_token_write(
        workflow_data.get("permissions")
    )

    for job_name, job_data in jobs.items():
        if not isinstance(job_data, dict):
            continue

        job_name_str = str(job_name)
        inherited_env = {
            **workflow_env,
            **_environment_mapping(job_data.get("env")),
        }
        job_has_oidc = _permissions_have_id_token_write(job_data.get("permissions"))
        has_oidc = workflow_has_oidc or job_has_oidc

        for step in _job_steps(job_data):
            uses = step.get("uses")
            if not isinstance(uses, str):
                continue
            uses = uses.strip()
            if not _is_local_action_reference(uses):
                continue

            sources, local_warnings = _inspect_local_composite_action(
                uses,
                step,
                repo_path,
                workflow_file,
                job_name_str,
                has_oidc,
                inherited_env,
            )
            credential_sources.extend(sources)
            warnings.extend(local_warnings)

    return credential_sources, warnings


def extract_env_var_references(step: dict) -> dict[str, str]:
    """Extract environment variable references from a workflow step."""
    env_block = step.get("env", {})
    if not isinstance(env_block, dict):
        return {}

    return {str(name): str(value) for name, value in env_block.items()}


def classify_role_reference(role_reference: str | None) -> str:
    """Classify the provenance of a workflow's ``role-to-assume`` value."""
    if role_reference is None or not role_reference.strip():
        return "absent"

    value = role_reference.strip()
    if "${{" not in value:
        return (
            "literal_arn"
            if IAM_ROLE_ARN_PATTERN.fullmatch(value)
            else "literal_name"
        )

    lowered = value.lower()
    for marker, kind in (
        ("secrets.", "secret"),
        ("vars.", "variable"),
        ("env.", "environment"),
        ("inputs.", "input"),
    ):
        if marker in lowered:
            return kind
    return "expression"


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

    Returns one of: ``sha``, ``tag``, ``branch``, ``short_sha``, ``local``, or
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
    if re.fullmatch(r"[0-9a-f]{7,39}", ref, re.IGNORECASE):
        return "short_sha"
    if re.fullmatch(
        r"(?:v?\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?|v\d+(?:[-+][0-9A-Za-z.-]+)?)",
        ref,
    ):
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

        direct_sources = extract_aws_credential_sources(
            workflow_data, workflow_file
        )
        delegated_sources, delegated_errors = extract_delegated_credential_sources(
            workflow_data,
            workflow_file,
            repo_path,
        )
        delegated_access_key_jobs = {
            source.job_name
            for source in delegated_sources
            if source.uses_access_keys
        }
        delegated_access_key_callers = _local_action_access_key_locations(
            workflow_data
        )
        direct_sources = [
            source
            for source in direct_sources
            if not (
                source.job_name in delegated_access_key_jobs
                and (
                    source.step_name == "Workflow/job environment"
                    or (source.job_name, source.step_name)
                    in delegated_access_key_callers
                )
            )
        ]
        credential_sources.extend(direct_sources)
        credential_sources.extend(delegated_sources)
        errors.extend(delegated_errors)
        token_permissions.extend(
            analyze_workflow_permissions(workflow_data, workflow_file)
        )
        unpinned_actions.extend(
            UnpinnedActionFinding(**finding)
            for finding in find_unpinned_action_uses(workflow_data, workflow_file)
        )

    return credential_sources, token_permissions, unpinned_actions, errors


def _job_steps(job_data: dict) -> list[dict]:
    steps = job_data.get("steps") or []
    if not isinstance(steps, list):
        return []
    return [step for step in steps if isinstance(step, dict)]


def _credential_source_from_step(
    step: dict,
    workflow_file: str,
    job_name: str,
    has_oidc_permission: bool,
    step_name_prefix: str = "",
    inherited_env: dict[str, str] | None = None,
) -> AwsCredentialSource | None:
    uses = step.get("uses")
    if not _is_configure_aws_credentials_action(uses):
        return None

    with_block = step.get("with", {})
    if not isinstance(with_block, dict):
        with_block = {}

    env_vars = {
        **(inherited_env or {}),
        **extract_env_var_references(step),
    }
    role_arn = _optional_string(with_block.get("role-to-assume"))
    step_name = str(step.get("name") or uses)
    if step_name_prefix:
        step_name = f"{step_name_prefix} -> {step_name}"

    return AwsCredentialSource(
        workflow_file=workflow_file,
        job_name=job_name,
        step_name=step_name,
        role_arn=role_arn,
        uses_access_keys=(
            "aws-access-key-id" in with_block
            or bool(AWS_STATIC_CREDENTIAL_ENV_KEYS.intersection(env_vars))
        ),
        uses_oidc=bool(role_arn and has_oidc_permission),
        aws_region=_optional_string(with_block.get("aws-region")),
        role_reference_kind=classify_role_reference(role_arn),
    )


def _credential_source_from_environment(
    job_data: dict,
    workflow_file: str,
    job_name: str,
    inherited_env: dict[str, str],
) -> AwsCredentialSource | None:
    """Return a source when a job exposes AWS SDK credential variables."""
    candidates = [("Workflow/job environment", inherited_env)]
    candidates.extend(
        (
            str(step.get("name") or "Shell step environment"),
            {**inherited_env, **extract_env_var_references(step)},
        )
        for step in _job_steps(job_data)
    )

    for location, env_vars in candidates:
        if not AWS_STATIC_CREDENTIAL_ENV_KEYS.intersection(env_vars):
            continue
        return AwsCredentialSource(
            workflow_file=workflow_file,
            job_name=job_name,
            step_name=location,
            role_arn=None,
            uses_access_keys=True,
            uses_oidc=False,
            aws_region=env_vars.get("AWS_REGION")
            or env_vars.get("AWS_DEFAULT_REGION"),
            role_reference_kind="absent",
        )
    return None


def _inspect_local_composite_action(
    uses_ref: str,
    caller_step: dict,
    repo_path: str,
    workflow_file: str,
    job_name: str,
    has_oidc_permission: bool,
    inherited_env: dict[str, str] | None = None,
) -> tuple[list[AwsCredentialSource], list[str]]:
    action_file = _local_action_file(repo_path, uses_ref)
    if action_file is None:
        return [], [
            (
                f"{workflow_file} job {job_name} uses local action {uses_ref}, "
                "but ActionScope could not find action.yml"
            )
        ]

    action_data = _parse_delegated_yaml(action_file)
    if action_data is None:
        return [], [
            (
                f"{workflow_file} job {job_name} uses local action {uses_ref}, "
                "but ActionScope could not parse it"
            )
        ]

    runs = action_data.get("runs") if isinstance(action_data, dict) else None
    steps = runs.get("steps") if isinstance(runs, dict) else None
    if not isinstance(steps, list):
        return [], []

    caller_with = caller_step.get("with", {})
    if not isinstance(caller_with, dict):
        caller_with = {}
    caller_env = {
        **(inherited_env or {}),
        **extract_env_var_references(caller_step),
    }

    sources: list[AwsCredentialSource] = []
    for nested_step in steps:
        if not isinstance(nested_step, dict):
            continue
        resolved_step = _resolve_composite_inputs(nested_step, caller_with)
        source = _credential_source_from_step(
            resolved_step,
            workflow_file,
            job_name,
            has_oidc_permission,
            step_name_prefix=f"Local action {uses_ref}",
            inherited_env=caller_env,
        )
        if source is not None:
            sources.append(source)

    return sources, []


def _local_action_access_key_locations(
    workflow_data: dict,
) -> set[tuple[str, str]]:
    """Return local-action caller steps that expose static AWS key variables."""
    jobs = workflow_data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return set()
    workflow_env = _environment_mapping(workflow_data.get("env"))
    locations: set[tuple[str, str]] = set()
    for job_name, job_data in jobs.items():
        if not isinstance(job_data, dict):
            continue
        inherited_env = {
            **workflow_env,
            **_environment_mapping(job_data.get("env")),
        }
        for step in _job_steps(job_data):
            uses = step.get("uses")
            if not isinstance(uses, str) or not _is_local_action_reference(
                uses.strip()
            ):
                continue
            caller_env = {**inherited_env, **extract_env_var_references(step)}
            if AWS_STATIC_CREDENTIAL_ENV_KEYS.intersection(caller_env):
                locations.add(
                    (str(job_name), str(step.get("name") or "Shell step environment"))
                )
    return locations


def _resolve_composite_inputs(step: dict, caller_with: dict) -> dict:
    resolved = dict(step)
    with_block = resolved.get("with")
    if isinstance(with_block, dict):
        resolved["with"] = {
            key: _resolve_input_expression(value, caller_with)
            for key, value in with_block.items()
        }
    env_block = resolved.get("env")
    if isinstance(env_block, dict):
        resolved["env"] = {
            key: _resolve_input_expression(value, caller_with)
            for key, value in env_block.items()
        }
    return resolved


def _environment_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(name): str(item) for name, item in value.items()}


def _resolve_input_expression(value: Any, caller_with: dict) -> Any:
    if not isinstance(value, str):
        return value
    match = re.fullmatch(r"\s*\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*}}\s*", value)
    if not match:
        return value
    input_name = match.group(1)
    return caller_with.get(input_name, value)


def _local_action_file(repo_path: str, uses_ref: str) -> Path | None:
    action_dir = _repo_relative_path(repo_path, uses_ref[2:])
    if action_dir is None:
        return None
    for name in ("action.yml", "action.yaml"):
        candidate = action_dir / name
        if candidate.is_file():
            return candidate
    return None


def _repo_relative_path(repo_path: str, relative_path: str) -> Path | None:
    repo = Path(repo_path).expanduser().resolve()
    candidate = (repo / relative_path).resolve()
    try:
        if not candidate.is_relative_to(repo):
            return None
    except ValueError:
        return None
    return candidate


def _parse_delegated_yaml(path: Path) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as yaml_file:
            data = yaml.load(yaml_file, Loader=GitHubWorkflowLoader)
    except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError) as exc:
        _warn(f"Could not read delegated workflow/action {path}: {exc}")
        return None
    except yaml.YAMLError as exc:
        _warn(f"Could not parse delegated workflow/action {path}: {exc}")
        return None
    return data if isinstance(data, dict) else None


def _is_local_action_reference(uses_ref: str) -> bool:
    return uses_ref.startswith("./") and not uses_ref.startswith(
        "./.github/workflows/"
    )


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
