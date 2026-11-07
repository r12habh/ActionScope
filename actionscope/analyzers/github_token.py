"""GITHUB_TOKEN permission analyzer for workflow-level and job-level scopes."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

import yaml

from actionscope.models import GitHubTokenPermission, RiskLevel

KNOWN_PERMISSION_SCOPES = (
    "actions",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
)

HIGH_WRITE_SCOPES = {"pull-requests", "packages", "id-token"}
MEDIUM_WRITE_SCOPES = {"contents", "actions", "deployments"}
AWS_OIDC_ACTION = "aws-actions/configure-aws-credentials"
KNOWN_OIDC_CONSUMER_ACTIONS = {
    "actions/deploy-pages",
    "ariga/atlas-action",
    "azure/login",
    "google-github-actions/auth",
    "hashicorp/vault-action",
    "pypa/gh-action-pypi-publish",
    "sigstore/gh-action-sigstore-python",
    "snowflakedb/snowflake-cli-action",
}
KNOWN_OIDC_CONSUMER_PREFIXES = ("slsa-framework/slsa-github-generator/",)
OIDC_RUN_HINTS = (
    "actions_id_token_request_url",
    "core.getidtoken",
    "getidtoken(",
    "npm publish --provenance",
)


def analyze_workflow_permissions(
    workflow_data: dict,
    workflow_file: str,
    repo_path: str | None = None,
) -> list[GitHubTokenPermission]:
    """Return GITHUB_TOKEN permission findings from parsed workflow YAML."""
    if not isinstance(workflow_data, dict):
        return []

    findings: list[GitHubTokenPermission] = []
    root = _repository_root(repo_path)

    if "permissions" in workflow_data and workflow_data["permissions"] is not None:
        findings.extend(
            _permissions_to_findings(
                permissions=workflow_data["permissions"],
                workflow_file=workflow_file,
                job_name="",
                oidc_expected=_workflow_uses_oidc_consumer(workflow_data, root),
            )
        )

    jobs = workflow_data.get("jobs")
    if jobs is None:
        jobs = {}
    if isinstance(jobs, dict):
        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue
            if "permissions" not in job_data or job_data["permissions"] is None:
                continue
            findings.extend(
                _permissions_to_findings(
                    permissions=job_data["permissions"],
                    workflow_file=workflow_file,
                    job_name=str(job_name),
                    oidc_expected=_job_uses_oidc_consumer(
                        job_data, root, inherited_env=workflow_data.get("env")
                    ),
                )
            )

    return findings


def get_dangerous_token_permissions(
    perms: list[GitHubTokenPermission],
) -> list[GitHubTokenPermission]:
    """Return only permissions with risk MEDIUM or higher."""
    return [
        permission for permission in perms if permission.risk_level >= RiskLevel.MEDIUM
    ]


def summarize_token_risk(perms: list[GitHubTokenPermission]) -> dict:
    """Summarize notable GITHUB_TOKEN permission risks."""
    write_permissions = {
        permission.scope for permission in perms if permission.access.lower() == "write"
    }

    return {
        "has_write_all": all(
            scope in write_permissions for scope in KNOWN_PERMISSION_SCOPES
        ),
        "has_code_write": "contents" in write_permissions,
        "has_workflow_write": "actions" in write_permissions,
        "has_pr_write": "pull-requests" in write_permissions,
        "has_package_write": "packages" in write_permissions,
        "overall_risk": max(
            (permission.risk_level for permission in perms),
            default=RiskLevel.INFO,
        ),
    }


def _permissions_to_findings(
    permissions: Any,
    workflow_file: str,
    job_name: str,
    oidc_expected: bool,
) -> list[GitHubTokenPermission]:
    if permissions is None or permissions == {}:
        return []

    if isinstance(permissions, str):
        access = permissions.strip().lower()
        if access == "write-all":
            return [
                GitHubTokenPermission(
                    workflow_file=workflow_file,
                    job_name=job_name,
                    scope=scope,
                    access="write",
                    risk_level=RiskLevel.HIGH,
                )
                for scope in KNOWN_PERMISSION_SCOPES
            ]
        if access == "read-all":
            return [
                GitHubTokenPermission(
                    workflow_file=workflow_file,
                    job_name=job_name,
                    scope=scope,
                    access="read",
                    risk_level=RiskLevel.LOW,
                )
                for scope in KNOWN_PERMISSION_SCOPES
            ]
        return []

    if not isinstance(permissions, dict):
        return []

    findings: list[GitHubTokenPermission] = []
    for scope, access in permissions.items():
        normalized_scope = str(scope).strip().lower()
        normalized_access = str(access).strip().lower()
        findings.append(
            GitHubTokenPermission(
                workflow_file=workflow_file,
                job_name=job_name,
                scope=normalized_scope,
                access=normalized_access,
                risk_level=_classify_permission(
                    normalized_scope,
                    normalized_access,
                    oidc_expected,
                ),
            )
        )
    return findings


def _classify_permission(scope: str, access: str, oidc_expected: bool) -> RiskLevel:
    if access != "write":
        return RiskLevel.LOW

    if scope == "id-token" and oidc_expected:
        return RiskLevel.INFO

    if scope in HIGH_WRITE_SCOPES:
        return RiskLevel.HIGH

    if scope in MEDIUM_WRITE_SCOPES:
        return RiskLevel.MEDIUM

    return RiskLevel.LOW


def _workflow_uses_oidc_consumer(workflow_data: dict, root: Path | None) -> bool:
    jobs = workflow_data.get("jobs")
    if jobs is None:
        jobs = {}
    if not isinstance(jobs, dict):
        return False
    inheriting_jobs = [
        job
        for job in jobs.values()
        if isinstance(job, dict) and job.get("permissions") is None
    ]
    return bool(inheriting_jobs) and all(
        _job_uses_oidc_consumer(job, root, inherited_env=workflow_data.get("env"))
        for job in inheriting_jobs
    )


def _job_uses_oidc_consumer(
    job_data: dict,
    root: Path | None = None,
    seen: frozenset[Path] = frozenset(),
    budget: list[int] | None = None,
    inherited_env: Any = None,
) -> bool:
    if budget is None:
        budget = [64]
    job_action = _action_name(job_data.get("uses"))
    if job_action in KNOWN_OIDC_CONSUMER_ACTIONS:
        return True
    if any(job_action.startswith(prefix) for prefix in KNOWN_OIDC_CONSUMER_PREFIXES):
        return True

    steps = job_data.get("steps", [])
    if not isinstance(steps, list):
        return False

    for step in steps:
        if not isinstance(step, dict):
            continue
        env = {}
        for layer in (inherited_env, job_data.get("env"), step.get("env")):
            if isinstance(layer, dict):
                env.update(layer)
        action = _action_name(step.get("uses"))
        step_with = step.get("with", {})
        if (
            action == AWS_OIDC_ACTION
            and isinstance(step_with, dict)
            and step_with.get("role-to-assume")
        ):
            return True
        if action in KNOWN_OIDC_CONSUMER_ACTIONS:
            return True
        if any(action.startswith(prefix) for prefix in KNOWN_OIDC_CONSUMER_PREFIXES):
            return True
        if root is not None and _local_composite_uses_oidc(
            step, root, seen, budget, env
        ):
            return True
        run_block = step.get("run")
        if isinstance(run_block, str):
            lowered = run_block.lower()
            if any(hint in lowered for hint in OIDC_RUN_HINTS):
                return True
            if _uses_keyless_cosign(run_block, env):
                return True
    return False


def _uses_keyless_cosign(run_block: str, env: dict) -> bool:
    # Recognize simple commands only, not echoed examples or heredoc contents.
    if "<<" in run_block or "SIGSTORE_ID_TOKEN" in env:
        return False
    for line in run_block.replace("\\\n", " ").splitlines():
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            continue
        if len(words) < 3 or words[:2] not in (
            ["cosign", "sign"],
            ["cosign", "sign-blob"],
        ):
            continue
        if any(
            word.split("=", 1)[0]
            in {
                "--key",
                "--sk",
                "--signing-config",
                "--identity-token",
                "--oidc-provider",
                "--oidc-issuer",
                "--oidc-disable-ambient-providers",
            }
            or word in {";", "&&", "||", "|"}
            for word in words[2:]
        ):
            continue
        return True
    return False


def _repository_root(repo_path: str | None) -> Path | None:
    if repo_path is None:
        return None
    path = Path(repo_path).expanduser().resolve()
    if path.is_file():
        if path.parent.name == "workflows" and path.parent.parent.name == ".github":
            return path.parent.parent.parent
        return path.parent
    return path if path.is_dir() else None


def _local_composite_uses_oidc(
    step: dict, root: Path, seen: frozenset[Path], budget: list[int], env: dict
) -> bool:
    uses = step.get("uses")
    if (
        not isinstance(uses, str)
        or not uses.strip().startswith(("./", "$/"))
        or len(seen) >= 8
        or budget[0] <= 0
    ):
        return False

    # Reuse credential discovery's path confinement and input substitution.
    # Import lazily because the workflow parser imports this analyzer.
    from actionscope.parsers.workflow import (
        GitHubWorkflowLoader,
        _local_action_file,
        _resolve_composite_inputs,
    )

    try:
        path = _local_action_file(str(root), uses.strip())
        if path is None:
            return False
        path = path.resolve()
        if path in seen or not path.is_relative_to(root):
            return False
        budget[0] -= 1
        with path.open("rb") as handle:
            raw = handle.read(262145)
        if len(raw) > 262144:
            return False
        data = yaml.load(raw.decode("utf-8"), Loader=GitHubWorkflowLoader)
        runs = data.get("runs") if isinstance(data, dict) else None
        if not isinstance(runs, dict) or runs.get("using") != "composite":
            return False
        steps = runs.get("steps")
        if not isinstance(steps, list):
            return False
        inputs = data.get("inputs") or {}
        values = (
            {
                name: spec.get("default", "") if isinstance(spec, dict) else ""
                for name, spec in inputs.items()
            }
            if isinstance(inputs, dict)
            else {}
        )
        caller_values = step.get("with")
        if isinstance(caller_values, dict):
            values.update(caller_values)
        resolved = [
            _resolve_composite_inputs(child, values, missing_inputs_empty=True)
            for child in steps
            if isinstance(child, dict)
        ]
        return _job_uses_oidc_consumer(
            {"steps": resolved}, root, seen | {path}, budget, env
        )
    except (OSError, ValueError, yaml.YAMLError, RuntimeError):
        return False


def _action_name(uses: object) -> str:
    if not isinstance(uses, str):
        return ""
    if uses.startswith(("./", "../", "docker://")):
        return ""
    action = uses.strip().split("@", 1)[0].lower()
    return action
