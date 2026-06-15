"""AI agent prompt injection surface detector.

Detects GitHub Actions workflows that run AI coding agents with access to
secrets, write permissions, or AWS credentials while processing untrusted
GitHub event content.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from actionscope.analyzers.github_token import analyze_workflow_permissions
from actionscope.models import (
    AiAgentInjectionFinding,
    AwsCredentialSource,
    GitHubTokenPermission,
    RiskLevel,
)

AI_AGENT_ACTIONS = [
    "anthropics/claude-code-action",
    "anthropics/claude-code",
    "github/copilot-action",
    "google-github-actions/run-gemini-cli",
    "google-gemini/gemini-cli-action",
    "opencode-ai/opencode",
    "sst/opencode",
    "continuedev/continue",
    "cline/cline",
]

AI_AGENT_ENV_VARS = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "CLAUDE_API_KEY",
    "COHERE_API_KEY",
    "MISTRAL_API_KEY",
]

UNTRUSTED_GITHUB_CONTEXT_PATTERNS = [
    r"github\.event\.pull_request\.(title|body|head\.ref|head\.label)",
    r"github\.event\.issue\.(title|body)",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.head_ref",
    r"github\.event\.discussion\.(title|body)",
]

_UNTRUSTED_RE = re.compile("|".join(UNTRUSTED_GITHUB_CONTEXT_PATTERNS), re.IGNORECASE)
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


def detect_ai_agent_steps(workflow_data: dict) -> list[tuple[str, str, dict]]:
    """Find steps that invoke or configure an AI coding agent."""
    matches: list[tuple[str, str, dict]] = []
    jobs = workflow_data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return matches

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            step_name = str(step.get("name") or step.get("uses") or "step")
            uses = str(step.get("uses") or "").lower()
            env = step.get("env") if isinstance(step.get("env"), dict) else {}
            if (
                any(agent in uses for agent in AI_AGENT_ACTIONS)
                or any(key in env for key in AI_AGENT_ENV_VARS)
                or _name_looks_like_ai_agent(step_name)
            ):
                matches.append((str(job_name), step_name, step))
    return matches


def has_untrusted_trigger(workflow_data: dict) -> bool:
    """Return True if the workflow runs on events with untrusted content."""
    return bool(
        _trigger_names(workflow_data.get("on"))
        & {
            "pull_request",
            "pull_request_target",
            "issue_comment",
            "issues",
            "discussion",
            "workflow_run",
        }
    )


def find_untrusted_inputs_in_step(step: dict) -> list[str]:
    """Find attacker-controlled GitHub context passed to the agent step."""
    found: list[str] = []
    for block_name in ("with", "env"):
        block = step.get(block_name)
        if not isinstance(block, dict):
            continue
        for value in block.values():
            for match in _UNTRUSTED_RE.finditer(str(value)):
                expression = match.group(0)
                if expression not in found:
                    found.append(expression)
    run_block = step.get("run")
    if isinstance(run_block, str):
        for match in _UNTRUSTED_RE.finditer(run_block):
            expression = match.group(0)
            if expression not in found:
                found.append(expression)
    return found


def classify_agent(action_string: str) -> str:
    """Return a normalized AI agent type label."""
    normalized = action_string.lower()
    if "claude" in normalized or "anthropic" in normalized:
        return "claude_code"
    if "copilot" in normalized:
        return "copilot_agent"
    if "gemini" in normalized:
        return "gemini_cli"
    if "opencode" in normalized:
        return "opencode"
    if "cline" in normalized:
        return "cline"
    if "continue" in normalized:
        return "continue"
    return "unknown_ai_agent"


def analyze_ai_agent_injection_surface(
    workflow_data: dict,
    workflow_file: str,
    credential_sources: list,
    github_token_perms: list,
) -> list[AiAgentInjectionFinding]:
    """Analyze one workflow for AI agent prompt injection exposure."""
    agent_steps = detect_ai_agent_steps(workflow_data)
    if not agent_steps:
        return []

    untrusted_trigger = has_untrusted_trigger(workflow_data)
    has_aws = _workflow_has_aws_credentials(
        workflow_data,
        workflow_file,
        credential_sources,
    )
    has_write = _workflow_has_write_token(workflow_file, github_token_perms)
    findings: list[AiAgentInjectionFinding] = []

    for job_name, step_name, step in agent_steps:
        uses = str(step.get("uses") or step_name)
        untrusted_inputs = find_untrusted_inputs_in_step(step)
        has_api_key = _step_has_ai_api_key_secret(step)
        risk = _risk(
            untrusted_trigger,
            bool(untrusted_inputs),
            has_api_key,
            has_aws,
            has_write,
        )
        findings.append(
            AiAgentInjectionFinding(
                workflow_file=workflow_file,
                job_name=job_name,
                step_name=step_name,
                agent_type=classify_agent(uses),
                agent_action=uses,
                has_api_key_secret=has_api_key,
                has_aws_secret_access=has_aws,
                has_write_permissions=has_write,
                untrusted_trigger=untrusted_trigger,
                untrusted_inputs=untrusted_inputs,
                risk_level=risk,
                description=(
                    "AI coding agent may process untrusted GitHub event content "
                    "while running with elevated credentials or repository access."
                ),
                recommendation=(
                    "Limit AI agent workflows to trusted actors, avoid passing PR "
                    "or issue bodies directly to agents, and gate execution with "
                    "environment protection rules."
                ),
            )
        )
    return findings


def scan_for_ai_agent_injection(
    repo_path: str,
    credential_sources: list[AwsCredentialSource] | None = None,
    github_token_perms: list[GitHubTokenPermission] | None = None,
) -> tuple[list[AiAgentInjectionFinding], list[str]]:
    """Scan workflow files for AI agent prompt injection surfaces."""
    findings: list[AiAgentInjectionFinding] = []
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
        if not isinstance(workflow_data, dict):
            continue
        token_perms = (
            github_token_perms
            if github_token_perms is not None
            else analyze_workflow_permissions(
                workflow_data,
                str(workflow_file.resolve()),
            )
        )
        findings.extend(
            analyze_ai_agent_injection_surface(
                workflow_data,
                str(workflow_file.resolve()),
                credential_sources or [],
                token_perms,
            )
        )
    return findings, errors


def _name_looks_like_ai_agent(step_name: str) -> bool:
    lowered = step_name.lower()
    return any(
        term in lowered
        for term in ("claude", "copilot", "gemini", "opencode", "cline", "continue")
    )


def _workflow_has_write_token(
    workflow_file: str,
    github_token_perms: list,
) -> bool:
    return any(
        getattr(permission, "workflow_file", None) == workflow_file
        and str(getattr(permission, "access", "")).lower() == "write"
        for permission in github_token_perms
    )


def _workflow_has_aws_credentials(
    workflow_data: dict,
    workflow_file: str,
    credential_sources: list,
) -> bool:
    if any(
        getattr(source, "workflow_file", None) == workflow_file
        for source in credential_sources
    ):
        return True
    return "aws-actions/configure-aws-credentials" in _stringify(workflow_data).lower()


def _step_has_ai_api_key_secret(step: dict) -> bool:
    text = _stringify(step)
    secret_names = {match.group(1).upper() for match in _SECRET_RE.finditer(text)}
    return any(name in secret_names for name in AI_AGENT_ENV_VARS)


def _risk(
    untrusted_trigger: bool,
    has_untrusted_inputs: bool,
    has_api_key: bool,
    has_aws: bool,
    has_write: bool,
) -> RiskLevel:
    if has_write and untrusted_trigger and has_untrusted_inputs:
        return RiskLevel.CRITICAL
    if untrusted_trigger and (has_aws or has_write):
        return RiskLevel.HIGH
    if has_api_key and untrusted_trigger:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


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
        return "\n".join(f"{key}: {_stringify(item)}" for key, item in value.items())
    if isinstance(value, list):
        return "\n".join(_stringify(item) for item in value)
    return str(value)
