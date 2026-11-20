"""Read-only comparison of declared access around direct Claude Code action steps."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass

import yaml


class GitHubWorkflowLoader(yaml.SafeLoader):
    """PyYAML loader that treats GitHub's ``on`` key as a string."""


GitHubWorkflowLoader.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


AGENT = "anthropics/claude-code-action"
AWS = "aws-actions/configure-aws-credentials"
CLAUDE_AUTH_INPUTS = (
    "anthropic_api_key",
    "claude_code_oauth_token",
    "anthropic_federation_rule_id",
    "anthropic_organization_id",
    "anthropic_service_account_id",
)
PR_ACTIVITIES = frozenset(
    "assigned auto_merge_disabled auto_merge_enabled closed converted_to_draft "
    "demilestoned dequeued edited enqueued labeled locked milestoned opened "
    "ready_for_review reopened review_request_removed review_requested synchronize "
    "unassigned unlabeled unlocked".split()
)
ROLE = re.compile(r"arn:aws(?:-[a-z0-9-]+)?:iam::\d{12}:role/[\w+=,.@/-]+", re.ASCII)
SCOPE = (
    "Only direct Claude Code steps and declared configuration are compared. "
    "No workflow ran. Effective permissions, conditions and app grants are unknown."
)


@dataclass(frozen=True)
class Fact:
    category: str
    field: str
    value: str
    source: str


def _action(step):
    uses = step.get("uses")
    return (
        uses.partition("@")[0].lower() if isinstance(uses, str) and "@" in uses else ""
    )


def _ptr(key):
    return str(key).replace("~", "~0").replace("/", "~1")


class ReviewLoader(GitHubWorkflowLoader):
    def construct_mapping(self, node, deep=False):
        result = super().construct_mapping(node, deep)
        if len(result) != len(node.value):
            raise yaml.YAMLError("Duplicate keys are ambiguous in an access review.")
        return result


def _event_filters(events, path):
    """Describe literal PR activity lists; leave other filters opaque."""
    readable, opaque = [], {}
    for event, config in events.items():
        if not config:
            continue
        if event not in ("pull_request", "pull_request_target") or not isinstance(
            config, dict
        ):
            opaque[event] = config
            continue
        types = config.get("types")
        types = [types] if isinstance(types, str) else types
        if (
            not isinstance(types, list)
            or not types
            or not all(isinstance(t, str) and t in PR_ACTIVITIES for t in types)
        ):
            opaque[event] = config
            continue
        readable.append(
            Fact(
                "trigger",
                f"{event} activity types",
                ", ".join(sorted(set(types))),
                f"{path}#/on/{event}/types",
            )
        )
        remainder = {k: v for k, v in config.items() if k != "types"}
        if remainder:
            opaque[event] = remainder
    return readable, opaque


def _same_repo_condition(value):
    if not isinstance(value, str):
        return False
    condition = value.strip()
    if condition.startswith("${{") and condition.endswith("}}"):
        condition = condition[3:-2].strip()
    return bool(
        re.fullmatch(
            r"github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository",
            condition,
        )
    )


def _job_facts(flow, path, name, job, steps, idx):
    prefix = f"{path}#/jobs/{_ptr(name)}"
    stepref = f"{prefix}/steps/{idx}"
    agent = steps[idx]
    opts = agent.get("with") or {}
    if not isinstance(opts, dict):
        raise ValueError(f"Invalid action inputs at {stepref}.")
    facts = [Fact("agent", "agent action", agent["uses"], f"{stepref}/uses")]
    backend = opts.get("use_bedrock", "false")
    if backend not in ("true", "false"):
        backend = "unknown"
    facts.append(Fact("agent", "use_bedrock", backend, stepref))
    for key in CLAUDE_AUTH_INPUTS:
        if key in opts:
            facts.append(
                Fact(
                    "agent",
                    "Claude authentication inputs",
                    f"{key} configured; value not inspected",
                    f"{stepref}/with/{key}",
                )
            )
    facts.append(
        Fact(
            "token",
            "agent GitHub credential input",
            "explicit token; grants unknown"
            if "github_token" in opts
            else "action default; app grants unknown",
            stepref,
        )
    )
    events = flow.get("on", [])
    events = [events] if isinstance(events, str) else events
    if not isinstance(events, (dict, list)):
        raise ValueError(f"Invalid triggers in {path}.")
    facts.extend(
        Fact("trigger", "event", key, f"{path}#/on")
        for key in events
        if isinstance(key, str)
    )
    filters, opaque = _event_filters(events if isinstance(events, dict) else {}, path)
    facts.extend(filters)
    condition = job.get("if")
    if _same_repo_condition(condition):
        facts.append(
            Fact(
                "trigger",
                "job condition",
                "PR head must be in the same repository as the workflow",
                f"{prefix}/if",
            )
        )
        condition = None
    # Compare other expressions/config without emitting prompts, tokens or scripts.
    for category, key, val, at in [
        (
            "trigger",
            "event filters",
            opaque or None,
            f"{path}#/on",
        ),
        ("trigger", "job condition", condition, f"{prefix}/if"),
        ("agent", "step condition", agent.get("if"), f"{stepref}/if"),
        ("agent", "Claude CLI arguments", opts.get("claude_args"), f"{stepref}/with"),
        ("agent", "Claude settings", opts.get("settings"), f"{stepref}/with"),
    ]:
        if val is not None:
            digest = hashlib.sha256(
                json.dumps(val, sort_keys=True, default=str).encode()
            ).hexdigest()[:16]
            facts.append(Fact(category, key, f"configured (digest {digest})", at))
    perms = job.get(
        "permissions", flow.get("permissions", "repository default; unknown")
    )
    loc = f"{prefix}/permissions" if "permissions" in job else f"{path}#"
    if "permissions" in flow and "permissions" not in job:
        loc += "/permissions"
    if isinstance(perms, dict):
        if not perms:
            facts.append(Fact("token", "GITHUB_TOKEN", "empty permission map", loc))
        for key, val in perms.items():
            facts.append(
                Fact(
                    "token",
                    f"GITHUB_TOKEN {key}",
                    val if val in ("read", "write", "none") else "unknown",
                    f"{loc}/{_ptr(key)}",
                )
            )
    else:
        facts.append(
            Fact(
                "token",
                "GITHUB_TOKEN",
                perms
                if perms in ("read-all", "write-all")
                else "unspecified or unresolved",
                loc,
            )
        )
    setup_order = 0
    for n, step in enumerate(steps[:idx]):
        if _action(step) != AWS:
            continue
        setup_order += 1
        settings = step.get("with") or {}
        role = settings.get("role-to-assume") if isinstance(settings, dict) else None
        role = role if isinstance(role, str) and ROLE.fullmatch(role) else "unresolved"
        at = f"{prefix}/steps/{n}"
        facts.append(
            Fact("aws", f"preceding AWS credential setup #{setup_order}", role, at)
        )
        facts.append(Fact("policy", "role policy evidence", f"{role}: unknown", at))
    return facts


def snapshot(root):
    directory = root / ".github" / "workflows"
    if directory.is_symlink() or directory.parent.is_symlink():
        raise ValueError("Refusing symlinked workflow directory.")
    jobs = {}
    for path in sorted(directory.glob("*")):
        if path.suffix not in {".yaml", ".yml"}:
            continue
        rel = path.relative_to(root).as_posix()
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ValueError(
                f"Cannot inspect {rel}: not a bounded regular workflow file."
            )
        try:
            raw = path.read_text(encoding="utf-8")
            # Untrusted checkouts: do not expand YAML aliases or merge chains.
            if any(isinstance(t, yaml.tokens.AliasToken) for t in yaml.scan(raw)):
                raise ValueError(f"Unsupported YAML alias in {rel}.")
            flow = yaml.load(raw, Loader=ReviewLoader)
        except (yaml.YAMLError, UnicodeError, RecursionError) as exc:
            raise ValueError(f"Cannot parse {rel}; review incomplete.") from exc
        if not isinstance(flow, dict) or not isinstance(flow.get("jobs"), dict):
            raise ValueError(f"No valid job mapping in {rel}; review incomplete.")
        for name, job in flow["jobs"].items():
            if not isinstance(job, dict):
                raise ValueError(f"Invalid job in {rel}.")
            steps = job.get("steps", [])
            if not isinstance(steps, list) or not all(
                isinstance(s, dict) for s in steps
            ):
                raise ValueError(f"Invalid steps in {rel}.")
            ordinal = 0
            for idx, step in enumerate(steps):
                if _action(step) == AGENT:
                    ordinal += 1
                    # IDs disambiguate repeated invocations; unnamed ones use ordinal.
                    identity = (rel, str(name), str(step.get("id") or f"@{ordinal}"))
                    if identity in jobs:
                        raise ValueError(f"Duplicate agent step identity in {rel}.")
                    jobs[identity] = _job_facts(flow, rel, name, job, steps, idx)
    return jobs


def compare(base, head):
    jobs = []
    for identity in sorted(base.keys() | head.keys()):
        sides = [
            {(f.category, f.field, f.value): f for f in side.get(identity, [])}
            for side in (base, head)
        ]
        before, after = sides
        facts = []
        for key in sorted(before.keys() | after.keys()):
            record = asdict((after.get(key) or before[key]))
            record.pop("source")
            record.update(
                status=(
                    "added"
                    if key not in before
                    else "removed"
                    if key not in after
                    else "unchanged"
                ),
                base_source=before[key].source if key in before else None,
                head_source=after[key].source if key in after else None,
            )
            facts.append(record)
        jobs.append(
            dict(
                workflow=identity[0],
                job=identity[1],
                agent_step=identity[2],
                presence=(
                    "both"
                    if before and after
                    else "head only"
                    if after
                    else "base only"
                ),
                facts=facts,
            )
        )
    return {"schema_version": 1, "scope": SCOPE, "agents": jobs}
