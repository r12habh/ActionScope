"""Read-only comparison of declared access around direct Claude Code action steps."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

import click
import yaml

from actionscope.explain import Evidence, action_description, load_encoder, rank_rows
from actionscope.parsers.workflow import GitHubWorkflowLoader

AGENT = "anthropics/claude-code-action"
AWS = "aws-actions/configure-aws-credentials"
ROLE = re.compile(r"arn:aws(?:-[a-z0-9-]+)?:iam::\d{12}:role/[\w+=,.@/-]+", re.ASCII)
SCOPE = (
    "Only direct Claude Code steps and declared configuration are compared. "
    "No workflow ran. Effective permissions, conditions and app grants are unknown."
)
CHECKS = {
    "aws": "Does the configured role need anything beyond Bedrock model invocation?",
    "policy": "Does the task need this IAM action and resource? Check conditions.",
    "token": "Does the task require these repository token permissions?",
    "trigger": "Who can start this job, and do its event filters restrict access?",
    "agent": "Is this agent configuration expected for the stated task?",
}


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


def _policies(report, path, name, role):
    if not report or not ROLE.fullmatch(role):
        return []
    matches = [
        (i, item)
        for i, item in enumerate(report["findings"])
        if item.get("workflow_file") == path
        and item.get("job_name") == name
        and item.get("role_arn") == role
    ]
    if len(matches) != 1:
        return []
    i, item = matches[0]
    policy = []
    for j, act in enumerate(item.get("actions") or []):
        if not isinstance(act, dict) or not isinstance(act.get("action"), str):
            raise ValueError("Invalid action in supplied report.")
        policy.append(
            Fact(
                "policy",
                f"reported IAM action for {role}",
                f"{action_description(act)} on {act.get('resource', 'unknown')}",
                f"report#/findings/{i}/actions/{j}",
            )
        )
    if policy:
        confidence = item.get("match_confidence") or "unknown"
        status = item.get("risk_status") or "unknown"
        policy.append(
            Fact(
                "policy",
                f"reported evidence for {role}",
                f"match confidence: {confidence}; risk status: {status}",
                f"report#/findings/{i}",
            )
        )
    return policy


def _job_facts(flow, path, name, job, steps, idx, report):
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
    for key in ("anthropic_api_key", "claude_code_oauth_token"):
        if key in opts:
            facts.append(
                Fact(
                    "agent",
                    key,
                    "configured; value not inspected",
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
    # Compare opaque expressions/config without emitting prompts, tokens or scripts.
    for category, key, val, at in [
        (
            "trigger",
            "event filters",
            events if isinstance(events, dict) and any(events.values()) else None,
            f"{path}#/on",
        ),
        ("trigger", "job condition", job.get("if"), f"{prefix}/if"),
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
        policies = _policies(report, path, name, role)
        if policies:
            facts.extend(policies)
        else:
            facts.append(Fact("policy", "role policy evidence", f"{role}: unknown", at))
    return facts


def snapshot(root, report=None):
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
                    jobs[identity] = _job_facts(
                        flow, rel, name, job, steps, idx, report
                    )
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
    return {"schema_version": 1, "scope": SCOPE, "agents": jobs, "review_questions": []}


def suggest(result, intent, download):
    rows = []
    for i, job in enumerate(result["agents"]):
        for j, fact in enumerate(job["facts"]):
            if fact["status"] != "added":
                continue
            text = f"{fact['field']}: {fact['value']}"
            check = CHECKS[fact["category"]]
            if fact["field"] == "role policy evidence":
                check = "Can the role owner supply its policy to verify the task scope?"
            elif fact["field"] == "GITHUB_TOKEN id-token":
                check = "Does this job need permission to request an OIDC token?"
            rows.append(
                Evidence(
                    f"/agents/{i}/facts/{j}", job["job"], f"{text}. {check}", check
                )
            )
    if not rows:
        return []
    ranked = rank_rows(intent, rows, load_encoder(download), len(rows))
    selected = {}
    for row in ranked:
        selected.setdefault(row.check, dict(question=row.check, evidence=row.pointer))
    return list(selected.values())[:3]


def _report(path, root):
    if path is None:
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("findings"), list)
        or not all(isinstance(item, dict) for item in data["findings"])
    ):
        raise ValueError("Expected an ActionScope JSON report with a findings array.")
    scan_path = data.get("scan_path")
    if not isinstance(scan_path, str) or Path(scan_path).resolve() != root.resolve():
        raise ValueError("Report scan_path must identify its corresponding checkout.")
    for item in data["findings"]:
        location = item.get("workflow_file")
        if isinstance(location, str) and Path(location).is_absolute():
            item["workflow_file"] = (
                Path(location).relative_to(root.resolve()).as_posix()
                if Path(location).is_relative_to(root.resolve())
                else None
            )
    return data


@click.command("agent-review")
@click.option(
    "--base",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--head",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--base-report", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--head-report", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--intent", help="Use local AI to prioritize checks for this intended task."
)
@click.option(
    "--download-model", is_flag=True, help="Allow fetching pinned model files."
)
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text")
def agent_review(base, head, base_report, head_report, intent, download_model, fmt):
    """Review declared access changes in two local workflow checkouts."""
    if bool(base_report) != bool(head_report):
        raise click.UsageError("Supply both revision-matched reports or neither.")
    if intent is not None and not intent.strip():
        raise click.UsageError("--intent must describe a non-empty task.")
    if download_model and not intent:
        raise click.UsageError("--download-model needs --intent.")
    try:
        result = compare(
            snapshot(base, _report(base_report, base)),
            snapshot(head, _report(head_report, head)),
        )
        if intent:
            result["review_questions"] = suggest(result, intent, download_model)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    if fmt == "json":
        click.echo(json.dumps(result, indent=2))
        return
    click.echo(SCOPE)
    if not result["agents"]:
        click.echo("No supported direct agent steps found in either snapshot.")

    def line(value):
        click.echo("".join(c if c.isprintable() else " " for c in value))

    for job in result["agents"]:
        click.echo()
        line(
            f"{job['workflow']} / {job['job']} / {job['agent_step']} "
            f"({job['presence']})"
        )
        for f in job["facts"]:
            side = "head" if f["head_source"] else "base"
            line(
                f"  {f['status']}: {f['field']}: {f['value']} "
                f"[{side}:{f[side + '_source']}]"
            )
    for q in result["review_questions"]:
        click.echo(f"Review question: {q['question']} [{q['evidence']}]")
