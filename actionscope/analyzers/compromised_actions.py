"""Known-compromised GitHub Actions detector.

Checks workflow files against ActionScope's documented compromised-actions
database and flags mutable references to actions with known supply-chain
compromises.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from actionscope.compromised_db import (
    BUNDLED_DB_FILE,
    load_best_database,
)
from actionscope.models import CompromisedActionFinding, RiskLevel
from actionscope.parsers.actions_lock import (
    canonical_action_key,
    dependency_closure,
    extract_external_uses,
    load_actions_lock,
    repository_root,
)
from actionscope.parsers.steps import job_steps
from actionscope.parsers.workflow import GitHubWorkflowLoader

DATA_FILE = BUNDLED_DB_FILE
_FULL_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)


def load_compromised_actions(
    *,
    cache_file: str | Path | None = None,
    offline: bool = False,
) -> dict:
    """Load the best local database without making network calls."""
    return load_best_database(cache_file, offline=offline)


def is_compromised_ref(
    action_name: str,
    ref: str,
    db: dict,
) -> tuple[bool, dict | None]:
    """Check if an action ref is explicitly listed as compromised."""
    normalized_action = action_name.strip().lower()
    normalized_ref = ref.strip()
    entry = _entry_for_action(normalized_action, db)
    if entry is None:
        return False, None

    affected_refs = [str(item) for item in entry.get("affected_refs") or []]
    malicious_shas = [str(item).lower() for item in entry.get("malicious_shas") or []]
    if _is_full_sha(normalized_ref):
        normalized_sha = normalized_ref.lower()
        if normalized_sha in malicious_shas:
            # Explicit known-malicious SHA: definitely compromised.
            return True, entry
        if normalized_sha in {item.lower() for item in affected_refs}:
            return True, entry
        if malicious_shas:
            # We have a known-bad SHA list and this pin isn't on it — the
            # consumer pinned to something other than the documented malicious
            # commit. Treat as safe; cross-references to the advisory show the
            # known-bad SHA differs from this pin.
            return False, None
        if affected_refs:
            # Explicit affected_refs list (tags) and this SHA isn't on it.
            # Without a separate `malicious_shas` list we cannot tell whether
            # an arbitrary SHA was the compromised commit, so treat as safe.
            return False, None
        # No malicious_shas and no affected_refs means the database only knows
        # that mutable refs were compromised. A full SHA pin is not vulnerable
        # to tag redirection unless the exact SHA is known bad.
        return False, None

    if affected_refs:
        if normalized_ref in affected_refs:
            return True, entry
        return False, None

    return True, entry


def check_workflow_for_compromised_actions(
    workflow_data: dict,
    workflow_file: str,
    db: dict,
) -> list[CompromisedActionFinding]:
    """Find known-compromised action references in one workflow."""
    findings: list[CompromisedActionFinding] = []
    jobs = workflow_data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return findings

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step in job_steps(job):
            uses = step.get("uses")
            if not isinstance(uses, str):
                continue
            parsed = _parse_uses_ref(uses.strip())
            if parsed is None:
                continue
            action_name, ref = parsed
            compromised, entry = is_compromised_ref(action_name, ref, db)
            is_sha_pinned = _is_full_sha(ref)
            if not compromised or entry is None:
                continue

            findings.append(
                CompromisedActionFinding(
                    workflow_file=workflow_file,
                    job_name=str(job_name),
                    step_name=str(step.get("name") or uses),
                    uses_ref=uses.strip(),
                    action_name=action_name.lower(),
                    ref=ref,
                    is_sha_pinned=is_sha_pinned,
                    compromise_date=str(entry.get("compromised_at", "")),
                    advisory_url=str(entry.get("advisory_url", "")),
                    description=str(entry.get("description", "")),
                    risk_level=(
                        RiskLevel.HIGH if is_sha_pinned else RiskLevel.CRITICAL
                    ),
                )
            )

    return findings


def scan_for_compromised_actions(
    repo_path: str,
    *,
    offline: bool = False,
    cache_file: str | Path | None = None,
) -> tuple[list[CompromisedActionFinding], list[str]]:
    """Scan workflow files for known-compromised action references."""
    findings: list[CompromisedActionFinding] = []
    errors: list[str] = []
    direct_keys_by_workflow: dict[str, set[str]] = {}
    try:
        db = load_compromised_actions(cache_file=cache_file, offline=offline)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [], [f"Could not load compromised actions database {DATA_FILE}: {exc}"]

    workflow_files = _workflow_files(repo_path)
    for workflow_file in workflow_files:
        try:
            with workflow_file.open("r", encoding="utf-8") as handle:
                workflow_data = yaml.load(handle, Loader=GitHubWorkflowLoader)
        except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError) as exc:
            errors.append(f"Could not read workflow file {workflow_file}: {exc}")
            continue
        except yaml.YAMLError as exc:
            errors.append(f"Could not parse workflow file {workflow_file}: {exc}")
            continue
        if isinstance(workflow_data, dict):
            resolved_workflow = str(workflow_file.resolve())
            direct_keys_by_workflow[resolved_workflow] = {
                key
                for uses_ref in extract_external_uses(workflow_data)
                if (key := canonical_action_key(uses_ref)) is not None
            }
            findings.extend(
                check_workflow_for_compromised_actions(
                    workflow_data,
                    resolved_workflow,
                    db,
                )
            )

    lockfile, _ = load_actions_lock(repo_path)
    if lockfile is not None and lockfile.valid:
        root = repository_root(repo_path)
        existing_workflows = {
            str(workflow_file.resolve()) for workflow_file in workflow_files
        }
        active_direct_by_workflow: dict[str, set[str]] = {}
        dependencies_by_workflow: dict[str, dict] = {}
        for workflow_path, pins in lockfile.workflows.items():
            resolved_workflow = str((root / workflow_path).resolve())
            if resolved_workflow not in existing_workflows:
                continue
            active_direct = set(pins) & direct_keys_by_workflow.get(
                resolved_workflow, set()
            )
            active_direct_by_workflow[resolved_workflow] = active_direct
            dependencies_by_workflow[resolved_workflow] = {
                pin: lockfile.dependencies[pin]
                for pin in dependency_closure(lockfile, active_direct)
                if pin in lockfile.dependencies
            }

        # A lock proves a compromised mutable ref safe only when the database
        # records the exact resolved commit as a verified safe SHA. Locking a
        # tag after it was moved is not evidence that the chosen commit is safe.
        retained_findings: list[CompromisedActionFinding] = []
        for finding in findings:
            key = canonical_action_key(finding.uses_ref)
            dependency = dependencies_by_workflow.get(finding.workflow_file, {}).get(
                key or ""
            )
            if dependency is None:
                retained_findings.append(finding)
                continue
            entry = _entry_for_action(finding.action_name, db)
            safe_sha = _entry_safe_sha(entry)
            locked_is_compromised, _ = is_compromised_ref(
                dependency.action_name,
                dependency.commit_sha,
                db,
            )
            if safe_sha == dependency.commit_sha and not locked_is_compromised:
                continue
            finding.description = (
                f"{finding.description} The dependency lock resolves this reference "
                f"to commit {dependency.commit_sha}, which is not recorded as a "
                "verified safe SHA."
            )
            retained_findings.append(finding)
        findings = retained_findings

        direct_finding_actions = {
            (finding.workflow_file, finding.action_name.lower()) for finding in findings
        }
        seen_locked_findings: set[tuple[str, str, str]] = set()
        for resolved_workflow, dependencies in dependencies_by_workflow.items():
            active_direct = active_direct_by_workflow.get(resolved_workflow, set())
            for pin, dependency in dependencies.items():
                compromised, entry = is_compromised_ref(
                    dependency.action_name,
                    dependency.commit_sha,
                    db,
                )
                finding_key = (
                    resolved_workflow,
                    dependency.action_name,
                    dependency.commit_sha,
                )
                if (
                    not compromised
                    or entry is None
                    or finding_key in seen_locked_findings
                ):
                    continue
                if (
                    pin in active_direct
                    and (resolved_workflow, dependency.action_name)
                    in direct_finding_actions
                ):
                    continue
                seen_locked_findings.add(finding_key)
                findings.append(
                    CompromisedActionFinding(
                        workflow_file=resolved_workflow,
                        job_name="actions.lock",
                        step_name="Locked direct or transitive dependency",
                        uses_ref=(f"{dependency.action_name}@{dependency.commit_sha}"),
                        action_name=dependency.action_name,
                        ref=dependency.commit_sha,
                        is_sha_pinned=True,
                        compromise_date=str(entry.get("compromised_at", "")),
                        advisory_url=str(entry.get("advisory_url", "")),
                        description=(
                            "The workflow dependency lock resolves this action "
                            "to a documented malicious commit. "
                            + str(entry.get("description", ""))
                        ),
                        risk_level=RiskLevel.CRITICAL,
                    )
                )

    return findings, errors


def _entry_safe_sha(entry: dict | None) -> str | None:
    if entry is None:
        return None
    value = entry.get("safe_sha")
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    for prefix in ("sha1-", "sha256-"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    return normalized if _is_full_sha(normalized) else None


def _entry_for_action(action_name: str, db: dict) -> dict | None:
    for entry in db.get("actions", []):
        if str(entry.get("action", "")).lower() == action_name:
            return entry
    return None


def _parse_uses_ref(uses_ref: str) -> tuple[str, str] | None:
    if uses_ref.startswith(("./", "../", "$/", "docker://")):
        return None
    if "@" not in uses_ref:
        return None
    action_part, ref = uses_ref.split("@", 1)
    pieces = action_part.split("/")
    if len(pieces) < 2:
        return None
    return "/".join(pieces[:2]), ref


def _workflow_files(repo_path: str) -> list[Path]:
    path = Path(repo_path).expanduser()
    if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}:
        return [path]
    workflow_dir = path / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    return sorted(
        workflow_dir.rglob("*.yml"),
    ) + sorted(workflow_dir.rglob("*.yaml"))


def _is_full_sha(ref: str) -> bool:
    return bool(_FULL_SHA_RE.fullmatch(ref))
