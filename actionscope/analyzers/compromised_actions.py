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

from actionscope.models import CompromisedActionFinding, RiskLevel
from actionscope.parsers.workflow import GitHubWorkflowLoader

DATA_FILE = Path(__file__).parent.parent / "data" / "compromised_actions.json"
_DB_CACHE: dict | None = None
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


def load_compromised_actions() -> dict:
    """Load and cache the compromised actions database."""
    global _DB_CACHE
    if _DB_CACHE is None:
        with DATA_FILE.open("r", encoding="utf-8") as handle:
            _DB_CACHE = json.load(handle)
    return _DB_CACHE


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
    malicious_shas = [
        str(item).lower() for item in entry.get("malicious_shas") or []
    ]
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
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
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
) -> tuple[list[CompromisedActionFinding], list[str]]:
    """Scan workflow files for known-compromised action references."""
    findings: list[CompromisedActionFinding] = []
    errors: list[str] = []
    try:
        db = load_compromised_actions()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [], [f"Could not load compromised actions database {DATA_FILE}: {exc}"]

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
        if isinstance(workflow_data, dict):
            findings.extend(
                check_workflow_for_compromised_actions(
                    workflow_data,
                    str(workflow_file.resolve()),
                    db,
                )
            )

    return findings, errors


def _entry_for_action(action_name: str, db: dict) -> dict | None:
    for entry in db.get("actions", []):
        if str(entry.get("action", "")).lower() == action_name:
            return entry
    return None


def _parse_uses_ref(uses_ref: str) -> tuple[str, str] | None:
    if uses_ref.startswith(("./", "../", "docker://")):
        return None
    if "@" not in uses_ref:
        return None
    action_part, ref = uses_ref.rsplit("@", 1)
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
