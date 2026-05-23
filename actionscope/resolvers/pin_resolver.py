"""Resolve GitHub Actions version tags to current commit SHAs."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from actionscope.parsers.workflow import SHA_PATTERN, classify_action_ref


@dataclass
class ResolvedPin:
    """A resolved GitHub Action pin suggestion."""

    original_ref: str
    action_name: str
    tag: str
    resolved_sha: str | None
    pinned_ref: str | None
    error: str | None


def resolve_tag_to_sha(
    action_name: str,
    tag: str,
    github_token: str | None = None,
) -> ResolvedPin:
    """Resolve a GitHub Action tag to the commit SHA it currently points at."""
    if "/" not in action_name:
        return _error_pin(action_name, tag, "invalid ref")

    owner, repo = action_name.split("/", 1)
    encoded_tag = urllib.parse.quote(tag, safe="")
    url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{encoded_tag}"

    ref_data, error = _api_get_json(url, github_token)
    if error is not None:
        return _error_pin(action_name, tag, error)

    obj = ref_data.get("object") if isinstance(ref_data, dict) else None
    if not isinstance(obj, dict):
        return _error_pin(action_name, tag, "unexpected response")

    obj_type = obj.get("type")
    sha = obj.get("sha")
    if obj_type == "tag" and isinstance(sha, str):
        tag_url = f"https://api.github.com/repos/{owner}/{repo}/git/tags/{sha}"
        tag_data, error = _api_get_json(tag_url, github_token)
        if error is not None:
            return _error_pin(action_name, tag, error)
        tag_obj = tag_data.get("object") if isinstance(tag_data, dict) else None
        if isinstance(tag_obj, dict):
            sha = tag_obj.get("sha")

    if not isinstance(sha, str) or not SHA_PATTERN.fullmatch(sha):
        return _error_pin(action_name, tag, "could not resolve commit SHA")

    original = f"{action_name}@{tag}"
    pinned = f"{action_name}@{sha}  # {tag}"
    return ResolvedPin(
        original_ref=original,
        action_name=action_name,
        tag=tag,
        resolved_sha=sha,
        pinned_ref=pinned,
        error=None,
    )


def resolve_pins_for_workflow(
    workflow_data: dict,
    workflow_file: str,
    github_token: str | None = None,
    delay_seconds: float = 0.5,
) -> list[ResolvedPin]:
    """Resolve unique non-SHA external action refs in a workflow."""
    refs = sorted(_unique_unpinned_refs(workflow_data))
    resolved: list[ResolvedPin] = []
    for index, uses_ref in enumerate(refs):
        if index > 0 and delay_seconds > 0:
            time.sleep(delay_seconds)
        action_name, tag = uses_ref.rsplit("@", 1)
        action_name = _repo_name(action_name)
        if action_name is None:
            continue
        resolved.append(resolve_tag_to_sha(action_name, tag, github_token))
    return resolved


def format_pinned_replacement(pin: ResolvedPin) -> str:
    """Format a ready-to-copy pin replacement suggestion."""
    if pin.error:
        return f"Original: {pin.original_ref}\nPinned:   (unresolved: {pin.error})"
    return f"Original: {pin.original_ref}\nPinned:   {pin.pinned_ref}"


def _api_get_json(
    url: str,
    github_token: str | None,
) -> tuple[dict, str | None]:
    request = urllib.request.Request(
        url,
        headers=_headers(github_token),
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}, "tag not found"
        if exc.code == 403:
            return {}, "rate limited"
        return {}, f"GitHub API error: {exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {}, f"network error: {exc}"
    except json.JSONDecodeError as exc:
        return {}, f"invalid GitHub API response: {exc}"


def _headers(github_token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "actionscope",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    return headers


def _unique_unpinned_refs(workflow_data: dict) -> set[str]:
    refs: set[str] = set()
    jobs = workflow_data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return refs
    for job in jobs.values():
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
            if uses.startswith(("./", "../", "docker://")):
                continue
            if "@" not in uses or classify_action_ref(uses) == "sha":
                continue
            refs.add(uses)
    return refs


def _repo_name(action_part: str) -> str | None:
    pieces = action_part.split("/")
    if len(pieces) < 2:
        return None
    return "/".join(pieces[:2])


def _error_pin(action_name: str, tag: str, error: str) -> ResolvedPin:
    return ResolvedPin(
        original_ref=f"{action_name}@{tag}",
        action_name=action_name,
        tag=tag,
        resolved_sha=None,
        pinned_ref=None,
        error=error,
    )
