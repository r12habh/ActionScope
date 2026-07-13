"""Fetch, merge, cache, and load compromised GitHub Action intelligence.

Network access is explicit through ``actionscope update-db``. Normal scans only
read the bundled database or a previously written local cache.
"""

from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from actionscope import __version__

BUNDLED_DB_FILE = Path(__file__).parent / "data" / "compromised_actions.json"
DEFAULT_CACHE_FILE = Path.home() / ".actionscope" / "compromised_actions_cache.json"
DEFAULT_TTL_HOURS = 24
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
OPENSSF_CONTENTS_URLS = (
    "https://api.github.com/repos/ossf/malicious-packages/contents/"
    "osv/malicious/github-actions",
    "https://api.github.com/repos/ossf/malicious-packages/contents/"
    "osv/malicious/actions",
)
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_OPENSSF_RECORDS = 1_000
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_ACTION_NAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?"
    r"/[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?$"
)


@dataclass(frozen=True)
class DatabaseUpdateResult:
    """Outcome of an explicit compromised-action database refresh."""

    cache_file: Path
    action_count: int
    remote_action_count: int
    wrote_cache: bool
    source_status: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class CompromisedDatabaseError(RuntimeError):
    """Raised when a remote feed cannot be parsed or safely consumed."""


def resolve_cache_file(cache_file: str | Path | None = None) -> Path:
    """Resolve the cache path, honoring the test/automation environment hook."""
    if cache_file is not None:
        return Path(cache_file).expanduser()
    configured = os.environ.get("ACTIONSCOPE_COMPROMISED_DB_CACHE")
    if configured:
        return Path(configured).expanduser()
    return DEFAULT_CACHE_FILE


def load_bundled_database() -> dict:
    """Load the release-bundled database."""
    with BUNDLED_DB_FILE.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    _validate_database(data, str(BUNDLED_DB_FILE))
    return data


def load_cached_database(
    cache_file: str | Path | None = None,
    *,
    allow_stale: bool = False,
    now: datetime | None = None,
) -> dict | None:
    """Load a valid local cache, optionally allowing an expired cache."""
    path = resolve_cache_file(cache_file)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        _validate_database(data, str(path))
    except (
        FileNotFoundError,
        PermissionError,
        OSError,
        ValueError,
        TypeError,
        CompromisedDatabaseError,
    ):
        return None

    cache_metadata = data.get("cache_metadata")
    if not isinstance(cache_metadata, dict):
        return None
    if allow_stale:
        return data

    expires_at = _parse_timestamp(cache_metadata.get("expires_at"))
    current = now or datetime.now(timezone.utc)
    if expires_at is None or expires_at <= current:
        return None
    return data


def load_best_database(
    cache_file: str | Path | None = None,
    *,
    offline: bool = False,
) -> dict:
    """Prefer a local cache, then fall back to the bundled database.

    Offline scans may use an expired cache because it can contain newer entries
    than the bundled release and still requires no network access.
    """
    cached = load_cached_database(cache_file, allow_stale=offline)
    return cached if cached is not None else load_bundled_database()


def fetch_ghsa_actions(github_token: str | None = None) -> list[dict]:
    """Fetch and normalize GitHub Actions malware advisories with pagination."""
    query = urlencode(
        {
            "type": "malware",
            "ecosystem": "actions",
            "per_page": 100,
        }
    )
    url: str | None = f"{GITHUB_ADVISORIES_URL}?{query}"
    advisories: list[dict] = []
    seen_urls: set[str] = set()

    while url:
        if url in seen_urls:
            raise CompromisedDatabaseError("GitHub advisory pagination loop detected")
        seen_urls.add(url)
        payload, headers = _request_json(url, github_token)
        if not isinstance(payload, list):
            raise CompromisedDatabaseError(
                "GitHub advisory response root is not a list"
            )
        advisories.extend(item for item in payload if isinstance(item, dict))
        url = _next_link(headers.get("link") or headers.get("Link"))

    return normalize_ghsa_advisories(advisories)


def fetch_openssf_actions(
    github_token: str | None = None,
) -> tuple[list[dict], bool]:
    """Probe the optional OpenSSF GitHub Actions feed.

    The malicious-packages repository does not currently publish a stable
    GitHub Actions directory. A 404 therefore means "unavailable", not an
    updater failure. The recursive reader is ready if either candidate path is
    added later.
    """
    for root_url in OPENSSF_CONTENTS_URLS:
        try:
            records = _fetch_openssf_records(root_url, github_token)
        except HTTPError as exc:
            if exc.code == 404:
                continue
            raise
        return normalize_osv_records(records), True
    return [], False


def normalize_ghsa_advisories(advisories: list[dict]) -> list[dict]:
    """Convert GitHub global advisory objects into ActionScope entries."""
    entries: list[dict] = []
    for advisory in advisories:
        vulnerabilities = advisory.get("vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            continue
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            package = vulnerability.get("package") or {}
            if not isinstance(package, dict) or not _is_actions_ecosystem(
                package.get("ecosystem")
            ):
                continue
            action_name = _normalize_action_name(package.get("name"))
            if action_name is None:
                continue
            published_at = advisory.get("published_at") or advisory.get("updated_at")
            advisory_url = advisory.get("html_url") or advisory.get("url")
            if not isinstance(published_at, str) or not isinstance(
                advisory_url, str
            ):
                continue
            description = advisory.get("description") or advisory.get("summary")
            entries.append(
                {
                    "action": action_name,
                    "compromised_at": published_at,
                    "safe_sha": None,
                    "advisory_url": advisory_url,
                    "description": str(description or "GitHub malware advisory."),
                    "status": "compromised",
                    # GHSA ranges do not reliably identify Git refs. An empty
                    # list intentionally means all mutable refs for this action.
                    "affected_refs": [],
                    "malicious_shas": [],
                    "source_ids": [str(advisory.get("ghsa_id") or "")],
                }
            )
    return _merge_duplicate_entries(entries)


def normalize_osv_records(records: list[dict]) -> list[dict]:
    """Convert OSV malicious-package records into ActionScope entries."""
    entries: list[dict] = []
    for record in records:
        affected_items = record.get("affected") or []
        if not affected_items and isinstance(record.get("package"), dict):
            affected_items = [{"package": record["package"]}]
        if not isinstance(affected_items, list):
            continue

        for affected in affected_items:
            if not isinstance(affected, dict):
                continue
            package = affected.get("package") or {}
            if not isinstance(package, dict) or not _is_actions_ecosystem(
                package.get("ecosystem")
            ):
                continue
            action_name = _normalize_action_name(package.get("name"))
            if action_name is None:
                continue

            published_at = record.get("published") or record.get("modified")
            if not isinstance(published_at, str):
                continue
            database_specific = record.get("database_specific") or {}
            if not isinstance(database_specific, dict):
                database_specific = {}
            versions = affected.get("versions") or []
            affected_refs = [
                str(item)
                for item in versions
                if isinstance(item, str) and item and not _FULL_SHA_RE.fullmatch(item)
            ]
            malicious_shas = _valid_shas(
                database_specific.get("malicious_shas") or []
            )
            references = record.get("references") or []
            advisory_url = _osv_advisory_url(references)
            entries.append(
                {
                    "action": action_name,
                    "compromised_at": published_at,
                    "safe_sha": None,
                    "advisory_url": advisory_url,
                    "description": str(
                        record.get("details") or "OpenSSF malicious package report."
                    ),
                    "status": "compromised",
                    "affected_refs": sorted(set(affected_refs)),
                    "malicious_shas": malicious_shas,
                    "source_ids": [str(record.get("id") or "")],
                }
            )
    return _merge_duplicate_entries(entries)


def merge_action_databases(
    bundled: dict,
    remote_entries: list[dict],
    *,
    fetched_at: datetime,
    ttl_hours: int,
    source_status: dict[str, str],
) -> dict:
    """Merge curated and remote entries while preserving ref/SHA semantics."""
    if ttl_hours <= 0:
        raise ValueError("ttl_hours must be greater than zero")
    merged_entries = [deepcopy(item) for item in bundled.get("actions", [])]
    by_action = {
        str(entry.get("action", "")).lower(): entry for entry in merged_entries
    }
    for remote_entry in remote_entries:
        action_name = str(remote_entry.get("action", "")).lower()
        if not action_name:
            continue
        existing = by_action.get(action_name)
        if existing is None:
            copied = deepcopy(remote_entry)
            merged_entries.append(copied)
            by_action[action_name] = copied
        else:
            _merge_entry(existing, remote_entry)

    fetched_utc = fetched_at.astimezone(timezone.utc)
    expires_at = fetched_utc + timedelta(hours=ttl_hours)
    return {
        "schema_version": "2",
        "updated_at": fetched_utc.date().isoformat(),
        "source": "ActionScope bundled database plus public advisory feeds",
        "cache_metadata": {
            "fetched_at": _format_timestamp(fetched_utc),
            "expires_at": _format_timestamp(expires_at),
            "ttl_seconds": ttl_hours * 3600,
            "sources": dict(source_status),
        },
        "actions": sorted(
            merged_entries,
            key=lambda entry: str(entry.get("action", "")).lower(),
        ),
    }


def write_cache_atomic(data: dict, cache_file: str | Path | None = None) -> Path:
    """Write the cache atomically so interrupted updates cannot corrupt it."""
    _validate_database(data, "generated cache")
    path = resolve_cache_file(cache_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(data, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return path


def update_compromised_actions_cache(
    *,
    github_token: str | None = None,
    cache_file: str | Path | None = None,
    ttl_hours: int = DEFAULT_TTL_HOURS,
    now: datetime | None = None,
) -> DatabaseUpdateResult:
    """Refresh public feeds and write a merged local cache."""
    bundled = load_bundled_database()
    remote_entries: list[dict] = []
    source_status: dict[str, str] = {}
    warnings: list[str] = []
    successful_source = False

    try:
        ghsa_entries = fetch_ghsa_actions(github_token)
        remote_entries.extend(ghsa_entries)
        source_status["github_advisories"] = f"ok ({len(ghsa_entries)} entries)"
        successful_source = True
    except (
        HTTPError,
        URLError,
        TimeoutError,
        OSError,
        ValueError,
        CompromisedDatabaseError,
    ) as exc:
        source_status["github_advisories"] = "error"
        warnings.append(f"GitHub advisory update failed: {_network_error_detail(exc)}")

    try:
        openssf_entries, available = fetch_openssf_actions(github_token)
        if available:
            remote_entries.extend(openssf_entries)
            source_status["openssf_malicious_packages"] = (
                f"ok ({len(openssf_entries)} entries)"
            )
            successful_source = True
        else:
            source_status["openssf_malicious_packages"] = "unavailable"
    except (
        HTTPError,
        URLError,
        TimeoutError,
        OSError,
        ValueError,
        CompromisedDatabaseError,
    ) as exc:
        source_status["openssf_malicious_packages"] = "error"
        warnings.append(f"OpenSSF update failed: {_network_error_detail(exc)}")

    path = resolve_cache_file(cache_file)
    if not successful_source:
        return DatabaseUpdateResult(
            cache_file=path,
            action_count=len(bundled.get("actions", [])),
            remote_action_count=0,
            wrote_cache=False,
            source_status=source_status,
            warnings=warnings,
        )

    fetched_at = now or datetime.now(timezone.utc)
    merged = merge_action_databases(
        bundled,
        remote_entries,
        fetched_at=fetched_at,
        ttl_hours=ttl_hours,
        source_status=source_status,
    )
    write_cache_atomic(merged, path)
    return DatabaseUpdateResult(
        cache_file=path,
        action_count=len(merged["actions"]),
        remote_action_count=len(
            {str(entry.get("action", "")).lower() for entry in remote_entries}
        ),
        wrote_cache=True,
        source_status=source_status,
        warnings=warnings,
    )


def _request_json(
    url: str,
    github_token: str | None,
) -> tuple[Any, dict[str, str]]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"ActionScope/{__version__}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=15) as response:  # noqa: S310
        payload = response.read(MAX_RESPONSE_BYTES + 1)
        if len(payload) > MAX_RESPONSE_BYTES:
            raise CompromisedDatabaseError(
                f"remote response exceeds {MAX_RESPONSE_BYTES} bytes"
            )
        response_headers = {str(k): str(v) for k, v in response.headers.items()}
    try:
        return json.loads(payload.decode("utf-8")), response_headers
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompromisedDatabaseError(f"remote response is not valid JSON: {exc}")


def _fetch_openssf_records(
    root_url: str,
    github_token: str | None,
) -> list[dict]:
    records: list[dict] = []
    pending = [root_url]
    visited: set[str] = set()
    while pending:
        url = pending.pop()
        if url in visited:
            continue
        visited.add(url)
        payload, _headers = _request_json(url, github_token)
        if isinstance(payload, dict) and "id" in payload:
            records.append(payload)
            continue
        if not isinstance(payload, list):
            raise CompromisedDatabaseError(
                "OpenSSF contents response root is not a list"
            )
        for item in payload:
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            if item_type == "dir" and isinstance(item.get("url"), str):
                pending.append(item["url"])
            elif (
                item_type == "file"
                and str(item.get("name", "")).endswith(".json")
                and isinstance(item.get("download_url"), str)
            ):
                record, _headers = _request_json(item["download_url"], None)
                if isinstance(record, dict):
                    records.append(record)
            if len(records) > MAX_OPENSSF_RECORDS:
                raise CompromisedDatabaseError(
                    f"OpenSSF feed exceeds {MAX_OPENSSF_RECORDS} records"
                )
    return records


def _next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        section = part.strip()
        if 'rel="next"' not in section:
            continue
        match = re.match(r"<([^>]+)>", section)
        if match:
            return match.group(1)
    return None


def _merge_duplicate_entries(entries: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for entry in entries:
        key = str(entry.get("action", "")).lower()
        if key in merged:
            _merge_entry(merged[key], entry)
        elif key:
            merged[key] = deepcopy(entry)
    return list(merged.values())


def _merge_entry(existing: dict, incoming: dict) -> None:
    existing_refs = existing.get("affected_refs") or []
    incoming_refs = incoming.get("affected_refs") or []
    if not existing_refs or not incoming_refs:
        existing["affected_refs"] = []
    else:
        existing["affected_refs"] = sorted(
            {str(item) for item in existing_refs + incoming_refs}
        )

    existing["malicious_shas"] = sorted(
        set(_valid_shas(existing.get("malicious_shas") or []))
        | set(_valid_shas(incoming.get("malicious_shas") or []))
    )
    existing["source_ids"] = sorted(
        {
            str(item)
            for item in (existing.get("source_ids") or [])
            + (incoming.get("source_ids") or [])
            if str(item)
        }
    )
    existing["compromised_at"] = min(
        str(existing.get("compromised_at") or incoming.get("compromised_at")),
        str(incoming.get("compromised_at") or existing.get("compromised_at")),
    )
    if incoming.get("status") == "compromised":
        existing["status"] = "compromised"
    if not existing.get("advisory_url") and incoming.get("advisory_url"):
        existing["advisory_url"] = incoming["advisory_url"]
    if not existing.get("description") and incoming.get("description"):
        existing["description"] = incoming["description"]


def _normalize_action_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if normalized.lower().startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    normalized = normalized.removesuffix(".git").strip("/")
    parts = normalized.split("/")
    if len(parts) != 2 or not _ACTION_NAME_RE.fullmatch(normalized):
        return None
    return normalized.lower()


def _is_actions_ecosystem(value: object) -> bool:
    if not isinstance(value, str):
        return False
    normalized = re.sub(r"[\s_-]", "", value).lower()
    return normalized in {"actions", "githubaction", "githubactions"}


def _valid_shas(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    return sorted(
        {
            str(value).lower()
            for value in values
            if isinstance(value, str) and _FULL_SHA_RE.fullmatch(value)
        }
    )


def _osv_advisory_url(references: object) -> str:
    if isinstance(references, list):
        for reference in references:
            if not isinstance(reference, dict):
                continue
            url = reference.get("url")
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                return url
    return "https://github.com/ossf/malicious-packages"


def _validate_database(data: object, source: str) -> None:
    if not isinstance(data, dict) or not isinstance(data.get("actions"), list):
        raise CompromisedDatabaseError(
            f"compromised actions database {source} has no actions list"
        )


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _network_error_detail(exc: BaseException) -> str:
    if isinstance(exc, HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, URLError):
        return str(exc.reason)
    return str(exc)
