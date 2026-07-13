"""Schema validation for the bundled compromised_actions.json database.

A malformed entry would crash the compromised-actions analyzer at startup
for every user of ActionScope: `load_compromised_actions()` is called early
in every scan and its result is consumed by downstream code that assumes a
specific shape. These tests assert the structural invariants the loader and
downstream analyzers rely on, so a bad entry never lands on `main`.

Lives in `tests/` (not in a CI workflow) so the same checks run in every
pytest invocation, including local development before push.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

DB_PATH = (
    Path(__file__).resolve().parent.parent
    / "actionscope"
    / "data"
    / "compromised_actions.json"
)

ACTION_NAME_RE = re.compile(
    r"^[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?"
    r"/[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?$"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
ALLOWED_STATUSES = {"compromised", "historical"}
REQUIRED_TOP_LEVEL_KEYS = {"schema_version", "updated_at", "source", "actions"}
REQUIRED_ENTRY_KEYS = {
    "action",
    "compromised_at",
    "advisory_url",
    "description",
    "status",
    "affected_refs",
}


def _load() -> dict:
    return json.loads(DB_PATH.read_text(encoding="utf-8"))


def test_db_loads_as_json() -> None:
    data = _load()
    assert isinstance(data, dict)


def test_db_has_required_top_level_keys() -> None:
    data = _load()
    missing = REQUIRED_TOP_LEVEL_KEYS - set(data.keys())
    assert not missing, f"compromised_actions.json missing top-level keys: {missing}"
    assert isinstance(data["actions"], list), "`actions` must be a list"


def test_db_has_at_least_one_entry() -> None:
    """If the DB is ever empty the analyzer becomes a no-op, which is worse
    than a noisy failure since users would silently miss real compromises."""
    data = _load()
    assert len(data["actions"]) >= 1, (
        "compromised_actions.json must list at least one action"
    )


def test_every_entry_has_required_keys() -> None:
    data = _load()
    for i, entry in enumerate(data["actions"]):
        missing = REQUIRED_ENTRY_KEYS - set(entry.keys())
        assert not missing, f"actions[{i}] missing required keys: {sorted(missing)}"


def test_action_names_are_owner_slash_repo_format() -> None:
    data = _load()
    for i, entry in enumerate(data["actions"]):
        name = entry["action"]
        assert ACTION_NAME_RE.match(name), (
            f"actions[{i}].action={name!r} is not in owner/repo format"
        )


def test_compromised_at_is_iso8601() -> None:
    data = _load()
    for i, entry in enumerate(data["actions"]):
        ts = entry["compromised_at"]
        try:
            datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise AssertionError(
                f"actions[{i}].compromised_at={ts!r} is not ISO 8601 ({exc})"
            ) from exc


def test_advisory_url_is_http_url() -> None:
    data = _load()
    for i, entry in enumerate(data["actions"]):
        url = entry["advisory_url"]
        assert isinstance(url, str) and url.startswith(("http://", "https://")), (
            f"actions[{i}].advisory_url={url!r} is not an http(s) URL"
        )


def test_status_is_known_value() -> None:
    data = _load()
    for i, entry in enumerate(data["actions"]):
        status = entry["status"]
        assert status in ALLOWED_STATUSES, (
            f"actions[{i}].status={status!r} must be one of {sorted(ALLOWED_STATUSES)}"
        )


def test_affected_refs_is_list_of_strings() -> None:
    data = _load()
    for i, entry in enumerate(data["actions"]):
        refs = entry["affected_refs"]
        assert isinstance(refs, list), (
            f"actions[{i}].affected_refs must be a list, got {type(refs).__name__}"
        )
        for j, ref in enumerate(refs):
            assert isinstance(ref, str) and ref, (
                f"actions[{i}].affected_refs[{j}]={ref!r} is not a non-empty string"
            )


def test_safe_sha_is_full_sha_or_null() -> None:
    """`safe_sha` is optional — if set it must be a full 40-char hex SHA so the
    SHA-pin reasoning in is_compromised_ref can compare without prefix logic."""
    data = _load()
    for i, entry in enumerate(data["actions"]):
        safe = entry.get("safe_sha")
        if safe is None:
            continue
        assert SHA_RE.match(safe), (
            f"actions[{i}].safe_sha={safe!r} is not a 40-char hex SHA"
        )


def test_no_duplicate_action_entries() -> None:
    """`_entry_for_action` returns the first match — duplicates would silently
    shadow later entries with stale fields."""
    data = _load()
    names = [entry["action"].lower() for entry in data["actions"]]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    assert not duplicates, f"duplicate action entries: {duplicates}"


def test_loader_round_trip_matches_file(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """The analyzer's loader must return the same data the file holds."""
    from actionscope.analyzers.compromised_actions import load_compromised_actions

    monkeypatch.setenv(
        "ACTIONSCOPE_COMPROMISED_DB_CACHE",
        str(tmp_path / "does-not-exist.json"),
    )
    loaded = load_compromised_actions()
    on_disk = _load()
    assert loaded == on_disk
