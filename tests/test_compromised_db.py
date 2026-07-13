"""Tests for compromised-action feed updates and local cache behavior."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest
from click.testing import CliRunner

import actionscope.compromised_db as compromised_db
from actionscope.cli import main
from actionscope.compromised_db import (
    DatabaseUpdateResult,
    fetch_ghsa_actions,
    fetch_openssf_actions,
    load_best_database,
    load_bundled_database,
    load_cached_database,
    merge_action_databases,
    normalize_ghsa_advisories,
    normalize_osv_records,
    resolve_cache_file,
    update_compromised_actions_cache,
    write_cache_atomic,
)

NOW = datetime(2026, 7, 12, 12, 0, tzinfo=timezone.utc)
MALICIOUS_SHA = "0e58ed867288e6711d10da9293b8db84f3f3ed85"


def _entry(
    action: str = "example/bad-action",
    *,
    refs: list[str] | None = None,
    shas: list[str] | None = None,
) -> dict:
    return {
        "action": action,
        "compromised_at": "2026-07-01T00:00:00Z",
        "safe_sha": None,
        "advisory_url": "https://github.com/advisories/GHSA-test-test-test",
        "description": "Test malware advisory.",
        "status": "compromised",
        "affected_refs": [] if refs is None else refs,
        "malicious_shas": [] if shas is None else shas,
        "source_ids": ["GHSA-test-test-test"],
    }


def _ghsa(action: str = "example/bad-action") -> dict:
    return {
        "ghsa_id": f"GHSA-{action.replace('/', '-')}",
        "type": "malware",
        "html_url": "https://github.com/advisories/GHSA-test-test-test",
        "published_at": "2026-07-01T00:00:00Z",
        "summary": "Malicious GitHub Action",
        "description": "Steals workflow credentials.",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "actions", "name": action},
                "vulnerable_version_range": ">= 0",
            }
        ],
    }


def _cache(
    tmp_path: Path,
    entries: list[dict],
    *,
    fetched_at: datetime | None = None,
    ttl_hours: int = 24,
) -> Path:
    data = merge_action_databases(
        load_bundled_database(),
        entries,
        fetched_at=fetched_at or datetime.now(timezone.utc),
        ttl_hours=ttl_hours,
        source_status={"test": "ok"},
    )
    return write_cache_atomic(data, tmp_path / "cache.json")


def test_resolve_cache_file_honors_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    expected = tmp_path / "custom.json"
    monkeypatch.setenv("ACTIONSCOPE_COMPROMISED_DB_CACHE", str(expected))

    assert resolve_cache_file() == expected


def test_load_cached_database_accepts_fresh_cache(tmp_path: Path) -> None:
    cache_file = _cache(tmp_path, [_entry()])

    loaded = load_cached_database(cache_file, now=NOW + timedelta(hours=1))

    assert loaded is not None
    assert any(item["action"] == "example/bad-action" for item in loaded["actions"])


def test_expired_cache_is_ignored_online_but_allowed_offline(tmp_path: Path) -> None:
    cache_file = _cache(tmp_path, [_entry()], fetched_at=NOW - timedelta(days=2))

    assert load_cached_database(cache_file, now=NOW) is None
    offline = load_cached_database(cache_file, allow_stale=True, now=NOW)
    assert offline is not None
    assert any(item["action"] == "example/bad-action" for item in offline["actions"])


def test_invalid_cache_falls_back_to_bundled(tmp_path: Path) -> None:
    cache_file = tmp_path / "cache.json"
    cache_file.write_text("not json", encoding="utf-8")

    loaded = load_best_database(cache_file)

    assert loaded == load_bundled_database()


def test_valid_json_with_invalid_cache_shape_falls_back_to_bundled(
    tmp_path: Path,
) -> None:
    cache_file = tmp_path / "cache.json"
    cache_file.write_text('{"actions": "not-a-list"}', encoding="utf-8")

    loaded = load_best_database(cache_file)

    assert loaded == load_bundled_database()


def test_normalize_ghsa_advisory_creates_mutable_ref_entry() -> None:
    entries = normalize_ghsa_advisories([_ghsa()])

    assert len(entries) == 1
    assert entries[0]["action"] == "example/bad-action"
    assert entries[0]["affected_refs"] == []
    assert entries[0]["status"] == "compromised"


def test_normalize_ghsa_ignores_non_actions_ecosystem() -> None:
    advisory = _ghsa()
    advisory["vulnerabilities"][0]["package"]["ecosystem"] = "pip"

    assert normalize_ghsa_advisories([advisory]) == []


def test_fetch_ghsa_actions_follows_pagination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_request(url: str, _token: str | None):
        calls.append(url)
        if len(calls) == 1:
            return (
                [_ghsa("one/action")],
                {"Link": '<https://api.github.com/advisories?page=2>; rel="next"'},
            )
        return [_ghsa("two/action")], {}

    monkeypatch.setattr(compromised_db, "_request_json", fake_request)

    entries = fetch_ghsa_actions("token")

    assert {entry["action"] for entry in entries} == {
        "one/action",
        "two/action",
    }
    assert len(calls) == 2


def test_fetch_ghsa_actions_rejects_pagination_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    loop_url = "https://api.github.com/advisories?loop=true"

    def fake_request(_url: str, _token: str | None):
        return [], {"Link": f'<{loop_url}>; rel="next"'}

    monkeypatch.setattr(compromised_db, "_request_json", fake_request)

    with pytest.raises(compromised_db.CompromisedDatabaseError):
        fetch_ghsa_actions()


def test_normalize_osv_preserves_refs_and_exact_bad_shas() -> None:
    record = {
        "id": "MAL-2026-1",
        "published": "2026-07-01T00:00:00Z",
        "details": "Credential stealer.",
        "affected": [
            {
                "package": {
                    "ecosystem": "GitHub Actions",
                    "name": "https://github.com/example/bad-action",
                },
                "versions": ["v1", MALICIOUS_SHA],
            }
        ],
        "database_specific": {"malicious_shas": [MALICIOUS_SHA]},
        "references": [{"url": "https://example.com/advisory"}],
    }

    entries = normalize_osv_records([record])

    assert entries[0]["affected_refs"] == ["v1"]
    assert entries[0]["malicious_shas"] == [MALICIOUS_SHA]


def test_openssf_missing_feed_is_cleanly_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(_url: str, _token: str | None):
        raise HTTPError("https://example.test", 404, "not found", {}, None)

    monkeypatch.setattr(compromised_db, "_request_json", missing)

    entries, available = fetch_openssf_actions()

    assert entries == []
    assert available is False


def test_merge_preserves_all_mutable_refs_and_known_bad_sha() -> None:
    bundled = {
        "schema_version": "1",
        "updated_at": "2026-01-01",
        "source": "test",
        "actions": [_entry(refs=["v1"], shas=[MALICIOUS_SHA])],
    }
    remote = [_entry(refs=[], shas=[])]

    merged = merge_action_databases(
        bundled,
        remote,
        fetched_at=NOW,
        ttl_hours=24,
        source_status={"github_advisories": "ok"},
    )

    entry = merged["actions"][0]
    assert entry["affected_refs"] == []
    assert entry["malicious_shas"] == [MALICIOUS_SHA]
    assert merged["cache_metadata"]["ttl_seconds"] == 86400


def test_write_cache_is_atomic_and_leaves_no_temp_file(tmp_path: Path) -> None:
    data = merge_action_databases(
        load_bundled_database(),
        [],
        fetched_at=NOW,
        ttl_hours=24,
        source_status={"test": "ok"},
    )
    target = tmp_path / "cache.json"

    write_cache_atomic(data, target)

    assert json.loads(target.read_text(encoding="utf-8"))["actions"]
    assert list(tmp_path.glob("*.tmp")) == []
    assert list(tmp_path.glob(".*.tmp")) == []


def test_updater_writes_cache_when_ghsa_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        compromised_db,
        "fetch_ghsa_actions",
        lambda _token=None: [_entry()],
    )
    monkeypatch.setattr(
        compromised_db,
        "fetch_openssf_actions",
        lambda _token=None: ([], False),
    )
    cache_file = tmp_path / "cache.json"

    result = update_compromised_actions_cache(
        cache_file=cache_file,
        now=NOW,
    )

    assert result.wrote_cache is True
    assert result.remote_action_count == 1
    assert cache_file.exists()


def test_updater_keeps_existing_data_when_all_sources_fail(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fail(_token=None):
        raise URLError("offline")

    monkeypatch.setattr(compromised_db, "fetch_ghsa_actions", fail)
    monkeypatch.setattr(compromised_db, "fetch_openssf_actions", fail)
    cache_file = tmp_path / "cache.json"

    result = update_compromised_actions_cache(cache_file=cache_file, now=NOW)

    assert result.wrote_cache is False
    assert len(result.warnings) == 2
    assert not cache_file.exists()


def test_update_db_cli_reports_written_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cache_file = tmp_path / "cache.json"
    monkeypatch.setattr(
        compromised_db,
        "update_compromised_actions_cache",
        lambda **_kwargs: DatabaseUpdateResult(
            cache_file=cache_file,
            action_count=5,
            remote_action_count=1,
            wrote_cache=True,
            source_status={"github_advisories": "ok (1 entries)"},
        ),
    )

    result = CliRunner().invoke(main, ["update-db", "--cache-file", str(cache_file)])

    assert result.exit_code == 0
    assert "Wrote 5 compromised-action entries" in result.output


@pytest.mark.parametrize("network_flag", ["--aws-verify", "--resolve-pins"])
def test_offline_rejects_network_scan_flags(
    tmp_path: Path,
    network_flag: str,
) -> None:
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--offline", network_flag],
    )

    assert result.exit_code == 2
    assert "--offline cannot be combined" in result.output


def test_offline_prevents_external_reusable_workflow_fetch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "caller.yml").write_text(
        """
on: push
jobs:
  deploy:
    uses: acme/platform/.github/workflows/deploy.yml@v1
""",
        encoding="utf-8",
    )

    def unexpected_fetch(*_args, **_kwargs):
        raise AssertionError("offline scan attempted a network fetch")

    monkeypatch.setattr(
        "actionscope.analyzers.reusable_workflows._fetch_external_workflow",
        unexpected_fetch,
    )
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--offline", "--output-format", "json"],
        env={"GITHUB_TOKEN": "ambient-token"},
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["reusable_workflows"][0]["status"] == "offline"


def test_scan_uses_fresh_compromised_action_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cache_file = _cache(tmp_path, [_entry("example/bad-action")])
    monkeypatch.setenv("ACTIONSCOPE_COMPROMISED_DB_CACHE", str(cache_file))
    workflow_dir = tmp_path / "repo" / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text(
        """
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: example/bad-action@v1
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(tmp_path / "repo"),
            "--offline",
            "--output-format",
            "json",
        ],
    )

    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["compromised_action_findings"][0]["action_name"] == (
        "example/bad-action"
    )
