"""Tests for GitHub's public-preview Actions dependency lockfile."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from actionscope.analyzers.compromised_actions import (
    scan_for_compromised_actions,
)
from actionscope.cli import main
from actionscope.models import RiskLevel
from actionscope.parsers.actions_lock import (
    canonical_action_key,
    load_actions_lock,
    scan_dependency_locks,
)
from actionscope.parsers.workflow import classify_action_ref, is_pinned_to_sha
from actionscope.pipeline import collect_static_evidence, correlate_evidence
from actionscope.reporters.json_reporter import to_json

FIXTURES = Path(__file__).parent / "fixtures" / "actions_lock"


def test_loads_current_v003_schema_and_transitive_graph() -> None:
    lockfile, errors = load_actions_lock(str(FIXTURES / "fully_locked"))

    assert errors == []
    assert lockfile is not None
    assert lockfile.version == "v0.0.3"
    assert lockfile.dependencies["actions/checkout@v4"].commit_sha == "1" * 40
    assert lockfile.dependencies["actions/setup-python@v5"].uses == (
        "actions/cache@v4",
    )


def test_fully_locked_workflow_suppresses_unpinned_findings() -> None:
    repo = str(FIXTURES / "fully_locked")
    evidence = collect_static_evidence(repo, offline=True)

    assert evidence.unpinned_actions == []
    assert len(evidence.dependency_locks) == 1
    coverage = evidence.dependency_locks[0]
    assert coverage.status == "fully_locked"
    assert coverage.direct_dependencies == 2
    assert coverage.locked_direct_dependencies == 2
    assert coverage.transitive_dependencies == 1


def test_partially_locked_workflow_keeps_uncovered_finding() -> None:
    evidence = collect_static_evidence(str(FIXTURES / "partially_locked"), offline=True)

    assert [item.uses for item in evidence.unpinned_actions] == [
        "actions/setup-python@v5"
    ]
    coverage = evidence.dependency_locks[0]
    assert coverage.status == "partially_locked"
    assert coverage.uncovered_dependencies == ["actions/setup-python@v5"]


def test_stale_lock_does_not_cover_changed_workflow_ref() -> None:
    evidence = collect_static_evidence(str(FIXTURES / "stale"), offline=True)

    assert [item.uses for item in evidence.unpinned_actions] == ["actions/checkout@v5"]
    assert evidence.dependency_locks[0].status == "partially_locked"
    assert evidence.dependency_locks[0].uncovered_dependencies == [
        "actions/checkout@v5"
    ]


def test_malformed_commit_fails_open_and_reports_error() -> None:
    evidence = collect_static_evidence(str(FIXTURES / "malformed"), offline=True)

    assert [item.uses for item in evidence.unpinned_actions] == ["actions/checkout@v4"]
    assert evidence.dependency_locks[0].status == "invalid"
    assert evidence.dependency_locks[0].invalid_dependencies == ["actions/checkout@v4"]
    assert evidence.dependency_locks[0].uncovered_dependencies == [
        "actions/checkout@v4"
    ]
    assert any("full commit digest" in error for error in evidence.errors)


def test_known_malicious_transitive_commit_is_critical() -> None:
    findings, errors = scan_for_compromised_actions(
        str(FIXTURES / "compromised_transitive"), offline=True
    )

    assert errors == []
    locked = [item for item in findings if item.job_name == "actions.lock"]
    assert len(locked) == 1
    assert locked[0].action_name == "tj-actions/changed-files"
    assert locked[0].ref == "0e58ed867288e6711d10da9293b8db84f3f3ed85"
    assert locked[0].risk_level is RiskLevel.CRITICAL


def test_pipeline_propagates_locked_malicious_commit_to_overall_risk() -> None:
    repo = str(FIXTURES / "compromised_transitive")
    evidence = collect_static_evidence(repo, offline=True)
    result = correlate_evidence(repo, evidence, offline=True)

    assert evidence.unpinned_actions == []
    assert result.overall_risk is RiskLevel.CRITICAL
    assert len(result.compromised_action_findings) == 1
    assert result.compromised_action_findings[0].job_name == "actions.lock"


def test_unverified_locked_commit_keeps_compromised_tag_finding(
    tmp_path: Path,
) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions-cool/issues-helper@v3\n",
        encoding="utf-8",
    )
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\n"
        "workflows:\n"
        "  .github/workflows/ci.yml:\n"
        "    - actions-cool/issues-helper@v3\n"
        "dependencies:\n"
        "  actions-cool/issues-helper@v3:\n"
        "    ref: v3\n"
        f"    commit: sha1-{'f' * 40}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n",
        encoding="utf-8",
    )

    findings, errors = scan_for_compromised_actions(str(tmp_path), offline=True)

    assert errors == []
    assert len(findings) == 1
    assert findings[0].uses_ref == "actions-cool/issues-helper@v3"
    assert "f" * 40 in findings[0].description
    assert "not recorded as a verified safe SHA" in findings[0].description


def test_verified_safe_locked_commit_suppresses_compromised_tag_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    safe_sha = "f" * 40
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: example/compromised@v1\n",
        encoding="utf-8",
    )
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\n"
        "workflows:\n"
        "  .github/workflows/ci.yml:\n"
        "    - example/compromised@v1\n"
        "dependencies:\n"
        "  example/compromised@v1:\n"
        "    ref: v1\n"
        f"    commit: sha1-{safe_sha}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n",
        encoding="utf-8",
    )
    db = {
        "actions": [
            {
                "action": "example/compromised",
                "affected_refs": ["v1"],
                "malicious_shas": [],
                "safe_sha": safe_sha,
                "compromised_at": "2026-01-01T00:00:00Z",
                "advisory_url": "https://example.test/advisory",
                "description": "Test compromise.",
            }
        ]
    }
    monkeypatch.setattr(
        "actionscope.analyzers.compromised_actions.load_compromised_actions",
        lambda **_kwargs: db,
    )

    findings, errors = scan_for_compromised_actions(str(tmp_path), offline=True)

    assert errors == []
    assert findings == []


def test_deleted_workflow_lock_entry_does_not_report_compromise(
    tmp_path: Path,
) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo safe\n",
        encoding="utf-8",
    )
    malicious_sha = "0e58ed867288e6711d10da9293b8db84f3f3ed85"
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\n"
        "workflows:\n"
        "  .github/workflows/deleted.yml:\n"
        "    - tj-actions/changed-files@v45\n"
        "dependencies:\n"
        "  tj-actions/changed-files@v45:\n"
        "    ref: v45\n"
        f"    commit: sha1-{malicious_sha}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n",
        encoding="utf-8",
    )

    findings, errors = scan_for_compromised_actions(str(tmp_path), offline=True)

    assert errors == []
    assert findings == []


def test_json_reports_per_workflow_lock_coverage() -> None:
    repo = str(FIXTURES / "fully_locked")
    evidence = collect_static_evidence(repo, offline=True)
    result = correlate_evidence(repo, evidence, offline=True)
    payload = json.loads(to_json(result))

    assert payload["summary"]["fully_locked_workflows"] == 1
    assert payload["dependency_locks"][0]["status"] == "fully_locked"
    assert payload["dependency_locks"][0]["transitive_dependencies"] == 1


def test_terminal_reports_lock_coverage_without_aws_credentials() -> None:
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(FIXTURES / "fully_locked"),
            "--output-format",
            "terminal",
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Workflow Dependency Locks" in result.output
    assert "fully locked" in result.output
    assert "Unpinned Actions" not in result.output


def test_unsupported_future_schema_fails_open(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    (workflows / "actions.lock").write_text(
        "version: v9.0.0\nworkflows: {}\ndependencies: {}\n",
        encoding="utf-8",
    )

    evidence = collect_static_evidence(str(tmp_path), offline=True)

    assert len(evidence.unpinned_actions) == 1
    assert evidence.dependency_locks[0].status == "invalid"
    assert any("Unsupported dependency lockfile version" in e for e in evidence.errors)


def test_unhashable_schema_version_fails_open(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  triage:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions-cool/issues-helper@v3\n",
        encoding="utf-8",
    )
    (workflows / "actions.lock").write_text(
        "version: []\nworkflows: {}\ndependencies: {}\n",
        encoding="utf-8",
    )

    lockfile, errors = load_actions_lock(str(tmp_path))
    findings, _ = scan_for_compromised_actions(str(tmp_path), offline=True)

    assert lockfile is None
    assert any("Unsupported dependency lockfile version" in error for error in errors)
    assert [finding.uses_ref for finding in findings] == [
        "actions-cool/issues-helper@v3"
    ]


def test_recursive_yaml_failure_is_reported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "actions.lock").write_text("version: v0.0.3\n", encoding="utf-8")

    def raise_recursion_error(*_args: object, **_kwargs: object) -> None:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(
        "actionscope.parsers.actions_lock.yaml.load",
        raise_recursion_error,
    )

    lockfile, errors = load_actions_lock(str(tmp_path))

    assert lockfile is None
    assert any("maximum recursion depth exceeded" in error for error in errors)


def test_unsafe_workflow_path_invalidates_entire_lockfile(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\n"
        "workflows:\n"
        "  ../../outside.yml:\n"
        "    - actions/checkout@v4\n"
        "dependencies:\n"
        "  actions/checkout@v4:\n"
        "    ref: v4\n"
        f"    commit: sha1-{'d' * 40}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n",
        encoding="utf-8",
    )

    evidence = collect_static_evidence(str(tmp_path), offline=True)

    assert evidence.dependency_locks[0].status == "invalid"
    assert len(evidence.unpinned_actions) == 1
    assert any("unsafe workflow path" in error for error in evidence.errors)


def test_duplicate_yaml_key_is_rejected_without_suppressing_finding(
    tmp_path: Path,
) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    dependency = (
        f"    ref: v4\n    commit: sha1-{'e' * 40}\n    owner_id: 1\n    repo_id: 2\n"
    )
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\n"
        "workflows:\n"
        "  .github/workflows/ci.yml:\n"
        "    - actions/checkout@v4\n"
        "dependencies:\n"
        f"  actions/checkout@v4:\n{dependency}"
        f"  actions/checkout@v4:\n{dependency}",
        encoding="utf-8",
    )

    evidence = collect_static_evidence(str(tmp_path), offline=True)

    assert evidence.dependency_locks[0].status == "invalid"
    assert len(evidence.unpinned_actions) == 1
    assert any("duplicate key" in error for error in evidence.errors)


def test_dependency_cycle_invalidates_lockfile(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: octo/a@v1\n",
        encoding="utf-8",
    )
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\n"
        "workflows:\n"
        "  .github/workflows/ci.yml:\n"
        "    - octo/a@v1\n"
        "dependencies:\n"
        "  octo/a@v1:\n"
        "    ref: v1\n"
        f"    commit: sha1-{'a' * 40}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n"
        "    uses: [octo/b@v1]\n"
        "  octo/b@v1:\n"
        "    ref: v1\n"
        f"    commit: sha1-{'b' * 40}\n"
        "    owner_id: 3\n"
        "    repo_id: 4\n"
        "    uses: [octo/a@v1]\n",
        encoding="utf-8",
    )

    evidence = collect_static_evidence(str(tmp_path), offline=True)

    assert evidence.dependency_locks[0].status == "invalid"
    assert evidence.dependency_locks[0].uncovered_dependencies == ["octo/a@v1"]
    assert len(evidence.unpinned_actions) == 1
    assert any("uses cycle" in error for error in evidence.errors)


def test_lock_loader_failure_preserves_direct_compromised_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  triage:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions-cool/issues-helper@v3\n",
        encoding="utf-8",
    )

    def raise_recursion_error(_repo_path: str) -> None:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(
        "actionscope.analyzers.compromised_actions.load_actions_lock",
        raise_recursion_error,
    )

    findings, errors = scan_for_compromised_actions(str(tmp_path), offline=True)

    assert [finding.uses_ref for finding in findings] == [
        "actions-cool/issues-helper@v3"
    ]
    assert any("maximum recursion depth exceeded" in error for error in errors)


def test_deep_dependency_chain_does_not_exhaust_recursion_limit(
    tmp_path: Path,
) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    dependencies: list[str] = []
    depth = 3000
    for index in range(depth):
        child = f"\n    uses: [octo/action-{index + 1}@v1]" if index + 1 < depth else ""
        dependencies.append(
            f"  octo/action-{index}@v1:\n"
            "    ref: v1\n"
            f"    commit: sha1-{index:040x}\n"
            f"    owner_id: {index + 1}\n"
            f"    repo_id: {index + 1}{child}\n"
        )
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\nworkflows: {}\ndependencies:\n" + "".join(dependencies),
        encoding="utf-8",
    )

    lockfile, errors = load_actions_lock(str(tmp_path))

    assert errors == []
    assert lockfile is not None
    assert lockfile.valid is True
    assert len(lockfile.dependencies) == depth


def test_sha_key_can_keep_symbolic_body_ref(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    sha = "36fa7d009e22618ca7cd599486979b8150596c74"
    (workflows / "actions.lock").write_text(
        "version: v0.0.2\n"
        "workflows: {}\n"
        "dependencies:\n"
        f"  actions/attest-build-provenance@{sha}:\n"
        "    ref: predicate@1.1.4\n"
        f"    commit: sha1-{sha}\n"
        "    owner_id: 44036562\n"
        "    repo_id: 760702757\n",
        encoding="utf-8",
    )

    lockfile, errors = load_actions_lock(str(tmp_path))

    assert errors == []
    assert lockfile is not None
    assert (
        lockfile.dependencies[f"actions/attest-build-provenance@{sha}"].ref
        == "predicate@1.1.4"
    )


def test_sha_key_must_match_commit_digest(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    sha = "a" * 40
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\n"
        "workflows: {}\n"
        "dependencies:\n"
        f"  octo/action@{sha}:\n"
        "    ref: v1\n"
        f"    commit: sha1-{'b' * 40}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n",
        encoding="utf-8",
    )

    lockfile, errors = load_actions_lock(str(tmp_path))

    assert lockfile is not None
    assert lockfile.valid is False
    assert any("full-SHA key" in error for error in errors)


def test_transitive_pin_does_not_cover_same_direct_use(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: octo/b@v1\n",
        encoding="utf-8",
    )
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\n"
        "workflows:\n"
        "  .github/workflows/ci.yml: [octo/a@v1]\n"
        "dependencies:\n"
        "  octo/a@v1:\n"
        "    ref: v1\n"
        f"    commit: sha1-{'a' * 40}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n"
        "    uses: [octo/b@v1]\n"
        "  octo/b@v1:\n"
        "    ref: v1\n"
        f"    commit: sha1-{'b' * 40}\n"
        "    owner_id: 3\n"
        "    repo_id: 4\n",
        encoding="utf-8",
    )

    evidence = collect_static_evidence(str(tmp_path), offline=True)

    assert [finding.uses for finding in evidence.unpinned_actions] == ["octo/b@v1"]
    coverage = evidence.dependency_locks[0]
    assert coverage.status == "partially_locked"
    assert coverage.locked_direct_dependencies == 0
    assert coverage.transitive_dependencies == 0
    assert coverage.locked_references == []
    assert coverage.uncovered_dependencies == ["octo/b@v1"]


def test_stale_locked_malicious_sha_is_not_reported(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    malicious_sha = "0e58ed867288e6711d10da9293b8db84f3f3ed85"
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\n"
        "workflows:\n"
        "  .github/workflows/ci.yml:\n"
        "    - actions/checkout@v4\n"
        "    - tj-actions/changed-files@v45\n"
        "dependencies:\n"
        "  actions/checkout@v4:\n"
        "    ref: v4\n"
        f"    commit: sha1-{'c' * 40}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n"
        "  tj-actions/changed-files@v45:\n"
        "    ref: v45\n"
        f"    commit: sha1-{malicious_sha}\n"
        "    owner_id: 3\n"
        "    repo_id: 4\n",
        encoding="utf-8",
    )

    findings, errors = scan_for_compromised_actions(str(tmp_path), offline=True)

    assert errors == []
    assert findings == []


def test_parallel_group_actions_are_covered_by_lock(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - parallel:\n"
        "          - uses: actions/checkout@v4\n"
        "          - uses: actions/setup-python@v5\n",
        encoding="utf-8",
    )
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\n"
        "workflows:\n"
        "  .github/workflows/ci.yml:\n"
        "    - actions/checkout@v4\n"
        "    - actions/setup-python@v5\n"
        "dependencies:\n"
        "  actions/checkout@v4:\n"
        "    ref: v4\n"
        f"    commit: sha1-{'d' * 40}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n"
        "  actions/setup-python@v5:\n"
        "    ref: v5\n"
        f"    commit: sha1-{'e' * 40}\n"
        "    owner_id: 3\n"
        "    repo_id: 4\n",
        encoding="utf-8",
    )

    evidence = collect_static_evidence(str(tmp_path), offline=True)

    assert evidence.unpinned_actions == []
    assert evidence.dependency_locks[0].status == "fully_locked"


def test_v001_pin_suffix_is_normalized(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    digest = "sha1-" + "a" * 40
    (workflows / "actions.lock").write_text(
        "version: v0.0.1\n"
        "workflows:\n"
        "  .github/workflows/ci.yml:\n"
        f"    - actions/checkout@v4:{digest}\n"
        "dependencies:\n"
        f"  actions/checkout@v4:{digest}:\n"
        "    tag: v4\n"
        f"    commit: {digest}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n",
        encoding="utf-8",
    )

    lockfile, errors = load_actions_lock(str(tmp_path))

    assert errors == []
    assert lockfile is not None
    assert list(lockfile.dependencies) == ["actions/checkout@v4"]


def test_v002_schema_is_supported(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "actions.lock").write_text(
        "version: v0.0.2\n"
        "dependencies:\n"
        "  actions/checkout@v4:\n"
        "    ref: v4\n"
        f"    commit: sha1-{'b' * 40}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n",
        encoding="utf-8",
    )

    lockfile, errors = load_actions_lock(str(tmp_path))

    assert errors == []
    assert lockfile is not None
    assert lockfile.dependencies["actions/checkout@v4"].hostname == "github.com"


def test_same_repository_dollar_reference_is_local() -> None:
    reference = "$/shared/action@main"

    assert canonical_action_key(reference) is None
    assert is_pinned_to_sha(reference) is True
    assert classify_action_ref(reference) == "local"


def test_ref_containing_at_sign_uses_the_full_ref() -> None:
    assert canonical_action_key("octo/action@release@2026") == (
        "octo/action@release@2026"
    )


def test_lock_dependency_ref_can_contain_at_sign(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\n"
        "workflows: {}\n"
        "dependencies:\n"
        "  octo/action@release@2026:\n"
        "    ref: release@2026\n"
        f"    commit: sha1-{'a' * 40}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n",
        encoding="utf-8",
    )

    lockfile, errors = load_actions_lock(str(tmp_path))

    assert errors == []
    assert lockfile is not None
    assert lockfile.dependencies["octo/action@release@2026"].ref == "release@2026"


def test_job_level_reusable_workflow_is_covered_by_lock(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  call:\n"
        "    uses: octo/shared/.github/workflows/test.yml@v1\n",
        encoding="utf-8",
    )
    (workflows / "actions.lock").write_text(
        "version: v0.0.3\n"
        "workflows:\n"
        "  .github/workflows/ci.yml:\n"
        "    - octo/shared@v1\n"
        "dependencies:\n"
        "  octo/shared@v1:\n"
        "    ref: v1\n"
        f"    commit: sha1-{'c' * 40}\n"
        "    owner_id: 1\n"
        "    repo_id: 2\n",
        encoding="utf-8",
    )

    coverage, errors = scan_dependency_locks(str(tmp_path))

    assert errors == []
    assert coverage[0].status == "fully_locked"
    assert coverage[0].locked_references == ["octo/shared@v1"]
