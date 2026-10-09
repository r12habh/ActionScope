"""Tests for reproducible corpus scans."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from actionscope import corpus
from actionscope.cli import main
from actionscope.corpus import (
    CorpusError,
    CorpusOptions,
    ManifestError,
    load_manifest,
    run_corpus,
)

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None, reason="corpus scans require git"
)

ACCOUNT_ID = "123456789012"
UNREACHABLE = "0" * 40
OIDC_PROVIDER = (
    f"arn:aws:iam::{ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
)

DEPLOY_WORKFLOW = f"""\
name: deploy
on: push
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: "=SUM(1,2)"
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::{ACCOUNT_ID}:role/corpus-deploy
          aws-region: us-east-1
"""

DYNAMIC_WORKFLOW = """\
name: dynamic
on: push
permissions:
  id-token: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.RELEASE_ROLE }}
          aws-region: us-east-1
"""

MISSING_WORKFLOW = f"""\
name: missing
on: push
permissions:
  id-token: write
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::{ACCOUNT_ID}:role/defined-elsewhere
          aws-region: us-east-1
"""

KEYS_WORKFLOW = """\
name: keys
on: push
jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
"""

IAM_TERRAFORM = f"""\
resource "aws_iam_role" "deploy" {{
  name = "corpus-deploy"
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect    = "Allow"
      Principal = {{
        Federated = "{OIDC_PROVIDER}"
      }}
      Action    = "sts:AssumeRoleWithWebIdentity"
    }}]
  }})
}}

resource "aws_iam_policy" "deploy" {{
  name = "corpus-deploy-policy"
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "iam:PassRole"]
      Resource = "*"
    }}]
  }})
}}

resource "aws_iam_role_policy_attachment" "deploy" {{
  role       = aws_iam_role.deploy.name
  policy_arn = aws_iam_policy.deploy.arn
}}
"""


def _commit(repo: Path) -> str:
    def git(*args: str) -> str:
        return subprocess.run(
            [
                "git",
                "-c",
                "user.name=Corpus Test",
                "-c",
                "user.email=corpus@example.invalid",
                "-c",
                "commit.gpgsign=false",
                *args,
            ],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    git("init", "--quiet")
    git("add", "--all")
    git("commit", "--quiet", "-m", "fixture")
    return git("rev-parse", "HEAD")


def _write_mixed_project(root: Path) -> None:
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "deploy.yml").write_text(DEPLOY_WORKFLOW)
    (workflows / "dynamic.yml").write_text(DYNAMIC_WORKFLOW)
    (workflows / "missing.yml").write_text(MISSING_WORKFLOW)
    (workflows / "keys.yml").write_text(KEYS_WORKFLOW)
    (root / "infra").mkdir()
    (root / "infra" / "iam.tf").write_text(IAM_TERRAFORM)


@pytest.fixture
def mixed_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "mixed"
    _write_mixed_project(repo)
    return repo, _commit(repo)


def _write_manifest(path: Path, rows: list[tuple[str, ...]], header: str) -> Path:
    lines = [header, *(",".join(row) for row in rows)]
    path.write_text("\n".join(lines) + "\n")
    return path


def _options(manifest: Path, output: Path, **overrides: object) -> CorpusOptions:
    settings: dict[str, object] = {
        "manifest_path": manifest,
        "output_dir": output,
        "jobs": 2,
        "fetch_timeout": 60,
        "scan_timeout": 60,
    }
    settings.update(overrides)
    return CorpusOptions(**settings)  # type: ignore[arg-type]


def _shareable_text(run_dir: Path) -> str:
    names = [
        "repositories.csv",
        "bindings.csv",
        "repositories.json",
        "bindings.json",
        "workflow_locks.csv",
        "workflow_locks.json",
        "summary.json",
    ]
    return "\n".join((run_dir / name).read_text() for name in names)


# --------------------------------------------------------------------------
# Manifest parsing


def test_manifest_csv_accepts_extra_columns_and_resolves_local_paths(
    tmp_path: Path,
) -> None:
    sha = "a" * 40
    manifest = _write_manifest(
        tmp_path / "manifest.csv",
        [("repos/one", sha.upper(), "sub/dir", "ignored note")],
        "Repo_URL,Commit,path,notes",
    )

    entry = load_manifest(manifest).entries[0]

    assert entry.problem is None
    assert entry.commit == sha
    assert entry.path == "sub/dir"
    assert entry.source == str((tmp_path / "repos" / "one").resolve())


def test_manifest_json_rows(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            [{"repo_url": "https://github.com/octo/repo", "commit": "b" * 40}]
        )
    )

    loaded = load_manifest(manifest)

    assert [entry.source for entry in loaded.entries] == [
        "https://github.com/octo/repo"
    ]
    assert len(loaded.sha256) == 64


@pytest.mark.parametrize(
    ("content", "suffix", "message"),
    [
        ("repo_url\nx\n", ".csv", "missing required column(s): commit"),
        ("", ".csv", "manifest is empty"),
        ('{"repo_url": "x"}', ".json", "must be an array"),
        ("[1]", ".json", "must be an object"),
        ("repo_url,commit\n", ".csv", "lists no repositories"),
    ],
)
def test_manifest_structural_errors(
    tmp_path: Path, content: str, suffix: str, message: str
) -> None:
    manifest = tmp_path / f"manifest{suffix}"
    manifest.write_text(content)

    with pytest.raises(ManifestError, match=re.escape(message)):
        load_manifest(manifest)


@pytest.mark.parametrize(
    ("repo_url", "commit", "path"),
    [
        ("https://github.com/octo/repo", "abc123", ""),
        ("https://github.com/octo/repo", "main", ""),
        ("http://github.com/octo/repo", "c" * 40, ""),
        ("ssh://git@github.com/octo/repo", "c" * 40, ""),
        ("git@github.com:octo/repo.git", "c" * 40, ""),
        ("ext::sh -c id", "c" * 40, ""),
        ("https://github.com/octo/repo", "c" * 40, "../escape"),
        ("https://github.com/octo/repo", "c" * 40, "/absolute"),
        ("https://github.com/octo/repo", "c" * 40, "a\\b"),
    ],
)
def test_manifest_flags_invalid_entries(
    tmp_path: Path, repo_url: str, commit: str, path: str
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps([{"repo_url": repo_url, "commit": commit, "path": path}])
    )

    assert load_manifest(manifest).entries[0].problem


def test_manifest_skips_duplicate_entries(tmp_path: Path) -> None:
    row = ("https://github.com/octo/repo", "d" * 40)
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [row, row], "repo_url,commit"
    )

    loaded = load_manifest(manifest)

    assert len(loaded.entries) == 1
    assert loaded.duplicates == 1


def test_manifest_keeps_distinct_rows_with_different_rejected_paths(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            [
                {"repo_url": "https://github.com/octo/repo", "commit": "f" * 40,
                 "path": "../first"},
                {"repo_url": "https://github.com/octo/repo", "commit": "f" * 40,
                 "path": "../second"},
            ]
        )
    )

    loaded = load_manifest(manifest)

    assert [entry.path for entry in loaded.entries] == ["../first", "../second"]
    assert all(entry.problem for entry in loaded.entries)
    assert loaded.duplicates == 0


def test_github_repository_identity_is_case_and_suffix_insensitive() -> None:
    assert (
        corpus._repo_identity("https://GitHub.com/Octo/Repo.git/")
        == "https://github.com/octo/repo"
    )
    assert (
        corpus._repo_identity("https://git.example.com/Team/Repo")
        == "https://git.example.com/Team/Repo"
    )


# --------------------------------------------------------------------------
# End-to-end runs


def test_run_records_every_entry_and_classifies_bindings(
    tmp_path: Path, mixed_repo: tuple[Path, str]
) -> None:
    repo, sha = mixed_repo
    manifest = _write_manifest(
        tmp_path / "manifest.csv",
        [(str(repo), sha), (str(repo), UNREACHABLE), ("http://bad", sha)],
        "repo_url,commit",
    )

    run = run_corpus(_options(manifest, tmp_path / "out"))

    repos = json.loads((tmp_path / "out" / "repositories.json").read_text())
    assert [row["status"] for row in repos] == [
        "scanned",
        "fetch_failed",
        "invalid_entry",
    ]
    scanned = repos[0]
    assert scanned["credential_bindings"] == 4
    assert scanned["static_matches"] == 1
    assert scanned["policy_not_found"] == 1
    assert scanned["dynamic_references"] == 1
    assert scanned["no_role"] == 1
    # Entries that never scanned report unknown values, not zero.
    assert repos[1]["credential_bindings"] is None
    # Two commits of the same repository share a repository ID.
    assert repos[0]["repo_id"] == repos[1]["repo_id"]

    bindings = json.loads((tmp_path / "out" / "bindings.json").read_text())
    assert sorted(row["policy_source"] for row in bindings) == [
        "dynamic_reference",
        "no_role",
        "not_found",
        "terraform",
    ]
    assert sorted(row["role_reference_kind"] for row in bindings) == [
        "absent",
        "literal_arn",
        "literal_arn",
        "secret",
    ]
    matched = next(row for row in bindings if row["matched"])
    assert matched["has_privilege_escalation"] is True
    assert matched["action_count"] == 2

    summary = run.summary
    assert summary["status_counts"] == {
        "fetch_failed": 1,
        "invalid_entry": 1,
        "scanned": 1,
    }
    assert summary["credential_bindings"] == 4
    assert summary["static_match_rate"] == 0.25
    assert summary["distinct_repositories_scanned"] == 1


def test_shareable_outputs_exclude_repository_identifiers(
    tmp_path: Path, mixed_repo: tuple[Path, str]
) -> None:
    repo, sha = mixed_repo
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [(str(repo), sha)], "repo_url,commit"
    )

    run_corpus(_options(manifest, tmp_path / "out"))

    shared = _shareable_text(tmp_path / "out")
    for secret in (str(repo), sha, "arn:aws", ACCOUNT_ID, "deploy.yml", "corpus-"):
        assert secret not in shared
    private = (tmp_path / "out" / "_private" / "bindings.csv").read_text()
    assert sha in private
    assert ".github/workflows/deploy.yml" in private
    assert "arn:aws" not in private


def test_no_anonymize_publishes_identifiers_but_never_role_arns(
    tmp_path: Path, mixed_repo: tuple[Path, str]
) -> None:
    repo, sha = mixed_repo
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [(str(repo), sha)], "repo_url,commit"
    )

    run_corpus(_options(manifest, tmp_path / "out", anonymize=False))

    shared = _shareable_text(tmp_path / "out")
    assert sha in shared
    assert ".github/workflows/deploy.yml" in shared
    assert "arn:aws" not in shared
    assert ACCOUNT_ID not in shared


def test_arns_quoted_in_step_names_are_redacted_everywhere(tmp_path: Path) -> None:
    repo = tmp_path / "quoted"
    _write_mixed_project(repo)
    deploy = repo / ".github" / "workflows" / "deploy.yml"
    deploy.write_text(
        deploy.read_text().replace(
            '"=SUM(1,2)"', f'"Assume arn:aws:iam::{ACCOUNT_ID}:role/corpus-deploy"'
        )
    )
    sha = _commit(repo)
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [(str(repo), sha)], "repo_url,commit"
    )

    # An owner run must not be blocked by an ARN in their own step names.
    run_corpus(_options(manifest, tmp_path / "out", anonymize=False))

    everything = _shareable_text(tmp_path / "out") + "".join(
        path.read_text() for path in (tmp_path / "out" / "_private").glob("*.csv")
    )
    assert "Assume <redacted-arn>" in everything
    assert "arn:aws" not in everything
    assert ACCOUNT_ID not in everything


def test_redaction_covers_arns_and_bare_account_ids() -> None:
    text = (
        f"role arn:aws-us-gov:iam::{ACCOUNT_ID}:role/x, account {ACCOUNT_ID}; "
        "a 13-digit 9876543210987 stays"
    )

    redacted = corpus._redact(text)

    assert ACCOUNT_ID not in redacted
    assert "role <redacted-arn>," in redacted
    assert "account <redacted-account-id>;" in redacted
    assert "9876543210987 stays" in redacted


def test_csv_neutralizes_formula_cells_from_scanned_repositories(
    tmp_path: Path, mixed_repo: tuple[Path, str]
) -> None:
    repo, sha = mixed_repo
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [(str(repo), sha)], "repo_url,commit"
    )

    run_corpus(_options(manifest, tmp_path / "out", anonymize=False))

    csv_text = (tmp_path / "out" / "bindings.csv").read_text()
    json_rows = json.loads((tmp_path / "out" / "bindings.json").read_text())
    assert "'=SUM(1,2)" in csv_text
    assert "=SUM(1,2)" in {row["step"] for row in json_rows}


def test_workflows_without_findings_are_still_counted(tmp_path: Path) -> None:
    repo = tmp_path / "clean"
    workflows = repo / ".github" / "workflows"
    workflows.mkdir(parents=True)
    # No permissions block, AWS credentials, or actions: nothing for any
    # detector to report, so only file discovery can count this workflow.
    (workflows / "lint.yml").write_text(
        "name: lint\non: push\njobs:\n"
        "  lint:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo lint\n"
    )
    sha = _commit(repo)
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [(str(repo), sha)], "repo_url,commit"
    )

    run_corpus(_options(manifest, tmp_path / "out"))

    row = json.loads((tmp_path / "out" / "repositories.json").read_text())[0]
    assert row["workflow_count"] == 1
    assert row["credential_bindings"] == 0


def test_path_column_scans_a_subdirectory(tmp_path: Path) -> None:
    repo = tmp_path / "mono"
    _write_mixed_project(repo / "services" / "api")
    (repo / "README.md").write_text("root without workflows\n")
    sha = _commit(repo)
    manifest = _write_manifest(
        tmp_path / "manifest.csv",
        [(str(repo), sha, "services/api"), (str(repo), sha, "services/missing")],
        "repo_url,commit,path",
    )

    run_corpus(_options(manifest, tmp_path / "out"))

    repos = json.loads((tmp_path / "out" / "repositories.json").read_text())
    assert repos[0]["status"] == "scanned"
    assert repos[0]["credential_bindings"] == 4
    assert repos[1]["status"] == "scan_failed"


# --------------------------------------------------------------------------
# Output directory and resume rules


def test_resume_skips_scanned_entries_and_retries_failures(
    tmp_path: Path,
    mixed_repo: tuple[Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, sha = mixed_repo
    manifest = _write_manifest(
        tmp_path / "manifest.csv",
        [(str(repo), sha), (str(repo), UNREACHABLE)],
        "repo_url,commit",
    )
    run_corpus(_options(manifest, tmp_path / "out"))

    fetched: list[str] = []
    original_fetch = corpus.fetch_commit

    def counting_fetch(source: str, commit: str, dest: Path, timeout: float) -> None:
        fetched.append(commit)
        original_fetch(source, commit, dest, timeout)

    monkeypatch.setattr(corpus, "fetch_commit", counting_fetch)
    run_corpus(_options(manifest, tmp_path / "out", resume=True))

    assert fetched == [UNREACHABLE]


def test_existing_run_requires_resume(
    tmp_path: Path, mixed_repo: tuple[Path, str]
) -> None:
    repo, sha = mixed_repo
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [(str(repo), sha)], "repo_url,commit"
    )
    run_corpus(_options(manifest, tmp_path / "out"))

    with pytest.raises(CorpusError, match="--resume"):
        run_corpus(_options(manifest, tmp_path / "out"))


def test_resume_rejects_a_changed_manifest(
    tmp_path: Path, mixed_repo: tuple[Path, str]
) -> None:
    repo, sha = mixed_repo
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [(str(repo), sha)], "repo_url,commit"
    )
    run_corpus(_options(manifest, tmp_path / "out"))
    _write_manifest(
        manifest, [(str(repo), sha), (str(repo), UNREACHABLE)], "repo_url,commit"
    )

    with pytest.raises(CorpusError, match="manifest changed"):
        run_corpus(_options(manifest, tmp_path / "out", resume=True))


def test_refuses_a_non_empty_output_directory(
    tmp_path: Path, mixed_repo: tuple[Path, str]
) -> None:
    repo, sha = mixed_repo
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [(str(repo), sha)], "repo_url,commit"
    )
    output = tmp_path / "out"
    output.mkdir()
    (output / "unrelated.txt").write_text("keep me\n")

    with pytest.raises(CorpusError, match="not empty"):
        run_corpus(_options(manifest, output))


# --------------------------------------------------------------------------
# Failure isolation


def test_scan_timeout_is_recorded_without_stopping_the_run(
    tmp_path: Path,
    mixed_repo: tuple[Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, sha = mixed_repo
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [(str(repo), sha)], "repo_url,commit"
    )
    monkeypatch.setattr(
        corpus,
        "_worker_command",
        lambda scan_root: [sys.executable, "-c", "import time; time.sleep(30)"],
    )

    run = run_corpus(_options(manifest, tmp_path / "out", scan_timeout=1))

    assert run.summary["status_counts"] == {"scan_timeout": 1}


def test_interrupt_cancels_queued_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            [
                {"repo_url": "https://github.com/octo/repo", "commit": str(n) * 40}
                for n in range(1, 7)
            ]
        )
    )
    started: list[str] = []

    def slow_entry(entry: corpus.ManifestEntry, options: object) -> dict[str, object]:
        started.append(entry.commit)
        time.sleep(0.05)
        return {
            "key": entry.key,
            "row": entry.row,
            "repo_url": entry.repo_url,
            "source": entry.source,
            "commit": entry.commit,
            "path": entry.path,
            "status": "fetch_failed",
            "error": "stub",
            "scan": None,
            "elapsed_seconds": 0.05,
        }

    def interrupt(line: str) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(corpus, "_process_entry", slow_entry)

    with pytest.raises(KeyboardInterrupt):
        run_corpus(_options(manifest, tmp_path / "out", jobs=1), progress=interrupt)

    # One entry completed and at most one more was already running; the rest
    # were cancelled instead of being processed after the interrupt.
    assert len(started) <= 2


def test_worker_crash_is_recorded_as_scan_failure(
    tmp_path: Path,
    mixed_repo: tuple[Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, sha = mixed_repo
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [(str(repo), sha)], "repo_url,commit"
    )
    monkeypatch.setattr(
        corpus,
        "_worker_command",
        lambda scan_root: [sys.executable, "-c", "import sys; sys.exit(3)"],
    )

    run_corpus(_options(manifest, tmp_path / "out"))

    private = (tmp_path / "out" / "_private" / "repositories.csv").read_text()
    assert "scan_failed" in private
    assert "status 3" in private


# --------------------------------------------------------------------------
# Hardening


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_fetch_checks_out_symlinks_as_plain_files(tmp_path: Path) -> None:
    repo = tmp_path / "linked"
    repo.mkdir()
    (repo / "policy.json").symlink_to("/etc/hosts")
    sha = _commit(repo)

    checkout = tmp_path / "checkout"
    corpus.fetch_commit(str(repo), sha, checkout, timeout=60)

    link = checkout / "policy.json"
    assert not link.is_symlink()
    assert link.read_text() == "/etc/hosts"


def test_git_environment_drops_user_git_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GIT_DIR", "/elsewhere/.git")
    monkeypatch.setenv("GIT_ASKPASS", "/usr/bin/prompt")
    monkeypatch.setenv("GIT_SSL_CAINFO", "/etc/proxy-ca.pem")

    env = corpus._git_env()

    assert "GIT_DIR" not in env
    assert "GIT_ASKPASS" not in env
    assert env["GIT_SSL_CAINFO"] == "/etc/proxy-ca.pem"
    assert env["GIT_ALLOW_PROTOCOL"] == "https:file"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull


def test_worker_uses_the_bundled_compromised_actions_database(
    tmp_path: Path,
) -> None:
    cache = corpus._worker_env(str(tmp_path))["ACTIONSCOPE_COMPROMISED_DB_CACHE"]

    assert Path(cache).parent == tmp_path
    assert not Path(cache).exists()


def test_publishable_check_flags_leaked_identifiers(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.csv"
    _write_manifest(
        manifest, [("https://github.com/octo/repo", "e" * 40)], "repo_url,commit"
    )
    leaked = tmp_path / "leak.csv"
    leaked.write_text(
        "arn:aws:iam::123456789012:role/x\n"
        "/tmp/actionscope-corpus-abc/repo\n"
        "https://github.com/octo/repo\n"
    )

    violations = corpus._check_publishable(
        [leaked], load_manifest(manifest), anonymize=True
    )

    assert len(violations) == 3


def test_worker_payload_never_contains_role_arns() -> None:
    fixture = Path(__file__).parent / "fixtures" / "coverage_repo"

    payload = corpus.scan_rows(str(fixture))

    assert payload["bindings"]
    assert "arn:aws" not in json.dumps(payload)


def test_corpus_exports_per_workflow_dependency_lock_coverage(
    tmp_path: Path,
) -> None:
    repo = (
        Path(__file__).parent
        / "fixtures"
        / "actions_lock"
        / "fully_locked"
    )
    # Corpus fetches a pinned git commit, so copy the fixture into a temporary
    # repository before constructing the manifest.
    checkout = tmp_path / "locked"
    shutil.copytree(repo, checkout)
    sha = _commit(checkout)
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [(str(checkout), sha)], "repo_url,commit"
    )

    run = run_corpus(_options(manifest, tmp_path / "out"))
    lock_rows = json.loads(
        (tmp_path / "out" / "workflow_locks.json").read_text()
    )

    assert run.summary["schema_version"] == 2
    assert run.summary["dependency_lock_status_counts"] == {"fully_locked": 1}
    assert len(lock_rows) == 1
    assert lock_rows[0]["status"] == "fully_locked"
    assert lock_rows[0]["locked_direct_dependencies"] == 2
    assert "workflow_path" not in lock_rows[0]


# --------------------------------------------------------------------------
# CLI


def test_cli_corpus_scan_writes_results(
    tmp_path: Path, mixed_repo: tuple[Path, str]
) -> None:
    repo, sha = mixed_repo
    manifest = _write_manifest(
        tmp_path / "manifest.csv", [(str(repo), sha)], "repo_url,commit"
    )

    result = CliRunner().invoke(
        main, ["corpus", "scan", str(manifest), "-o", str(tmp_path / "out")]
    )

    assert result.exit_code == 0, result.output
    assert "credential bindings" in result.stderr
    assert (tmp_path / "out" / "summary.json").exists()


def test_cli_corpus_scan_reports_manifest_errors(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.csv"
    manifest.write_text("repo_url\nhttps://github.com/octo/repo\n")

    result = CliRunner().invoke(
        main, ["corpus", "scan", str(manifest), "-o", str(tmp_path / "out")]
    )

    assert result.exit_code == 1
    assert "missing required column" in result.output
