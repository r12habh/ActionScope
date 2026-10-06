"""Reproducible corpus scans for empirical studies.

A corpus scan runs ActionScope's static pipeline over a manifest of
repositories pinned to immutable commit SHAs and writes per-repository and
per-credential-binding tables. Repository identities are replaced with salted
hashes by default so the tables can be shared; the mapping back to real
repositories stays under ``_private/`` in the output directory.

Each repository is fetched at its pinned commit with hardened git settings and
scanned in a separate worker process, so a hung or crashing scan becomes a
failed row instead of stopping the run.
"""

from __future__ import annotations

import contextlib
import csv
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from actionscope import __version__

SCHEMA_VERSION = 1
PRIVATE_DIRNAME = "_private"
DEFAULT_TIMEOUT_SECONDS = 300

STATUS_SCANNED = "scanned"
STATUS_INVALID = "invalid_entry"
STATUS_FETCH_FAILED = "fetch_failed"
STATUS_FETCH_TIMEOUT = "fetch_timeout"
STATUS_SCAN_FAILED = "scan_failed"
STATUS_SCAN_TIMEOUT = "scan_timeout"

_CHECKOUT_PREFIX = "actionscope-corpus-"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SCP_STYLE_RE = re.compile(r"^[\w.-]+@[\w.-]+:")
_ACCOUNT_ARN_RE = re.compile(r"arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:\d{12}:")
_ARN_TO_REDACT_RE = re.compile(
    r"arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:\d{12}:[^\s\"',;)\]]*"
)
_ACCOUNT_ID_RE = re.compile(r"(?<![0-9A-Za-z])\d{12}(?![0-9A-Za-z])")
# Cells that spreadsheet applications may evaluate as formulas.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
# Strings copied from scanned repositories; sanitized before CSV export.
_UNTRUSTED_COLUMNS = frozenset({"workflow_path", "job", "step"})
# git environment variables worth keeping: custom CA bundles for proxies.
_KEPT_GIT_ENV = frozenset({"GIT_SSL_CAINFO", "GIT_SSL_CAPATH"})

_DETECTOR_COLUMNS = (
    "oidc_trust_findings",
    "script_injection_findings",
    "artifact_poisoning_findings",
    "ai_agent_findings",
    "compromised_action_findings",
    "environment_findings",
    "exposure_paths",
)
_REPO_COLUMNS = (
    "entry_id",
    "repo_id",
    "status",
    "workflow_count",
    "credential_bindings",
    "static_matches",
    "policy_not_found",
    "dynamic_references",
    "no_role",
    "overall_risk",
    "coverage_status",
    *_DETECTOR_COLUMNS,
    "unpinned_actions",
    "error_count",
    "elapsed_seconds",
)
_REPO_IDENTITY_COLUMNS = ("repo_url", "commit", "path")
_BINDING_COLUMNS = (
    "entry_id",
    "repo_id",
    "binding_index",
    "workflow_id",
    "uses_oidc",
    "uses_access_keys",
    "role_reference_kind",
    "policy_source",
    "matched",
    "match_confidence",
    "matched_risk",
    "has_privilege_escalation",
    "action_count",
    "policy_coverage_complete",
)
_BINDING_IDENTITY_COLUMNS = (
    "repo_url",
    "commit",
    "path",
    "workflow_path",
    "job",
    "step",
)


class ManifestError(ValueError):
    """The corpus manifest cannot be read."""


class CorpusError(RuntimeError):
    """A corpus run cannot start, or its outputs failed validation."""


@dataclass(frozen=True)
class ManifestEntry:
    """One repository pinned to a commit, as listed in the manifest."""

    row: int
    repo_url: str
    source: str
    commit: str
    path: str = ""
    problem: str | None = None

    @property
    def key(self) -> str:
        """Stable identity of this entry within a run."""
        return "\x1f".join((self.source or self.repo_url, self.commit, self.path))


@dataclass(frozen=True)
class Manifest:
    """Parsed manifest entries plus the digest of the manifest file."""

    entries: list[ManifestEntry]
    sha256: str
    duplicates: int


@dataclass(frozen=True)
class CorpusOptions:
    """Settings for :func:`run_corpus`."""

    manifest_path: Path
    output_dir: Path
    jobs: int = 4
    fetch_timeout: float = DEFAULT_TIMEOUT_SECONDS
    scan_timeout: float = DEFAULT_TIMEOUT_SECONDS
    resume: bool = False
    anonymize: bool = True


@dataclass(frozen=True)
class CorpusRun:
    """Outcome of a completed corpus run."""

    summary: dict[str, Any]
    output_dir: Path
    public_files: tuple[Path, ...]


class _StepError(Exception):
    """A fetch or scan step failed for one entry."""

    def __init__(self, message: str, *, timed_out: bool = False) -> None:
        super().__init__(message)
        self.timed_out = timed_out


# --------------------------------------------------------------------------
# Manifest


def load_manifest(manifest_path: Path) -> Manifest:
    """Parse a CSV or JSON manifest of ``repo_url``/``commit``/``path`` rows.

    Malformed files raise :class:`ManifestError`. Individual rows with a bad
    URL, commit, or path are kept and flagged so they appear as
    ``invalid_entry`` results instead of aborting the run.
    """
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise ManifestError(f"could not read manifest {manifest_path}: {exc}") from exc
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"{manifest_path}: manifest is not UTF-8") from exc

    if manifest_path.suffix.lower() == ".json":
        rows = _json_rows(text, manifest_path)
    else:
        rows = _csv_rows(text, manifest_path)

    base_dir = manifest_path.resolve().parent
    entries: list[ManifestEntry] = []
    seen: set[str] = set()
    duplicates = 0
    for number, values in enumerate(rows, start=1):
        entry = _parse_entry(number, values, base_dir)
        if entry.key in seen:
            duplicates += 1
            continue
        seen.add(entry.key)
        entries.append(entry)
    if not entries:
        raise ManifestError(f"{manifest_path}: manifest lists no repositories")
    return Manifest(
        entries=entries,
        sha256=hashlib.sha256(raw).hexdigest(),
        duplicates=duplicates,
    )


def _csv_rows(text: str, manifest_path: Path) -> Iterator[dict[str, str]]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ManifestError(f"{manifest_path}: manifest is empty")
    columns = {
        name.strip().lower(): name
        for name in reader.fieldnames
        if name and name.strip()
    }
    missing = [name for name in ("repo_url", "commit") if name not in columns]
    if missing:
        raise ManifestError(
            f"{manifest_path}: missing required column(s): {', '.join(missing)}"
        )
    for row in reader:
        values = {
            key: (row.get(original) or "").strip() for key, original in columns.items()
        }
        if any(values.values()):
            yield values


def _json_rows(text: str, manifest_path: Path) -> Iterator[dict[str, str]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{manifest_path}: invalid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ManifestError(f"{manifest_path}: JSON manifest must be an array")
    for item in data:
        if not isinstance(item, dict):
            raise ManifestError(
                f"{manifest_path}: each JSON manifest item must be an object"
            )
        yield {
            str(key).strip().lower(): "" if value is None else str(value).strip()
            for key, value in item.items()
        }


def _parse_entry(number: int, values: dict[str, str], base_dir: Path) -> ManifestEntry:
    repo_url = values.get("repo_url", "")
    commit = values.get("commit", "").lower()
    problems: list[str] = []

    source, url_problem = _resolve_source(repo_url, base_dir)
    if url_problem:
        problems.append(url_problem)
    if not _COMMIT_RE.fullmatch(commit):
        problems.append("commit must be a full 40-character hexadecimal SHA")
    path, path_problem = _normalize_subpath(values.get("path", ""))
    if path_problem:
        problems.append(path_problem)

    return ManifestEntry(
        row=number,
        repo_url=repo_url,
        source=source,
        commit=commit,
        path=path,
        problem="; ".join(problems) or None,
    )


def _resolve_source(repo_url: str, base_dir: Path) -> tuple[str, str | None]:
    """Return the value passed to ``git fetch`` for a manifest URL."""
    value = repo_url.strip()
    if not value:
        return "", "repo_url is empty"
    if any(character.isspace() for character in value):
        return "", "repo_url must not contain whitespace"
    lowered = value.lower()
    if lowered.startswith("https://"):
        return value.rstrip("/"), None
    if lowered.startswith("file://"):
        return value, None
    if "://" in value or "::" in value or _SCP_STYLE_RE.match(value):
        return "", "repo_url must be an https:// URL or a local path"
    # Local paths resolve to absolute paths, so they can never be mistaken
    # for git command-line options.
    local = Path(value).expanduser()
    if not local.is_absolute():
        local = base_dir / local
    return str(local.resolve()), None


def _normalize_subpath(path: str) -> tuple[str, str | None]:
    # A rejected path is returned unchanged so distinct invalid rows keep
    # distinct keys; invalid entries are never fetched or scanned.
    if not path:
        return "", None
    if "\\" in path:
        return path, "path must use forward slashes"
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts:
        return path, "path must be relative to the repository root without '..'"
    normalized = pure.as_posix().strip("/")
    return ("" if normalized == "." else normalized), None


def _repo_identity(source: str) -> str:
    """Normalize a repository location so commits of one repo share an ID."""
    if not source.lower().startswith("https://"):
        return source
    parts = urlsplit(source)
    path = parts.path.rstrip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    host = parts.netloc.lower()
    if host == "github.com":
        # GitHub owner and repository names are case-insensitive.
        path = path.lower()
    return urlunsplit(("https", host, path, "", ""))


# --------------------------------------------------------------------------
# Fetching and scanning one entry


def _git_env() -> dict[str, str]:
    """Environment for git: no prompts, no user config, https/file only."""
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("GIT_") or name in _KEPT_GIT_ENV
    }
    env.pop("SSH_ASKPASS", None)
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "https:file",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
    )
    return env


def _git(step: str, args: list[str], env: dict[str, str], deadline: float) -> str:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _StepError("fetch exceeded its time limit", timed_out=True)
    try:
        completed = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=remaining,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise _StepError("fetch exceeded its time limit", timed_out=True) from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        reason = detail[-1] if detail else f"exit status {completed.returncode}"
        raise _StepError(f"git {step} failed: {reason}")
    return completed.stdout


def fetch_commit(source: str, commit: str, dest: Path, timeout: float) -> None:
    """Fetch exactly ``commit`` from ``source`` into a new checkout at ``dest``.

    The fetch is shallow and tag-free, submodules and LFS objects are skipped,
    and symlinks are checked out as plain files so repository content cannot
    point the scanner at files outside the checkout.
    """
    deadline = time.monotonic() + timeout
    env = _git_env()
    dest.mkdir(parents=True)
    _git("init", ["init", "--quiet", str(dest)], env, deadline)
    _git(
        "fetch",
        [
            "-C",
            str(dest),
            "fetch",
            "--quiet",
            "--depth",
            "1",
            "--no-tags",
            "--no-recurse-submodules",
            source,
            commit,
        ],
        env,
        deadline,
    )
    _git(
        "checkout",
        [
            "-C",
            str(dest),
            "-c",
            "core.symlinks=false",
            "-c",
            "advice.detachedHead=false",
            "checkout",
            "--quiet",
            "--detach",
            "FETCH_HEAD",
        ],
        env,
        deadline,
    )
    head = _git(
        "rev-parse", ["-C", str(dest), "rev-parse", "HEAD"], env, deadline
    ).strip()
    if head != commit:
        raise _StepError(f"checked out {head} instead of the pinned commit")


def _worker_command(scan_root: str) -> list[str]:
    return [sys.executable, "-m", "actionscope.corpus", "--worker", scan_root]


def _worker_env(cache_dir: str) -> dict[str, str]:
    env = dict(os.environ)
    # Use the compromised-actions database bundled with this ActionScope
    # version, never a machine-local cache, so results are reproducible.
    env["ACTIONSCOPE_COMPROMISED_DB_CACHE"] = os.path.join(
        cache_dir, "no-compromised-actions-cache.json"
    )
    return env


def _run_worker(scan_root: str, timeout: float, cache_dir: str) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            _worker_command(scan_root),
            capture_output=True,
            text=True,
            env=_worker_env(cache_dir),
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise _StepError(
            f"scan exceeded {timeout:g} seconds", timed_out=True
        ) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        reason = detail[-1] if detail else "no error output"
        raise _StepError(
            f"scan worker exited with status {completed.returncode}: {reason}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise _StepError("scan worker returned invalid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("bindings"), list):
        raise _StepError("scan worker returned an unexpected payload")
    return payload


def _process_entry(entry: ManifestEntry, options: CorpusOptions) -> dict[str, Any]:
    started = time.monotonic()
    record: dict[str, Any] = {
        "key": entry.key,
        "row": entry.row,
        "repo_url": entry.repo_url,
        "source": entry.source,
        "commit": entry.commit,
        "path": entry.path,
        "status": STATUS_SCANNED,
        "error": None,
        "scan": None,
    }
    try:
        if entry.problem:
            record.update(status=STATUS_INVALID, error=entry.problem)
            return record
        with tempfile.TemporaryDirectory(
            prefix=_CHECKOUT_PREFIX, ignore_cleanup_errors=True
        ) as workdir:
            checkout = Path(workdir) / "repo"
            try:
                fetch_commit(
                    entry.source, entry.commit, checkout, options.fetch_timeout
                )
            except _StepError as exc:
                status = STATUS_FETCH_TIMEOUT if exc.timed_out else STATUS_FETCH_FAILED
                record.update(status=status, error=str(exc))
                return record

            scan_root = (checkout / entry.path) if entry.path else checkout
            if not scan_root.is_dir() or not scan_root.resolve().is_relative_to(
                checkout.resolve()
            ):
                record.update(
                    status=STATUS_SCAN_FAILED,
                    error=f"path {entry.path!r} is not a directory at this commit",
                )
                return record
            try:
                record["scan"] = _run_worker(
                    str(scan_root), options.scan_timeout, workdir
                )
            except _StepError as exc:
                status = STATUS_SCAN_TIMEOUT if exc.timed_out else STATUS_SCAN_FAILED
                record.update(status=status, error=str(exc))
        return record
    except Exception as exc:  # never let one entry abort the run
        record.update(status=STATUS_SCAN_FAILED, error=f"internal error: {exc}")
        return record
    finally:
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)


# --------------------------------------------------------------------------
# Worker process: runs inside ``python -m actionscope.corpus --worker PATH``


def scan_rows(scan_root: str) -> dict[str, Any]:
    """Scan one checkout and return rows without IAM ARNs or account IDs."""
    from actionscope.config import ActionScopeConfig
    from actionscope.parsers.workflow import find_workflow_files
    from actionscope.pipeline import collect_static_evidence, correlate_evidence

    evidence = collect_static_evidence(scan_root, offline=True)
    # Ignore any repository-local .actionscope.yml: its suppressions would
    # make results incomparable across repositories.
    result = correlate_evidence(
        scan_root, evidence, offline=True, config=ActionScopeConfig()
    )
    root = Path(scan_root).resolve()
    return {
        # result.workflow_count only counts files that produced evidence, so a
        # clean workflow would look like no workflow at all.
        "workflow_count": len(find_workflow_files(scan_root)),
        "overall_risk": result.overall_risk.name.lower(),
        "coverage_status": result.coverage_status,
        "oidc_trust_findings": len(result.oidc_trust_findings),
        "script_injection_findings": len(result.script_injection_findings),
        "artifact_poisoning_findings": len(result.artifact_poisoning_findings),
        "ai_agent_findings": len(result.ai_agent_injection_findings),
        "compromised_action_findings": len(result.compromised_action_findings),
        "environment_findings": len(result.environment_findings),
        "exposure_paths": len(result.exposure_paths),
        "unpinned_actions": len(result.unpinned_actions),
        "errors": [_redact(str(error)) for error in result.errors],
        "bindings": [_binding_payload(binding, root) for binding in result.bindings],
    }


def _redact(text: str) -> str:
    """Remove role ARNs and AWS account IDs from free text.

    Job names, step names, and parser error messages come from the scanned
    repository and can quote ARNs; nothing ARN-shaped leaves the worker.
    """
    text = _ARN_TO_REDACT_RE.sub("<redacted-arn>", text)
    return _ACCOUNT_ID_RE.sub("<redacted-account-id>", text)


def _binding_payload(binding: Any, root: Path) -> dict[str, Any]:
    source = binding.credential_source
    policy = binding.policy_finding
    return {
        "workflow_path": _redact(_relative_path(source.workflow_file, root)),
        "job": _redact(source.job_name or ""),
        "step": _redact(source.step_name or ""),
        "uses_oidc": bool(source.uses_oidc),
        "uses_access_keys": bool(source.uses_access_keys),
        "role_reference_kind": source.role_reference_kind,
        "policy_source": binding.policy_source,
        "matched": policy is not None,
        "match_confidence": binding.match_confidence,
        "matched_risk": policy.overall_risk.name.lower() if policy else None,
        "has_privilege_escalation": (
            bool(policy.has_privilege_escalation) if policy else None
        ),
        "action_count": len(policy.actions) if policy else None,
        "policy_coverage_complete": (
            policy.metadata.get("policy_coverage_complete") is not False
            if policy
            else None
        ),
    }


def _relative_path(path: str, root: Path) -> str:
    candidate = Path(path)
    if not candidate.is_absolute():
        return candidate.as_posix()
    try:
        return candidate.resolve().relative_to(root).as_posix()
    except ValueError:
        return candidate.name


def _worker_main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "--worker":
        print("usage: python -m actionscope.corpus --worker PATH", file=sys.stderr)
        return 2
    real_stdout = sys.stdout
    # Some analyzers print diagnostics; keep stdout reserved for the payload.
    with contextlib.redirect_stdout(sys.stderr):
        payload = scan_rows(argv[1])
    json.dump(payload, real_stdout)
    return 0


# --------------------------------------------------------------------------
# Run orchestration


def run_corpus(
    options: CorpusOptions,
    progress: Callable[[str], None] | None = None,
) -> CorpusRun:
    """Scan every manifest entry and write the result tables."""
    if shutil.which("git") is None:
        raise CorpusError("git is required for corpus scans but was not found on PATH")
    manifest = load_manifest(options.manifest_path)
    private_dir, meta = _prepare_output(options, manifest.sha256)
    identity = _Identity(_load_or_create_salt(private_dir))
    progress_path = private_dir / "progress.jsonl"
    records = _load_progress(progress_path)

    total = len(manifest.entries)
    pending = [
        entry
        for entry in manifest.entries
        if records.get(entry.key, {}).get("status") != STATUS_SCANNED
    ]
    finished = total - len(pending)
    with ThreadPoolExecutor(max_workers=options.jobs) as pool:
        futures = [pool.submit(_process_entry, entry, options) for entry in pending]
        with progress_path.open("a", encoding="utf-8") as log:
            for future in as_completed(futures):
                record = future.result()
                log.write(json.dumps(record, sort_keys=True) + "\n")
                log.flush()
                records[record["key"]] = record
                finished += 1
                if progress is not None:
                    progress(_progress_line(record, finished, total, identity, options))

    ordered = [records[entry.key] for entry in manifest.entries]
    repo_rows, binding_rows = _build_tables(ordered, identity)
    summary = _summarize(manifest, meta, options, repo_rows, binding_rows)
    public_files = _write_outputs(
        options, private_dir, repo_rows, binding_rows, summary
    )

    violations = _check_publishable(public_files, manifest, options.anonymize)
    if violations:
        for path in public_files:
            path.unlink(missing_ok=True)
        raise CorpusError(
            "refusing to keep shareable outputs: " + "; ".join(violations)
        )
    return CorpusRun(summary, options.output_dir, tuple(public_files))


def _prepare_output(
    options: CorpusOptions, manifest_sha: str
) -> tuple[Path, dict[str, Any]]:
    output_dir = options.output_dir
    private_dir = output_dir / PRIVATE_DIRNAME
    run_file = private_dir / "run.json"
    if run_file.exists():
        if not options.resume:
            raise CorpusError(
                f"{output_dir} already contains a corpus run; pass --resume to "
                "continue it or choose a new output directory"
            )
        meta = json.loads(run_file.read_text(encoding="utf-8"))
        if meta.get("manifest_sha256") != manifest_sha:
            raise CorpusError(
                "the manifest changed since this run started; start a new run "
                "in a new output directory"
            )
        if meta.get("anonymized") != options.anonymize:
            raise CorpusError("--no-anonymize must match the run being resumed")
        if meta.get("actionscope_version") != __version__:
            raise CorpusError(
                f"this run started with ActionScope {meta.get('actionscope_version')}; "
                f"resume it with the same version (installed: {__version__})"
            )
        return private_dir, meta

    if output_dir.exists() and any(output_dir.iterdir()):
        raise CorpusError(
            f"{output_dir} is not empty; choose an empty or new output directory"
        )
    private_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "schema_version": SCHEMA_VERSION,
        "actionscope_version": __version__,
        "manifest_sha256": manifest_sha,
        "anonymized": options.anonymize,
        "started_at": _now(),
    }
    run_file.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    (private_dir / "README.txt").write_text(
        "This directory maps anonymized corpus results back to real repositories\n"
        "and holds the salt used to derive the anonymized IDs. Do not publish it.\n",
        encoding="utf-8",
    )
    return private_dir, meta


def _load_or_create_salt(private_dir: Path) -> bytes:
    salt_file = private_dir / "salt"
    if salt_file.exists():
        return bytes.fromhex(salt_file.read_text(encoding="utf-8").strip())
    salt = os.urandom(32)
    descriptor = os.open(salt_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(salt.hex() + "\n")
    return salt


def _load_progress(progress_path: Path) -> dict[str, dict[str, Any]]:
    """Latest record per entry key; a torn final line from a crash is ignored."""
    records: dict[str, dict[str, Any]] = {}
    if not progress_path.exists():
        return records
    for line in progress_path.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and isinstance(record.get("key"), str):
            records[record["key"]] = record
    return records


class _Identity:
    """Salted, keyed hashes used as anonymized identifiers."""

    def __init__(self, salt: bytes) -> None:
        self._salt = salt

    def token(self, *parts: str, length: int = 16) -> str:
        message = "\x1f".join(parts).encode("utf-8")
        return hmac.new(self._salt, message, hashlib.sha256).hexdigest()[:length]


def _progress_line(
    record: dict[str, Any],
    finished: int,
    total: int,
    identity: _Identity,
    options: CorpusOptions,
) -> str:
    if options.anonymize:
        label = identity.token("entry", record["key"])
    else:
        label = f"{record['repo_url']}@{record['commit'][:12]}"
        if record["path"]:
            label += f":{record['path']}"
    line = f"[{finished}/{total}] {label} {record['status']}"
    scan = record.get("scan")
    if record["status"] == STATUS_SCANNED and scan:
        bindings = scan["bindings"]
        matched = sum(1 for binding in bindings if binding.get("matched"))
        line += f" ({len(bindings)} bindings, {matched} matched)"
    return line


# --------------------------------------------------------------------------
# Output tables


def _build_tables(
    records: list[dict[str, Any]], identity: _Identity
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    repo_rows: list[dict[str, Any]] = []
    binding_rows: list[dict[str, Any]] = []
    for record in records:
        repo_key = _repo_identity(record["source"] or record["repo_url"])
        entry_id = identity.token("entry", record["key"])
        repo_id = identity.token("repo", repo_key)
        scan = record.get("scan") if record["status"] == STATUS_SCANNED else None
        bindings = scan["bindings"] if scan else []
        sources = Counter(binding.get("policy_source") for binding in bindings)
        # Unscanned entries report unknown (None), never zero.
        measured: dict[str, Any] = (
            {
                "workflow_count": scan.get("workflow_count"),
                "credential_bindings": len(bindings),
                "static_matches": sum(1 for item in bindings if item.get("matched")),
                "policy_not_found": sources["not_found"],
                "dynamic_references": sources["dynamic_reference"],
                "no_role": sources["no_role"],
                "overall_risk": scan.get("overall_risk"),
                "coverage_status": scan.get("coverage_status"),
                **{name: scan.get(name) for name in _DETECTOR_COLUMNS},
                "unpinned_actions": scan.get("unpinned_actions"),
                "error_count": len(scan.get("errors", [])),
            }
            if scan
            else {}
        )
        scan_errors = scan.get("errors", []) if scan else []
        repo_rows.append(
            {
                "entry_id": entry_id,
                "repo_id": repo_id,
                "repo_url": record["repo_url"],
                "commit": record["commit"],
                "path": record["path"],
                "status": record["status"],
                **measured,
                "elapsed_seconds": record.get("elapsed_seconds"),
                "error": record["error"] or "; ".join(scan_errors[:3]) or None,
            }
        )
        for index, binding in enumerate(bindings, start=1):
            binding_rows.append(
                {
                    "entry_id": entry_id,
                    "repo_id": repo_id,
                    "repo_url": record["repo_url"],
                    "commit": record["commit"],
                    "path": record["path"],
                    "binding_index": index,
                    "workflow_id": identity.token(
                        "workflow",
                        repo_key,
                        record["path"],
                        binding.get("workflow_path", ""),
                        length=12,
                    ),
                    **{
                        name: binding.get(name)
                        for name in (
                            "workflow_path",
                            "job",
                            "step",
                            "uses_oidc",
                            "uses_access_keys",
                            "role_reference_kind",
                            "policy_source",
                            "matched",
                            "match_confidence",
                            "matched_risk",
                            "has_privilege_escalation",
                            "action_count",
                            "policy_coverage_complete",
                        )
                    },
                }
            )
    return repo_rows, binding_rows


def _columns(
    base: tuple[str, ...], identity_columns: tuple[str, ...], include_identity: bool
) -> list[str]:
    if not include_identity:
        return list(base)
    # entry_id and repo_id first, then the identifying columns.
    return [*base[:2], *identity_columns, *base[2:]]


def _write_outputs(
    options: CorpusOptions,
    private_dir: Path,
    repo_rows: list[dict[str, Any]],
    binding_rows: list[dict[str, Any]],
    summary: dict[str, Any],
) -> list[Path]:
    output_dir = options.output_dir
    shared = not options.anonymize
    repo_columns = _columns(_REPO_COLUMNS, _REPO_IDENTITY_COLUMNS, shared)
    binding_columns = _columns(_BINDING_COLUMNS, _BINDING_IDENTITY_COLUMNS, shared)

    public_files = [
        _write_csv(output_dir / "repositories.csv", repo_rows, repo_columns),
        _write_csv(output_dir / "bindings.csv", binding_rows, binding_columns),
        _write_json(output_dir / "repositories.json", repo_rows, repo_columns),
        _write_json(output_dir / "bindings.json", binding_rows, binding_columns),
        _write_summary(output_dir / "summary.json", summary),
    ]
    full_repo = [*_columns(_REPO_COLUMNS, _REPO_IDENTITY_COLUMNS, True), "error"]
    full_binding = _columns(_BINDING_COLUMNS, _BINDING_IDENTITY_COLUMNS, True)
    _write_csv(private_dir / "repositories.csv", repo_rows, full_repo)
    _write_csv(private_dir / "bindings.csv", binding_rows, full_binding)
    return public_files


def _write_csv(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> Path:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        for row in rows:
            writer.writerow([_csv_cell(name, row.get(name)) for name in columns])
    return path


def _csv_cell(column: str, value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if column in _UNTRUSTED_COLUMNS and text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def _write_json(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> Path:
    payload = [{name: row.get(name) for name in columns} for row in rows]
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _write_summary(path: Path, summary: dict[str, Any]) -> Path:
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return path


def _summarize(
    manifest: Manifest,
    meta: dict[str, Any],
    options: CorpusOptions,
    repo_rows: list[dict[str, Any]],
    binding_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    scanned = [row for row in repo_rows if row["status"] == STATUS_SCANNED]
    matches = sum(1 for row in binding_rows if row.get("matched"))
    notes = [
        "Scans ran offline with the compromised-actions database bundled with "
        "this ActionScope version; external reusable workflows were not fetched.",
        "Repository-local .actionscope.yml files were ignored.",
    ]
    if options.anonymize:
        notes.append(
            "Repository identities are salted hashes. The _private/ directory "
            "maps them back to repositories and must not be published."
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "actionscope_version": __version__,
        "manifest_sha256": manifest.sha256,
        "anonymized": options.anonymize,
        "started_at": meta.get("started_at"),
        "finished_at": _now(),
        "fetch_timeout_seconds": options.fetch_timeout,
        "scan_timeout_seconds": options.scan_timeout,
        "entries": len(manifest.entries),
        "duplicate_entries_skipped": manifest.duplicates,
        "status_counts": _counts(repo_rows, "status"),
        "entries_scanned": len(scanned),
        "distinct_repositories_scanned": len({row["repo_id"] for row in scanned}),
        "credential_bindings": len(binding_rows),
        "static_matches": matches,
        "static_match_rate": (
            round(matches / len(binding_rows), 4) if binding_rows else None
        ),
        "policy_source_counts": _counts(binding_rows, "policy_source"),
        "role_reference_kind_counts": _counts(binding_rows, "role_reference_kind"),
        "notes": notes,
    }


def _counts(rows: list[dict[str, Any]], column: str) -> dict[str, int]:
    return dict(sorted(Counter(str(row.get(column)) for row in rows).items()))


def _check_publishable(
    files: list[Path], manifest: Manifest, anonymize: bool
) -> list[str]:
    """Scan shareable outputs for identifiers that must never appear in them."""
    identifiers: set[str] = set()
    if anonymize:
        for entry in manifest.entries:
            identifiers.update(
                value for value in (entry.source, entry.commit) if len(value) >= 12
            )
    violations: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        if _ACCOUNT_ARN_RE.search(text):
            violations.append(f"{path.name} contains an ARN with an AWS account ID")
        if _CHECKOUT_PREFIX in text:
            violations.append(f"{path.name} contains a temporary checkout path")
        if any(identifier in text for identifier in identifiers):
            violations.append(f"{path.name} contains a repository URL, path, or commit")
    return violations


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


if __name__ == "__main__":
    raise SystemExit(_worker_main(sys.argv[1:]))
