"""Parser and coverage analysis for GitHub Actions dependency lockfiles.

GitHub's public-preview lockfile lives at ``.github/workflows/actions.lock``.
The authoritative format is maintained by ``github/actions-lockfile``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import yaml

from actionscope.models import (
    UnpinnedActionFinding,
    WorkflowDependencyLockCoverage,
)
from actionscope.parsers.workflow import find_workflow_files, parse_workflow_file

LOCKFILE_RELATIVE_PATH = Path(".github/workflows/actions.lock")
SUPPORTED_VERSIONS = frozenset({"v0.0.1", "v0.0.2", "v0.0.3"})
_SHA1_DIGEST_RE = re.compile(r"^sha1-([0-9a-f]{40})$", re.IGNORECASE)
_SHA256_DIGEST_RE = re.compile(r"^sha256-([0-9a-f]{64})$", re.IGNORECASE)
_V1_PIN_RE = re.compile(
    r"^(?P<action>[^/@:]+/[^/@:]+)@(?P<ref>[^:]+):"
    r"(?P<digest>(?:sha1|sha256)-[0-9a-f]+)$",
    re.IGNORECASE,
)
_CURRENT_PIN_RE = re.compile(r"^(?P<action>[^/@:]+/[^/@:]+)@(?P<ref>[^:]+)$")
_HOSTNAME_RE = re.compile(
    r"^(?:github\.com|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ghe\.com)$"
)


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict:
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class LockedActionDependency:
    """Normalized metadata for one lockfile dependency."""

    key: str
    action_name: str
    ref: str
    commit: str
    commit_sha: str
    owner_id: int
    repo_id: int
    hostname: str = "github.com"
    uses: tuple[str, ...] = ()


@dataclass
class ActionsLockFile:
    """Normalized representation of a supported actions.lock document."""

    path: str
    version: str
    workflows: dict[str, tuple[str, ...]] = field(default_factory=dict)
    dependencies: dict[str, LockedActionDependency] = field(default_factory=dict)
    invalid_dependencies: set[str] = field(default_factory=set)
    valid: bool = True


def repository_root(repo_path: str) -> Path:
    """Return the repository root for a directory or workflow-file scan."""
    path = Path(repo_path).expanduser().resolve()
    if not path.is_file():
        return path
    if path.parent.name == "workflows" and path.parent.parent.name == ".github":
        return path.parent.parent.parent
    return path.parent


def load_actions_lock(
    repo_path: str,
) -> tuple[ActionsLockFile | None, list[str]]:
    """Load and normalize a supported ``actions.lock`` file.

    Invalid entries are omitted and returned as errors. Callers must therefore
    fail open: an omitted or malformed entry never suppresses an unpinned-action
    finding.
    """
    lock_path = repository_root(repo_path) / LOCKFILE_RELATIVE_PATH
    if not lock_path.is_file():
        return None, []

    try:
        data = yaml.load(
            lock_path.read_text(encoding="utf-8"),
            Loader=_UniqueKeyLoader,
        )
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        return None, [f"Could not parse dependency lockfile {lock_path}: {exc}"]

    if not isinstance(data, dict):
        return None, [
            f"Could not parse dependency lockfile {lock_path}: root is not a mapping"
        ]

    version = data.get("version")
    if version not in SUPPORTED_VERSIONS:
        return None, [
            f"Unsupported dependency lockfile version {version!r} in {lock_path}; "
            f"supported versions: {', '.join(sorted(SUPPORTED_VERSIONS))}"
        ]

    extra_keys = set(data) - {"version", "workflows", "dependencies"}
    errors = [
        f"Invalid dependency lockfile {lock_path}: unsupported top-level key {key!r}"
        for key in sorted(extra_keys)
    ]
    workflows_data = data.get("workflows") or {}
    dependencies_data = data.get("dependencies") or {}
    if not isinstance(workflows_data, dict) or not isinstance(dependencies_data, dict):
        return None, errors + [
            f"Invalid dependency lockfile {lock_path}: workflows and "
            "dependencies must be mappings"
        ]

    lockfile = ActionsLockFile(path=str(lock_path), version=str(version))
    for raw_key, raw_dependency in dependencies_data.items():
        dependency, dependency_errors = _normalize_dependency(
            raw_key,
            raw_dependency,
            str(version),
            lock_path,
        )
        errors.extend(dependency_errors)
        if dependency is None:
            if isinstance(raw_key, str):
                normalized = _normalize_pin(raw_key, str(version))
                lockfile.invalid_dependencies.add(
                    normalized[0] if normalized else raw_key
                )
            continue
        if dependency.key in lockfile.dependencies:
            errors.append(
                f"Invalid dependency lockfile {lock_path}: duplicate normalized "
                f"dependency {dependency.key!r}"
            )
            lockfile.invalid_dependencies.add(dependency.key)
            lockfile.dependencies.pop(dependency.key, None)
            continue
        lockfile.dependencies[dependency.key] = dependency

    for raw_workflow, raw_pins in workflows_data.items():
        if not isinstance(raw_workflow, str) or not isinstance(raw_pins, list):
            errors.append(
                f"Invalid dependency lockfile {lock_path}: workflow entries must "
                "map paths to pin lists"
            )
            continue
        workflow_path = _normalize_workflow_path(raw_workflow)
        if workflow_path is None:
            errors.append(
                f"Invalid dependency lockfile {lock_path}: unsafe workflow path "
                f"{raw_workflow!r}"
            )
            continue
        pins: list[str] = []
        for raw_pin in raw_pins:
            normalized = (
                _normalize_pin(raw_pin, str(version))
                if isinstance(raw_pin, str)
                else None
            )
            if normalized is None:
                errors.append(
                    f"Invalid dependency lockfile {lock_path}: malformed pin "
                    f"{raw_pin!r} for {raw_workflow}"
                )
                continue
            key, _ = normalized
            pins.append(key)
            if key not in lockfile.dependencies:
                lockfile.invalid_dependencies.add(key)
                errors.append(
                    f"Invalid dependency lockfile {lock_path}: {raw_workflow} "
                    f"references missing dependency {key!r}"
                )
        lockfile.workflows[workflow_path] = tuple(dict.fromkeys(pins))

    for dependency in lockfile.dependencies.values():
        for child in dependency.uses:
            if child not in lockfile.dependencies:
                errors.append(
                    f"Invalid dependency lockfile {lock_path}: dependency "
                    f"{dependency.key!r} references missing child {child!r}"
                )

    cycle = _dependency_cycle(lockfile)
    if cycle is not None:
        errors.append(
            f"Invalid dependency lockfile {lock_path}: uses cycle detected at "
            f"dependency {cycle!r}"
        )

    lockfile.valid = not errors
    return lockfile, errors


def scan_dependency_locks(
    repo_path: str,
) -> tuple[list[WorkflowDependencyLockCoverage], list[str]]:
    """Measure lock coverage for every workflow in a repository."""
    root = repository_root(repo_path)
    lock_path = root / LOCKFILE_RELATIVE_PATH
    lockfile, errors = load_actions_lock(repo_path)
    lockfile_present = lock_path.is_file()
    coverage: list[WorkflowDependencyLockCoverage] = []

    for workflow_file in find_workflow_files(repo_path):
        workflow_data = parse_workflow_file(workflow_file)
        if workflow_data is None:
            continue
        uses_refs = extract_external_uses(workflow_data)
        direct_keys = {
            key
            for uses_ref in uses_refs
            if (key := canonical_action_key(uses_ref)) is not None
        }
        relative_workflow = _relative_workflow_path(root, workflow_file)

        if not direct_keys:
            status = "no_dependencies"
            listed_pins: set[str] = set()
            valid_pins: set[str] = set()
        elif lockfile is None or not lockfile.valid:
            status = "invalid" if lockfile_present else "not_locked"
            listed_pins = (
                set(lockfile.workflows.get(relative_workflow, ()))
                if lockfile is not None
                else set()
            )
            valid_pins = set()
        else:
            listed_pins = set(lockfile.workflows.get(relative_workflow, ()))
            valid_pins = dependency_closure(lockfile, listed_pins)
            locked_direct = direct_keys & valid_pins
            if locked_direct == direct_keys:
                status = "fully_locked"
            elif listed_pins:
                status = "partially_locked"
            else:
                status = "not_locked"

        locked_direct = direct_keys & valid_pins
        invalid_pins = (
            listed_pins & lockfile.invalid_dependencies
            if lockfile is not None
            else set()
        )
        coverage.append(
            WorkflowDependencyLockCoverage(
                workflow_file=str(Path(workflow_file).resolve()),
                lockfile_path=(str(lock_path) if lockfile_present else None),
                schema_version=(lockfile.version if lockfile else None),
                status=status,
                direct_dependencies=len(direct_keys),
                locked_direct_dependencies=len(locked_direct),
                transitive_dependencies=len(valid_pins - direct_keys),
                locked_references=sorted(valid_pins),
                uncovered_dependencies=sorted(direct_keys - valid_pins),
                invalid_dependencies=sorted(invalid_pins),
            )
        )

    return coverage, errors


def filter_lock_covered_unpinned_actions(
    findings: list[UnpinnedActionFinding],
    coverage: list[WorkflowDependencyLockCoverage],
) -> list[UnpinnedActionFinding]:
    """Remove unpinned findings proved covered by a valid lock entry."""
    locked_by_workflow = {
        str(Path(item.workflow_file).resolve()): set(item.locked_references)
        for item in coverage
    }
    filtered: list[UnpinnedActionFinding] = []
    for finding in findings:
        key = canonical_action_key(finding.uses)
        try:
            workflow_key = str(Path(finding.workflow_file).resolve())
        except OSError:
            workflow_key = finding.workflow_file
        if key is not None and key in locked_by_workflow.get(workflow_key, set()):
            continue
        filtered.append(finding)
    return filtered


def extract_external_uses(workflow_data: dict) -> list[str]:
    """Return step and reusable-workflow references governed by actions.lock."""
    references: list[str] = []
    jobs = workflow_data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return references
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        job_uses = job.get("uses")
        if isinstance(job_uses, str) and canonical_action_key(job_uses) is not None:
            references.append(job_uses.strip())
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if isinstance(uses, str) and canonical_action_key(uses) is not None:
                references.append(uses.strip())
    return references


def canonical_action_key(uses_ref: str) -> str | None:
    """Return the ``OWNER/REPO@REF`` lock key for an external uses reference."""
    value = uses_ref.strip()
    if value.startswith(("./", "../", "$/", "docker://")) or "@" not in value:
        return None
    action_part, ref = value.split("@", 1)
    pieces = action_part.split("/")
    if len(pieces) < 2 or not pieces[0] or not pieces[1] or not ref:
        return None
    return f"{pieces[0].lower()}/{pieces[1].lower()}@{ref}"


def dependency_closure(
    lockfile: ActionsLockFile,
    pins: set[str] | tuple[str, ...],
) -> set[str]:
    """Return valid direct and transitive pins reachable from ``pins``."""
    reachable: set[str] = set()
    pending = list(pins)
    while pending:
        pin = pending.pop()
        if pin in reachable:
            continue
        dependency = lockfile.dependencies.get(pin)
        if dependency is None:
            continue
        reachable.add(pin)
        pending.extend(dependency.uses)
    return reachable


def _normalize_dependency(
    raw_key: object,
    raw_dependency: object,
    version: str,
    lock_path: Path,
) -> tuple[LockedActionDependency | None, list[str]]:
    errors: list[str] = []
    normalized = _normalize_pin(raw_key, version) if isinstance(raw_key, str) else None
    if normalized is None or not isinstance(raw_dependency, dict):
        return None, [
            f"Invalid dependency lockfile {lock_path}: malformed dependency {raw_key!r}"
        ]
    key, key_digest = normalized
    action_name, key_ref = key.rsplit("@", 1)

    ref = raw_dependency.get("ref")
    if version == "v0.0.1":
        tag = raw_dependency.get("tag")
        branch = raw_dependency.get("branch")
        ref = tag if isinstance(tag, str) and tag else branch
        if not isinstance(ref, str) or not ref:
            ref = key_ref
    if not isinstance(ref, str) or not ref or ref != key_ref:
        errors.append(
            f"Invalid dependency lockfile {lock_path}: dependency {raw_key!r} "
            "has a missing or mismatched ref"
        )

    commit = raw_dependency.get("commit")
    commit_sha = _commit_sha(commit) if isinstance(commit, str) else None
    if commit_sha is None:
        errors.append(
            f"Invalid dependency lockfile {lock_path}: dependency {raw_key!r} "
            "does not contain a full commit digest"
        )
    if key_digest is not None and commit != key_digest:
        errors.append(
            f"Invalid dependency lockfile {lock_path}: dependency {raw_key!r} "
            "commit does not match its v0.0.1 pin suffix"
        )

    owner_id = raw_dependency.get("owner_id")
    repo_id = raw_dependency.get("repo_id")
    if not _positive_int(owner_id) or not _positive_int(repo_id):
        errors.append(
            f"Invalid dependency lockfile {lock_path}: dependency {raw_key!r} "
            "requires positive owner_id and repo_id values"
        )

    hostname = raw_dependency.get("hostname", "github.com")
    if version != "v0.0.3" and "hostname" in raw_dependency:
        errors.append(
            f"Invalid dependency lockfile {lock_path}: dependency {raw_key!r} "
            f"uses hostname before schema v0.0.3"
        )
    if not isinstance(hostname, str) or not _HOSTNAME_RE.fullmatch(hostname):
        errors.append(
            f"Invalid dependency lockfile {lock_path}: dependency {raw_key!r} "
            "has an invalid hostname"
        )

    normalized_uses: list[str] = []
    uses = raw_dependency.get("uses") or []
    if not isinstance(uses, list):
        errors.append(
            f"Invalid dependency lockfile {lock_path}: dependency {raw_key!r} "
            "uses must be a list"
        )
    else:
        for item in uses:
            normalized_use = (
                _normalize_pin(item, version) if isinstance(item, str) else None
            )
            if normalized_use is None:
                errors.append(
                    f"Invalid dependency lockfile {lock_path}: dependency "
                    f"{raw_key!r} has malformed child pin {item!r}"
                )
            else:
                normalized_uses.append(normalized_use[0])

    allowed = {"commit", "owner_id", "repo_id", "uses"}
    allowed.update({"tag", "branch"} if version == "v0.0.1" else {"ref"})
    if version == "v0.0.3":
        allowed.add("hostname")
    extra = set(raw_dependency) - allowed
    if extra:
        errors.append(
            f"Invalid dependency lockfile {lock_path}: dependency {raw_key!r} "
            f"contains unsupported fields {sorted(extra)!r}"
        )

    if errors or commit_sha is None or not isinstance(ref, str):
        return None, errors
    return (
        LockedActionDependency(
            key=key,
            action_name=action_name.lower(),
            ref=ref,
            commit=str(commit),
            commit_sha=commit_sha,
            owner_id=int(owner_id),
            repo_id=int(repo_id),
            hostname=hostname,
            uses=tuple(dict.fromkeys(normalized_uses)),
        ),
        [],
    )


def _normalize_pin(value: str, version: str) -> tuple[str, str | None] | None:
    match = (_V1_PIN_RE if version == "v0.0.1" else _CURRENT_PIN_RE).fullmatch(value)
    if match is None:
        return None
    key = f"{match.group('action').lower()}@{match.group('ref')}"
    return key, match.groupdict().get("digest")


def _commit_sha(commit: str) -> str | None:
    for pattern in (_SHA1_DIGEST_RE, _SHA256_DIGEST_RE):
        match = pattern.fullmatch(commit)
        if match:
            return match.group(1).lower()
    return None


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _normalize_workflow_path(path: str) -> str | None:
    if any(ord(character) <= 0x1F or ord(character) == 0x7F for character in path):
        return None
    if "\\" in path or ":" in path:
        return None
    candidate = PurePosixPath(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    normalized = str(candidate).removeprefix("./")
    if not normalized.startswith(".github/workflows/"):
        return None
    if PurePosixPath(normalized).suffix.lower() not in {".yml", ".yaml"}:
        return None
    return normalized


def _dependency_cycle(lockfile: ActionsLockFile) -> str | None:
    colors: dict[str, int] = {}

    def visit(key: str) -> str | None:
        color = colors.get(key, 0)
        if color == 1:
            return key
        if color == 2:
            return None
        colors[key] = 1
        dependency = lockfile.dependencies.get(key)
        if dependency is not None:
            for child in dependency.uses:
                cycle = visit(child)
                if cycle is not None:
                    return cycle
        colors[key] = 2
        return None

    for key in lockfile.dependencies:
        cycle = visit(key)
        if cycle is not None:
            return cycle
    return None


def _relative_workflow_path(root: Path, workflow_file: str) -> str:
    try:
        relative = Path(workflow_file).resolve().relative_to(root)
    except ValueError:
        return _normalize_workflow_path(workflow_file) or workflow_file
    return relative.as_posix()
