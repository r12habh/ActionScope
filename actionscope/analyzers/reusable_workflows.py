"""Reusable GitHub Actions workflow discovery and inspection.

Local reusable workflows are resolved from the repository. External workflows
are fetched through GitHub's repository contents API only when a token is
explicitly supplied. The traversal follows GitHub's documented limits of ten
levels and fifty unique called workflows.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

import yaml

from actionscope import __version__
from actionscope.analyzers.ai_agent_injection import (
    analyze_ai_agent_injection_surface,
)
from actionscope.analyzers.artifact_poisoning import analyze_artifact_poisoning
from actionscope.analyzers.compromised_actions import (
    check_workflow_for_compromised_actions,
    load_compromised_actions,
)
from actionscope.analyzers.github_environments import analyze_environment_usage
from actionscope.analyzers.github_token import analyze_workflow_permissions
from actionscope.analyzers.script_injection import scan_workflow_for_injections
from actionscope.models import (
    AiAgentInjectionFinding,
    ArtifactPoisoningFinding,
    AwsCredentialSource,
    CompromisedActionFinding,
    EnvironmentFinding,
    GitHubTokenPermission,
    ReusableWorkflowReference,
    ScriptInjectionFinding,
    UnpinnedActionFinding,
)
from actionscope.parsers.workflow import (
    GitHubWorkflowLoader,
    classify_action_ref,
    extract_aws_credential_sources,
    find_unpinned_action_uses,
    find_workflow_files,
    parse_workflow_file,
)

MAX_REUSABLE_LEVELS = 10
MAX_UNIQUE_REUSABLE_WORKFLOWS = 50
MAX_WORKFLOW_BYTES = 1024 * 1024
_GITHUB_REPOSITORY_PART = re.compile(r"^[A-Za-z0-9_.-]+$")


@dataclass
class ReusableWorkflowScan:
    """Findings collected from reusable workflows outside the normal file set."""

    references: list[ReusableWorkflowReference] = field(default_factory=list)
    credential_sources: list[AwsCredentialSource] = field(default_factory=list)
    github_token_permissions: list[GitHubTokenPermission] = field(
        default_factory=list
    )
    unpinned_actions: list[UnpinnedActionFinding] = field(default_factory=list)
    script_injection_findings: list[ScriptInjectionFinding] = field(
        default_factory=list
    )
    artifact_poisoning_findings: list[ArtifactPoisoningFinding] = field(
        default_factory=list
    )
    ai_agent_injection_findings: list[AiAgentInjectionFinding] = field(
        default_factory=list
    )
    compromised_action_findings: list[CompromisedActionFinding] = field(
        default_factory=list
    )
    environment_findings: list[EnvironmentFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _WorkflowDocument:
    key: str
    source: str
    data: dict
    repository: Optional[str]
    ref: Optional[str]
    local_path: Optional[Path]


@dataclass(frozen=True)
class _Target:
    key: str
    source: str
    repository: Optional[str]
    ref: Optional[str]
    path: str
    local_path: Optional[Path]
    is_local: bool
    pin_type: str


class _Traversal:
    def __init__(
        self,
        repo_path: str,
        root_keys: set[str],
        github_token: str | None,
    ) -> None:
        path = Path(repo_path).expanduser()
        self.repo_root = _repository_root(path)
        self.root_keys = root_keys
        self.github_token = github_token
        self.references: list[ReusableWorkflowReference] = []
        self.documents: dict[str, _WorkflowDocument] = {}
        self.loaded: dict[str, tuple[dict | None, str, str | None]] = {}
        self.expanded: set[str] = set()
        self.errors: list[str] = []

    def walk(
        self,
        document: _WorkflowDocument,
        depth: int,
        ancestry: frozenset[str],
        root_targets: set[str],
    ) -> None:
        if document.key in self.expanded:
            return
        self.expanded.add(document.key)

        jobs = document.data.get("jobs") or {}
        if not isinstance(jobs, dict):
            return

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            uses = job.get("uses")
            if not isinstance(uses, str):
                continue
            uses = uses.strip()
            target, target_error = self._resolve_target(document, uses)
            if target is None:
                self._add_reference(
                    document,
                    str(job_name),
                    uses,
                    target_workflow=uses,
                    repository=None,
                    ref=None,
                    pin_type="unresolvable",
                    is_local=uses.startswith("./"),
                    status="invalid_reference",
                    depth=depth + 1,
                    error=target_error,
                )
                continue

            next_depth = depth + 1
            # GitHub counts the top-level caller as level one, so depth nine
            # is the deepest reusable workflow allowed in a ten-level chain.
            if next_depth >= MAX_REUSABLE_LEVELS:
                self._add_target_reference(
                    document,
                    str(job_name),
                    uses,
                    target,
                    "depth_limit",
                    next_depth,
                    (
                        "reusable workflow nesting exceeds "
                        f"{MAX_REUSABLE_LEVELS} total levels"
                    ),
                )
                continue

            if target.key in ancestry:
                self._add_target_reference(
                    document,
                    str(job_name),
                    uses,
                    target,
                    "cycle",
                    next_depth,
                    "reusable workflow cycle detected; target was not scanned again",
                )
                continue

            if target.key not in root_targets:
                if len(root_targets) >= MAX_UNIQUE_REUSABLE_WORKFLOWS:
                    self._add_target_reference(
                        document,
                        str(job_name),
                        uses,
                        target,
                        "workflow_limit",
                        next_depth,
                        "reusable workflow graph exceeds GitHub's 50-workflow limit",
                    )
                    continue
                root_targets.add(target.key)

            target_data, status, load_error = self._load_target(target)
            self._add_target_reference(
                document,
                str(job_name),
                uses,
                target,
                status,
                next_depth,
                load_error,
            )
            if target_data is None:
                continue

            called_document = _WorkflowDocument(
                key=target.key,
                source=target.source,
                data=target_data,
                repository=target.repository,
                ref=target.ref,
                local_path=target.local_path,
            )
            if target.key not in self.root_keys:
                self.documents.setdefault(target.key, called_document)
            self.walk(
                called_document,
                next_depth,
                ancestry | {target.key},
                root_targets,
            )

    def _resolve_target(
        self,
        caller: _WorkflowDocument,
        uses: str,
    ) -> tuple[_Target | None, str | None]:
        if "${{" in uses:
            return None, "dynamic reusable workflow references cannot be resolved"

        if uses.startswith("./"):
            relative = uses[2:]
            if not relative.startswith(".github/workflows/"):
                return None, "job-level uses must reference a reusable workflow"
            if caller.repository:
                if not caller.ref:
                    return None, "external workflow context is missing a Git ref"
                return self._external_target(
                    caller.repository,
                    relative,
                    caller.ref,
                    is_local=True,
                    pin_type="local",
                ), None

            local_path = (self.repo_root / relative).resolve()
            try:
                local_path.relative_to(self.repo_root)
            except ValueError:
                return None, "local reusable workflow target is outside the repo"
            return (
                _Target(
                    key=_local_key(local_path),
                    source=str(local_path),
                    repository=None,
                    ref=None,
                    path=relative,
                    local_path=local_path,
                    is_local=True,
                    pin_type="local",
                ),
                None,
            )

        if "@" not in uses:
            return None, "external reusable workflow reference is missing @ref"
        action_path, ref = uses.rsplit("@", 1)
        parts = action_path.split("/")
        if (
            len(parts) < 4
            or not ref
            or not _valid_repository_part(parts[0])
            or not _valid_repository_part(parts[1])
            or parts[2] != ".github"
            or parts[3] != "workflows"
            or any(part in {"", ".", ".."} for part in parts[4:])
            or not action_path.endswith((".yml", ".yaml"))
        ):
            return (
                None,
                "external reusable workflow must use "
                "owner/repo/.github/workflows/file@ref",
            )
        repository = "/".join(parts[:2])
        workflow_path = "/".join(parts[2:])
        return self._external_target(
            repository,
            workflow_path,
            ref,
            is_local=False,
            pin_type=classify_action_ref(uses),
        ), None

    def _external_target(
        self,
        repository: str,
        workflow_path: str,
        ref: str,
        *,
        is_local: bool,
        pin_type: str,
    ) -> _Target:
        source = f"{repository}/{workflow_path}@{ref}"
        return _Target(
            key=f"external:{repository.lower()}/{workflow_path}@{ref}",
            source=source,
            repository=repository,
            ref=ref,
            path=workflow_path,
            local_path=None,
            is_local=is_local,
            pin_type=pin_type,
        )

    def _load_target(
        self,
        target: _Target,
    ) -> tuple[dict | None, str, str | None]:
        cached = self.loaded.get(target.key)
        if cached is not None:
            return cached

        if target.local_path is not None:
            data = parse_workflow_file(str(target.local_path))
            if data is None:
                result = (
                    None,
                    "load_error",
                    "local reusable workflow was not found or could not be parsed",
                )
            else:
                result = (data, "inspected", None)
            self.loaded[target.key] = result
            return result

        if not self.github_token:
            result = (
                None,
                "no_token",
                "external workflow not inspected; pass --github-token or set "
                "GITHUB_TOKEN",
            )
            self.loaded[target.key] = result
            return result

        assert target.repository is not None
        assert target.ref is not None
        data, fetch_error = _fetch_external_workflow(
            target.repository,
            target.path,
            target.ref,
            self.github_token,
        )
        if data is None:
            result = (None, "fetch_error", fetch_error or "GitHub API fetch failed")
            self.errors.append(
                f"Could not inspect reusable workflow {target.source}: {result[2]}"
            )
        else:
            result = (data, "inspected", None)
        self.loaded[target.key] = result
        return result

    def _add_target_reference(
        self,
        caller: _WorkflowDocument,
        job_name: str,
        uses: str,
        target: _Target,
        status: str,
        depth: int,
        error: str | None,
    ) -> None:
        self._add_reference(
            caller,
            job_name,
            uses,
            target_workflow=target.source,
            repository=target.repository,
            ref=target.ref,
            pin_type=target.pin_type,
            is_local=target.is_local,
            status=status,
            depth=depth,
            error=error,
        )

    def _add_reference(
        self,
        caller: _WorkflowDocument,
        job_name: str,
        uses: str,
        *,
        target_workflow: str,
        repository: str | None,
        ref: str | None,
        pin_type: str,
        is_local: bool,
        status: str,
        depth: int,
        error: str | None,
    ) -> None:
        self.references.append(
            ReusableWorkflowReference(
                caller_workflow=caller.source,
                caller_job=job_name,
                uses=uses,
                target_workflow=target_workflow,
                repository=repository,
                ref=ref,
                pin_type=pin_type,
                is_local=is_local,
                status=status,
                depth=depth,
                error=error,
            )
        )


def scan_reusable_workflows(
    repo_path: str,
    github_token: str | None = None,
) -> ReusableWorkflowScan:
    """Discover, resolve, and inspect job-level reusable workflow calls."""
    root_files = find_workflow_files(repo_path)
    root_keys = {_local_key(Path(path).resolve()) for path in root_files}
    traversal = _Traversal(repo_path, root_keys, github_token)

    for workflow_file in root_files:
        workflow_data = parse_workflow_file(workflow_file)
        if workflow_data is None:
            continue
        path = Path(workflow_file).resolve()
        document = _WorkflowDocument(
            key=_local_key(path),
            source=str(path),
            data=workflow_data,
            repository=None,
            ref=None,
            local_path=path,
        )
        traversal.walk(
            document,
            depth=0,
            ancestry=frozenset({document.key}),
            root_targets=set(),
        )

    result = ReusableWorkflowScan(
        references=traversal.references,
        errors=traversal.errors,
    )
    _analyze_documents(result, traversal.documents.values())
    _add_reusable_ref_pinning_findings(result)
    return result


def _analyze_documents(
    result: ReusableWorkflowScan,
    documents: Iterable[_WorkflowDocument],
) -> None:
    try:
        compromised_db = load_compromised_actions()
    except (OSError, ValueError) as exc:
        compromised_db = None
        result.errors.append(f"Could not load compromised actions database: {exc}")

    for document in documents:
        workflow_file = document.source
        credentials = extract_aws_credential_sources(document.data, workflow_file)
        permissions = analyze_workflow_permissions(document.data, workflow_file)
        result.credential_sources.extend(credentials)
        result.github_token_permissions.extend(permissions)
        result.unpinned_actions.extend(
            UnpinnedActionFinding(**finding)
            for finding in find_unpinned_action_uses(document.data, workflow_file)
        )
        result.script_injection_findings.extend(
            scan_workflow_for_injections(document.data, workflow_file)
        )
        result.artifact_poisoning_findings.extend(
            analyze_artifact_poisoning(document.data, workflow_file)
        )
        result.ai_agent_injection_findings.extend(
            analyze_ai_agent_injection_surface(
                document.data,
                workflow_file,
                credentials,
                permissions,
            )
        )
        if compromised_db is not None:
            result.compromised_action_findings.extend(
                check_workflow_for_compromised_actions(
                    document.data,
                    workflow_file,
                    compromised_db,
                )
            )
        result.environment_findings.extend(
            analyze_environment_usage(
                document.data,
                workflow_file,
                credentials,
                [],
            )
        )


def _add_reusable_ref_pinning_findings(result: ReusableWorkflowScan) -> None:
    for reference in result.references:
        if reference.is_local or reference.pin_type in {"sha", "local"}:
            continue
        result.unpinned_actions.append(
            UnpinnedActionFinding(
                workflow_file=reference.caller_workflow,
                job_name=reference.caller_job,
                step_name="Reusable workflow call",
                uses=reference.uses,
                pin_type=reference.pin_type,
            )
        )


def _fetch_external_workflow(
    repository: str,
    workflow_path: str,
    ref: str,
    github_token: str,
) -> tuple[dict | None, str | None]:
    encoded_path = quote(workflow_path, safe="/")
    query = urlencode({"ref": ref})
    url = f"https://api.github.com/repos/{repository}/contents/{encoded_path}?{query}"
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github.raw+json",
            "Authorization": f"Bearer {github_token}",
            "User-Agent": f"ActionScope/{__version__}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=10) as response:  # noqa: S310
            payload = response.read(MAX_WORKFLOW_BYTES + 1)
    except HTTPError as exc:
        if exc.code == 404:
            return None, "not found or token cannot access the repository"
        if exc.code == 403:
            return None, "GitHub API denied the request or rate limit was exceeded"
        return None, f"GitHub API returned HTTP {exc.code}"
    except (URLError, TimeoutError, OSError) as exc:
        detail = exc.reason if isinstance(exc, URLError) else exc
        return None, f"network error: {detail}"

    if len(payload) > MAX_WORKFLOW_BYTES:
        return None, "workflow exceeds the 1 MiB inspection limit"
    try:
        workflow_data = yaml.load(
            payload.decode("utf-8"),
            Loader=GitHubWorkflowLoader,
        )
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        return None, f"response is not valid workflow YAML: {exc}"
    if not isinstance(workflow_data, dict):
        return None, "response YAML root is not a mapping"
    return workflow_data, None


def _local_key(path: Path) -> str:
    return f"local:{path.resolve()}"


def _repository_root(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_file():
        return resolved
    for parent in resolved.parents:
        if parent.name == "workflows" and parent.parent.name == ".github":
            return parent.parent.parent
    return resolved.parent


def _valid_repository_part(value: str) -> bool:
    return value not in {".", ".."} and bool(_GITHUB_REPOSITORY_PART.fullmatch(value))
