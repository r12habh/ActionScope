"""Explicit local IAM inputs. No cloud calls or secret-value discovery."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import replace
from pathlib import Path
from urllib.parse import unquote

from actionscope.models import AwsCredentialSource, PolicyFinding
from actionscope.parsers.policy_json import extract_actions_from_policy

ROLE_ARN = re.compile(
    r"arn:aws(?:-[a-z0-9-]+)?:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+"
)


class EvidenceError(ValueError):
    """An explicitly supplied input cannot be interpreted safely."""


def _unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("Duplicate JSON keys are not supported")
        result[key] = value
    return result


def _bounded_integer(value: str) -> int:
    if len(value) > 256:
        raise EvidenceError("JSON integer exceeds 256 digits")
    return int(value)


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise EvidenceError("Non-finite JSON numbers are unsupported")
    return number


def _reject_constant(value: str) -> None:
    raise EvidenceError("Non-standard JSON constants are unsupported")


def _json_loads(value: bytes | str) -> object:
    return json.loads(
        value,
        object_pairs_hook=_unique_object,
        parse_int=_bounded_integer,
        parse_float=_finite_float,
        parse_constant=_reject_constant,
    )


def read_evidence_json(path: str, limit: int = 20 * 1024 * 1024) -> tuple[dict, dict]:
    """Read a bounded JSON file and return content-hash provenance."""
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise EvidenceError(f"Evidence file exceeds {limit} bytes")
        data = _json_loads(raw)
    except (OSError, ValueError, RecursionError) as exc:
        raise EvidenceError(f"Cannot read evidence JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise EvidenceError("Evidence JSON must be an object")
    return data, {"file": Path(path).name, "sha256": hashlib.sha256(raw).hexdigest()}


def _document(value: object) -> dict:
    if isinstance(value, str):
        try:
            try:
                value = _json_loads(value)
            except json.JSONDecodeError:
                value = _json_loads(unquote(value))
        except (ValueError, RecursionError) as exc:
            raise EvidenceError("Invalid encoded IAM policy document") from exc
    if not isinstance(value, dict):
        raise EvidenceError("IAM policy document must be an object")
    statements = value.get("Statement")
    if not isinstance(statements, (dict, list)):
        raise EvidenceError("IAM policy document requires Statement")
    for statement in _objects(
        statements if isinstance(statements, list) else [statements], "Statement"
    ):
        if statement.get("Effect") not in ("Allow", "Deny"):
            raise EvidenceError("IAM statement requires Allow or Deny Effect")
        action = statement.get("Action", statement.get("NotAction"))
        if (
            not isinstance(action, (str, list))
            or isinstance(action, list)
            and any(not isinstance(item, str) for item in action)
        ):
            raise EvidenceError("IAM statement requires string action values")
    return value


def _objects(value: object, label: str) -> list[dict]:
    if not isinstance(value, list) or len(value) > 10000:
        raise EvidenceError(f"{label} must be a list of at most 10000 objects")
    if any(not isinstance(item, dict) for item in value):
        raise EvidenceError(f"{label} contains a non-object entry")
    return value


def load_iam_snapshot(path: str) -> list[PolicyFinding]:
    """Load AWS GetAccountAuthorizationDetails JSON, indexed by exact role ARN.

    Each role becomes one policy inventory. It is deliberately not labeled live
    verification or complete authorization, even if every attachment is present.
    """
    data, provenance = read_evidence_json(path)
    if data.get("IsTruncated") not in (None, False):
        raise EvidenceError("Snapshot is truncated; export all IAM pages first")
    roles = _objects(data.get("RoleDetailList"), "RoleDetailList")
    policies = {}
    for policy in _objects(data.get("Policies", []), "Policies"):
        arn = policy.get("Arn")
        if not isinstance(arn, str) or arn in policies:
            raise EvidenceError("Managed policies need unique ARNs")
        versions = _objects(policy.get("PolicyVersionList", []), "PolicyVersionList")
        current = [v for v in versions if v.get("IsDefaultVersion") is True]
        if len(current) > 1:
            raise EvidenceError("Managed policy has multiple default versions")
        policies[arn] = _document(current[0].get("Document")) if current else None

    findings = []
    seen = set()
    for role in roles:
        arn = role.get("Arn")
        if not isinstance(arn, str) or not ROLE_ARN.fullmatch(arn) or arn.endswith("/"):
            raise EvidenceError("Snapshot role must have a literal IAM role ARN")
        if arn in seen:
            raise EvidenceError("Snapshot contains duplicate role ARNs")
        seen.add(arn)
        name = arn.rsplit("/", 1)[-1]
        if role.get("RoleName", name) != name:
            raise EvidenceError("RoleName does not agree with role ARN")
        statements, documents, missing = [], [], []
        for inline in _objects(role.get("RolePolicyList", []), "RolePolicyList"):
            document = _document(inline.get("PolicyDocument"))
            documents.append(
                {
                    "kind": "inline",
                    "name": inline.get("PolicyName"),
                    "document": document,
                }
            )
        for attached in _objects(
            role.get("AttachedManagedPolicies", []), "AttachedManagedPolicies"
        ):
            policy_arn = attached.get("PolicyArn")
            if not isinstance(policy_arn, str):
                raise EvidenceError("Policy attachment must have PolicyArn")
            document = policies.get(policy_arn)
            if document is None:
                missing.append(policy_arn)
            else:
                documents.append(
                    {"kind": "managed", "arn": policy_arn, "document": document}
                )
        for document in documents:
            value = document["document"]["Statement"]
            statements.extend(value if isinstance(value, list) else [value])
        finding = extract_actions_from_policy(
            {"Statement": statements}, str(Path(path).resolve())
        )
        finding.source_type = "aws_snapshot"
        finding.role_arn, finding.role_name = arn, name
        finding.policy_name = "snapshot role policy inventory"
        unknown = list(finding.metadata.get("uninspectable_policy_elements", []))
        unknown.append(
            "Session, resource, organization policies and role chaining not evaluated"
        )
        for key in ("RolePolicyList", "AttachedManagedPolicies"):
            if key not in role:
                unknown.append(f"Snapshot omits {key}")
        boundary = role.get("PermissionsBoundary")
        boundaries = []
        if boundary:
            if not isinstance(boundary, dict) or not isinstance(
                boundary.get("PermissionsBoundaryArn"), str
            ):
                raise EvidenceError("Malformed permissions boundary")
            boundary_arn = boundary["PermissionsBoundaryArn"]
            boundaries.append(
                {"arn": boundary_arn, "document": policies.get(boundary_arn)}
            )
            unknown.append("Permissions boundary retained but not evaluated")
        trust = role.get("AssumeRolePolicyDocument")
        finding.metadata.update(
            {
                "evidence_sources": [{**provenance, "kind": "aws_iam_snapshot"}],
                "policy_documents": documents,
                "assume_role_policy": _document(trust) if trust is not None else None,
                "permissions_boundaries": boundaries,
                "unresolved_policy_attachments": missing,
                "uninspectable_policy_elements": list(dict.fromkeys(unknown)),
                "policy_coverage_complete": False,
                "authorization_evaluated": False,
            }
        )
        findings.append(finding)
    return findings


def apply_role_map(
    sources: list[AwsCredentialSource], path: str, repo_path: str
) -> None:
    """Resolve only unambiguous, owner-selected workflow/job/step identities."""
    data, provenance = read_evidence_json(path, 256 * 1024)
    if (
        type(data.get("version")) is not int
        or data["version"] != 1
        or set(data) != {"version", "roles"}
    ):
        raise EvidenceError("Role map requires version: 1 and roles")
    entries = _objects(data["roles"], "roles")
    planned: dict[int, str] = {}
    root = Path(repo_path).resolve()
    if root.is_file():
        root = (
            root.parent.parent.parent
            if root.parent.name == "workflows"
            else root.parent
        )
    for entry in entries:
        if set(entry) - {"workflow", "job", "step", "role_arn"}:
            raise EvidenceError("Unknown role-map field")
        if any(
            not isinstance(entry.get(key), str) or not entry[key]
            for key in ("workflow", "job", "role_arn")
        ):
            raise EvidenceError(
                "Role mapping requires workflow, job and role_arn strings"
            )
        target = Path(entry["workflow"])
        if target.is_absolute() or ".." in target.parts or "\\" in entry["workflow"]:
            raise EvidenceError("Mapped workflow must be repository-relative")
        if not ROLE_ARN.fullmatch(entry["role_arn"]) or entry["role_arn"].endswith("/"):
            raise EvidenceError("Role mapping requires a literal IAM role ARN")
        if "step" in entry and not isinstance(entry["step"], str):
            raise EvidenceError("Mapped step must be a string")
        matches = []
        for index, source in enumerate(sources):
            try:
                workflow = (
                    Path(source.workflow_file).resolve().relative_to(root).as_posix()
                )
            except ValueError:
                continue
            if workflow == target.as_posix() and source.job_name == entry["job"]:
                if "step" not in entry or source.step_name == entry["step"]:
                    matches.append(index)
        if len(matches) != 1:
            raise EvidenceError(
                "Role mapping must select exactly one credential source; "
                "specify step if needed"
            )
        index = matches[0]
        source = sources[index]
        if index in planned:
            raise EvidenceError("Duplicate or overlapping role mappings")
        if (
            source.role_arn
            and "${{" not in source.role_arn
            and source.role_arn != entry["role_arn"]
        ):
            raise EvidenceError("Role map conflicts with a literal workflow identity")
        planned[index] = entry["role_arn"]
    for index, arn in planned.items():
        source = sources[index]
        sources[index] = replace(
            source,
            role_arn=arn,
            original_role_reference=source.original_role_reference or source.role_arn,
            role_resolution="owner_mapping",
            role_resolution_evidence={**provenance, "kind": "owner_mapping"},
        )


def load_iam_roots(
    paths: tuple[str, ...], repo_path: str, max_policy_files: int | None = None
) -> tuple[list[PolicyFinding], list[str]]:
    """Reuse existing IaC parsers over explicit, symlink-free evidence roots."""
    from actionscope.parsers.cloudformation import scan_cloudformation_files
    from actionscope.parsers.policy_json import scan_policy_files
    from actionscope.parsers.terraform import scan_terraform_files

    findings, errors = [], []
    repository = Path(repo_path).resolve()
    if repository.is_file():
        repository = (
            repository.parent.parent.parent
            if repository.parent.name == "workflows"
            else repository.parent
        )
    requested = sorted({Path(value).resolve() for value in paths})
    roots = []
    for root in requested:
        if not root.is_dir():
            raise EvidenceError("--iam-path requires a directory")
        if root == repository or root.is_relative_to(repository):
            continue
        if repository.is_relative_to(root):
            raise EvidenceError("An IAM root must not contain the scanned repository")
        if not any(root != other and root.is_relative_to(other) for other in requested):
            roots.append(root)
    seen_files = set()
    for index, root in enumerate(roots):
        for path in root.rglob("*"):
            if path.is_symlink():
                raise EvidenceError("IAM evidence roots must not contain symlinks")
            if path.suffix.lower() in {".tf", ".json", ".yaml", ".yml"}:
                if path.stat().st_size > 20 * 1024 * 1024:
                    raise EvidenceError("IAM source exceeds 20 MiB before parsing")
        json_kwargs = (
            {} if max_policy_files is None else {"max_other_files": max_policy_files}
        )
        for scan, kwargs in (
            (scan_policy_files, json_kwargs),
            (scan_terraform_files, {}),
            (scan_cloudformation_files, {}),
        ):
            try:
                parsed, scan_errors = scan(str(root), **kwargs)
            except (ValueError, RecursionError) as exc:
                errors.append(
                    f"Could not parse IAM root iam-{index + 1}: {type(exc).__name__}"
                )
                continue
            errors.extend(scan_errors)
            for finding in parsed:
                source = Path(finding.source_file).resolve()
                if not source.is_relative_to(root):
                    raise EvidenceError("IAM policy evidence escaped its root")
                key = (
                    source,
                    finding.source_type,
                    finding.role_arn,
                    finding.role_name,
                    finding.policy_name,
                )
                if key in seen_files:
                    continue
                seen_files.add(key)
                with source.open("rb") as handle:
                    raw = handle.read(20 * 1024 * 1024 + 1)
                if len(raw) > 20 * 1024 * 1024:
                    raise EvidenceError("IAM source exceeds 20 MiB")
                finding.metadata["evidence_sources"] = [
                    {
                        "kind": "iam_root",
                        "root": f"iam-{index + 1}",
                        "file": source.relative_to(root).as_posix(),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                ]
                if finding.role_arn is None:
                    finding.metadata["policy_coverage_complete"] = False
                    constraints = list(
                        finding.metadata.get("uninspectable_policy_elements", [])
                    )
                    finding.metadata["uninspectable_policy_elements"] = list(
                        dict.fromkeys(
                            constraints
                            + ["IAM-root account identity lacks an exact ARN"]
                        )
                    )
                findings.append(finding)
    return findings, errors


def oidc_trust_candidates(
    repo_path: str,
    repository: str,
    policies: list[PolicyFinding],
    sources: list[AwsCredentialSource],
) -> list[AwsCredentialSource]:
    """Potential identities, not a claim that a secret resolves to those roles.

    Only exact aud/sub conditions are supported. Additional constraints, Deny,
    wildcard subjects and reusable caller contexts are deliberately not inferred.
    """
    from actionscope.parsers.workflow import find_workflow_files, parse_workflow_file

    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise EvidenceError("--github-repo must be owner/repository")
    by_subject: dict[str, list[str]] = {}
    for policy in policies:
        trust = policy.metadata.get("assume_role_policy")
        if not isinstance(trust, dict):
            continue
        statements = trust.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if any(isinstance(s, dict) and s.get("Effect") == "Deny" for s in statements):
            continue
        for statement in statements:
            if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                continue
            if statement.get("Action") != "sts:AssumeRoleWithWebIdentity":
                continue
            principal = statement.get("Principal")
            if not isinstance(principal, dict) or set(principal) != {"Federated"}:
                continue
            provider = principal["Federated"]
            parts = policy.role_arn.split(":")
            expected = (
                f"arn:{parts[1]}:iam::{parts[4]}:"
                "oidc-provider/token.actions.githubusercontent.com"
            )
            if provider != expected:
                continue
            condition = statement.get("Condition")
            if not isinstance(condition, dict) or set(condition) != {"StringEquals"}:
                continue
            claims = condition["StringEquals"]
            prefix = "token.actions.githubusercontent.com:"
            if not isinstance(claims, dict) or set(claims) != {
                prefix + "aud",
                prefix + "sub",
            }:
                continue
            subject = claims[prefix + "sub"]
            if claims[prefix + "aud"] != "sts.amazonaws.com" or not isinstance(
                subject, str
            ):
                continue
            by_subject.setdefault(subject, []).append(policy.role_arn)

    candidates = []
    existing = {(s.workflow_file, s.job_name, s.role_arn) for s in sources}
    for filename in find_workflow_files(repo_path):
        workflow = parse_workflow_file(filename)
        if not isinstance(workflow, dict):
            continue
        triggers = workflow.get("on")
        if isinstance(triggers, dict) and "workflow_call" in triggers:
            continue
        if (
            triggers == "workflow_call"
            or isinstance(triggers, list)
            and "workflow_call" in triggers
        ):
            continue
        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            continue
        for name, job in jobs.items():
            if not isinstance(job, dict) or "uses" in job:
                continue
            permissions = job.get("permissions", workflow.get("permissions", {}))
            if not (
                permissions == "write-all"
                or isinstance(permissions, dict)
                and permissions.get("id-token") == "write"
            ):
                continue
            environment = job.get("environment")
            if isinstance(environment, dict):
                environment = environment.get("name")
            subject = None
            if (
                isinstance(environment, str)
                and environment
                and "${{" not in environment
            ):
                subject = (
                    f"repo:{repository}:environment:{environment.replace(':', '%3A')}"
                )
            elif (
                environment is None
                and isinstance(triggers, dict)
                and set(triggers) == {"push"}
            ):
                push = triggers["push"]
                branches = push.get("branches") if isinstance(push, dict) else None
                if (
                    isinstance(branches, list)
                    and len(branches) == 1
                    and isinstance(branches[0], str)
                ):
                    branch = branches[0]
                    if (
                        not any(
                            token in branch for token in ("*", "?", "[", "!", "${{")
                        )
                        and "tags" not in push
                    ):
                        subject = f"repo:{repository}:ref:refs/heads/{branch}"
            for arn in by_subject.get(subject, []):
                key = (filename, str(name), arn)
                if key in existing:
                    continue
                if len(candidates) >= 1000:
                    raise EvidenceError(
                        "Trust candidates exceed 1000; "
                        "narrow the snapshot or workflow input"
                    )
                existing.add(key)
                candidates.append(
                    AwsCredentialSource(
                        workflow_file=filename,
                        job_name=str(name),
                        step_name="Potential OIDC trust-policy reachability",
                        role_arn=arn,
                        uses_access_keys=False,
                        uses_oidc=True,
                        aws_region=None,
                        role_reference_kind="trust_policy",
                        role_resolution="trust_candidate",
                    )
                )
    return candidates
