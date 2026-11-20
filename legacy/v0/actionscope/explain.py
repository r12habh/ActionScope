"""Local semantic retrieval over cited evidence in a saved scan; never a CI gate."""

from __future__ import annotations

import re
from dataclasses import dataclass

MODEL = "minishlab/potion-base-8M"
REVISION = "bf8b056651a2c21b8d2565580b8569da283cab23"


@dataclass(frozen=True)
class Evidence:
    pointer: str
    location: str
    text: str
    check: str


def _text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join("".join(c if c.isprintable() else " " for c in value).split())


def action_description(action):
    name = _text(action.get("action"))
    excluded = action.get("excluded_actions", [])
    if not isinstance(excluded, list) or not all(isinstance(a, str) for a in excluded):
        raise ValueError("Expected a list of excluded IAM actions.")
    if excluded:
        name += " except " + ", ".join(sorted({_text(a) for a in excluded}))
    return name


def evidence_rows(scan: dict) -> list[Evidence]:
    if not isinstance(scan, dict) or not isinstance(scan.get("findings"), list):
        raise ValueError("Expected an ActionScope JSON report with a findings array.")
    rows = []
    for section in ("coverage_gaps", "findings", "exposure_paths", "finding_records"):
        items = scan.get(section, [])
        if not isinstance(items, list):
            raise ValueError(f"Expected an array at /{section}.")
        for i, item in enumerate(items):
            ptr = f"/{section}/{i}"
            if not isinstance(item, dict):
                raise ValueError(f"Expected an object at {ptr}.")
            location = (
                " / ".join(
                    filter(
                        None,
                        (
                            _text(item.get("workflow_file")),
                            _text(item.get("job_name")),
                        ),
                    )
                )
                or "(scan-wide)"
            )
            if section == "coverage_gaps":
                fact = f"Coverage gap: {_text(item.get('description'))}"
                check = "Inspect the missing evidence before relying on this scan."
            elif section == "findings":
                status = _text(item.get("risk_status")) or "unknown"
                role = _text(item.get("role_arn")) or "no resolved role"
                source = _text(item.get("policy_source")) or "unknown"
                fact = f"AWS credential binding: {role}. Policy: {source} ({status})."
                check = (
                    "Check the role and policy against the deployment configuration."
                )
                if status == "unknown":
                    fact += " AWS permissions could not be determined."
                actions = item.get("actions", [])
                if not isinstance(actions, list):
                    raise ValueError(f"Expected an array at {ptr}/actions.")
                for j, action in enumerate(actions):
                    if not isinstance(action, dict) or not _text(action.get("action")):
                        raise ValueError(f"Invalid action at {ptr}/actions/{j}.")
                    name = action_description(action)
                    resource = _text(action.get("resource")) or "unspecified"
                    rows.append(
                        Evidence(
                            f"{ptr}/actions/{j}",
                            location,
                            f"Policy record for {role}: {name}; resource: {resource}.",
                            "Review source policy conditions and denies.",
                        )
                    )
            elif section == "exposure_paths":
                ref = _text(item.get("action_ref"))
                fact = f"Workflow dependency {ref} and AWS credentials in the same job."
                check = (
                    "Review the dependency and credential step ordering in this job."
                )
            else:
                rule = _text(item.get("rule_id"))
                title = _text(item.get("title"))
                risk = _text(item.get("risk_level"))
                fact = f"{rule} ({risk}): {title}"
                check = "Inspect the referenced finding before changing the workflow."
            rows.append(Evidence(ptr, location, fact, check))
    return rows


def load_encoder(download: bool):
    try:
        from huggingface_hub import snapshot_download
        from model2vec import StaticModel
    except ImportError as exc:
        raise ValueError(
            "Install the optional AI dependencies: pip install '.[ai]' "
            "(from the ActionScope checkout)."
        ) from exc
    try:
        path = snapshot_download(
            MODEL,
            revision=REVISION,
            token=False,
            local_files_only=not download,
            allow_patterns=["model.safetensors", "tokenizer.json", "config.json"],
        )
        return StaticModel.from_pretrained(path, normalize=True)
    except Exception as exc:
        raise ValueError(
            "Could not load the pinned local model. Use --download-model "
            "once with network access to populate the cache."
        ) from exc


def exact_action_rows(question, rows):
    pattern = re.compile(
        r"(?<![\w:-])[a-z][a-z0-9-]*:[a-z][a-z0-9*]*(?![\w:*])", re.IGNORECASE
    )
    named = {name.lower() for name in pattern.findall(question)}
    if not named:
        return rows
    return [
        row
        for row in rows
        if named.intersection(name.lower() for name in pattern.findall(row.text))
    ]


def rank_rows(
    question: str, rows: list[Evidence], encoder, limit: int
) -> list[Evidence]:
    query = encoder.encode([question])[0]
    scores = []
    for start in range(0, len(rows), 256):
        batch = rows[start : start + 256]
        vectors = encoder.encode([f"{row.text} {row.location}" for row in batch])
        scores.extend(vectors @ query)
    indices = sorted(range(len(scores)), key=scores.__getitem__, reverse=True)
    return [rows[i] for i in indices[:limit] if scores[i] > 0]
