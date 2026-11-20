"""Local semantic retrieval over cited changes; never an authorization verdict."""

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


def load_encoder(download: bool):
    try:
        from huggingface_hub import snapshot_download
        from model2vec import StaticModel
    except ImportError as exc:
        raise ValueError(
            "Install ActionScope with its required model dependencies (pip install .)."
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
