"""Replay merged upstream changes, inspecting a single pinned YAML per revision.

Run with --fetch once. The default reads only cached blobs and model weights.
"""

import argparse
import json
import re
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.request import urlopen

from actionscope.evidence import compare, snapshot
from actionscope.retrieval import load_encoder, rank_rows
from actionscope.review import _changes

REPO = "anthropics/claude-code-action"
FILE = Path(".github/workflows/claude-review.yml")
# Required fragments in the SAME top-ranked group, with side and source.
CASES = [
    (
        1344,
        "bbfaf8e1ffe3e688f7ab65ceee78de241e24a238",
        "4257c8e0591343e1130ae550a49ae34dd17c7060",
        "What authentication replaced the review bot's long-lived key?",
        [
            ("removed", "anthropic_api_key", "/with/anthropic_api_key"),
            ("added", "federation", "/with/anthropic_federation_rule_id"),
        ],
    ),
    (
        1655,
        "b49813d0e7f26cce63155bbb0695d44320998e50",
        "a2cac87e2759e8936c7e05edb8001b9298a2b5cb",
        "Which pull requests does the new job condition select?",
        [
            ("added", "same repository", "/jobs/review/if"),
        ],
    ),
    (
        691,
        "11571151c420f520bf8a4ed8be81727df71abb07",
        "4318310481bb86de0d1f1c864f4474aa3a50f18c",
        "When does a pull request start the review now?",
        [
            ("added", "opened", "/on/pull_request/types"),
            ("removed", "synchronize", "/on/pull_request/types"),
        ],
    ),
    (
        862,
        "0c704179b5caf6267b7002268193a23bb73652e3",
        "ba45bb9506c90614f565e1e1c183ea099426a2a3",
        "What changed in the agent's declared access?",
        [],
    ),
]


def read_snapshot(cache, repo, file, revision, fetch):
    blob = cache / f"{revision}-{file.name}"
    if not blob.exists():
        if not fetch:
            raise SystemExit(f"Missing {blob.name}; use --fetch first.")
        url = f"https://raw.githubusercontent.com/{repo}/{revision}/{file.as_posix()}"
        with urlopen(url, timeout=15) as response:
            data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("Workflow exceeds reviewer input limit.")
        blob.write_bytes(data)
    with TemporaryDirectory() as tmp:
        path = Path(tmp) / file
        path.parent.mkdir(parents=True)
        shutil.copyfile(blob, path)
        return snapshot(Path(tmp))


def answers(facts, expected):
    if not expected:
        return not facts
    for status, term, suffix in expected:
        side = "head_source" if status == "added" else "base_source"
        if not any(
            f["status"] == status
            and term in (f["field"] + " " + f["value"])
            and f[side].endswith(suffix)
            for f in facts
        ):
            return False
    return True


def run(cache, fetch):
    cache.mkdir(parents=True, exist_ok=True)
    encoder = load_encoder(False)
    cases = [(REPO, FILE, *case) for case in CASES]
    # Transfer case chosen after calibration. Do not tune on its outcome.
    cases.append(
        (
            "anthropics/claude-agent-sdk-python",
            Path(".github/workflows/claude-issue-triage.yml"),
            884,
            "9ee52dfd5c7372552fdab39b08a9777580e636dc",
            "3600dd02d58da38c7957ed8978c59dc1d1b17840",
            "How does the triage bot authenticate itself to Anthropic?",
            [("added", "anthropic_api_key", "/with/anthropic_api_key")],
        )
    )
    for repo, file, pr, base, head, question, expected in cases:
        result = compare(
            *[read_snapshot(cache, repo, file, sha, fetch) for sha in (base, head)]
        )
        rows, sources = _changes(result)
        words = set(re.findall("[a-z0-9]+", question.lower()))
        keyword = sorted(
            rows,
            reverse=True,
            key=lambda r: len(words & set(re.findall("[a-z0-9]+", r.text.lower()))),
        )
        model = rank_rows(question, rows, encoder, 1) if rows else []
        outcome = {"repo": repo, "pr": pr, "changed_fields": len(rows)}
        for label, ranked in [("keyword", keyword), ("model", model)]:
            best = ranked[0] if ranked else None
            outcome[label] = {
                "field": best.check if best else None,
                "pass": (
                    bool(result["agents"])
                    and (
                        answers(sources[best.pointer], expected)
                        if best
                        else not expected and not rows
                    )
                ),
            }
        print(json.dumps(outcome))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    run(args.cache, args.fetch)
