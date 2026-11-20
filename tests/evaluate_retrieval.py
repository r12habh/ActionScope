"""Run: HF_HUB_OFFLINE=1 python tests/evaluate_retrieval.py (cached weights)."""

import json
import re
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from actionscope.evidence import compare, snapshot
from actionscope.retrieval import load_encoder, rank_rows
from actionscope.review import _changes


def evaluate():
    cases = json.loads(Path(__file__).with_name("access_cases.json").read_text())
    encoder = load_encoder(False)
    for c in cases:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / ".github/workflows"
            directory.mkdir(parents=True)
            sides = []
            for side in ("base", "head"):
                job = {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"uses": "anthropics/claude-code-action@v1"}],
                    **c[side],
                }
                (directory / "review.yml").write_text(
                    yaml.safe_dump({"on": "pull_request", "jobs": {"review": job}})
                )
                sides.append(snapshot(root))
            rows, _ = _changes(compare(*sides))

        def words(text):
            return set(re.findall(r"[a-z0-9]+", text.lower()))

        tokens = words(c["q"])
        lexical = max(rows, key=lambda r: len(words(r.text) & tokens)).check
        top = rank_rows(c["q"], rows, encoder, 1)
        yield dict(
            question=c["q"],
            expected=c["field"],
            keyword=lexical,
            model=top[0].check if top else None,
        )


if __name__ == "__main__":
    for result in evaluate():
        print(json.dumps(result))
