# Contributing

Start with a realistic question about a proposed change to a coding-agent
workflow. Use synthetic base/head YAML, mark the exact facts that support
the answer, and include one thing the reviewer cannot know. Do not contribute
credentials or private incident details. Keep deterministic evidence extraction
separate from ranking. Do not train on a held-out evaluation set.

```sh
pip install -e '.[dev]'
actionscope review --demo --download-model
HF_HUB_OFFLINE=1 ACTIONSCOPE_TEST_LOCAL_MODEL=1 pytest
ruff check src tests
python -m build
```

A retrieval smoke test is not a maintainer study. Compare the same inputs
against keyword retrieval and ordinary Git diff; record false claims,
time to a correct decision and repeat use with consenting maintainers.
See [the evaluation issue](https://github.com/r12habh/ActionScope/issues/173).

Run `HF_HUB_OFFLINE=1 python tests/evaluate_retrieval.py` for the small local
comparison. On the four checked-in synthetic changes, the pinned model put
the expected field first in 4/4; unstemmed keyword overlap did so in 3/4.
The difference was the question about issue permissions. Cases and labels
are author-written; no maintainer time, real-world accuracy, or comparison
against a coding assistant was measured.
