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

## Merged PR replay

With cached model weights, run the commands below from the development checkout.
The first run downloads ten historical workflow files from immutable upstream
commits into a local cache. The second reads that cache only. Neither runs
the workflows nor uses a GitHub token.

```sh
HF_HUB_OFFLINE=1 python tests/replay_merged_prs.py --fetch --cache .venv/replay-cache
HF_HUB_OFFLINE=1 python tests/replay_merged_prs.py --cache .venv/replay-cache
```

One selected workflow file per PR is compared against the merge commit's first
parent, not the full PR. A positive case passes only if the top-ranked group
contains the labeled fact fragments, change directions and cited source suffixes.
The checkout-only control requires a recognized agent and no changed records.

| Upstream change | Outcome before calibration | Outcome after |
| --- | --- | --- |
| [Auth migration](https://github.com/anthropics/claude-code-action/pull/1344) | Removed key visible; no replacement | Removed key and configured federation inputs |
| [Fork condition](https://github.com/anthropics/claude-code-action/pull/1655) | Opaque digest | Exact same-repository condition described |
| [PR activity filter](https://github.com/anthropics/claude-code-action/pull/691) | Opaque digest | Old activity list and new opened-only list |
| [Checkout version](https://github.com/anthropics/claude-code-action/pull/862) | Correctly no change | Correctly no change |

Both the model and keyword baseline passed 1/4 at commit `397f5db` and 4/4
after parser changes. There was only one candidate field in each positive case:
these are **evidence coverage regressions**, not meaningful ranking wins.
An additional [SDK triage migration](https://github.com/anthropics/claude-agent-sdk-python/pull/884)
was tested without tuning on it: both methods selected the Claude authentication
input from eight changed fields. The base used a different, unsupported action;
the result describes the head step's configured input, not newly granted access.

All questions were author-written after inspecting the diffs. These five
selected PRs from one organization are not a prevalence sample, a blind user
study or proof that AI saves time. The remaining test is whether maintainers
make better or faster decisions on their own changes.
