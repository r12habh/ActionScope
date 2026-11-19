# Review the access of a coding agent

Use two **local repository directories**, not refs or URLs. Compare a trusted
base checkout with the proposed checkout as data. Install ActionScope from
trusted source, never from an untrusted PR. No workflow, action, model output,
or repository script is executed by the review command.

```sh
pip install -e '.[ai]'
actionscope agent-review --base examples/agent-review/base \
    --head examples/agent-review/head --intent 'Review pull requests via Bedrock' \
    --download-model
```

This development command is not in the existing PyPI release. The example is
synthetic. It changes the review job from a direct API key to Bedrock and adds
an OIDC token permission and a named role. **The checkout does not establish
what that role can do in AWS.** A permission to request a token does not prove
that any role trusts the token.

## Read the report

Each fact has a status and base or head source: a relative workflow filename
plus a JSON Pointer into the parsed YAML, or a pointer into a supplied report.
Unchanged records are retained. A job or file rename appears as removal plus
addition, not evidence of a granted/revoked permission. Use step IDs for
repeated agent calls; unnamed calls match by ordinal within the job.

To include **policy records**, generate fresh reports from both snapshots:

```sh
actionscope scan "$BASE" --offline -f json -o base.json
actionscope scan "$HEAD" --offline -f json -o head.json
actionscope agent-review --base "$BASE" --head "$HEAD" \
    --base-report base.json --head-report head.json --format json
```

Reports must correspond to those checkout paths; paths alone do not attest
to revision or freshness. The join requires one matching workflow, job and
literal role ARN. Ambiguous, dynamic and missing matches remain unknown.
Even a matched policy record does not evaluate effective AWS access.

## How AI is used

With `--intent`, a pinned [Model2Vec embedding model](https://huggingface.co/minishlab/potion-base-8M)
ranks added facts and their predefined review questions against the maintainer's
task on your CPU. Each selected question links to an actual diff record. No
prompt or scan is uploaded; model files are downloaded only on explicit opt-in.
The ranker is not an IAM simulator or a merge gate. It does not change the
factual diff. Without `--intent` no model or extra dependency is required.
Use `actionscope explain scan.json "Which job has unpinned actions?"` to search
a single saved scan. Results are nearest records, not generated answers.

To rerun the two real-model retrieval smoke tests after caching the weights,
install pytest in the same environment and run
`HF_HUB_OFFLINE=1 ACTIONSCOPE_TEST_LOCAL_MODEL=1 python -m pytest tests/test_agent_review.py`.
The two questions use the same synthetic change. They check wiring and ranking
regressions; they do not establish useful rankings on real reviews.

## CI and limitations

The `agent-review/` composite action accepts two already-checked-out
directories (`base`, `head`), optional `intent` and `download-model`; the
`report-path` output points to JSON on the runner. Use a trusted, reviewed
ActionScope revision. Use a read-only token and do not execute either checkout
or install its dependencies. The action installs ActionScope itself into a
temporary virtual environment; dependency installation needs network or a mirror.
Reports may contain role, policy and workflow identifiers. Do not post them
publicly without review.

Only direct `anthropics/claude-code-action@...` calls in top-level workflow YAML
are recognized. Composite calls, reusable workflows, parallel wrappers, shell
agents, runner credentials, env-only credentials, external agent settings and
runtime behavior are not resolved. A preceding setup is configuration, not
proof its condition passed. Event filters and selected settings can be compared
as opaque digests; their semantics are not evaluated. No matches is not a clean
bill of health. Malformed or unsupported YAML aliases fail the comparison rather
than reporting missing jobs as removals.
