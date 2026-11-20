# ActionScope

Ask **what changed about a coding agent's access in this PR?** A local embedding model
matches your question to changed declarations and returns the old or new value,
the workflow, the job, and the source pointer. This development edition supports
direct Claude Code GitHub Actions steps. It is not a general code reviewer.

```sh
pip install .
actionscope review --demo "Was the API key removed?" --download-model
actionscope review "Which AWS role was added?" --repo /path/to/checkout --base-ref main
```

The first command installs from this checkout, not the published 0.x package.
The model weights are fetched only with explicit permission. After caching
them, omit `--download-model`. Questions, code and inference stay on your
machine. Without `--base-ref`, compare local HEAD with the working tree.
Use a trusted installation to inspect another repo; never install from a PR
you are reviewing.

**Example:** The bundled change removes an explicit Anthropic API-key input
and configures a role before running Claude with Bedrock. The reviewer can
show that the key **input** was removed. It cannot tell you that the secret
was revoked, that the role was successfully assumed, or that AWS permits only
model inference.

## Why this task

- [Anthropic documents Claude Code in CI](https://code.claude.com/docs/en/github-actions),
  including alternative credentials and Bedrock. This gives us a real change
  a maintainer has to reason about.
- [Wang et al.](https://arxiv.org/abs/2605.07135) studied 13,392 agentic
  workflows. Their results motivate inspecting agent configurations; they are
  not validation of ActionScope or evidence that maintainers want this CLI.
- [Copilot already reviews code](https://docs.github.com/en/copilot/concepts/agents/code-review)
  and [AWS already checks for new policy access](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_CheckNoNewAccess.html).
  This product instead retrieves evidence for a question about **a particular
  change to an agent job**. No cloud account or inference API key is needed.

## What the model does (and doesn't do)

The pinned Model2Vec encoder ranks changed fields by semantic similarity to
your question. Source revisions and field values come from parsed Git and YAML,
not generated text. Related is not the same as supported. No findings means
no supported changes were retrieved, not that the PR is safe. Unchanged access,
external policies, composite actions, and effective runtime permissions are
outside scope. There is no automated merge decision.

The AI edition exposes only `review`. The [0.x archive](legacy/v0/) is retained
as source history; its scanner, gates, action database, release automation,
and docs are not installed. Existing PyPI releases and Marketplace tags have
not been changed. This branch is a development preview.

See [contributing and evaluation](CONTRIBUTING.md) for how to test the model
rather than assume that AI improves a review.
