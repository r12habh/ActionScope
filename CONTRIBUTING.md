# Contributing to ActionScope

## Adding a New IAM Risk Rule

The easiest contribution is adding IAM action risk classifications.
See `actionscope/analyzers/iam_risk.py` — the `ALWAYS_CRITICAL` set.

To add a new always-critical action:

1. Add it to the `ALWAYS_CRITICAL` set in iam_risk.py
2. Add a test in tests/test_iam_risk.py
3. Open a PR

## Adding a New Workflow Parser Pattern

ActionScope currently detects `aws-actions/configure-aws-credentials`.
To add support for another credential provider (e.g. Google Cloud):

1. Add a parser function in `actionscope/parsers/workflow.py`
2. Add a new CredentialSource type in models.py if needed
3. Add test fixtures in tests/fixtures/workflows/
4. Open a PR

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## AI Code Review

ActionScope uses CodeRabbit as an additional AI pull request reviewer for this
public open-source repository. The repository-local configuration lives in
`.coderabbit.yaml`.

See `docs/ai-code-review.md` for setup notes and the Marketplace install link.

## Development with uv

You can use `uv` for faster local setup while keeping `pyproject.toml` as the
source of truth:

```bash
uv venv
uv pip install -e ".[dev]"
uv run pytest tests/ -v
uv run actionscope scan tests/fixtures/demo_repo
```

To generate a reproducible development lockfile:

```bash
uv lock --extra dev --extra aws --extra research
```

Commit `uv.lock` only when it is intentionally refreshed. The published package
and GitHub Action should continue to use standard `pip install actionscope` for
maximum compatibility.

## Self-Scan

ActionScope scans itself in CI. This repo intentionally uses minimal
permissions (contents: read only) to demonstrate good practice.

## Merging Pull Requests

**Every PR — including dependabot, docs-only changes, and your own — must be
up to date with `main` before it is merged.** This is repo policy regardless
of whether GitHub branch protection enforces it.

### Why

CI ran against the PR's base commit, not against current `main`. If `main`
has moved since CI ran, the merge can silently introduce regressions that
neither CI nor the original review caught — overlapping diffs, removed APIs
that the PR still references, test fixtures the PR depends on that another
PR just deleted, version pins that conflict with a sibling dependabot PR, and
so on.

A clean `git merge` (status `MERGEABLE`) is necessary but not sufficient.
"Merges cleanly" only proves there are no textual conflicts, not that the
combined result still works. Re-running CI on the PR after rebasing is what
proves it.

### Before merging — every time

1. Check the PR's merge state. If GitHub reports `BEHIND`, the branch is
   stale relative to `main`.
2. Bring it up to date. Pick whichever applies:
   - **GitHub UI:** click the "Update branch" button on the PR page.
   - **Dependabot PR:** comment `@dependabot rebase` (or `@dependabot
     recreate` if the rebase fails). Dependabot will push a fresh branch.
   - **Human-authored PR:** ask the contributor to rebase, or rebase it
     yourself if you have push access to their branch:
     ```bash
     gh pr checkout <number>
     git rebase origin/main
     git push --force-with-lease
     ```
3. Wait for CI to finish on the rebased branch. Re-run any required checks
   that did not auto-trigger.
4. Confirm all required checks are green on the rebased commit, not on the
   stale commit.
5. Merge.

### Batches (multiple PRs at once)

When merging several PRs back-to-back (typical for dependabot weekend
batches), repeat the up-to-date step **for each PR after every preceding
merge**. PR #2 was up to date five minutes ago; the moment you merge PR #1
it goes stale. Rebase #2, wait for CI, then merge.

If two PRs in a batch actually conflict, the rebase will surface it. That
is the point — better a five-minute rebase than a broken `main`.

### Admin overrides

`gh pr merge --admin --squash` bypasses the `BEHIND` block on
branch-protected repositories. Using `--admin` to skip the rebase step is a
deliberate decision to accept the risk; it should be reserved for cases
where you have manually verified the combined result is safe (for example,
two dependabot PRs that touch entirely different files). Document the
reason in the PR or the commit message when you do this.

### Why this is more than dependabot hygiene

The same hazard applies to any PR that sat in review for more than a few
hours, especially when several PRs are open at once. Treat "up to date with
main" as a precondition for merging anything, not a special case for
dependabot.
