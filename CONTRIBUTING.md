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
