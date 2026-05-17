# AI Code Review Setup

ActionScope uses GitHub Actions, Codex review, and CodeRabbit as independent
review layers for pull requests.

## CodeRabbit

CodeRabbit is configured with `.coderabbit.yaml` in the repository root. It is
the preferred additional AI reviewer because CodeRabbit's Open Source plan is
free for public open-source repositories and does not require committing any
API keys or secrets.

Install it from the GitHub Marketplace:

<https://github.com/marketplace/coderabbitai>

Recommended setup:

1. Click **Set up** on the Marketplace page.
2. Select **Only select repositories**.
3. Choose `r12habh/ActionScope`.
4. Confirm that the selected plan is the free Open Source plan.
5. Open a pull request or push a new commit to an existing pull request.

CodeRabbit will automatically detect `.coderabbit.yaml` from the pull request
branch and review PRs after the GitHub App is installed.

## Why CodeRabbit

- Free for public open-source repositories.
- Runs as a GitHub App, so no repository secret is needed.
- Supports repository-local YAML configuration.
- Can provide PR summaries, inline review comments, and chat follow-up.

## Configuration Intent

The current configuration:

- keeps reviews automatic for non-draft PRs;
- avoids request-changes enforcement so it cannot block merges on its own;
- excludes build, coverage, and large research-output files;
- gives security-focused instructions for parsers, analyzers, workflows, and
  research scripts;
- restricts public chat auto-replies to repository/org members where supported.
