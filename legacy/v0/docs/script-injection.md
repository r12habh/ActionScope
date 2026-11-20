# GitHub Actions Script Injection

GitHub Actions workflows often copy pull request, issue, or comment text into
shell commands. Script injection happens when attacker-controlled GitHub context
is interpolated directly into a `run:` block before the shell starts.

ActionScope's script injection detector flags direct use of untrusted GitHub
contexts in workflow shell steps and recommends moving the value through an
environment variable first.

## What Script Injection Looks Like

A pull request title can contain shell syntax. In this unsafe workflow, GitHub
expands `${{ github.event.pull_request.title }}` into the script before Bash
runs it:

```yaml
name: unsafe-pr-title
on: pull_request

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Echo PR title
        run: |
          echo "PR title: ${{ github.event.pull_request.title }}"
```

If the title contains command substitution or shell metacharacters, the final
script may execute more than the workflow author intended.

## Safer Pattern: Use `env:` First

Pass untrusted GitHub context through `env:` and then reference the shell
variable from the `run:` block. Quote the variable when using it.

```yaml
name: safe-pr-title
on: pull_request

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Echo PR title
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "PR title: $PR_TITLE"
```

This keeps the untrusted value as data instead of splicing it into the shell
program text.

## Untrusted Events and Contexts

ActionScope treats these GitHub contexts as untrusted when they appear directly
inside a `run:` command:

- Pull request fields such as `github.event.pull_request.title`,
  `github.event.pull_request.body`, `github.event.pull_request.head.ref`,
  `github.event.pull_request.head.label`, and `github.head_ref`
- Issue and comment text such as `github.event.issue.title`,
  `github.event.issue.body`, `github.event.comment.body`,
  `github.event.review.body`, and `github.event.review_comment.body`
- Push metadata such as `github.event.commits`,
  `github.event.head_commit.message`, `github.event.head_commit.author.email`,
  `github.event.head_commit.author.name`, `github.event.pusher.email`, and
  `github.event.pusher.name`
- Discussion content such as `github.event.discussion.title` and
  `github.event.discussion.body`
- Page-build data from `github.event.pages`

Findings are higher severity for high-risk workflow triggers such as
`pull_request_target` and `workflow_run`, because those runs can combine
attacker-controlled content with a more privileged execution context.

## Running the Detector

Run ActionScope from the repository root:

```bash
actionscope scan .
```

ActionScope scans `.github/workflows/*.yml` and `.github/workflows/*.yaml`, then
reports any `run:` steps that directly interpolate the untrusted contexts above.

## How Findings Appear

In the terminal report, script injection findings are grouped under the script
injection section with the workflow file, job, step name, untrusted expression,
risk level, and a short run-command snippet.

Markdown and JSON reports include the same finding details so they can be
reviewed in CI artifacts or consumed by automation.

SARIF output uses rule `AS009` for script injection findings, which lets GitHub
code scanning group these alerts separately from compromised action, OIDC trust,
and IAM findings.

## Remediation Checklist

- Do not place `${{ github.event.* }}` attacker-controlled values directly in
  `run:` blocks.
- Assign untrusted values to `env:` variables first.
- Quote shell variables when expanding them.
- Avoid running untrusted pull request content in privileged triggers unless the
  workflow has additional review or allowlist gates.
