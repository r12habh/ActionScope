# Reusable Workflow Inspection

GitHub Actions jobs can delegate their entire implementation to another
workflow:

```yaml
jobs:
  deploy:
    uses: acme/platform/.github/workflows/deploy.yml@v1
```

The called workflow runs in the caller's security context. It can receive
secrets, use the caller's `GITHUB_TOKEN`, configure cloud credentials, and
invoke other actions. Scanning only the caller file can therefore understate
the caller repository's exposure.

## What ActionScope Does

ActionScope builds a call graph from every `jobs.<job_id>.uses` reference.

- Local calls such as `./.github/workflows/deploy.yml` are loaded from the
  checkout and followed recursively.
- External calls are classified as full SHA, short SHA, tag, or branch refs.
- Mutable external refs appear in the existing unpinned-action findings.
- External workflow contents are fetched and analyzed only when a GitHub token
  is supplied.
- Cycles and repeated references are safe: each unique workflow is fetched at
  most once.
- Traversal stops at GitHub's documented limits of 10 nesting levels and 50
  unique called workflows.

Findings retain both sides of the call. Terminal, Markdown, and JSON reports
show the caller job and reusable target. SARIF findings discovered inside an
external workflow point to the caller file in the scanned repository and name
the external source in the message.

## Local Workflows

No extra option is needed:

```bash
actionscope scan .
```

ActionScope scans local reusable workflows without network access. A local
workflow that is already part of the repository-wide workflow set is not
analyzed twice.

## External Workflows

Supply a GitHub token to inspect external reusable workflow contents:

```bash
export GITHUB_TOKEN=ghp_your_token
actionscope scan .

# Equivalent explicit option
actionscope scan . --github-token "$GITHUB_TOKEN"
```

For public repositories, a token with public-repository read access is enough.
For private or internal reusable-workflow repositories, the token must be able
to read the repository contents and the repository's Actions access policy
must allow the caller.

The Marketplace Action passes its `github-token` input to ActionScope. Its
default is the current workflow token:

```yaml
- uses: r12habh/ActionScope@v0
  with:
    github-token: ${{ github.token }}
```

## No-Token Behavior

Reusable-workflow inspection does not make anonymous network requests. Without
a token, an external call is reported as `no_token`:

```text
Reusable Workflows (1 call(s))
caller.yml -> deploy -> acme/platform/.github/workflows/deploy.yml@v1
Status: no token | Pin: tag | Depth: 1
```

This is a coverage limitation, not a clean result. JSON includes the same
status under `reusable_workflows`, and SARIF emits AS015 so CI consumers can
see that delegated code was not inspected.

## Pin External Calls

GitHub allows reusable workflows to be referenced by branch, tag, or commit
SHA. A full 40-character commit SHA is the immutable option:

```yaml
jobs:
  deploy:
    uses: acme/platform/.github/workflows/deploy.yml@0123456789abcdef0123456789abcdef01234567
```

Tags, branches, and short SHAs are reported as mutable. This is separate from
whether ActionScope could fetch the workflow: a fetched `@v1` call is still an
unpinned supply-chain risk.

## Status Values

| Status | Meaning |
|--------|---------|
| `inspected` | The target YAML was loaded and analyzed. |
| `no_token` | External target was not fetched because no token was supplied. |
| `fetch_error` | GitHub returned an error or the response could not be parsed. |
| `load_error` | A local target was missing or invalid. |
| `invalid_reference` | The `uses:` value was dynamic or not valid reusable-workflow syntax. |
| `cycle` | A recursive cycle was detected; the target was not scanned again. |
| `depth_limit` | The call graph exceeded 10 levels. |
| `workflow_limit` | The graph exceeded 50 unique called workflows. |

## Current Boundary

ActionScope fetches workflow YAML, not the external repository's Terraform or
IAM policy files. It can detect credentials and workflow-layer risks inside a
called workflow, but static IAM-role correlation still depends on policy
evidence in the repository being scanned or on `--aws-verify`.
