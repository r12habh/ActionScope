---
title: "ActionScope — Map the AWS Blast Radius of GitHub Actions Workflows"
description: >-
  Static-analysis CLI and GitHub Action that detects known-compromised
  actions, OIDC trust misconfigurations, script injection, IAM privilege
  escalation paths, and unpinned actions in GitHub Actions workflows.
---

# ActionScope

> **If a GitHub Actions workflow in your repo is compromised, what can an
> attacker actually do in your AWS account?**

ActionScope reads your `.github/workflows/` files, Terraform and JSON IAM
policies, and tells you — in plain English — what your CI/CD pipeline can
actually do in AWS, and which workflow-layer attack surfaces it exposes.

[Get started in 30 seconds :material-arrow-right:](getting-started.md){ .md-button .md-button--primary }
[Install from PyPI :material-package:](https://pypi.org/project/actionscope/){ .md-button }

## What it catches

<div class="grid cards" markdown>

-   :material-skull-crossbones-outline:{ .lg .middle } **Known-compromised actions**

    ---

    Curated database of compromised actions — `tj-actions/changed-files`,
    `actions-cool/issues-helper`, `actions-cool/maintain-one-comment`,
    `aquasecurity/trivy-action`. Mutable-tag references produce a CRITICAL
    finding with the advisory URL.

    [Browse the database :material-arrow-right:](compromised-actions-database.md)

-   :material-shield-key:{ .lg .middle } **OIDC trust misconfigurations**

    ---

    Wildcard org subjects, missing `sub`/`aud` conditions, branch scoping
    instead of environment scoping. SARIF rule AS007/AS008.

    [Read the guide :material-arrow-right:](oidc-trust.md)

-   :material-code-tags-check:{ .lg .middle } **Script injection / pwn requests**

    ---

    Detects direct interpolation of attacker-controlled GitHub event fields
    (`github.event.pull_request.title`, `github.event.issue.body`, …) into
    `run:` blocks — the pattern behind the April 2026 prt-scan attack.

-   :material-aws:{ .lg .middle } **IAM blast radius**

    ---

    Extracts every `aws-actions/configure-aws-credentials` role ARN,
    correlates with Terraform or JSON IAM policies in your repo, and
    classifies the resulting blast radius. Optionally verifies live via
    read-only IAM API calls.

    [AWS verification setup :material-arrow-right:](aws-verify-permissions.md)

-   :material-package-variant-closed-remove:{ .lg .middle } **Unpinned actions**

    ---

    Distinguishes full-SHA pins (safe) from short SHAs (still mutable),
    tags, and branches. `--resolve-pins` suggests current SHAs via the
    GitHub API.

-   :material-file-document-multiple:{ .lg .middle } **SARIF for Code Scanning**

    ---

    Native SARIF 2.1.0 output with 14 rules (AS001-AS014). Upload to the
    GitHub Security tab for first-class alerts.

    [SARIF integration :material-arrow-right:](sarif.md)

</div>

## How it's different from `actionlint`, `zizmor`, `Scorecard`, `Checkov`

Most workflow-security tools answer **one side** of the boundary:

- `actionlint` — is this workflow YAML valid?
- `zizmor` / `Scorecard` — does this workflow have dangerous patterns?
- `Checkov` — are these IAM policies misconfigured (in isolation)?

ActionScope crosses the boundary. It ties **a specific workflow** to **a
specific IAM role** to **a specific blast radius** and emits a single,
correlated report.

## 30-second install

```bash
pip install actionscope
actionscope scan .                  # static analysis, no AWS creds needed
actionscope scan . --aws-verify     # live IAM verification (read-only)
actionscope scan . --resolve-pins   # suggest full-SHA pins for unpinned actions
```

Or use it as a GitHub Action:

```yaml
- uses: r12habh/ActionScope@v0
  with:
    fail-on: high
    comment-pr: true
    upload-sarif: true
```

## Research-backed

ActionScope ships with findings from a public study of **493 GitHub
repositories** and **3,981 AWS-enabled workflows**:

- **95.5%** use at least one external action not pinned to a full SHA
- **58.2%** use static AWS access keys instead of OIDC
- **44.0%** expose role ARNs directly in workflow YAML
- **8.1%** combine `pull_request_target` with write-capable token
  permissions — the pattern behind the April 2026 prt-scan attack

[Full research findings](https://github.com/r12habh/ActionScope/blob/main/research/FINDINGS.md){ .md-button }
