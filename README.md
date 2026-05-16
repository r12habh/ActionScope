# ActionScope

> Map the AWS blast radius of your GitHub Actions workflows.

[![PyPI](https://img.shields.io/pypi/v/actionscope)](https://pypi.org/project/actionscope/)
[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-ActionScope-blue?logo=github)](https://github.com/marketplace/actions/actionscope)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/r12habh/ActionScope/actions/workflows/ci.yml/badge.svg)](https://github.com/r12habh/ActionScope/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/r12habh/ActionScope/branch/main/graph/badge.svg)](https://codecov.io/gh/r12habh/ActionScope)

ActionScope reads your `.github/workflows/` files, Terraform IAM resources,
and inline JSON IAM policies, then tells you — in plain English — what your
CI/CD pipelines can actually do to your AWS environment.

**It answers the question no other tool answers:**
"If this workflow is compromised, what can an attacker do in AWS?"

## Install

```bash
pip install actionscope
```

## Quick Start

```bash
actionscope scan .
```

## Example Output

```
ActionScope — Blast Radius Report
Path: /my-repo  |  Workflows: 2  |  Overall Risk: 🔴 CRITICAL

deploy.yml → deploy → Configure AWS credentials
  AWS Role: arn:aws:iam::123456789012:role/github-deploy-role
  Auth: OIDC ✓

  ┌─────────────────────────────┬────────────────────┬──────────┐
  │ Action                      │ Access Level       │ Risk     │
  ├─────────────────────────────┼────────────────────┼──────────┤
  │ iam:PassRole                │ Permissions mgmt   │ 🔴 CRIT  │
  │ ec2:TerminateInstances      │ Write              │ 🟠 HIGH  │
  │ s3:GetObject                │ Read               │ 🟢 LOW   │
  └─────────────────────────────┴────────────────────┴──────────┘

  ⚠️  iam:PassRole on * — privilege escalation path exists
```

## Use as a GitHub Action

```yaml
- uses: r12habh/ActionScope@v0
  with:
    fail-on: high
    comment-pr: true
```

## What ActionScope Adds Beyond Existing Tools

| Capability | actionlint | zizmor | Scorecard | ActionScope |
|-----------|-----------|--------|-----------|-------------|
| Workflow syntax validation | ✅ | Partial | ❌ | Partial |
| Security pattern detection | ❌ | ✅ | ✅ | ✅ |
| GITHUB_TOKEN review | ❌ | ✅ | ✅ | ✅ |
| Unpinned actions detection | ❌ | ✅ | ✅ | ✅ |
| AWS credential source detection | ❌ | ❌ | ❌ | ✅ |
| Workflow → IAM role correlation | ❌ | ❌ | ❌ | ✅ |
| Blast-radius plain-English report | ❌ | ❌ | ❌ | ✅ |
| SARIF / GitHub Security tab | ❌ | ✅ | ✅ | ✅ |

## How It Works

ActionScope performs **static analysis by default** — it never sends your code
to any external service unless you explicitly enable live AWS verification.

1. Finds all `.github/workflows/*.yml` files
2. Extracts AWS role ARNs and GITHUB_TOKEN permission declarations
3. Finds matching IAM policies in Terraform or JSON files in your repo
4. Classifies each IAM action by risk using the
   [policy-sentry](https://github.com/salesforce/policy_sentry) database
5. Outputs a plain-English blast radius report

### What If My Policies Aren't in the Repo?

```
ℹ️  Policy not found in repo for role: arn:aws:iam::123456:role/ci-deploy
💡  Run with --aws-verify to fetch live policies from AWS
```

`--aws-verify` uses read-only IAM API calls to fetch the real attached
policies for any role ARN found in your workflows. See
[`docs/aws-verify-permissions.md`](docs/aws-verify-permissions.md) for the
exact AWS permissions required.

## Research

ActionScope is backed by a public measurement study of 493 GitHub repositories
and 3,981 workflow files that use AWS via GitHub Actions.

Key findings from May 2026:
- **95.5%** use at least one unpinned action (the supply-chain attack surface)
- **58.2%** use static AWS access keys instead of OIDC
- **44.0%** expose role ARNs directly in workflow files
- **8.1%** use `pull_request_target` with write-capable permissions

→ [Full research findings](research/FINDINGS.md) | [Scanner and data](research/)

## Built By

Rishabh Singh — AWS Security Engineer.
[GitHub](https://github.com/r12habh)
