# ActionScope

> Map the AWS blast radius of your GitHub Actions workflows.

[![PyPI](https://img.shields.io/pypi/v/actionscope)](https://pypi.org/project/actionscope/)
[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-ActionScope-blue?logo=github)](https://github.com/marketplace/actions/actionscope)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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

## Public Research

ActionScope includes reproducible public-data research from 493 public GitHub
repositories and 3,981 workflow files that use AWS from GitHub Actions. See
[`research/FINDINGS.md`](research/FINDINGS.md) for the findings and
[`research/`](research/) for the scanner and methodology.

## Built By

Rishabh Singh — AWS Security Engineer.
[GitHub](https://github.com/r12habh)
