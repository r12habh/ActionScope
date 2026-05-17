# ActionScope

> Map the AWS blast radius of your GitHub Actions workflows.

[![PyPI](https://img.shields.io/pypi/v/actionscope)](https://pypi.org/project/actionscope/)
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

ActionScope performs **static analysis only** — it never sends your code to
any external service.

1. Finds all `.github/workflows/*.yml` files
2. Extracts AWS role ARNs and GITHUB_TOKEN permission declarations
3. Finds matching IAM policies in Terraform or JSON files in your repo
4. Classifies each IAM action by risk using the
   [policy-sentry](https://github.com/salesforce/policy_sentry) database
5. Outputs a plain-English blast radius report

### What If My Policies Aren't in the Repo?

```
ℹ️  Policy not found in repo for role: arn:aws:iam::123456:role/ci-deploy
💡  Run with --aws-verify to fetch live policies from AWS (coming in v1.0)
```

In v1.0, `--aws-verify` will use read-only AWS API calls to fetch the real
attached policies for any role ARN found in your workflows.

## Public Research

ActionScope includes a reproducible public-data research scaffold for analyzing
workflow-level AWS security patterns across public GitHub repositories. See
[`research/`](research/) for the scanner, methodology, and anonymized findings
template.

## Built By

Rishabh Singh.
[GitHub](https://github.com/r12habh)
