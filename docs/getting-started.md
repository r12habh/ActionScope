---
title: "ActionScope Quick Start"
description: >-
  Install ActionScope, run your first scan, and understand the output in
  under 5 minutes. No AWS credentials needed for static analysis.
---

# Quick Start

ActionScope runs in three modes. Pick whichever fits.

## 1. As a CLI (static analysis, no AWS creds)

```bash
pip install actionscope
cd /path/to/your/repo
actionscope scan .
```

Output looks like:

```text
ActionScope — Blast Radius Report
Path: /my-repo  |  Workflows: 4  |  Overall Risk: 🔴 CRITICAL

⛔ KNOWN COMPROMISED ACTIONS (1 found)
⛔ CRITICAL: actions-cool/issues-helper@v3 (issue-triage.yml)

deploy.yml → deploy → Configure AWS credentials
  AWS Role: arn:aws:iam::123456789012:role/github-deploy-role
  Auth: OIDC ✓

  ┌─────────────────────────────┬────────────────────┬──────────┐
  │ iam:PassRole                │ Permissions mgmt   │ 🔴 CRIT  │
  │ ec2:TerminateInstances      │ Write              │ 🟠 HIGH  │
  └─────────────────────────────┴────────────────────┴──────────┘

  🔴 Privilege Escalation Path: iam:PassRole on * — can escalate to any role
```

### Common flags

```bash
actionscope scan . --aws-verify        # fetch live IAM policies (read-only)
actionscope scan . --resolve-pins      # suggest full-SHA pins
actionscope scan . --fail-on high      # exit 1 if risk >= HIGH
actionscope scan . --output-format sarif --output-file results.sarif
actionscope scan . --output-format json --output-file results.json
actionscope scan . --save-state        # save state for delta tracking
actionscope scan . --load-state        # compare against previous state
```

See the [CLI Reference](cli-reference.md) for every flag.

## 2. As a GitHub Action (PR comments + Code Scanning)

Add this to `.github/workflows/security.yml`:

```yaml
name: ActionScope
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # for SARIF upload
  pull-requests: write     # for PR comments

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: r12habh/ActionScope@v0
        with:
          fail-on: high          # fail CI if HIGH or above
          comment-pr: true       # post findings as PR comment
          upload-sarif: true     # show in GitHub Security tab
          resolve-pins: true     # suggest SHA pins
```

This gives you:

- A PR comment on every pull request summarising the risk delta
- SARIF results in the Security tab as first-class Code Scanning alerts
- CI failure on HIGH/CRITICAL findings so issues block merges

## 3. With live AWS verification

For repos where the IAM policies aren't in the same repo, ActionScope can
hit the IAM API directly (read-only):

```bash
pip install "actionscope[aws]"
export AWS_PROFILE=my-profile
actionscope scan . --aws-verify
```

Required IAM permissions are minimal and documented at
[AWS Verification Permissions](aws-verify-permissions.md).

## What's next

- Browse the [Compromised Actions Database](compromised-actions-database.md)
  to check if any of your `uses:` references are known-malicious
- Read about [OIDC trust policy analysis](oidc-trust.md) for AWS deploy
  workflows
- Set up [SARIF and GitHub Code Scanning](sarif.md) for first-class alerts
