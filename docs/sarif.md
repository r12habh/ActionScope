# GitHub Code Scanning Integration (SARIF)

ActionScope can upload findings to GitHub's Security tab via SARIF.

## Quick Setup

```yaml
- uses: r12habh/ActionScope@v0
  with:
    upload-sarif: true
    fail-on: high
```

This posts findings to the GitHub Security → Code Scanning Alerts tab.

## What Gets Reported

| Rule ID | Finding | Severity |
|---------|---------|----------|
| AS001 | AWS blast radius detected | Error/Warning |
| AS002 | Privilege escalation path | Error |
| AS003 | iam:PassRole detected | Error |
| AS004 | Dangerous GITHUB_TOKEN permission | Warning |
| AS005 | Static AWS credentials used | Warning |
| AS006 | Unpinned GitHub Action | Warning |

## Required Permissions

The workflow using ActionScope must have:

```yaml
permissions:
  security-events: write  # required for SARIF upload
  contents: read
```
