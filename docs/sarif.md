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
| AS007 | Broad GitHub OIDC subject or unsafe condition | Error/Warning |
| AS008 | Missing GitHub OIDC `sub` condition | Error |
| AS009 | Script injection risk | Error/Warning |
| AS010 | Artifact poisoning risk | Error/Warning |
| AS011 | AI agent prompt injection surface | Error/Warning |
| AS012 | AI agent running with AWS access | Error/Warning |
| AS013 | Known-compromised action | Error |
| AS014 | GitHub Environment OIDC hardening issue | Warning |
| AS015 | Reusable workflow was not inspected | Note |

Findings discovered inside an authenticated external reusable workflow point
to the caller workflow in the scanned repository. The SARIF message names the
external `owner/repo/.github/workflows/file@ref` source.

## Required Permissions

The workflow using ActionScope must have:

```yaml
permissions:
  security-events: write  # required for SARIF upload
  contents: read
```
