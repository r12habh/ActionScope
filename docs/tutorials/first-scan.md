---
title: "Your First ActionScope Scan — Step-by-Step Tutorial"
description: >-
  Install ActionScope and run your first scan against a GitHub repository
  in under 5 minutes. No AWS credentials required for the static analysis
  path. Covers reading the output, understanding policy correlation, and
  enabling live AWS verification.
---

# Your First Scan

This is the 5-minute walkthrough from "never heard of ActionScope" to
"I just found a CRITICAL finding in my own repo." No AWS credentials
needed for the static-analysis path.

## 1. Install

```bash
pip install actionscope
```

That's it. Python 3.10+ required. No external services; the install is a
single Python package.

If you want the optional `--aws-verify` mode that makes read-only AWS IAM
API calls, install with the `aws` extra:

```bash
pip install "actionscope[aws]"
```

You can do this later — the static-analysis path works without it.

## 2. Pick a repository to scan

You have three options, from fastest to most realistic:

=== "Your own repo"

    ```bash
    cd /path/to/your/repo-with-github-actions
    actionscope scan .
    ```

    This is the most useful — ActionScope only takes 1–2 seconds on a
    repo of any size, so it costs you nothing to try.

=== "ActionScope's bundled fixture"

    ```bash
    git clone https://github.com/r12habh/ActionScope
    cd ActionScope
    actionscope scan tests/fixtures/coverage_repo
    ```

    The bundled `coverage_repo` is a small synthetic repository
    designed to trigger every detector. Best for understanding what
    ActionScope can find before you point it at your own code.

=== "A real public AWS-enabled repo"

    Pick any public repo that uses
    `aws-actions/configure-aws-credentials`. Clone it and scan:

    ```bash
    git clone <repo-url>
    cd <repo>
    actionscope scan .
    ```

    The [GitHub Code Search query](https://github.com/search?q=path%3A.github%2Fworkflows+aws-actions%2Fconfigure-aws-credentials&type=code)
    finds thousands.

## 3. Read the output

This is what scanning the bundled `coverage_repo` fixture produces. Your
own repo's output will be smaller — `coverage_repo` is deliberately
overloaded to demonstrate every detector at once.

### The header

```text
╭──────────────────────────────────────────────────────────────────╮
│  ActionScope — Blast Radius Report                               │
│  Path: ./tests/fixtures/coverage_repo                            │
│  Workflows: 6 | Credential Sources: 2                            │
│  Overall Risk: 🔴 CRITICAL                                        │
╰──────────────────────────────────────────────────────────────────╯
```

- **Workflows**: how many `.yml` files in `.github/workflows/`
  produced at least one finding
- **Credential Sources**: how many `aws-actions/configure-aws-credentials`
  steps ActionScope found
- **Overall Risk**: the maximum severity across every detector. Drives
  exit codes when `--fail-on` is set

### Known-compromised actions

```text
⛔ KNOWN COMPROMISED ACTIONS (1 found)

⛔ CRITICAL: actions-cool/issues-helper@v3
   Workflow: triage.yml → triage → Compromised helper
   Status: Compromised 2026-05-18T19:10:24Z — documented supply-chain compromise
   Impact: Mutable tags may run credential-stealing code in this job
   Fix:    Remove this action OR pin to a verified pre-compromise SHA
   Advisory: https://www.stepsecurity.io/blog/...
```

ActionScope ships a curated database of compromised actions and flags any
`uses:` reference that matches. Mutable-tag references (`@v3`) produce
**CRITICAL** findings. Full-SHA pins to an action with a known compromise,
where the SHA is not in the published affected-refs list, produce
**HIGH** findings so a human can verify whether the pinned commit
predates the compromise. See the
[full Compromised Actions Database](../compromised-actions-database.md)
for every entry.

### AWS blast radius per workflow

```text
Workflow: deploy.yml → Job: deploy → Step: Configure AWS credentials
AWS Role: arn:aws:iam::123456789012:role/deployer-role
Policy Match: terraform (high)
Auth: OIDC ✓

┌─────────────────────────┬────────────────────────┬─────────┐
│ Action                  │ Access                 │ Risk    │
├─────────────────────────┼────────────────────────┼─────────┤
│ iam:CreatePolicyVersion │ Permissions management │ 🔴 CRIT │
│ iam:PassRole            │ Permissions management │ 🔴 CRIT │
│ ec2:TerminateInstances  │ Write                  │ 🟠 HIGH │
│ s3:PutObject            │ Write                  │ 🟡 MED  │
└─────────────────────────┴────────────────────────┴─────────┘

🔴 Privilege Escalation Paths Detected:
  ↳ IAM PassRole + Wildcard Resource
  ↳ Create New IAM Policy Version
```

This is the **blast radius** — what `deploy.yml` can actually do in AWS
if it's compromised. The table is derived from the IAM policies attached
to the role assumed by the workflow.

The `Policy Match` line tells you where ActionScope got the policy
from:

| Value | What it means |
|---|---|
| `terraform (high)` | Found an `aws_iam_role_policy` resource in `*.tf` files |
| `json (medium)` | Found a `.json` policy file in `iam/` or `policies/` |
| `aws_verified` | Fetched live from AWS via `--aws-verify` |
| `not_found` | No matching IAM policy in the repo |
| `dynamic_reference` | Role ARN computed at runtime — can't statically resolve |

### Other detectors

The rest of the output includes:

- **OIDC trust policy issues**: wildcard subjects, missing `aud`,
  branch- instead of environment-scoping
- **GitHub Environment issues**: deploy jobs missing environment
  protection rules
- **Script injection**: `${{ github.event.pull_request.title }}` inside
  `run:` blocks
- **Artifact poisoning**: `workflow_run` jobs that execute downloaded
  artifacts
- **AI agent prompt injection**: Claude Code / Copilot / Gemini agents
  with write permissions on PR triggers
- **Unpinned actions**: external `uses:` references not pinned to a
  full 40-char SHA
- **GITHUB_TOKEN permissions**: write-capable scopes that elevate risk

## 4. Add IAM policy files for deeper analysis

If your `Policy Match` column shows `not_found`, ActionScope didn't find
the IAM policy attached to your deploy role. Two ways to fix that:

**Option A — same-repo Terraform / JSON:**

If your IAM policies live as Terraform (`*.tf` with `aws_iam_role` /
`aws_iam_role_policy` resources) or as JSON files under `iam/` or
`policies/` in the same repo, ActionScope picks them up automatically.
No flag needed.

**Option B — separate infrastructure repo:**

If your IAM lives in a different repo, scan that repo separately and
correlate manually:

```bash
actionscope scan /path/to/infra-repo --output-format json > infra.json
```

Or skip ahead to live AWS verification.

## 5. Use `--aws-verify` for live IAM policy data

When the policy isn't in the same repo, you can have ActionScope fetch
the live attached policies via read-only IAM API calls:

```bash
pip install "actionscope[aws]"
export AWS_PROFILE=my-profile          # or use any standard AWS auth
actionscope scan . --aws-verify
```

This uses these IAM actions and nothing else:

- `iam:GetRole`
- `iam:ListAttachedRolePolicies`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`
- `iam:ListRolePolicies`
- `iam:GetRolePolicy`

The exact minimum-required JSON policy is in
[AWS Verification Permissions](../aws-verify-permissions.md). All calls
are read-only — ActionScope makes no IAM changes.

## 6. Add ActionScope to your CI/CD

The most useful path: run ActionScope on every PR, post results as a
comment, and upload SARIF to the GitHub Security tab.

Add this to `.github/workflows/actionscope.yml`:

```yaml
name: ActionScope
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # for SARIF upload to the Security tab
  pull-requests: write     # for PR comments

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: r12habh/ActionScope@v0
        with:
          fail-on: high          # exit 1 if any finding is HIGH or above
          comment-pr: true       # post findings as a PR comment
          upload-sarif: true     # send to the Security tab
          resolve-pins: true     # suggest full-SHA pins for unpinned actions
```

You get:

- A **PR comment** on every pull request, with a risk delta versus the
  previous scan if you also use `--save-state` / `--load-state`
- **First-class Code Scanning alerts** in the Security tab via SARIF
- **CI failure** on HIGH/CRITICAL findings so issues block merges

## What's next

- [Compromised Actions Database](../compromised-actions-database.md) —
  every action ActionScope flags and why
- [OIDC Trust Policy Analysis](../oidc-trust.md) — what the detector
  looks for, with examples
- [SARIF and GitHub Security Tab](../sarif.md) — wiring up Code Scanning
- [FAQ](../faq.md) — common questions (no findings? `not_found`? is it
  safe?)
- [CLI Reference](../cli-reference.md) — every flag and subcommand
