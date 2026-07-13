# ActionScope

> **Map the AWS blast radius of your GitHub Actions workflows.**
> One command. No AWS credentials required. Instant plain-English results.

[![PyPI version](https://img.shields.io/pypi/v/actionscope)](https://pypi.org/project/actionscope/)
[![PyPI downloads](https://img.shields.io/pypi/dm/actionscope)](https://pypi.org/project/actionscope/)
[![CI](https://github.com/r12habh/ActionScope/actions/workflows/ci.yml/badge.svg)](https://github.com/r12habh/ActionScope/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/r12habh/ActionScope/branch/main/graph/badge.svg)](https://codecov.io/gh/r12habh/ActionScope)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-ActionScope-blue?logo=github)](https://github.com/marketplace/actions/actionscope)
[![Docs](https://img.shields.io/badge/docs-r12habh.github.io%2FActionScope-blue)](https://r12habh.github.io/ActionScope/)

📖 **Full documentation:** <https://r12habh.github.io/ActionScope/>
&nbsp;&middot;&nbsp;
🛡️ **Compromised Actions Database:** <https://r12habh.github.io/ActionScope/compromised-actions-database/>

**Your GitHub Actions workflows hold AWS credentials. Do you know what they can do?**

ActionScope reads your `.github/workflows/` files, Terraform IAM resources,
and JSON IAM policies, then tells you in plain English what your CI/CD
pipeline can do in AWS if it is compromised.

It also detects:
- 🚨 **Known-compromised actions** (`actions-cool`, `tj-actions`, `trivy-action`)
- 🔓 **OIDC trust policy misconfigurations** (wildcards, missing claims, unsafe set operators)
- 💉 **Script injection** (PR titles, issue bodies in `run:` blocks)
- 🎭 **Artifact poisoning** (`workflow_run` + untrusted artifact execution)
- 🤖 **AI agent prompt injection surfaces** (Claude Code, Copilot in CI)
- 📌 **Unpinned actions** with SHA resolution

![ActionScope mapping a workflow's AWS blast radius](docs/demo.gif)

The workflow only says it *assumes a role*. ActionScope joins it to the IAM
behind it and shows what that role can actually do if CI is compromised — here:
pass any IAM role (privilege escalation), wipe S3, and terminate EC2.
**[Reproduce this scan yourself »](examples/aws-blast-radius-demo/)**

## Try it on your repo in 30 seconds

```bash
pip install actionscope
cd /path/to/your/repo-with-github-actions
actionscope scan .
```

That's it. No AWS credentials needed, no telemetry, no sign-up. Static
analysis runs in under a second on a typical repo. If you have nothing
relevant, you get `Overall Risk: ℹ️ INFO`. If you have something, you'll
see exactly what and why.

**Want a guided first-scan walkthrough?** See
[**Your First Scan**](https://r12habh.github.io/ActionScope/tutorials/first-scan/)
— 5 minutes from install to understanding the output.

## Common flags

```bash
actionscope scan . --aws-verify        # fetch live IAM policies (read-only)
actionscope scan . --resolve-pins      # suggest full-SHA pins for unpinned actions
actionscope scan . --fail-on high      # exit 1 if any finding is HIGH or above
actionscope scan . --output-format sarif --output-file results.sarif
actionscope scan . --save-state        # save state for PR delta comparison
```

## Example Output

```text
ActionScope — Blast Radius Report
Path: /my-repo  |  Workflows: 2  |  Overall Risk: 🔴 CRITICAL

⛔ KNOWN COMPROMISED ACTIONS (1 found)
──────────────────────────────────────────────────────────────
⛔ CRITICAL: actions-cool/issues-helper@v3 (issue-triage.yml)
   Compromised 2026-05-18 — mutable tags may run credential-stealing code
   Fix: Remove this action or pin to a verified pre-compromise SHA

─────────────────────────────────────────────────────────────

deploy.yml → deploy → Configure AWS credentials
  AWS Role: arn:aws:iam::123456789012:role/github-deploy-role
  Auth: OIDC ✓

  ┌─────────────────────────────┬────────────────────┬──────────┐
  │ iam:PassRole                │ Permissions mgmt   │ 🔴 CRIT  │
  │ ec2:TerminateInstances      │ Write              │ 🟠 HIGH  │
  │ s3:GetObject                │ Read               │ 🟢 LOW   │
  └─────────────────────────────┴────────────────────┴──────────┘

  🔴 Privilege Escalation Path: iam:PassRole on * — can escalate to any role
```

## Use as a GitHub Action

```yaml
name: ActionScope Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # for SARIF upload
  pull-requests: write     # for PR comments

jobs:
  actionscope:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: r12habh/ActionScope@v0
        with:
          fail-on: high          # fail CI if HIGH or above
          comment-pr: true       # post findings as PR comment
          upload-sarif: true     # show in GitHub Security tab
          resolve-pins: true     # suggest SHA pins for unpinned actions
```

## What Makes ActionScope Different

ActionScope answers a question no other tool answers:

> "This workflow assumes **this IAM role**. If the workflow is compromised,
> what can an attacker **actually do** in your AWS account?"

| Capability | actionlint | zizmor | Scorecard | ActionScope |
|---|---|---|---|---|
| Workflow syntax validation | ✅ | Partial | ❌ | Partial |
| Security pattern detection | ❌ | ✅ | ✅ | ✅ |
| GITHUB_TOKEN permission review | ❌ | ✅ | ✅ | ✅ |
| Unpinned action detection | ❌ | ✅ | ✅ | ✅ |
| **Known-compromised action detection** | ❌ | ❌ | ❌ | **✅** |
| **AWS credential source detection** | ❌ | ❌ | ❌ | **✅** |
| **Workflow → IAM role correlation** | ❌ | ❌ | ❌ | **✅** |
| **Live AWS IAM policy verification** | ❌ | ❌ | ❌ | **✅** |
| **Blast radius in plain English** | ❌ | ❌ | ❌ | **✅** |
| **OIDC trust policy analysis** | ❌ | ❌ | ❌ | **✅** |
| **Script injection detection** | ❌ | Partial | ❌ | **✅** |
| SARIF / GitHub Security tab | ❌ | ✅ | ✅ | **✅** |

## How It Works

ActionScope performs **static analysis only** by default. It never sends your
code to an external service and does not require AWS credentials unless you
explicitly enable live AWS verification.

```text
.github/workflows/*.yml
terraform/**/*.tf          →  ActionScope  →  Blast Radius Report
policies/**/*.json                              + PR Comment
                                                + SARIF → GitHub Security Tab
```

1. Find `aws-actions/configure-aws-credentials` in workflows
2. Extract role ARNs and credential patterns
3. Match roles to IAM policies in Terraform or JSON files
4. Classify IAM actions using the `policy-sentry` action database
5. Detect privilege escalation paths
6. Check for known-compromised actions in the bundled database
7. Output a plain-English blast radius report

### Live AWS Verification (`--aws-verify`)

```bash
pip install actionscope[aws]
actionscope scan . --aws-verify
```

Requires read-only IAM permissions:
`iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`,
`iam:GetPolicyVersion`, `iam:ListRolePolicies`, `iam:GetRolePolicy`.

See [docs/aws-verify-permissions.md](docs/aws-verify-permissions.md)
for the minimal required policy.

## Security Detectors

### 🚨 Known-Compromised Actions

Checks workflows against a curated database of GitHub Actions with documented
supply chain compromises. Updated with each ActionScope release.

Current entries: `actions-cool/issues-helper` (2026-05-18),
`actions-cool/maintain-one-comment` (2026-05-18),
`tj-actions/changed-files` (2025-03-19), and
`aquasecurity/trivy-action` (2026-03-19).

### 🔓 OIDC Trust Policy Analysis

Detects wildcard subjects, missing `sub`/`aud` conditions, unsafe
`ForAllValues` use, and insufficient branch/environment scoping in GitHub
OIDC trust policies.

### 💉 Script Injection Detection

Finds direct interpolation of attacker-controlled GitHub context values
(`github.event.pull_request.title`, `github.event.issue.body`, etc.) into
`run:` shell blocks: the "Pwn Request" attack class.

### 🎭 Artifact Poisoning Detection

Identifies `workflow_run` workflows that download and execute artifacts from
potentially untrusted fork PR workflows with secret access.

### 🤖 AI Agent Prompt Injection Surface

Detects Claude Code, GitHub Copilot Agent, Gemini CLI and similar AI coding
agents configured with write permissions in untrusted PR contexts.

### 📌 Action Pinning + SHA Resolution

Detects unpinned actions and resolves tags to current SHAs via the GitHub API.
Distinguishes full SHAs (safe) from short SHAs (still mutable) and tags.

### ⚡ IAM Privilege Escalation Paths

Detects documented escalation paths including PassRole, CreatePolicyVersion,
AttachRolePolicy, CreateAccessKey, Lambda+PassRole, EC2+PassRole,
CloudFormation+PassRole, and more.

## Research

ActionScope is backed by an empirical study of 493 public GitHub repositories
and 3,981 GitHub Actions workflow files using AWS.

| Finding | Result |
|---------|--------|
| Using static AWS keys (not OIDC) | 58.2% of repos |
| Using unpinned external actions | 95.5% of repos |
| `pull_request_target` + write permissions | 8.1% of repos |
| Exposing role ARNs directly in workflows | 44.0% of repos |

→ [Full research findings](research/FINDINGS.md) |
[Scanner and anonymized dataset](research/)

## Output Formats

```bash
actionscope scan . --output-format terminal   # default: colored Rich output
actionscope scan . --output-format json       # for CI integration
actionscope scan . --output-format markdown   # for PR comments
actionscope scan . --output-format sarif      # for GitHub Security tab
```

## FAQ

### How do I detect compromised GitHub Actions like tj-actions or actions-cool?

ActionScope ships a curated database of known-compromised actions (tj-actions,
actions-cool/issues-helper, actions-cool/maintain-one-comment, trivy-action)
and scans every `uses:` reference in your workflows against it. Run
`actionscope scan .` and any compromised reference appears as a CRITICAL
finding with the advisory URL.

### What can my GitHub Actions workflow do in my AWS account?

ActionScope extracts every `aws-actions/configure-aws-credentials` step from
your workflows, follows the role ARN, and correlates it with Terraform or JSON
IAM policy files in the same repo. The output is a plain-English blast-radius
report — every IAM action the workflow can perform, classified by risk. Add
`--aws-verify` to fetch the live policies from AWS using read-only IAM calls.

### How do I scan a GitHub Actions workflow for security issues without AWS credentials?

`actionscope scan .` runs as pure static analysis by default. It needs no AWS
credentials, no GitHub token (except for `--resolve-pins`), and never sends
your code to an external service.

### How do I find script injection or `pull_request_target` risks?

ActionScope detects direct injection of attacker-controlled GitHub event
fields (PR titles, issue bodies, branch names) into `run:` blocks, and flags
`pull_request_target` jobs that combine untrusted event data with
write-capable `GITHUB_TOKEN` permissions — the pattern behind the April 2026
prt-scan attack.

### How do I get GitHub Code Scanning alerts for my workflows?

Run `actionscope scan . --output-format sarif --output-file results.sarif`
and upload `results.sarif` to the GitHub Security tab via the
`github/codeql-action/upload-sarif` action. ActionScope emits SARIF rules
AS001–AS014 covering AWS exposure, OIDC trust, unpinned actions,
compromised actions, script injection, and environment hardening.

### How do I pin GitHub Actions to a full commit SHA?

`actionscope scan . --resolve-pins` uses the GitHub API to look up the
current full-SHA tip for every mutable `uses: owner/repo@vX` reference in
your workflows and prints a suggested pinned version with the tag preserved
as a comment.

### What's the difference between ActionScope and actionlint, zizmor, or Checkov?

actionlint validates workflow YAML syntax. zizmor and Scorecard detect
workflow security patterns. Checkov scans IAM policies independently.
ActionScope is the only tool that **crosses the boundary** — it ties a
specific workflow to a specific IAM role to a specific blast radius.

### Does ActionScope require AWS credentials?

Only if you opt in to `--aws-verify`, which makes read-only IAM API calls to
fetch live attached policies. See
[`docs/aws-verify-permissions.md`](docs/aws-verify-permissions.md) for the
exact permission set required.

## Documentation

📖 **Full docs site:** <https://r12habh.github.io/ActionScope/>

- **[First Scan Tutorial](https://r12habh.github.io/ActionScope/tutorials/first-scan/)** — install → first scan → reading the output, in 5 minutes
- **[FAQ](https://r12habh.github.io/ActionScope/faq/)** — empty scans, `policy_source: not_found`, `--aws-verify` safety, DB refresh cadence, tool comparisons
- [Compromised Actions Database](https://r12habh.github.io/ActionScope/compromised-actions-database/) — every action ActionScope flags, with permalinks
- [CLI reference](docs/cli-reference.md)
- [OIDC trust policy analysis](docs/oidc-trust.md)
- [Known-compromised actions detector](docs/compromised-actions.md)
- [SARIF and GitHub Security tab](docs/sarif.md)
- [AWS verification permissions](docs/aws-verify-permissions.md)
- [Release runbook](docs/release-runbook.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions.

New to the codebase? Start with a
[good first issue](https://github.com/r12habh/ActionScope/issues?q=label%3A%22good+first+issue%22).

The most impactful contributions right now:

1. **Add IAM actions to the risk database**
2. **Add compromised action entries** when a new supply-chain attack happens
3. **Add test fixtures** from real-world workflows, anonymized
4. **Improve error messages** when policies are missing

## Built By

Rishabh Singh.

[GitHub](https://github.com/r12habh)

---

*ActionScope performs static analysis by default. It does not transmit your
code or credentials to any external service.*
