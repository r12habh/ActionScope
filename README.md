# ActionScope

> **Connect GitHub Actions exposure to AWS IAM policy evidence.**
> CI-to-cloud impact analysis, with explicit gaps when permissions are unknown.

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
CloudFormation/SAM templates, and JSON IAM policies. It reports the AWS
permissions recoverable from that evidence and marks missing policy context as
a coverage gap instead of treating unknown permissions as safe.

The main report connects an action in a workflow job to its AWS credential
source, then to available role-policy evidence. With no matching IAM evidence,
it reports unknown cloud impact rather than assuming the role is safe. Static
mode needs no AWS credentials; `--aws-verify` optionally fetches policies using
authorized read-only IAM calls.

**Development focus:** reliability and owner-led validation. Broader feature
expansion is on hold while the workflow-to-IAM capability is evaluated with
owner-controlled evidence. See the [roadmap](docs/roadmap.md) and
[validation protocol](docs/owner-validation.md).

![ActionScope mapping a workflow's AWS blast radius](docs/demo.gif)

The workflow only says it *assumes a role*. This controlled example supplies
local IAM evidence with broad S3 access, instance termination, and `iam:PassRole`.
These are policy-derived exposure indicators, not a proof of exploitation or a
complete calculation of effective AWS permissions.
**[Reproduce this scan yourself »](examples/aws-blast-radius-demo/)**

## Run a Scan

```bash
pip install actionscope
cd /path/to/your/repo-with-github-actions
actionscope scan .
```

No AWS credentials are needed for static mode, with no telemetry or sign-up.
Analysis runs locally. If you have nothing
relevant, you get `Observed Risk: ℹ️ INFO`. If an AWS role cannot be matched
to a policy, ActionScope reports `Coverage: PARTIAL` instead of treating the
unknown permissions as safe.

**Want a guided first-scan walkthrough?** See
[**Your First Scan**](https://r12habh.github.io/ActionScope/tutorials/first-scan/)
— 5 minutes from install to understanding the output.

## Common flags

```bash
actionscope scan . --aws-verify        # fetch live IAM policies (read-only)
actionscope scan . --resolve-pins      # suggest full-SHA pins for unpinned actions
actionscope scan . --github-token "$GITHUB_TOKEN"  # inspect external reusable workflows
actionscope update-db                  # refresh compromised-action advisories
actionscope scan . --offline           # guarantee no scan-time API calls
actionscope scan . --fail-on high      # legacy: gate on aggregate observed risk
actionscope scan . --fail-on high --min-confidence high
actionscope scan . --fail-on high --new-only --min-confidence high
actionscope scan . --output-format sarif --output-file results.sarif
actionscope scan . --save-state        # save state for PR delta comparison
actionscope config init                # create a repository risk policy
```

For CI, start in report-only mode. Once a default-branch baseline exists,
block only new, high-confidence findings. See
[Confidence-Aware CI Gating](docs/ci-gating.md).
Use [`.actionscope.yml`](docs/config.md) for reviewed hard blocks,
time-bounded suppressions, custom IAM escalation paths, and repository-specific
risk calibration.

## Example Output

```text
ActionScope — Blast Radius Report
Path: /my-repo  |  Workflows: 2
Observed Risk: 🔴 CRITICAL
Coverage: COMPLETE
Gate: REPORT ONLY

⛔ KNOWN COMPROMISED ACTIONS (1 found)
──────────────────────────────────────────────────────────────
⛔ CRITICAL: actions-cool/issues-helper@v3 (issue-triage.yml)
   Compromised 2026-05-18 — mutable tags may run credential-stealing code
   Fix: Remove this action or pin to a verified pre-compromise SHA

Correlated Exposure Paths (1 found)
──────────────────────────────────────────────────────────────
🔴 CRITICAL: mutable action → AWS credentials
   Workflow: deploy.yml → deploy
   Action: third-party/deploy-helper@v1
   Credential: arn:aws:iam::123456789012:role/github-deploy-role
   Reachable IAM: iam:PassRole, ec2:TerminateInstances, s3:PutObject

─────────────────────────────────────────────────────────────

deploy.yml → deploy → Configure AWS credentials
  AWS Role: arn:aws:iam::123456789012:role/github-deploy-role
  Auth: OIDC ✓

  ┌─────────────────────────────┬────────────────────┬──────────┐
  │ iam:PassRole                │ Permissions mgmt   │ 🔴 CRIT  │
  │ ec2:TerminateInstances      │ Write              │ 🟠 HIGH  │
  │ s3:GetObject                │ Read               │ 🟢 LOW   │
  └─────────────────────────────┴────────────────────┴──────────┘

  Review: iam:PassRole on *; check service permissions and role constraints.
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
          fail-on: high          # block new, high-confidence HIGH/CRITICAL findings
          new-only: true         # only newly gate-eligible findings
          min-confidence: high   # avoid blocking on heuristic matches
          save-state: true       # save trusted default-branch baselines
          comment-pr: true       # post findings as a PR comment
          upload-sarif: true     # show findings in the Security tab
```

The first run has no baseline, so a new-only gate is reported as
`NOT EVALUATED` and the trusted default-branch run seeds the cache. The
Marketplace Action is report-only unless `fail-on` is explicitly set.

## What Makes ActionScope Different

ActionScope focuses on the connection between workflow execution and AWS
policy evidence:

> "This workflow assumes **this IAM role**. If the workflow is compromised,
> what can an attacker **actually do** in your AWS account?"

Use it alongside workflow analyzers such as [zizmor](https://docs.zizmor.sh/),
syntax validators such as [actionlint](https://github.com/rhysd/actionlint),
and cloud-trust tools such as
[gha-oidc-auditor](https://github.com/gamesapeca/gha-oidc-auditor).
Their scopes overlap; this is not an exclusive-capability or comparative
accuracy claim. ActionScope emphasizes inspectable workflow-to-role joins,
policy provenance, and explicit unresolved evidence.

Conditions, explicit denies, permissions boundaries, SCPs, session policies,
resource policies, and role chains can change effective authority. Fetching
attached policies does not fully evaluate these constraints. See
[limitations](docs/limitations.md) and the [roadmap](docs/roadmap.md).

## How It Works

ActionScope performs **static analysis only** by default. It never sends your
code to an external service and does not require AWS credentials unless you
explicitly enable live AWS verification. When a GitHub token is supplied, it
can fetch referenced external reusable workflow YAML from GitHub for analysis.
Use `--offline` to disable every scan-time GitHub and AWS API call even when
credentials are present in the environment.

```text
.github/workflows/*.yml
terraform/**/*.tf
CloudFormation/SAM templates  →  ActionScope  →  Blast Radius Report
IAM policy JSON                                  + PR Comment
                                                 + SARIF → GitHub Security Tab
```

1. Find AWS role assumptions and static credential environments in workflows
2. Follow local reusable workflows and optionally inspect external calls
3. Extract role ARNs and credential patterns
4. Match roles to IAM policies in Terraform, CloudFormation/SAM, or JSON files
5. Classify IAM actions using the `policy-sentry` action database
6. Correlate risky actions with AWS credentials in the same job
7. Detect privilege escalation paths
8. Check for known-compromised actions in the bundled or local cached database
9. Output a plain-English blast radius report

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

These supporting checks help identify how workflow influence could reach cloud
credentials. They complement the correlated impact report; they do not replace
specialist workflow analyzers or establish exploitability by themselves.

### 🚨 Known-Compromised Actions

Checks workflows against a curated database of GitHub Actions with documented
supply chain compromises. The bundled copy is updated with each release;
`actionscope update-db` can refresh a 24-hour local cache between releases.

```bash
actionscope update-db
actionscope scan . --offline  # uses local data only, including a stale cache
```

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
Distinguishes full SHAs (immutable references) from short SHAs and mutable tags.
A SHA pin does not establish that the referenced code is trustworthy.

### 🔁 Reusable Workflow Inspection

Detects job-level `uses:` calls, reports mutable reusable-workflow refs, and
recursively inspects local workflows. Supply `--github-token` (or
`GITHUB_TOKEN`) to fetch external reusable workflow YAML through GitHub's API;
without a token, ActionScope reports the delegated workflow as uninspected
instead of treating it as clean. Traversal is cycle-safe and follows GitHub's
10-level and 50-workflow limits.

[Reusable workflow inspection guide](docs/reusable-workflows.md)

### 🔗 Correlated Exposure Paths

Connects mutable or known-compromised actions to AWS credentials configured in
the same workflow job. When IAM policy context is available, the path includes
the highest-risk permissions that action could reach; otherwise it explicitly
marks the blast radius as unknown.

[Correlated exposure paths guide](docs/exposure-paths.md)

### ⚡ IAM Privilege Escalation Paths

Detects documented escalation paths including PassRole, CreatePolicyVersion,
AttachRolePolicy, CreateAccessKey, Lambda+PassRole, EC2+PassRole,
CloudFormation+PassRole, and more.

## Research

ActionScope is backed by an empirical study of 493 public GitHub repositories
and 3,981 GitHub Actions workflow files using AWS.

| Finding | Result |
|---------|--------|
| Using static AWS keys (not OIDC) | 58.2% of repos (lower bound) |
| Using unpinned external actions | 95.5% of repos |
| `pull_request_target` + write permissions | 8.1% of repos |
| Exposing role ARNs directly in workflows | 44.0% of repos |

The static-key collector used for this 2026 snapshot did not count credentials
provided only through environment variables, so 58.2% is a lower bound. The
current product parser reports those forms; the historical dataset is unchanged.

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

ActionScope extracts AWS credential configuration from your workflows, follows
literal role ARNs, and correlates them with Terraform, CloudFormation/SAM, or
JSON IAM policy files in the same repo. The output is a plain-English
blast-radius report with each recovered IAM action classified by risk. Add
`--aws-verify` to fetch the live policies from AWS using read-only IAM calls.

### How do I scan a GitHub Actions workflow for security issues without AWS credentials?

`actionscope scan .` runs as pure static analysis by default. It needs no AWS
credentials and no GitHub token. A token is optional for `--resolve-pins` and
for inspecting external reusable workflows; local workflow analysis never
needs one.

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
AS001–AS016 covering AWS exposure, OIDC trust, unpinned actions,
compromised actions, script injection, environment hardening, and correlated
action-to-AWS exposure paths.

### How do I pin GitHub Actions to a full commit SHA?

`actionscope scan . --resolve-pins` uses the GitHub API to look up the
current full-SHA tip for every mutable `uses: owner/repo@vX` reference in
your workflows and prints a suggested pinned version with the tag preserved
as a comment.

### What's the difference between ActionScope and actionlint, zizmor, or Checkov?

actionlint validates workflow YAML syntax. zizmor and Scorecard detect
workflow security patterns. Checkov scans IAM policies independently.
ActionScope correlates workflow credential sources with available IAM policy
evidence and reports missing context explicitly. Other workflow and cloud
security tools overlap; no exclusive capability or accuracy claim is made.

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
- [Reusable workflow inspection](docs/reusable-workflows.md)
- [Correlated exposure paths](docs/exposure-paths.md)
- [Known-compromised actions detector](docs/compromised-actions.md)
- [SARIF and GitHub Security tab](docs/sarif.md)
- [AWS verification permissions](docs/aws-verify-permissions.md)
- [Release runbook](docs/release-runbook.md)
- [CI-to-cloud roadmap](docs/roadmap.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions.

New to the codebase? Start with a
[good first issue](https://github.com/r12habh/ActionScope/issues?q=label%3A%22good+first+issue%22).

The most impactful contributions right now:

1. **Reproduce correctness bugs** with focused regression fixtures
2. **Improve coverage reporting** when IAM evidence is missing or unsupported
3. **Validate an owned workflow** using the [owner protocol](docs/owner-validation.md)
4. **Maintain existing checks and documentation**, including sourced advisory updates

## Citation and Community

Research users can cite ActionScope using the machine-readable metadata in
[`CITATION.cff`](CITATION.cff). GitHub also exposes this through the
repository's **Cite this repository** menu.

Project decisions and maintainer responsibilities are documented in
[`GOVERNANCE.md`](GOVERNANCE.md). For usage questions, bug reports, and support
expectations, see [`SUPPORT.md`](SUPPORT.md). Participation in project spaces
is governed by the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Built By

Rishabh Singh.

[GitHub](https://github.com/r12habh)

---

*ActionScope performs static analysis by default. It does not transmit your
code or credentials to any external service.*
