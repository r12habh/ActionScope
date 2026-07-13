---
title: "ActionScope FAQ — Common Questions"
description: >-
  Answers to the questions ActionScope users ask most: empty scans,
  policy_source not_found, AWS verify safety, compromised actions
  database refresh cadence, and more.
---

# Frequently Asked Questions

## Why does my scan show no findings?

A scan returning `Overall Risk: ℹ️ INFO` with no detector hits is
**usually correct** — your repo probably doesn't use any of the patterns
ActionScope looks for. Specifically:

- No `aws-actions/configure-aws-credentials` step in any workflow (so
  there's no AWS surface to analyse)
- No `uses:` reference matches the compromised-actions database
- No `${{ github.event.* }}` interpolation in `run:` blocks
- No `pull_request_target` jobs with write-capable token permissions
- No `workflow_run` jobs downloading and executing artifacts
- All external action references are pinned to full 40-char SHAs

If you expected a finding and didn't get one, sanity-check with:

```bash
actionscope scan . --output-format json | python3 -m json.tool | head -40
```

If `workflow_count` is `0`, ActionScope didn't see any workflow file. Make
sure you're running from the repo root and the workflows live in
`.github/workflows/`. ActionScope only scans that path by default.

If you think you've found a true false-negative — a known issue ActionScope
should have caught but didn't — please
[open an issue](https://github.com/r12habh/ActionScope/issues/new/choose).
False negatives are the most important class of bug for a security tool.

## What does `policy_source: not_found` mean?

It means ActionScope detected an `aws-actions/configure-aws-credentials`
step that assumes an IAM role, but couldn't find the IAM policy attached
to that role anywhere in the repository.

This isn't a bug — it just means the policy isn't co-located with the
workflow. Common reasons:

- IAM is managed in a separate "infrastructure" repository (Terraform
  monorepo, terragrunt, AWS CDK, CloudFormation in a different repo, …)
- IAM is created out-of-band (ClickOps, AWS Console, scripts you ran
  once and don't keep in version control)
- The role is in a different AWS account and you don't have the policy
  source

Three ways to get a populated blast radius despite this:

| Approach | Command |
|---|---|
| Scan the infra repo separately | `actionscope scan /path/to/infra-repo` |
| Use live AWS verification | `actionscope scan . --aws-verify` |
| Add a JSON policy snapshot to your repo | Drop the policy JSON in `iam/` or `policies/` |

ActionScope looks for IAM policies in these paths:

- `*.tf` (Terraform files with `aws_iam_role`, `aws_iam_role_policy`,
  `aws_iam_policy` resources)
- `**/iam/*.json` (raw IAM policy JSON)
- `**/policies/*.json` (same)

## How do I get the most from `--aws-verify`?

`--aws-verify` switches the tool from "what does the repo say about the
role" to "what does AWS actually say about the role." It makes read-only
IAM API calls to fetch:

1. The role's trust policy (who can assume it)
2. The list of attached managed policies
3. Each attached managed policy's current version document
4. The list of inline policies on the role
5. Each inline policy's document

Use it when:

- The repo doesn't have the IAM source ([see above](#what-does-policy_source-not_found-mean))
- You want to verify that the live AWS state matches what your IaC says
- You're auditing a role created out-of-band

Required IAM permissions are minimal and **read-only**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

ActionScope uses standard AWS credential resolution (env vars, profiles,
IAM Instance Profile, IMDS, SSO). The most common setup:

```bash
export AWS_PROFILE=my-audit-profile
actionscope scan . --aws-verify
```

Full reference at [AWS Verification Permissions](aws-verify-permissions.md).

## Is ActionScope safe to run? Does it make network calls?

The local parsers make no network calls and ActionScope has no telemetry. If a
`GITHUB_TOKEN` is supplied, however, a scan can inspect referenced external
reusable workflows. Use `actionscope scan . --offline` when you need a hard
guarantee that ambient GitHub or AWS credentials cannot trigger scan-time API
calls.

These features use the network:

| Flag | What it does | Network calls |
|---|---|---|
| `--aws-verify` | Fetches live IAM policies from AWS | Only AWS IAM API, read-only |
| `--resolve-pins` | Looks up current SHA for unpinned action refs | Only GitHub API (uses `GITHUB_TOKEN` env var if set, otherwise unauthenticated) |
| `--github-token` or `$GITHUB_TOKEN` | Inspects external reusable workflow YAML | Only GitHub repository contents API |
| `actionscope update-db` | Refreshes the local compromised-action cache | GitHub advisory and repository APIs |
| (GitHub Action) `comment-pr: true` | Posts a comment on the PR | Only GitHub API for the comment |

`--offline` cannot be combined with `--aws-verify` or `--resolve-pins`; it also
prevents external reusable-workflow fetches even if `GITHUB_TOKEN` is set.

ActionScope is open-source under MIT. The full source for what runs on
your machine is in
[github.com/r12habh/ActionScope](https://github.com/r12habh/ActionScope)
— audit it before running if your environment requires that.

## How often is the compromised actions database updated?

The database lives in
[`actionscope/data/compromised_actions.json`](https://github.com/r12habh/ActionScope/blob/main/actionscope/data/compromised_actions.json)
and ships with each ActionScope release. When a new GitHub Actions
supply-chain compromise becomes public, the typical update cadence is
**within 24-48 hours of the advisory being published**, via a patch
release (e.g. `0.3.1`).

To update the package and bundled database:

```bash
pip install --upgrade actionscope
```

The CHANGELOG entry for each release lists added compromise entries.

To refresh advisory intelligence between package releases:

```bash
actionscope update-db
```

This writes a merged cache to
`~/.actionscope/compromised_actions_cache.json`. The cache is valid for 24
hours by default. Scans read it locally and never refresh it in the background.

You can also see the current full list at
[Compromised Actions Database](compromised-actions-database.md), which
is auto-generated from the bundled JSON on every docs deploy — so the
site always reflects the latest released version.

**Found a compromise that isn't in the database?** Please open a
[Report Compromised Action](https://github.com/r12habh/ActionScope/issues/new?template=compromised_action_report.yml)
issue. We aim to land it within a few hours.

## How is ActionScope different from `actionlint`, `zizmor`, `Checkov`?

| Question | actionlint | zizmor | Scorecard | Checkov | **ActionScope** |
|---|---|---|---|---|---|
| Workflow YAML validation | ✅ | partial | ❌ | ❌ | partial |
| Security pattern detection | ❌ | ✅ | ✅ | ❌ | ✅ |
| `GITHUB_TOKEN` permission review | ❌ | ✅ | ✅ | ❌ | ✅ |
| Unpinned action detection | ❌ | ✅ | ✅ | ❌ | ✅ |
| **Known-compromised action database** | ❌ | ❌ | ❌ | ❌ | **✅** |
| **AWS credential source detection** | ❌ | ❌ | ❌ | ❌ | **✅** |
| **Workflow → IAM role correlation** | ❌ | ❌ | ❌ | ❌ | **✅** |
| **Live AWS IAM policy verification** | ❌ | ❌ | ❌ | ❌ | **✅** |
| **Plain-English blast radius** | ❌ | ❌ | ❌ | ❌ | **✅** |
| **OIDC trust policy analysis** | ❌ | ❌ | ❌ | partial | **✅** |
| **GitHub Environment hardening** | ❌ | ❌ | ❌ | ❌ | **✅** |
| Static IAM policy analysis | ❌ | ❌ | ❌ | ✅ | ✅ |
| SARIF / Code Scanning output | ❌ | ✅ | ✅ | ✅ | ✅ |

The short version: actionlint validates YAML, zizmor and Scorecard find
risky workflow patterns, Checkov audits IAM in isolation. ActionScope
**crosses the boundary** — it ties a specific workflow to a specific
IAM role to a specific blast radius and emits one correlated report.

They're complementary; run multiple if you can.

## Can I scan private repos?

Yes. Everything except `--resolve-pins` and `comment-pr` (the
GitHub-Action-only flag) runs entirely against the local filesystem and
doesn't care whether the repo is public or private. If you use
`--resolve-pins`, set `GITHUB_TOKEN` to a token with `public_repo`
scope (private repo metadata isn't needed for resolving public actions).

## How long does a scan take?

Sub-second on a typical repo. The largest factor is the number of `.tf`
files (Terraform HCL parsing is the dominant cost). ActionScope is
designed to feel free — it's intentionally cheap enough to put in
pre-commit hooks if you want to.

## How do I report a bug or a false positive?

Open an [issue](https://github.com/r12habh/ActionScope/issues/new/choose).
There are dedicated templates for:

- **False positives** — finding raised but the workflow is actually safe
- **False negatives** — known issue ActionScope should have caught
- **New compromised actions** to add to the database
- **New IAM privilege-escalation paths** to detect

False positives erode trust; false negatives miss real attacks. Both
are the most important class of bug for a security tool — your reports
make ActionScope better.
