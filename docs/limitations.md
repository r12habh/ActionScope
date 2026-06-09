# Limitations and Finding Calibration

> **Status:** This document ships with ActionScope v0.4.0.
> **Last updated:** 2026-06-08

ActionScope reports **security exposure** from static analysis. That is
valuable, but users need clear calibration: some findings are confirmed
risks, some are exposure signals that need human review, and some are
edge cases that may not apply to your setup.

This guide explains what ActionScope can and cannot detect, how to
interpret confidence levels, and how to tune results for your
environment.

---

## Static mode vs `--aws-verify` mode

ActionScope has two analysis modes:

| Mode | What it does | Confidence |
|---|---|---|
| **Static** (default) | Reads workflow files, Terraform, and JSON policies locally. Infers blast radius from IAM action names and resource patterns. | Exposure signal — may over-report |
| **`--aws-verify`** | Fetches live IAM policies from AWS (read-only) and cross-references with workflow usage. | Higher confidence — grounded in actual policy state |

### When to use static mode

- Quick triage of a new repo
- CI pipelines where AWS credentials are not available
- Auditing workflow files before they reach production

### When to use `--aws-verify`

- You have read-only AWS credentials configured
- You want to confirm that a detected exposure is actually exploitable
- You need to present findings to a security team with confidence

### What `--aws-verify` cannot do

- It cannot read **private IAM policies** unless the attached role has `iam:Get*` permissions
- It cannot inspect **organization-level SCPs** (Service Control Policies) unless the role has `organizations:Describe*`
- It cannot verify **cross-account trust relationships** unless the role has access to the trusted account

---

## Understanding `policy_source: not_found`

When ActionScope reports `policy_source: not_found`, it means:

1. The workflow references an IAM role (e.g., `role-to-assume: arn:aws:iam::123456789012:role/my-role`)
2. ActionScope could not fetch the live policy for that role (static mode) or the AWS API returned access denied

### What to do next

- **If you control the role:** Run with `--aws-verify` and ensure the attached role has `iam:GetRolePolicy` and `iam:ListAttachedRolePolicies`
- **If you don't control the role:** Treat the finding as a **review-needed signal**. The role may have more permissions than what's visible
- **If the role is cross-account:** The finding is likely a true positive — cross-account trust with overly broad permissions is a known risk pattern

---

## Confidence levels explained

| Label | Meaning | Action |
|---|---|---|
| **HIGH** | Confirmed vulnerability. The workflow pattern is a known attack vector and the IAM permissions confirm exploitability. | Fix immediately |
| **MEDIUM** | Security exposure. The pattern is concerning but may require additional context (e.g., branch protection, environment rules) to exploit. | Review within 1 sprint |
| **LOW** | Hardening opportunity. The finding represents a defense-in-depth improvement rather than an immediate risk. | Add to backlog |
| **INFO** | Informational. The finding is documented for completeness but does not represent a current risk. | No action required |

### Likely true positives (fix these)

- OIDC trust with `repo:*` subject and no `aud` restriction
- `run:` block that interpolates `${{ github.event.head_commit.message }}` without sanitization
- Unpinned third-party actions (e.g., `uses: some-action@v1` without SHA)
- `workflow_run` trigger with artifact download from untrusted source
- AI agent (`claude-code`, `copilot`) in CI with access to secrets

### Likely review-needed findings (context matters)

- Broad IAM permissions on a role used only in `push-to-main` workflows (branch protection may mitigate)
- `pull_request_target` workflows that check out the PR ref (safe if you don't use secrets in the same step)
- Terraform `aws_iam_role` with `Resource: "*"` (may be intentional for infrastructure provisioning)
- Actions from verified publishers that are unpinned (lower risk than unverified publishers)

---

## Known blind spots

### External reusable workflows

When a workflow uses `uses: org/repo/.github/workflows/reusable.yml@ref`,
ActionScope can analyze the **calling** workflow but cannot inspect the
**called** reusable workflow unless it's in the same repository.

**Mitigation:** Run ActionScope in the repository that defines the reusable workflow, or pin to a known SHA.

### Private IAM policies

ActionScope can read inline policies and managed policies attached to
the calling role. It cannot read:

- Permissions boundaries
- Session policies applied at assume-role time
- SCPs that restrict the role's effective permissions

**Mitigation:** Use `--aws-verify` with a role that has `iam:SimulatePrincipalPolicy`.

### YAML expression edge cases

ActionScope parses YAML workflow files but does not evaluate GitHub
Expression syntax at runtime. Edge cases include:

- Dynamic job matrix expressions that conditionally set permissions
- `if:` conditions that gate secret access on branch/environment
- Reusable workflow inputs that override default permissions

**Mitigation:** Review findings in context of your branch protection rules.

### Generated workflows

Some projects generate workflow files at build time (e.g., via
`actions/setup-python` matrix generation). ActionScope analyzes the
file as-is and may flag patterns that are generated safely at runtime.

### Organization-level GitHub settings

ActionScope does not currently check:

- Organization-wide `GITHUB_TOKEN` permission policies
- Required workflows that enforce security settings
- Organization-level OIDC trust policies

---

## Suppression and configuration

Individual findings can be suppressed via `.actionscope-suppressions.yml`:

```yaml
suppressions:
  - rule: "oidc-wildcard-subject"
    workflow: ".github/workflows/deploy.yml"
    reason: "OIDC subject is scoped to main branch via environment protection rules"
    expires: "2026-09-01"
```

See [Configuration](cli-reference.md) for the full suppression schema.

---

## Examples

### Example 1: OIDC wildcard subject (HIGH)

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    permissions:
      id-token: write
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
```

**Finding:** `oidc-wildcard-subject` — The OIDC subject claim allows any repo in the org.

**Why it's HIGH:** Any fork in the org can assume this role and access AWS.

**Fix:** Scope the subject to the specific repo and branch:
```yaml
subject: "repo:my-org/my-repo:ref:refs/heads/main"
```

### Example 2: Script injection in run block (MEDIUM)

```yaml
- name: Run tests
  run: |
    echo "Testing PR: ${{ github.event.pull_request.title }}"
```

**Finding:** `script-injection` — PR title is interpolated in a `run:` block.

**Why it's MEDIUM:** Exploitable only if the workflow runs on `pull_request_target` AND secrets are accessible in the same context.

**Fix:** Pass the value via an environment variable instead:
```yaml
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: echo "Testing PR: $PR_TITLE"
```

### Example 3: Unpinned action (LOW)

```yaml
- uses: actions/checkout@v4
```

**Finding:** `unpinned-action` — Action is referenced by tag, not SHA.

**Why it's LOW:** `actions/checkout` is a GitHub-verified publisher. The risk is supply-chain, not immediate exploitation.

**Fix:** Pin to a full commit SHA:
```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

---

## Further reading

- [AWS Verify Permissions](aws-verify-permissions.md) — How to set up live IAM verification
- [CLI Reference](cli-reference.md) — Full command-line options
- [FAQ](faq.md) — Common questions
- [Compromised Actions Database](compromised-actions-database.md) — Known-compromised actions
