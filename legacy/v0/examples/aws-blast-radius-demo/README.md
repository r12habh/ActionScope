# Demo: AWS blast radius of a GitHub Actions workflow

One narrow question: **when a GitHub Actions workflow assumes an AWS role, how do
you quickly review what that workflow can do in AWS if it's compromised?**

This tiny repo has two files that, in real life, live far apart and are reviewed
by different people:

- [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) — a deploy job
  that assumes `arn:aws:iam::123456789012:role/github-actions-deploy` via OIDC.
  **Reading this file alone, you cannot tell what the role can do.**
- [`infra/iam.tf`](infra/iam.tf) — the Terraform that defines that role and
  attaches its policy.

## Run it

```bash
pip install actionscope
actionscope scan examples/aws-blast-radius-demo
```

## What you get

ActionScope joins the workflow's role reference to the in-repo IAM evidence and
reports the blast radius:

- `iam:PassRole` on `*` — a **privilege-escalation path** (CRITICAL)
- `s3:*` and `ec2:TerminateInstances`
- Two named escalation chains (PassRole, RunInstances + instance profiles)
- The OIDC trust policy is missing a `sub` condition, so **any repository** could
  assume this role (CRITICAL)
- The deploy job has no GitHub Environment gating it, and the actions are not
  SHA-pinned

That's the point: the workflow says "I assume a role"; ActionScope says "that
role can pass any IAM role, wipe S3, and terminate EC2."

> Note: this demo resolves the role statically because the IAM lives in the repo.
> When IAM lives only in your AWS account, run `actionscope scan . --aws-verify`
> with read-only IAM credentials to pull the same answer from live AWS.
