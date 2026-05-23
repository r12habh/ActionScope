# Launch Posts

## HACKER NEWS — Show HN

Title: "Show HN: ActionScope – map what your GitHub Actions can do in AWS"

Body:

```text
While building cloud security tooling, I kept running into the same question:
"We know what our CI/CD workflows are supposed to do in AWS. But what can
they actually do if compromised?"

Existing tools answer adjacent questions:
- actionlint: is this workflow YAML valid?
- zizmor: does this workflow have dangerous patterns?
- Checkov: are these IAM policies misconfigured?

None of them cross the boundary: "this workflow assumes THIS role, which
has THESE permissions, and here's the blast radius in plain English."

That's what ActionScope does.

    pip install actionscope
    actionscope scan .

It reads .github/workflows/*.yml, finds AWS role assumptions, correlates
them with Terraform or JSON policy files in your repo, and outputs a
plain-English blast radius report. With --aws-verify, it calls the AWS IAM
API (read-only) to fetch the actual attached policies.

It also flags OIDC trust-policy mistakes, script injection, artifact
poisoning, AI-agent prompt-injection surfaces, and known-compromised actions.

To validate the problem, we scanned 493 public repos. Results:
research/FINDINGS.md in the repo.

Most surprising finding: 8.1% have pull_request_target
with write permissions — the pattern the April 2026 prt-scan campaign exploited.
Also: 95.5% used at least one action that was not pinned to a full SHA.

GitHub: https://github.com/r12habh/ActionScope

Happy to answer questions about the IAM analysis or the research methodology.
```

## REDDIT — r/devops

Title: "I built an open-source tool that maps what your GitHub Actions workflows can do in AWS — feedback welcome"

Body:

```text
Background: I got tired of asking "what can this
CI/CD role actually do if someone compromises the workflow?"

Existing scanners check your workflow files for security patterns. Nobody
was mapping the actual AWS blast radius — what specific actions the assumed
IAM role can perform.

So I built ActionScope. It:
1. Reads .github/workflows/*.yml
2. Finds aws-actions/configure-aws-credentials steps
3. Extracts role ARNs
4. Correlates with Terraform/JSON IAM policies in your repo
5. Detects workflow-layer risks like unpinned/compromised actions,
   script injection, artifact poisoning, and OIDC trust-policy mistakes
6. Outputs a plain-English blast radius report

    actionscope scan .

    deploy.yml → Configure AWS credentials
    Role: arn:aws:iam::123456:role/github-deploy-role

    ⚠️  iam:PassRole on * — privilege escalation path exists
    🔴 ec2:TerminateInstances — can terminate production instances

With --aws-verify it calls the AWS IAM API read-only and fetches the
real attached policies.

To understand the problem scope, I also scanned 493 public
repos with AWS-connected workflows. Findings document is in the repo.

Most interesting finding: 8.1% use pull_request_target
with write permissions — the exact pattern exploited in April's prt-scan attack.
95.5% also use at least one external action that is not pinned to a full SHA.

Repo: https://github.com/r12habh/ActionScope

What I'd love feedback on: is the blast radius output format useful?
What else would you want to see in the report?
```

## REDDIT — r/aws

Title: "Open source tool that maps what your GitHub Actions workflows can actually do in AWS — static analysis + optional live IAM verification"

Body:

```text
Quick background: one pattern I kept seeing was teams thinking their CI/CD
roles were scoped correctly, but nobody had
actually verified what the role could do given its attached policies.

Built ActionScope to automate this:

Static mode (no AWS creds needed):
- Reads .github/workflows/*.yml
- Finds aws-actions/configure-aws-credentials role ARNs
- Correlates with Terraform/JSON IAM policies in the repo
- Outputs blast radius report

Live mode (--aws-verify, read-only IAM calls):
- Calls iam:GetRole, iam:ListAttachedRolePolicies, iam:GetPolicyVersion
- Fetches the actual policies attached to the role
- Real blast radius based on what AWS says the role can do

Also detects 13 privilege escalation paths including PassRole + wildcard,
CreatePolicyVersion, AttachRolePolicy, CreateAccessKey, CloudFormation +
PassRole, and Lambda + PassRole combos.

Newer checks cover OIDC trust-policy wildcards, direct script injection,
artifact poisoning, AI agent prompt-injection surfaces, and known-compromised
GitHub Actions.

Install: pip install actionscope
Required IAM perms for --aws-verify: just read-only IAM actions (policy in docs/)

Repo: https://github.com/r12habh/ActionScope
Research findings from 493 public repos: research/FINDINGS.md

Curious if this fills a gap people have been feeling or if there are
existing tools I'm not aware of.
```

## LINKEDIN

```text
I've spent a long time looking at AWS security incidents where the root
cause was "the CI/CD role had more access than anyone realized."

A workflow was set up to deploy to S3. Over time, someone added
iam:PassRole. Then cloudformation:*. Nobody reviewed it because it was
a GitHub Actions config, not application code.

That pattern is how a compromised workflow becomes an account takeover.

I built ActionScope to make this visible before it matters:

    pip install actionscope
    actionscope scan .

It reads your GitHub Actions workflows, correlates the AWS roles they
assume with your Terraform or IAM policy files, and outputs a plain-English
report showing what each workflow can do in AWS.

With --aws-verify, it calls the IAM API (read-only) and shows you the real
effective permissions — not just what's in your repo.

To understand how widespread the problem is, I scanned 493
public repositories. 8.1% had pull_request_target with
write permissions — the pattern that prt-scan exploited in April.
58.2% still use static access keys instead of OIDC. 95.5% had at least
one external action not pinned to a full SHA. Full findings in the repo.

It's open source, one command to install, and the --aws-verify analysis takes
about 30 seconds for a typical repo.

Would appreciate stars if you find it useful:
https://github.com/r12habh/ActionScope

Happy to answer questions in the comments.
```
