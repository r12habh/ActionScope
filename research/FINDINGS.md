# We Scanned 493 Public GitHub Repos That Use AWS.
# Here's What Their CI/CD Can Do.

**Posted May 2026 by Rishabh Singh**

---

We built ActionScope to answer a question we kept asking internally:
"If a GitHub Actions workflow is compromised, what can an attacker
actually do in our AWS environment?"

Before scanning your own repos, we wanted to understand how the public
ecosystem looks. So we used the GitHub API to analyze 493
public repositories that use `aws-actions/configure-aws-credentials`.

**Important:** We only analyzed public workflow YAML files. We did not
access any AWS account, call any AWS API for external repos, or read any
IAM policy. We can see how workflows are *configured* — not what the
underlying AWS roles can actually do. That deeper analysis is what
ActionScope does on your own infrastructure.

---

## How We Selected Repos

GitHub's code search API finds files containing specific strings.
We searched for `aws-actions/configure-aws-credentials path:.github/workflows`
and collected the top 493 unique repositories.

We did not filter by repo size, stars, or organization type.
These are random public repos that happen to use AWS.

---

## Auth Method: Who's Using OIDC vs Static Keys?

41.8% use OIDC (recommended — no long-lived credentials)
58.2% use static access keys stored as GitHub secrets

AWS has recommended migrating to OIDC since 2023. GitHub's own docs
recommend it. And yet, 58.2% of AWS-connected repos in our
sample still use static credentials.

Static keys stored in GitHub secrets are higher risk because:
- A compromised PAT with repo access can read them
- They don't expire unless manually rotated
- If logged accidentally, they remain valid until rotation

---

## GITHUB_TOKEN Permissions: How Broad?

The GITHUB_TOKEN is the built-in credential every workflow gets.
Its permissions determine what the workflow can do to the repository itself.

2.0% use `permissions: write-all`

That grants every permission GitHub supports: code writes, PR writes,
package publishing, deployment writes, and more.

23.5% grant `pull-requests: write` explicitly

This matters because of a specific attack pattern: pull_request_target
workflows with write access can be manipulated via malicious PR content.
The April 2026 prt-scan campaign exploited exactly this.

---

## The Dangerous Pattern: pull_request_target + Write Access

15.0% use the `pull_request_target` trigger
8.1% use it WITH write permissions

`pull_request_target` runs in the context of the target repo (with its
secrets and permissions) but against code from a fork. A malicious PR
can include content that exfiltrates those permissions.

In April 2026, the prt-scan campaign opened over 475 malicious PRs in
26 hours exploiting exactly this trigger. 8.1% of
repos in our sample have this configuration today.

---

## Unpinned Actions: The Supply Chain Risk

95.5% use at least one unpinned action (floating tag, not SHA)

The tj-actions/changed-files compromise in March 2025 compromised 23,000+
repos through a single action with a floating tag. The Trivy compromise in
March 2026 followed the same pattern.

SHA-pinning is the recommended mitigation. 95.5% of repos
in our sample have not adopted it.

---

## What We Couldn't Measure

We cannot see the actual IAM permissions attached to the AWS roles these
workflows assume. Those are private to each AWS account.

For a workflow that assumes `arn:aws:iam::123456:role/ci-deploy`,
we can see the role exists in the workflow. We cannot see whether it has
`iam:PassRole` on `*`, or `s3:*`, or `ec2:TerminateInstances`.

That's the gap ActionScope fills for your own infrastructure:

```bash
pip install actionscope
actionscope scan .                    # correlates workflows with local IaC
actionscope scan . --aws-verify       # fetches live AWS policies
```

---

## Reproduce This Research

The scanner that generated these findings is open source:

```bash
git clone https://github.com/r12habh/ActionScope
pip install requests tqdm
export GITHUB_TOKEN=your_pat_here
python research/scan_public_repos.py --limit 500
```

Raw data (anonymized — no repo names): research/findings.json

---

*ActionScope is an open-source tool. If this was useful,
[star the repo](https://github.com/r12habh/ActionScope).*
