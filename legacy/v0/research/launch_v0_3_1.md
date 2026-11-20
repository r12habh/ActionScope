# v0.3.1 launch-day copy

Drop-in copy for the channels listed in `research/launch_posts.md`. Each
piece is self-contained — pick whichever fits the audience and post. The
0.3.1 hook is fresh: we shipped a tool that caught a real bug in its own
GitHub Action wrapper on the first run of the new E2E regression check.

---

## Hacker News (Show HN)

**Title:**

`Show HN: ActionScope – static analysis for GitHub Actions + AWS blast radius`

**Body:**

```text
I kept asking myself: "this CI workflow assumes an AWS role — what can it
actually do to my account if it gets compromised?" Existing tools answered
half the question:

  - actionlint: is the workflow YAML valid?
  - zizmor: does the workflow have dangerous patterns?
  - Checkov: are these IAM policies misconfigured (in isolation)?

None of them cross the workflow ↔ IAM boundary. So I built ActionScope.
It reads .github/workflows/, extracts AWS role ARNs, correlates them with
Terraform or JSON IAM policies in the same repo, and prints a plain-English
blast-radius report. With --aws-verify it makes read-only IAM API calls to
fetch the live policies for any role it finds.

It also detects:

  - Known-compromised actions (tj-actions, actions-cool, trivy-action)
  - OIDC trust-policy misconfigurations (wildcard org subjects,
    missing sub/aud, branch- instead of environment-scoped trust)
  - Script injection (the "pwn request" pattern that the April 2026
    prt-scan campaign exploited)
  - IAM privilege-escalation paths (PassRole + wildcard, CreatePolicyVersion,
    AttachRolePolicy, Lambda+PassRole, CFN+PassRole, …)
  - Unpinned action references, with --resolve-pins to suggest full SHAs

To validate the problem, I scanned 493 public AWS-enabled repos. 95.5%
use at least one external action that is not pinned to a full SHA. 58.2%
still use static AWS access keys instead of OIDC. 8.1% combine
pull_request_target with write-capable token permissions.

v0.3.1 just shipped. The release also fixed a one-line bug in the action's
own composite shell glue that was silently dropping its `findings-json`
output for every consumer — caught by a CI regression check I added in the
same PR, on its first run against a fresh fixture.

Install: pip install actionscope
GitHub: https://github.com/r12habh/ActionScope
Docs: https://r12habh.github.io/ActionScope/
Research: https://github.com/r12habh/ActionScope/blob/main/research/FINDINGS.md

Feedback welcome, especially on detectors I'm missing.
```

---

## Reddit r/devops

**Title:**

`I scanned 493 public AWS-enabled GitHub repos; here's what the workflows can actually do in AWS`

**Body:**

```text
Built a static-analysis tool (ActionScope) that ties workflow → IAM role →
blast radius and ran it across 493 public repos that use
aws-actions/configure-aws-credentials. Findings:

- 95.5%: at least one unpinned external action (mutable supply chain)
- 58.2%: static AWS access keys instead of OIDC
- 44.0%: visible role ARNs directly in workflow YAML
- 8.1%: pull_request_target + write-capable GITHUB_TOKEN — the prt-scan
   pattern from the April 2026 campaign

Full methodology + anonymised dataset:
https://github.com/r12habh/ActionScope/blob/main/research/FINDINGS.md

The tool itself runs as a CLI or a GitHub Action. Static analysis only by
default (no AWS creds needed); optional --aws-verify makes read-only IAM
calls to verify the live policy. Outputs terminal, JSON, Markdown (for PR
comments), or SARIF (for Code Scanning).

  pip install actionscope
  actionscope scan .

Or:

  - uses: r12habh/ActionScope@v0
    with:
      fail-on: high
      comment-pr: true
      upload-sarif: true

Code: https://github.com/r12habh/ActionScope
Docs: https://r12habh.github.io/ActionScope/

Happy to take feedback on detectors I should add — currently covers
compromised actions, OIDC trust misconfigs, script injection, artifact
poisoning, AI-agent prompt injection surfaces, IAM privesc paths,
unpinned-action detection, and GitHub Environment hardening.
```

---

## Reddit r/aws

**Title:**

`What can your GitHub Actions workflow actually do in AWS? (open-source scanner)`

**Body:**

```text
A common question I had: my repo uses
aws-actions/configure-aws-credentials to assume role X. If someone slips
malicious code into a PR or a third-party action gets compromised, what
can they do in my AWS account?

The answer requires correlating three things:

  1. The workflow YAML (what role gets assumed)
  2. The IAM role's trust policy (who can assume it)
  3. The role's attached and inline IAM policies (what it can do)

Existing tools look at one of these in isolation. ActionScope correlates
all three and produces a plain-English blast-radius report. Open source,
MIT.

  pip install actionscope
  actionscope scan .                  # static, no AWS creds needed
  actionscope scan . --aws-verify     # live IAM verification (read-only)

The IAM API calls are read-only (iam:GetRole,
iam:ListAttachedRolePolicies, iam:GetPolicyVersion, iam:ListRolePolicies,
iam:GetRolePolicy). Documented at:
https://r12habh.github.io/ActionScope/aws-verify-permissions/

Also detects PassRole on *, CreatePolicyVersion, Lambda+PassRole, and
other documented privesc paths in the assumed role's policy. Outputs
SARIF for GitHub Code Scanning alerts.

Source: https://github.com/r12habh/ActionScope
```

---

## LinkedIn

```text
Most GitHub Actions security tools answer "is this workflow YAML
syntactically valid?" or "does it have dangerous patterns?".

The question I actually needed answered was: "if this workflow assumes
an AWS role, what can an attacker do in our account if the workflow gets
compromised?"

So I built ActionScope. It reads .github/workflows/, extracts AWS role
ARNs, correlates them with Terraform or JSON IAM policies in the same
repo, and prints a plain-English blast-radius report. Optional --aws-verify
makes read-only IAM API calls to fetch live policies.

To understand the scale of the problem I scanned 493 public AWS-enabled
GitHub repos. 8.1% combined pull_request_target with write-capable token
permissions — the exact pattern exploited in April 2026's prt-scan
campaign. 95.5% used at least one external action not pinned to a full
commit SHA.

Open source, MIT licensed:
https://github.com/r12habh/ActionScope

Docs:
https://r12habh.github.io/ActionScope/

Built with Claude Code as part of a security-tool experimentation series.
```

---

## Twitter / X thread (5 posts)

**1/**
```
I scanned 493 public AWS-enabled GitHub repos to answer one question:

"if a CI workflow is compromised, what can an attacker actually do
in your AWS account?"

Most GitHub Actions security tools don't cross the workflow ↔ IAM
boundary. So I built one that does.

🧵
```

**2/**
```
The headline findings:

  • 95.5% use ≥1 unpinned external action (supply-chain attack surface)
  • 58.2% use static AWS access keys instead of OIDC
  • 44.0% expose role ARNs directly in workflow YAML
  • 8.1% combine pull_request_target + write-capable GITHUB_TOKEN
    (the prt-scan pattern from April 2026)

Full data: https://github.com/r12habh/ActionScope/blob/main/research/FINDINGS.md
```

**3/**
```
The tool is ActionScope. It reads workflows + IAM policies (Terraform /
JSON), correlates them, and prints a plain-English blast radius.

  pip install actionscope
  actionscope scan .

No AWS creds needed for static analysis. --aws-verify uses read-only
IAM calls if you want to check what the role actually has attached.
```

**4/**
```
Detects:

  • known-compromised actions (tj-actions, actions-cool)
  • OIDC trust misconfigurations (wildcard subs, missing aud)
  • script injection / "pwn request"
  • IAM privesc paths (PassRole, CreatePolicyVersion, …)
  • unpinned actions (with --resolve-pins to suggest SHAs)
  • GitHub Environment hardening gaps

SARIF output → GitHub Code Scanning alerts.
```

**5/**
```
Open source, MIT.

Code: https://github.com/r12habh/ActionScope
Docs: https://r12habh.github.io/ActionScope/
Compromised actions DB: https://r12habh.github.io/ActionScope/compromised-actions-database/

Feedback welcome on detectors I'm missing.
```

---

## Notes

- **Don't post all of these on the same day.** Stagger by 24-48h across
  channels so the conversation in one place doesn't fragment the
  audience in another.
- **HN posting time matters.** Best windows: weekday US mornings,
  ~7-9am Pacific. Avoid weekends.
- **Reddit r/devops** has a "no self-promotion" rule that's loosely
  enforced — frame as "I studied X, here's the data" rather than
  "check out my tool."
- **Tag the right accounts on Twitter/LinkedIn**: GitHub Security
  (@github), the OSSF account, security folks who've published on
  GitHub Actions security (Ariel Caparelli, John Stawinski, others).
- After posting, monitor for an hour or two for replies and answer
  quickly. Sustained engagement window helps surface posts.
