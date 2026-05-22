# Submitting ActionScope to Awesome Lists

This guide tracks which awesome lists ActionScope has been submitted to and
provides the PR description text to use.

## Target Lists

### Tier 1 (Submit Immediately)

- [ ] https://github.com/devsecops/awesome-devsecops
  Section: Static Analysis / CI/CD Security
  PR title: "Add ActionScope — GitHub Actions AWS blast radius mapper"

- [ ] https://github.com/analysis-tools-dev/static-analysis
  Section: GitHub Actions / CI Security

- [ ] https://github.com/hysnsec/awesome-devsecops

- [ ] https://github.com/AcalephStorage/awesome-devops

- [ ] https://github.com/meirwah/awesome-incident-response
  Relevant for compromised actions detection.

### Tier 2

- [ ] https://github.com/0xedward/awesome-infosec
- [ ] https://github.com/kaiiyer/awesome-vulnerable
- [ ] https://github.com/dustinspecker/awesome-eslint

## Standard PR Description Text

```markdown
## Add ActionScope

ActionScope is an open-source CLI and GitHub Action that maps the AWS
blast radius of GitHub Actions workflows.

**What it does differently:** Most GitHub Actions security tools scan for
workflow misconfigurations. ActionScope crosses the boundary between the
workflow and the cloud account — it extracts IAM role ARNs from workflows,
correlates them with Terraform/JSON IAM policies, and outputs a plain-English
blast radius report.

**Key features:**
- Known-compromised actions detection (actions-cool, tj-actions, trivy-action)
- OIDC trust policy misconfiguration analysis
- Script injection detection (PR/issue body in run: blocks)
- IAM privilege escalation path detection
- Live AWS verification via read-only IAM API calls
- SARIF output for GitHub Security tab

**Research backed:** Based on empirical study of 493 public GitHub repos.
Found 95.5% use unpinned actions, 58.2% use static AWS keys.

**Install:** pip install actionscope | GitHub: r12habh/ActionScope
```

