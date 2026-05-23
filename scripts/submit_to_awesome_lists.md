# Submitting ActionScope to Awesome Lists

This guide tracks which awesome lists ActionScope has been submitted to and
provides the PR description text to use.

Liveness checked against the GitHub API as of 2026-05-23. Each list is rated
on three axes: **fit** (does ActionScope belong there?), **activity** (is the
list actively maintained?), and **audience** (star count as a rough proxy).

## Target Lists

### Tier 1 — Submit first (high fit + active)

- [ ] **[toniblyx/my-arsenal-of-aws-security-tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools)**
      — 9.4k ⭐, active, AWS-focused. Best single-list match.
      Section: `Defensive (Blue Team)` → `AWS IAM` or a new entry under
      `GitHub Actions / CI security`.

- [ ] **[analysis-tools-dev/static-analysis](https://github.com/analysis-tools-dev/static-analysis)**
      — 14.5k ⭐, very active. Uses a JSON entry under `data/api/tools.json`
      (not a README edit). Categories will likely be `linter` +
      `security`; language `yaml`; types `cli` + `github-action`.

- [ ] **[sbilly/awesome-security](https://github.com/sbilly/awesome-security)**
      — 14.4k ⭐, active. Plain markdown; pick a section like
      `Network > Cloud / Server / Tools` or `Code Auditing`.

### Tier 2 — Submit if Tier 1 lands well

- [ ] **[4ndersonLin/awesome-cloud-security](https://github.com/4ndersonLin/awesome-cloud-security)**
      — 2.4k ⭐, active, cloud-security focus.

- [ ] **[devsecops/awesome-devsecops](https://github.com/devsecops/awesome-devsecops)**
      — 5.4k ⭐, last push May 2024 (somewhat stale; PR may sit).
      Section: `Tools > Testing` or `Tools > Automation`.

- [ ] **[meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response)**
      — 9k ⭐, active. Marginal fit — ActionScope is more
      detection/prevention than IR. Worth a try given the
      compromised-actions database.

### Skipped — not viable

- ❌ **hysnsec/awesome-devsecops** — repo deleted (404).
- ❌ **AcalephStorage/awesome-devops** — archived (read-only repo).
- ❌ **0xedward/awesome-infosec** — last push 2020, list appears abandoned.
- ❌ **kaiiyer/awesome-vulnerable** — active, but for *intentionally
  vulnerable apps*, not security tools. Wrong fit.
- ❌ **dustinspecker/awesome-eslint** — ESLint-specific, off-topic.

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

## Format quirks per list

- **analysis-tools-dev/static-analysis**: Edit `data/api/tools.json`,
  not the README. Bot regenerates the rendered list. Schema includes:
  `name`, `categories`, `languages`, `types`, `licenses`, `homepage`,
  `source`, `description`. Reference an existing similar tool (e.g.
  `actionlint`) for the right keys.
- **toniblyx/my-arsenal-of-aws-security-tools**: Strict alphabetical
  order within each section. Read `CONTRIBUTING.md` if present.
- **sbilly/awesome-security**: Bullet-list under topical headings,
  format is `- [Name](link) - description.` (one line, period at end).
- **devsecops/awesome-devsecops**: Bullet-list with `* [Name](link)`
  prefix; description is a sentence with no trailing period.
- **meirwah/awesome-incident-response**: Same as sbilly format; pick the
  least-bad subcategory and explain the fit in the PR body.
