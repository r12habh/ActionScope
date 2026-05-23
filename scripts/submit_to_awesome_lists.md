# Submitting ActionScope to Awesome Lists

This guide tracks which awesome lists ActionScope has been submitted to and
provides the PR description text to use.

Liveness checked against the GitHub API as of 2026-05-23. Each list is rated
on three axes: **fit** (does ActionScope belong there?), **activity** (is the
list actively maintained?), and **audience** (star count as a rough proxy).

## Submission strategy

ActionScope is currently 1 ⭐, 7 days old. Awesome-list curators generally
expect some organic adoption signal (stars, downloads, mentions) before
accepting a tool, and submitting a brand-new repo to multiple curated lists
at once reads as spam and tends to produce quick closures that pollute the
PR history for future resubmits.

Current approach: send one foundational PR (toniblyx, the loosest-bar
list), then defer the rest until ActionScope has organic adoption
(target: ~30 days old, ~50+ stars). Drive that adoption via the launch
posts in `research/launch_posts.md` (HN, Reddit, LinkedIn) and the SEO
FAQ section in the README.

## Target Lists

### Sent

- [x] **[toniblyx/my-arsenal-of-aws-security-tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools)**
      — 9.4k ⭐, AWS-focused, only requires "Open Source."
      Submitted as [PR #128](https://github.com/toniblyx/my-arsenal-of-aws-security-tools/pull/128)
      on 2026-05-23.

### Deferred — wait for adoption milestones

Resubmit when ActionScope reaches roughly 30 days old + 50+ stars.

- [ ] **[analysis-tools-dev/static-analysis](https://github.com/analysis-tools-dev/static-analysis)**
      — 14.5k ⭐. Has hard requirements: >20 stars + project ≥3 months old.
      File format is YAML under `data/tools/<toolname>.yml` (not JSON, not
      README). 500-char description cap; tags from `data/tags.yml`. **Do
      not submit until ActionScope clears the age + star bar.**

- [ ] **[sbilly/awesome-security](https://github.com/sbilly/awesome-security)**
      — 14.4k ⭐, no formal CONTRIBUTING. Curators set an implicit quality
      bar; risky to submit while at 1 ⭐.

- [ ] **[4ndersonLin/awesome-cloud-security](https://github.com/4ndersonLin/awesome-cloud-security)**
      — 2.4k ⭐, follows the awesome-manifesto "must be useful" rule. Same
      risk as sbilly while at 1 ⭐.

- [ ] **[devsecops/awesome-devsecops](https://github.com/devsecops/awesome-devsecops)**
      — 5.4k ⭐, last push May 2024 (stale). Empty CONTRIBUTING. Low merge
      probability regardless of timing; revisit only if list resumes
      activity.

- [ ] **[meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response)**
      — 9k ⭐, active. Marginal fit — ActionScope is more
      detection/prevention than IR. Worth a try after adoption catches up.

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

- **analysis-tools-dev/static-analysis**: Edit `data/tools/<toolname>.yml`
  (YAML, not JSON; not README). Description ≤500 chars. Tags from
  `data/tags.yml` — add new tags there if needed. Reference an existing
  similar tool (e.g. `actionlint.yml`) for the schema.
- **toniblyx/my-arsenal-of-aws-security-tools**: Markdown table; entries
  are appended over time rather than strictly alphabetical. Format
  includes the badgen.net star/contributor/watcher badges per row.
- **sbilly/awesome-security**: Bullet-list under topical headings,
  format is `- [Name](link) - description.` (one line, period at end).
- **devsecops/awesome-devsecops**: Bullet-list with `* [Name](link)`
  prefix; description is a sentence with no trailing period.
- **meirwah/awesome-incident-response**: Same as sbilly format; pick the
  least-bad subcategory and explain the fit in the PR body.
- **4ndersonLin/awesome-cloud-security**: `[Name](link)` format per the
  awesome manifesto; reference back to awesome-cloud-security from
  ActionScope's README is appreciated.
