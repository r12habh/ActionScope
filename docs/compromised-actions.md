# Known-Compromised GitHub Actions Database

ActionScope checks workflow `uses:` references against a curated database of
GitHub Actions with documented supply-chain compromises.

This page is for searches like:

- `actions-cool/issues-helper compromised`
- `GitHub Action supply chain attack`
- `malicious GitHub Action detection`
- `tj-actions changed-files compromise`

## Check Your Repository

```bash
pip install actionscope
actionscope scan .
```

If a workflow uses a known-compromised action by mutable tag, ActionScope emits
a CRITICAL finding:

```text
⛔ KNOWN COMPROMISED ACTIONS (1 found)
⛔ CRITICAL: actions-cool/issues-helper@v3
   Fix: Remove this action OR pin to a verified pre-compromise SHA
```

SHA-pinned references are treated separately because a full 40-character SHA is
immutable. ActionScope reports a SHA pin only when that exact commit is listed
in `malicious_shas`; a different full SHA is not vulnerable to tag redirection.

## Current Database Entries

| Action | Date | Status | Notes |
|--------|------|--------|-------|
| `actions-cool/issues-helper` | 2026-05-18 | Compromised | Version tags redirected to an imposter commit. |
| `actions-cool/maintain-one-comment` | 2026-05-18 | Compromised | Coordinated compromise with issues-helper. |
| `tj-actions/changed-files` | 2025-03-19 | Historical | Tags redirected to malicious commit; secrets exposed in workflow logs. |
| `aquasecurity/trivy-action` | 2026-03-19 | Historical | Action and related scanner release compromised. |

The bundled database lives at:

```text
actionscope/data/compromised_actions.json
```

## How the Database Is Maintained

The curated database is updated with ActionScope releases. Between releases,
refresh a local cache explicitly:

```bash
actionscope update-db
```

The cache merges the bundled entries with GitHub's global malware advisories,
lives at `~/.actionscope/compromised_actions_cache.json`, and is fresh for 24
hours by default. Normal scans never make a background update request. A fresh
cache is preferred over bundled data; `scan --offline` may use a stale cache
because it can still contain newer intelligence than the installed release.

Each entry includes:

- action name in `owner/repo` form
- compromise timestamp
- advisory URL
- affected refs, if known
- exact known-malicious SHAs, if confirmed
- short description of the attack
- status (`compromised` or `historical`)

For real-time runtime protection, consider tools such as StepSecurity
Harden-Runner. ActionScope is a static analyzer and does not monitor live
network or process behavior.

## Report a Newly Compromised Action

Open a new issue using the compromised action template:

[Report Compromised GitHub Action](https://github.com/r12habh/ActionScope/issues/new?template=compromised_action_report.yml)

Please include:

- advisory or incident report URL
- affected action name
- affected tags or commits
- what the malicious code does
- whether secrets, tokens, or workflow logs are affected

## External Data Sources

- [GitHub Security Advisories](https://github.com/advisories) is the automated
  primary feed.
- [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) is
  probed conditionally; it currently has no stable GitHub Actions directory.
- Security vendor reports such as StepSecurity advisories remain human-reviewed
  sources for the curated bundled database rather than scraped HTML.
