# ActionScope CLI Reference

This page documents the current ActionScope command-line interface.

## Global Options

| Option | Default | Description | Example |
|--------|---------|-------------|---------|
| `--version` | n/a | Print the installed ActionScope version. | `actionscope --version` |
| `--help` | n/a | Show command help. | `actionscope --help` |

## `actionscope scan [PATH] [OPTIONS]`

Scan a repository or a single workflow file for GitHub Actions AWS security
exposure.

```bash
actionscope scan .
actionscope scan tests/fixtures/demo_repo --output-format json
```

### Arguments

| Argument | Default | Description | Example |
|----------|---------|-------------|---------|
| `PATH` | `.` | Repository root or workflow file to scan. | `actionscope scan /path/to/repo` |

### Options

| Flag | Short | Default | Description | Example |
|------|-------|---------|-------------|---------|
| `--output-format` | `-f` | `terminal` | Output format: `terminal`, `json`, `markdown`, or `sarif`. | `actionscope scan . -f sarif` |
| `--output-file` | `-o` | none | Write output to a file. Terminal mode writes Markdown when this is used. | `actionscope scan . -f json -o scan.json` |
| `--fail-on` | none | none | Enable CI gating at `critical`, `high`, `medium`, or `low`. With no confidence or new-only option, this preserves aggregate-risk behavior. | `actionscope scan . --fail-on high` |
| `--new-only` | none | `False` | Apply `--fail-on` only to findings not already eligible under the loaded baseline. This includes new findings and existing findings that cross the configured severity or confidence threshold. Implies `--load-state`. | `actionscope scan . --fail-on high --new-only` |
| `--min-confidence` | none | none | Gate only findings at or above `high`, `medium`, or `low` confidence. Requires `--fail-on`. | `actionscope scan . --fail-on high --min-confidence high` |
| `--require-baseline` | none | `False` | Exit with code 2 when `--new-only` cannot load an exact version-2 baseline. | `actionscope scan . --fail-on high --new-only --require-baseline` |
| `--aws-verify` | none | `False` | Fetch live AWS IAM role policies with read-only IAM API calls. Requires `actionscope[aws]` and AWS credentials. | `actionscope scan . --aws-verify` |
| `--no-color` | none | `False` | Disable terminal color output. | `actionscope scan . --no-color` |
| `--quiet` | `-q` | `False` | Suppress terminal output, useful with `--output-file`. | `actionscope scan . -q -o report.md` |
| `--save-state` | none | `False` | Save compact scan state to `.actionscope/last_scan.json`. | `actionscope scan . --save-state` |
| `--load-state` | none | `False` | Load previous state and compute a risk delta. | `actionscope scan . --load-state` |
| `--state-file` | none | `.actionscope/last_scan.json` | Custom path for state save/load. | `actionscope scan . --save-state --state-file /tmp/state.json` |
| `--resolve-pins` | none | `False` | Resolve unpinned GitHub Action tags to current commit SHAs via GitHub API. | `actionscope scan . --resolve-pins` |
| `--github-token` | none | `$GITHUB_TOKEN` | GitHub token used for pin resolution and authenticated inspection of external reusable workflows. | `actionscope scan . --github-token "$GITHUB_TOKEN"` |
| `--offline` | none | `False` | Disable all scan-time network calls. Cannot be combined with `--aws-verify` or `--resolve-pins`. | `actionscope scan . --offline` |

### Common Scan Examples

```bash
# Human-readable output
actionscope scan .

# CI JSON output
actionscope scan . --output-format json --output-file actionscope.json

# GitHub Code Scanning SARIF
actionscope scan . --output-format sarif --output-file actionscope.sarif

# Fail CI on high or critical findings
actionscope scan . --fail-on high

# Recommended: fail only on new, high-confidence findings
actionscope scan . --load-state --fail-on high --new-only \
  --min-confidence high

# Compare with the previous scan
actionscope scan . --load-state --save-state

# Inspect external reusable workflows referenced by jobs.<id>.uses.
# This example assumes GITHUB_TOKEN is already configured in the environment.
actionscope scan . --github-token "$GITHUB_TOKEN"

# Guarantee that ambient credentials cannot trigger API calls
actionscope scan . --offline
```

## `actionscope update-db [OPTIONS]`

Fetch GitHub Actions malware advisories and write a merged local cache. This is
the only command that refreshes advisory data; normal scans never update it in
the background.

```bash
actionscope update-db
actionscope update-db --ttl-hours 12
```

The updater always preserves the bundled curated entries. GitHub's global
malware advisory endpoint is the primary feed. The OpenSSF malicious-packages
repository is probed conditionally and skipped cleanly while it has no stable
GitHub Actions feed.

| Flag | Default | Description | Example |
|------|---------|-------------|---------|
| `--github-token` | `$GITHUB_TOKEN` | Token for higher GitHub API rate limits. | `actionscope update-db --github-token "$GITHUB_TOKEN"` |
| `--cache-file` | `~/.actionscope/compromised_actions_cache.json` | Override the local cache path. | `actionscope update-db --cache-file /tmp/actions.json` |
| `--ttl-hours` | `24` | Number of hours the cache remains fresh. | `actionscope update-db --ttl-hours 12` |

## `actionscope report [JSON_FILE] [OPTIONS]`

Render a previously saved ActionScope JSON result without re-scanning.

```bash
actionscope report scan.json --format markdown
actionscope report --from-json scan.json --format sarif
```

### Arguments

| Argument | Default | Description | Example |
|----------|---------|-------------|---------|
| `JSON_FILE` | none | Saved JSON result from `actionscope scan --output-format json`. | `actionscope report scan.json` |

### Options

| Flag | Short | Default | Description | Example |
|------|-------|---------|-------------|---------|
| `--from-json` | none | none | Alternate way to provide the saved JSON file. | `actionscope report --from-json scan.json` |
| `--format` | `-f` | `markdown` | Render as `markdown`, `terminal`, `json`, or `sarif`. | `actionscope report scan.json -f terminal` |

## `actionscope gate JSON_FILE [OPTIONS]`

Evaluate CI policy against a saved ActionScope JSON report without rescanning.
This is the command used by the Marketplace Action after producing its single
JSON scan.

```bash
actionscope gate scan.json --fail-on high
actionscope gate scan.json --fail-on high --new-only --min-confidence high
```

| Flag | Default | Description | Example |
|------|---------|-------------|---------|
| `--fail-on` | required | Severity threshold: `critical`, `high`, `medium`, or `low`. | `actionscope gate scan.json --fail-on high` |
| `--min-confidence` | `high` | Minimum confidence for a finding to block. | `actionscope gate scan.json --fail-on high --min-confidence medium` |
| `--new-only` | `False` | Gate findings that are absent from the exact baseline or newly cross the configured severity/confidence policy. | `actionscope gate scan.json --fail-on high --new-only` |
| `--require-baseline` | `False` | Exit 2 instead of 0 when a new-only gate has no exact baseline. Requires `--new-only`. | `actionscope gate scan.json --fail-on high --new-only --require-baseline` |
| `--write-back` | `False` | Store the gate decision in the JSON report for later rendering. | `actionscope gate scan.json --fail-on high --write-back` |

## Planned Commands

The roadmap issues below are open, but these commands are not implemented in
the current release:

| Command | Status | Tracking issue |
|---------|--------|----------------|
| `actionscope trend` | Planned | GitHub issue: historical risk tracking and trend reporting |
| `actionscope pin` | Not implemented; current support is `scan --resolve-pins` | GitHub issue: auto-pin resolver follow-ups |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan or gate completed without a blocking finding. This also covers a new-only gate with no baseline unless `--require-baseline` is set. |
| `1` | At least one finding matched the configured gate policy. |
| `2` | CLI usage error, report-file read error, or required baseline unavailable. |

## Environment Variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | `--resolve-pins`, reusable workflow inspection | Authenticates GitHub API calls for tag resolution and access to external reusable workflow YAML. |
| `ACTIONSCOPE_COMPROMISED_DB_CACHE` | `scan`, `update-db` | Override the compromised-action cache path. Primarily useful for CI and tests. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, AWS profile variables | `--aws-verify` | Standard AWS SDK credential sources used by boto3. |
