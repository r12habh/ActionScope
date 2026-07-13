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
| `--fail-on` | none | none | Exit with code 1 if overall risk is at or above `critical`, `high`, `medium`, or `low`. | `actionscope scan . --fail-on high` |
| `--aws-verify` | none | `False` | Fetch live AWS IAM role policies with read-only IAM API calls. Requires `actionscope[aws]` and AWS credentials. | `actionscope scan . --aws-verify` |
| `--no-color` | none | `False` | Disable terminal color output. | `actionscope scan . --no-color` |
| `--quiet` | `-q` | `False` | Suppress terminal output, useful with `--output-file`. | `actionscope scan . -q -o report.md` |
| `--save-state` | none | `False` | Save compact scan state to `.actionscope/last_scan.json`. | `actionscope scan . --save-state` |
| `--load-state` | none | `False` | Load previous state and compute a risk delta. | `actionscope scan . --load-state` |
| `--state-file` | none | `.actionscope/last_scan.json` | Custom path for state save/load. | `actionscope scan . --save-state --state-file /tmp/state.json` |
| `--resolve-pins` | none | `False` | Resolve unpinned GitHub Action tags to current commit SHAs via GitHub API. | `actionscope scan . --resolve-pins` |
| `--github-token` | none | `$GITHUB_TOKEN` | GitHub token used for pin resolution and authenticated inspection of external reusable workflows. | `actionscope scan . --github-token "$GITHUB_TOKEN"` |

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

# Compare with the previous scan
actionscope scan . --load-state --save-state

# Inspect external reusable workflows referenced by jobs.<id>.uses.
# This example assumes GITHUB_TOKEN is already configured in the environment.
actionscope scan . --github-token "$GITHUB_TOKEN"
```

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

## Planned Commands

The roadmap issues below are open, but these commands are not implemented in
the current release:

| Command | Status | Tracking issue |
|---------|--------|----------------|
| `actionscope update-db` | Planned | GitHub issue: auto-update compromised actions database |
| `actionscope trend` | Planned | GitHub issue: historical risk tracking and trend reporting |
| `actionscope pin` | Not implemented; current support is `scan --resolve-pins` | GitHub issue: auto-pin resolver follow-ups |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed and did not meet the `--fail-on` threshold. |
| `1` | Scan completed and overall risk met or exceeded `--fail-on`. |
| `2` | CLI usage or report-file read error. |

## Environment Variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `GITHUB_TOKEN` | `--resolve-pins`, reusable workflow inspection | Authenticates GitHub API calls for tag resolution and access to external reusable workflow YAML. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, AWS profile variables | `--aws-verify` | Standard AWS SDK credential sources used by boto3. |
