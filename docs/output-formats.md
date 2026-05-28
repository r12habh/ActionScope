# Output Formats

ActionScope supports multiple output formats so you can use it locally,
in CI pipelines, and with GitHub's security tooling.

## Formats

### terminal (default)

Human-readable output for local development.

```bash
actionscope scan .
```

### json

Machine-readable output for CI pipelines and custom tooling.

```bash
actionscope scan . --format json
actionscope scan . --format json --output-file scan.json
```

### markdown

Formatted output for PR comments and reports.

```bash
actionscope scan . --format markdown
actionscope report --from-json scan.json --format markdown
```

### sarif

SARIF 2.1.0 output for GitHub Code Scanning and other SAST tools.

```bash
actionscope scan . --format sarif
actionscope report --from-json scan.json --format sarif
```

## Saving Output with --output-file

Save any format to a file instead of stdout:

```bash
actionscope scan . --format json --output-file scan.json
actionscope scan . --format sarif --output-file results.sarif
```

## Rendering Reports from Saved JSON

Use `actionscope report` to convert a saved JSON scan into another format
without re-scanning:

```bash
actionscope report --from-json scan.json --format markdown
actionscope report --from-json scan.json --format sarif
```

This is useful in CI when you scan once and publish multiple report formats.