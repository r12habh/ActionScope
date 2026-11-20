---
title: "Confidence-Aware CI Gating"
description: >-
  Roll out ActionScope safely in CI using report-only scans, scan coverage,
  exact finding baselines, and new high-confidence finding gates.
---

# Confidence-Aware CI Gating

ActionScope reports three separate signals:

- **Observed Risk** is the highest severity supported by evidence the scan
  could inspect.
- **Coverage** is `COMPLETE` or `PARTIAL`. Partial coverage means some
  evidence could not be resolved, such as an AWS role whose policy is not in
  the repository.
- **Gate** is the CI policy decision: `REPORT ONLY`, `PASSED`, `FAILED`, or
  `NOT EVALUATED`.

An observed risk of `INFO` with partial coverage is not proof that the AWS
role is low risk. Its permissions are unknown to the static scan.

## Recommended Rollout

### 1. Start report-only

The Marketplace Action is report-only by default:

```yaml
- uses: r12habh/ActionScope@v0
  with:
    comment-pr: true
    upload-sarif: true
```

Review the findings and coverage gaps before deciding what should block
merges.

### 2. Establish a trusted baseline

Enable state saving. ActionScope only writes the shared baseline cache from a
push to the repository's default branch. Pull requests can restore that
baseline but cannot replace it. Pull requests restore only the cache keyed to
their exact base commit; they never accept a fallback cache created from the
pull-request workspace.

The baseline represents the current trusted default-branch state, not a
"clean" scan. It is still saved when that branch reports a gate failure so an
existing finding on the base branch does not block every unrelated pull
request. The failing default-branch run remains visible and should be fixed.

```yaml
- uses: r12habh/ActionScope@v0
  with:
    save-state: true
```

The first trusted default-branch run creates the baseline.

### 3. Block only new, high-confidence findings

```yaml
name: ActionScope
on: [push, pull_request]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: r12habh/ActionScope@v0
        with:
          fail-on: high
          new-only: true
          min-confidence: high
          save-state: true
          comment-pr: true
          upload-sarif: true
```

This policy fails only when a finding:

1. Is absent from the exact default-branch baseline, or newly crosses the
   configured severity or confidence threshold.
2. Is `HIGH` or `CRITICAL`.
3. Has `high` detection confidence.
4. Is eligible for automated gating.

Existing findings remain visible without blocking unrelated pull requests.

## First Run Behavior

If no exact version-2 baseline is available, a new-only gate returns:

```text
ActionScope gate: NOT EVALUATED. No exact baseline was available, so
new-only findings could not be evaluated.
```

The default exit code is `0`, allowing the first trusted run to seed state.
Set `require-baseline: true` to return exit code `2` instead:

```yaml
with:
  fail-on: high
  new-only: true
  min-confidence: high
  require-baseline: true
```

Use this strict setting only after the default-branch baseline has been
created successfully.

## CLI Usage

Create a baseline:

```bash
actionscope scan . --save-state
```

Compare a later scan and block new high-confidence findings:

```bash
actionscope scan . \
  --load-state \
  --fail-on high \
  --new-only \
  --min-confidence high
```

Evaluate an existing JSON report without rescanning:

```bash
actionscope gate actionscope-results.json \
  --fail-on high \
  --new-only \
  --min-confidence high
```

## Confidence Levels

| Confidence | Typical meaning | Recommended CI use |
|---|---|---|
| `high` | Direct workflow evidence or an exact IAM relationship | Safe starting point for merge blocking |
| `medium` | Strong heuristic or contextual correlation | Report first; enable after review |
| `low` | Ambiguous IAM-policy match or incomplete correlation | Human review only |

Confidence does not change finding severity. It controls how certain
ActionScope is that the reported relationship exists.

## Coverage Gaps

Coverage becomes partial when ActionScope encounters cases such as:

- An AWS role ARN with no matching local IAM policy.
- A role reference computed dynamically at runtime.
- Static AWS keys whose effective IAM principal is unknown.
- An external reusable workflow that could not be inspected.
- An analyzer error.

Coverage gaps are reported, not silently converted into passing findings. Use
`--aws-verify` for read-only live IAM policy resolution when local
infrastructure evidence is unavailable.
