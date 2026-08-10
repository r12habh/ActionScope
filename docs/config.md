# Repository Risk Policy (`.actionscope.yml`)

ActionScope supports a versioned repository policy for tuning IAM severity,
adding organization-specific escalation paths, enforcing hard blocks, and
recording time-bounded suppressions.

Create a documented starter file:

```bash
actionscope config init
```

ActionScope automatically loads `.actionscope.yml` from the scanned repository
root. Use a different file with:

```bash
actionscope scan . --config security/actionscope.yml
```

## Complete Example

```yaml
version: 1

critical_actions:
  - kms:Decrypt
  - secretsmanager:GetSecretValue

accepted_risks:
  - cloudwatch:PutMetricData

hard_blocks:
  - iam:CreateAccessKey
  - iam:CreateUser

custom_privesc_paths:
  - id: custom_data_exfiltration
    name: Bedrock and S3 data exfiltration
    required_actions:
      - bedrock:InvokeModel
      - s3:GetObject
    description: Can send data read from S3 to a model endpoint.
    severity: high
    example_attack: Read sensitive S3 objects and include them in model prompts.

severity_overrides:
  AS014: low

deploy_job_patterns:
  - deploy*
  - release*
non_deploy_job_patterns:
  - "*plan*"

suppress:
  - rule: AS005
    reason: Legacy vendor key is rotated weekly while OIDC migration is underway.
    expires: 2026-12-31
```

## IAM Action Policy

`critical_actions` elevates matching IAM actions to CRITICAL.
`accepted_risks` lowers matching actions to LOW while keeping them visible.
Shell-style wildcards are supported in the action part, such as `kms:*` or
`iam:Create*`. The service name must be exact or the complete `*` wildcard;
partial service wildcards such as `s3*:GetObject` are rejected.

`hard_blocks` always fail the scan, even when `--fail-on` is not set. A hard
block cannot be neutralized by a suppression or severity override.

When settings overlap, ActionScope applies this precedence:

1. `hard_blocks`
2. `critical_actions`
3. `accepted_risks`
4. `severity_overrides`
5. Built-in classification

## Custom Escalation Paths

Each `custom_privesc_paths` entry triggers when all `required_actions` are
present in one parsed IAM policy. The finding uses SARIF rule AS002 and appears
with built-in escalation paths in terminal, Markdown, JSON, and SARIF output.
An `AS002` entry in `severity_overrides` takes precedence over the severity on
both built-in and repository-defined escalation paths.

## Rule Severity Overrides

`severity_overrides` maps an ActionScope SARIF rule ID to `critical`, `high`,
`medium`, `low`, or `info`. This is most useful for calibrating hardening rules
such as AS014 to a repository's deployment model.

See [SARIF and Code Scanning](sarif.md) for the rule catalog.

Configuration files are limited to 256 KiB so an untrusted branch cannot make
the Marketplace Action parse an unbounded YAML document.

## Suppressions

Suppressions require a rule ID, a reason, and an ISO date (`YYYY-MM-DD`). They
remain active through the expiry date. Expired entries generate a warning and
are not applied.

An active suppression excludes that rule from:

- `--fail-on` and confidence-aware CI gates
- SARIF / GitHub Code Scanning alerts
- effective risk and gate finding counts

The underlying finding remains visible in terminal and Markdown reports next
to the suppression reason and expiry. This preserves an audit trail and avoids
silent risk acceptance.

## Deploy-Job Calibration

`deploy_job_patterns` marks repository-specific job names as deployment jobs.
`non_deploy_job_patterns` excludes names such as `terraform-plan` even when a
built-in deploy keyword is present. Exclusions take precedence over inclusions
and built-in heuristics.

## GitHub Action

The Marketplace Action automatically discovers `.actionscope.yml` beneath its
`path` input. To use a different file:

```yaml
- uses: r12habh/ActionScope@v0
  with:
    path: .
    config: security/actionscope.yml
    fail-on: high
```

Treat changes to `.actionscope.yml` like changes to a CI security policy:
require review from the team that owns your deployment controls.
