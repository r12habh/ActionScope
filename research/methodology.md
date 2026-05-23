# Methodology

## Data Source

The public scan uses GitHub Code Search to find workflow files containing
`aws-actions/configure-aws-credentials` under `.github/workflows`. Only public
GitHub repository content returned by the GitHub API is downloaded.

## Collection Query

```text
aws-actions/configure-aws-credentials path:.github/workflows
```

The scanner deduplicates by repository full name, then downloads every
`.yml` and `.yaml` workflow file from each repository's `.github/workflows`
directory.

## Authentication and Rate Limits

Use a GitHub Personal Access Token through the `GITHUB_TOKEN` environment
variable. The token is used only for GitHub API authentication. GitHub Code
Search has a low request limit, so the scanner backs off on `403`, `429`, and
`Retry-After` responses.

## Measurements

Each workflow is parsed locally with ActionScope's workflow parser. The scanner
records:

- OIDC usage through `role-to-assume` plus `id-token: write`
- Static AWS access key usage through `aws-access-key-id` or
  `AWS_ACCESS_KEY_ID`
- Direct role ARN presence
- GITHUB_TOKEN write scopes, including `write-all`
- `pull_request_target` triggers
- `pull_request_target` paired with write-capable token permissions
- Floating action references such as `actions/checkout@v4`

## Validation

We manually reviewed a deterministic stratified sample of 50 workflows from the
same GitHub Code Search population. The sample intentionally overrepresents
positive examples for rare fields such as `write-all`, `pull_request_target`,
and visible role ARNs, so validation TP/TN counts should not be read as
population frequencies.

The validation sample found 100.0% precision across all measured fields.
Recall was 100.0% for OIDC usage, visible role ARNs, `write-all`,
`pull-requests: write`, `pull_request_target`, and the dangerous
`pull_request_target` combination; 90.5% for static access-key usage; and
95.7% for non-SHA-pinned external action references.

## Privacy and Publication

Generated output is anonymized by default:

- Repository names are replaced with stable SHA-256 hashes
- Role ARNs are omitted unless `--include-role-arns` is set
- Aggregated percentages are safe to publish

Do not publish non-anonymized repository lists or role ARNs without a clear
reason and a separate review.

## Limitations

This method cannot see private IAM policies, AWS account configuration, branch
protection, organization rules, environment protection, or secret values. A
workflow can look risky while being constrained elsewhere, and a workflow can
look minimal while its AWS role is over-privileged. Treat the results as
workflow-layer exposure, not full cloud blast radius.

## Reproducibility

Record the generated timestamp, query, target repository count, and script
version in the output JSON. Keep the raw anonymized JSON file with the report so
others can recalculate the aggregate statistics.

## Publication Status

The technical paper draft is pending publication and should not be linked from
public docs, README files, package metadata, or launch posts until explicitly
approved for public sharing.
