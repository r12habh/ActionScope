# Correlated Exposure Paths

ActionScope can connect a risky GitHub Action dependency to AWS credentials
configured in the same workflow job. This answers a more useful question
than either finding alone:

> If this action is compromised, which AWS role and IAM permissions can it
> reach in this job?

## Example

Consider a deployment job with a mutable third-party action followed by AWS
OIDC authentication:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: third-party/deploy-helper@v1
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy
      - run: aws s3 sync dist/ s3://production-bucket/
```

If ActionScope matches that role to an IAM policy, the report includes a
correlated path:

```text
CRITICAL: mutable action -> AWS credentials
Workflow: deploy.yml -> deploy
Action: third-party/deploy-helper@v1
Credential: arn:aws:iam::123456789012:role/github-deploy
Reachable IAM: iam:PassRole, cloudformation:*, s3:PutObject
```

Known-compromised actions are labeled separately and take precedence over an
unpinned-action finding for the same step.

## Correlation Rules

ActionScope emits a path only when all of these are true:

1. A mutable or known-compromised external action is present.
2. An AWS credential source is present in the same workflow file.
3. Both occur in the same job.

The detector does not connect findings across unrelated jobs merely because
they are in the same workflow. GitHub job isolation, dependencies, outputs,
artifacts, and runner reuse can affect real reachability; treating every pair
as connected would create misleading paths.

Reusable workflows are analyzed in their own workflow and job context. When an
external reusable workflow is inspected with `--github-token`, SARIF attributes
the resulting path to the local root caller and names the delegated source.

## IAM Context

When a policy is matched locally or fetched with `--aws-verify`, ActionScope
shows up to five reachable HIGH or CRITICAL IAM actions, ordered by severity.
It also marks paths that reach a detected privilege-escalation combination.
The report preserves the binding's match confidence so path-based or
content-based heuristic matches are not presented as exact role relationships.

When the policy is unavailable, the path is still reported because the action
can reach AWS credentials, but the report says that the IAM blast radius is
unknown. Run the live verifier for the missing policy context:

```bash
pip install "actionscope[aws]"
actionscope scan . --aws-verify
```

## Output Formats

- Terminal and Markdown include a **Correlated Exposure Paths** section.
- JSON includes an `exposure_paths` array and `summary.exposure_paths` count.
- SARIF emits rule **AS016** and links a matched local IAM policy as a related
  location.

Standalone action and IAM findings remain in the report so integrations that
consume existing rule IDs continue to work.
