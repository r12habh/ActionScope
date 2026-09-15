# GitHub Environments hardening

GitHub Environments give deployment jobs a named boundary such as
`production`. An environment can require reviewers, restrict which branches
may deploy, and expose environment-scoped secrets only after its protection
rules pass. Those controls are useful when a workflow uses GitHub OIDC to
assume an AWS role.

ActionScope checks whether an AWS credential-bearing deployment job declares an
environment and whether the related OIDC trust evidence uses that same
environment. The detector is a hardening signal: it does not prove that a
workflow is exploitable, and it does not evaluate GitHub's protection rules or
AWS policy conditions at runtime.

## Findings

The detector reports two finding types. Both are `MEDIUM` severity and are
represented by SARIF rule `AS014`.

### `deploy_without_environment`

An AWS deploy job does not declare a GitHub Environment. Without an
environment, GitHub cannot apply environment reviewers or branch gates before
the job receives its OIDC token.

This finding is raised only when ActionScope also sees an AWS credential source
and the job looks like a deployment. Deployment signals include names such as
`deploy`, `release`, `publish`, `prod`, or `production`, deployment commands
such as `terraform apply` and `sam deploy`, and selected AWS deployment
actions. A build or read-only audit job that merely obtains AWS credentials is
not treated as a deployment by this detector.

### `environment_not_in_trust_policy`

The job declares an environment, but the related OIDC trust evidence is scoped
to a branch reference such as `:ref:refs/heads/main` rather than the
environment subject `:environment:<name>`.

Branch scoping is still narrower than an organization-wide wildcard. The
finding explains that the workflow and trust policy use different boundaries;
review the repository's branch protection and deployment controls before
deciding whether to change the role.

## Supported workflow forms

ActionScope recognizes the short string form:

```yaml
jobs:
  deploy:
    environment: production
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy-role
          aws-region: us-east-1
      - run: terraform apply -auto-approve
```

It also recognizes the object form. `name` is the value used for the OIDC
subject; `url` is retained as the environment's deployment URL.

```yaml
jobs:
  deploy:
    environment:
      name: production
      url: https://example.invalid
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy-role
          aws-region: us-east-1
      - run: sam deploy --no-confirm-changeset
```

The analyzer does not resolve arbitrary expression values at runtime. Keep
the environment name and the trust-policy subject explicit when possible.

## Unsafe and safer boundaries

An unsafe pairing is a production job without an environment:

```yaml
jobs:
  deploy:
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy-role
          aws-region: us-east-1
      - run: aws cloudformation deploy --template-file template.yml
```

The corresponding trust policy may be branch-scoped:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:ref:refs/heads/main"
      }
    }
  }]
}
```

A safer production pairing names the environment in both places:

```yaml
jobs:
  deploy:
    environment: production
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy-role
          aws-region: us-east-1
      - run: aws cloudformation deploy --template-file template.yml
```

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:environment:production"
      }
    }
  }]
}
```

Configure the `production` environment in repository settings with the
reviewers and branch restrictions that match the deployment policy. The trust
policy subject is an additional AWS-side boundary; it does not configure the
GitHub Environment for you.

## How to interpret `AS014`

`AS014` is a medium hardening finding. It identifies a mismatch or a missing
deployment boundary in static repository evidence. It does not establish that
an attacker can obtain the role, that the environment has no protection rules,
or that AWS will accept the token. Verify the following before changing a
role:

1. The job really deploys or publishes infrastructure.
2. The `role-to-assume` value resolves to the role whose trust evidence was
   found.
3. The repository's `production` environment has the intended reviewers and
   branch restrictions.
4. The trust policy's `aud` and `sub` conditions match the workflow's actual
   OIDC claims.

If the role or trust policy is external, ActionScope has incomplete static
evidence. Inspect the role trust policy in AWS and confirm that its `sub`
condition matches the environment. The `--aws-verify` mode can enrich IAM
permission evidence, but it does not currently import role trust policies for
this detector. ActionScope also does not fetch or infer GitHub Environment
protection rules, evaluate dynamic matrix or `if:` expressions, or prove the
effective permissions of a role.

## Running the check

```bash
actionscope scan .
```

Review `AS014` together with the OIDC trust findings and the coverage notes in
[Limitations and Calibration](limitations.md). The scan is most useful as a
review prompt in pull requests and deployment changes, followed by validation
in GitHub and AWS.
