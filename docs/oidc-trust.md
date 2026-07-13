# GitHub Actions OIDC Trust Policy Misconfigurations

GitHub Actions OIDC lets workflows assume cloud roles without storing
long-lived access keys in GitHub Secrets. For AWS, the workflow requests an
OIDC token from GitHub, then exchanges it through `sts:AssumeRoleWithWebIdentity`.

The security boundary is the IAM role trust policy. If that policy is too broad,
more workflows can assume the role than intended.

## What ActionScope Checks

ActionScope scans Terraform and JSON trust policies for GitHub's OIDC provider:

```text
token.actions.githubusercontent.com
```

It reports the following issues.

## Missing `sub` Condition

The `sub` claim identifies which repository, branch, tag, pull request, or
environment the workflow came from.

Risky trust policy:

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    }
  }
}
```

Without a `token.actions.githubusercontent.com:sub` condition, the role is not
scoped to a specific GitHub repository or workflow context.

ActionScope reports this as `AS008 OIDCMissingSubCondition`.

## Wildcard Organization Subject

A common misconfiguration is scoping the subject to an entire organization:

```json
{
  "StringLike": {
    "token.actions.githubusercontent.com:sub": "repo:acme-corp/*"
  }
}
```

This does **not** mean "only our production repository." It means any repository
under `acme-corp`, including test repositories, archived projects, and newly
created repositories, may be able to assume the role.

ActionScope reports this as `AS007 OIDCWildcardSubject`.

ActionScope also catches broader variants that are easy to overlook:

```json
{
  "StringLike": {
    "token.actions.githubusercontent.com:sub": [
      "repo:*",
      "repo:acme-corp/api:*",
      "repo:acme-corp/api:ref:refs/heads/*"
    ]
  }
}
```

The first pattern crosses repository and organization boundaries. The latter
two stay within one repository but allow every workflow context or branch.

## `ForAllValues` on Single-Valued Claims

`ForAllValues` and `ForAnyValue` are IAM set operators. They are intended for
request context keys that can carry multiple values. GitHub's OIDC `sub` and
`aud` claims are single-valued, so a trust policy should use scalar
`StringLike` or `StringEquals` operators instead.

Risky trust policy:

```json
{
  "ForAllValues:StringLike": {
    "token.actions.githubusercontent.com:sub":
      "repo:acme-corp/api:ref:refs/heads/main"
  }
}
```

AWS warns that `ForAllValues` in an `Allow` statement evaluates to true when
the request context key is absent. ActionScope reports this as a medium-risk
operator error and includes a corrected condition block in terminal, JSON,
Markdown, and SARIF output:

```json
{
  "StringLike": {
    "token.actions.githubusercontent.com:sub":
      "repo:acme-corp/api:ref:refs/heads/main"
  }
}
```

The `amr` claim is multivalued and is not flagged when it legitimately uses a
set operator. ActionScope also ignores `Deny` statements for this check; the
overly permissive behavior is relevant to statements that grant role
assumption.

See AWS's documentation on
[single-valued and multivalued context keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html)
and
[GitHub OIDC role trust policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html#idp_oidc_Create_GitHub).

## Branch vs Environment Scoping

Branch scoping is better than organization-wide scoping:

```json
{
  "StringEquals": {
    "token.actions.githubusercontent.com:sub": "repo:acme-corp/api:ref:refs/heads/main"
  }
}
```

For production deploy roles, GitHub Environments are usually stronger:

```json
{
  "StringEquals": {
    "token.actions.githubusercontent.com:sub": "repo:acme-corp/api:environment:production"
  }
}
```

Environment scoping lets GitHub Environment protection rules add required
reviewers and deployment gates before a workflow can receive the OIDC token.

## Missing `aud` Condition

The `aud` claim should be constrained to AWS STS:

```json
{
  "StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
  }
}
```

ActionScope reports missing `aud` as a medium-severity hardening issue.

## Recommended Trust Policy

For a production deployment from a protected GitHub Environment:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:acme-corp/api:environment:production"
        }
      }
    }
  ]
}
```

Workflow job:

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
```

## Running the Check

```bash
actionscope scan .
```

ActionScope automatically scans Terraform `aws_iam_role.assume_role_policy`
values and standalone JSON trust-policy files.
