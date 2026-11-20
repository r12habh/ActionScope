# AWS Permissions Required for --aws-verify

ActionScope's --aws-verify mode makes read-only IAM API calls.
It requires these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

This policy grants no write access and cannot modify any resources.
It can only read IAM role and policy metadata.

Save this as your "ActionScope Read" policy in AWS and attach it
to the identity running actionscope locally.
