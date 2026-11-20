# The IAM definition lives here, in a different file from the workflow.
# This is the evidence ActionScope joins to the workflow above to answer
# "what can this CI workflow actually do in AWS if compromised?"

resource "aws_iam_role" "deploy" {
  name = "github-actions-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      # Note: no `sub` condition scoping this to a specific repo/branch.
    }]
  })
}

resource "aws_iam_policy" "deploy" {
  name = "github-actions-deploy-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:TerminateInstances", "ec2:RunInstances"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "deploy" {
  role       = aws_iam_role.deploy.name
  policy_arn = aws_iam_policy.deploy.arn
}
