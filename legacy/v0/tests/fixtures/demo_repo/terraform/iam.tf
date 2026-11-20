# IAM policies for GitHub Actions OIDC roles in this demo repository.

resource "aws_iam_role_policy" "github_deploy" {
  name = "github-deploy-inline"
  role = "github-deploy-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
        ]
        Resource = "arn:aws:s3:::demo-app-artifacts/*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:GetFunctionConfiguration",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "cloudformation:*"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "ec2:DescribeInstances"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy" "github_release" {
  name = "github-release-inline"
  role = "github-release-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = "arn:aws:s3:::demo-releases-bucket/*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
        ]
        Resource = "*"
      },
    ]
  })
}
