resource "aws_iam_role_policy" "ci_deploy" {
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole", "ec2:DescribeInstances"]
        Resource = "*"
      }
    ]
  })
}
