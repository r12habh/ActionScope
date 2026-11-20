resource "aws_iam_role" "github_deploy" {
  name = "github-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = []
  })
}

resource "aws_iam_policy" "deploy_policy" {
  name   = "GitHubDeployPolicy"
  policy = file("role_attachment_policy.json")
}

resource "aws_iam_role_policy_attachment" "deploy" {
  role       = aws_iam_role.github_deploy.name
  policy_arn = aws_iam_policy.deploy_policy.arn
}
