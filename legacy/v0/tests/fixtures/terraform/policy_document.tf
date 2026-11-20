data "aws_iam_policy_document" "s3_readonly" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
  }
}
