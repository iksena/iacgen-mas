data "aws_caller_identity" "current" {
  provider = aws.primary_region
}
data "aws_partition" "current" {
  provider = aws.primary_region
}
data "aws_iam_policy_document" "assume_role" {
  provider = aws.primary_region
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}
