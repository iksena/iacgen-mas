data aws_iam_policy_document s3 {
  count = length(var.s3bucket_arns) > 0 ? 1 : 0

  dynamic statement {
    for_each = var.s3bucket_arns

    content {
      actions = [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:GetObject",
        "s3:GetObjectAcl",
        "s3:DeleteObject"
      ]

      resources = ["${var.s3bucket_arns[statement.key]}/${lookup(var.s3_paths, var.s3bucket_arns[statement.key], "*")}"]
    }
  }

  statement {
    actions   = ["s3:ListBucket"]
    resources = var.s3bucket_arns
  }
}

resource aws_iam_policy s3 {
  count = length(var.s3bucket_arns) > 0 ? 1 : 0

  name   = "${var.username}-S3Policy"
  policy = data.aws_iam_policy_document.s3[0].json
}

resource aws_iam_user_policy_attachment user {
  count = length(var.s3bucket_arns) > 0 ? 1 : 0

  user       = aws_iam_user.user.name
  policy_arn = aws_iam_policy.s3[0].arn
}
