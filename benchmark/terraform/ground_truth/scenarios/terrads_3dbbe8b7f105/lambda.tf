data aws_iam_policy_document lambda {
  count = length(var.lambda_arns) > 0 ? 1 : 0

  statement {
    actions   = ["lambda:UpdateFunctionCode"]
    resources = var.lambda_arns
  }
}

resource aws_iam_policy lambda {
  count = length(var.lambda_arns) > 0 ? 1 : 0

  name   = "${var.username}-LambdaPolicy"
  policy = data.aws_iam_policy_document.lambda[0].json
}

resource "aws_iam_user_policy_attachment" lambda {
  count = length(var.lambda_arns) > 0 ? 1 : 0

  user       = aws_iam_user.user.name
  policy_arn = aws_iam_policy.lambda[0].arn
}
