resource "aws_iam_service_linked_role" "main" {
  aws_service_name = "es.amazonaws.com"
}

data "aws_iam_policy_document" "main" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:PutLogEventsBatch",
    ]

    resources = ["arn:aws:logs:*"]

    principals {
      identifiers = ["es.amazonaws.com"]
      type        = "Service"
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "main" {
  policy_document = data.aws_iam_policy_document.main.json
  policy_name     = "elasticsearch-log-publishing-policy"
}

