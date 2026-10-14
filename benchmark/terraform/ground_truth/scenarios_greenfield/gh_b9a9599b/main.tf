data "aws_caller_identity" "current" {}

resource "aws_kms_key" "sns" {
  description             = "CMK for the incident-response SNS topic"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_sns_topic" "this" {
  name              = "incident-response"
  kms_master_key_id = aws_kms_key.sns.id
}

resource "aws_sns_topic_policy" "this" {
  arn = aws_sns_topic.this.arn

  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

data "aws_iam_policy_document" "sns_topic_policy" {
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        data.aws_caller_identity.current.account_id,
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      aws_sns_topic.this.arn,
    ]

    sid = "__default_statement_ID"
  }

  statement {
    actions = [
      "sns:Publish"
    ]
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [
      aws_sns_topic.this.arn,
    ]

    sid = "AllowAWSEvents"
  }
}
