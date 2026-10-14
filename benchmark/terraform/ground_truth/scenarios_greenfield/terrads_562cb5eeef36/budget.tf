data "aws_iam_policy_document" "budget" {
  statement {
    actions   = ["SNS:Publish"]
    effect    = "Allow"
    resources = [aws_sns_topic.budget.arn]
    principals {
      type        = "Service"
      identifiers = ["budgets.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "budget" {
  description         = "CMK for the budget alerts topic"
  enable_key_rotation = true
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid = "AccountAdmin", Effect = "Allow", Action = "kms:*", Resource = "*",
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" } },
    { Sid = "AllowBudgetsPublish", Effect = "Allow", Action = ["kms:GenerateDataKey*", "kms:Decrypt"], Resource = "*",
      Principal = { Service = "budgets.amazonaws.com" } }
  ] })
}

resource "aws_sns_topic" "budget" {
  name              = "budget"
  kms_master_key_id = aws_kms_key.budget.arn
}

resource "aws_sns_topic_policy" "budget" {
  arn    = aws_sns_topic.budget.arn
  policy = data.aws_iam_policy_document.budget.json
}

resource "aws_sns_topic_subscription" "budget" {
  topic_arn = aws_sns_topic.budget.arn
  protocol  = "sms"
  endpoint  = "+447828835419"
}

resource "aws_budgets_budget" "budget" {
  name              = "budget"
  budget_type       = "COST"
  limit_amount      = "25.0"
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = "2021-07-01_00:00"

  notification {
    notification_type          = "ACTUAL"
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    subscriber_email_addresses = ["hello@chriswilding.co.uk"]
    subscriber_sns_topic_arns  = [aws_sns_topic.budget.arn]
  }
}
