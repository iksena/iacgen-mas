provider "aws" {
  region = "ap-northeast-2"
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "notification_queue" {
  description             = "CMK for the notificationQueue SQS queue"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

# Define the SQS queue
resource "aws_sqs_queue" "notification_queue" {
  name                       = "notificationQueue"
  delay_seconds              = 0
  max_message_size           = 2048
  message_retention_seconds  = 345600
  visibility_timeout_seconds = 30
  kms_master_key_id          = aws_kms_key.notification_queue.id
}

resource "aws_sqs_queue_policy" "sqs_policy" {
  queue_url = aws_sqs_queue.notification_queue.id
  policy    = data.aws_iam_policy_document.sqs_policy_document.json
}

data "aws_iam_policy_document" "sqs_policy_document" {
  statement {
    sid    = "sqs_policy"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.account_id]
    }

    actions = [
      "sqs:SendMessage",
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]
    resources = [aws_sqs_queue.notification_queue.arn]
  }
}
