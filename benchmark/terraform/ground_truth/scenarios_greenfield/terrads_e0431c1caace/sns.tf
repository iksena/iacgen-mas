resource "aws_kms_key" "sg_sns_topic" {
  description         = "CMK for ${var.sns_topic_name} SNS topic"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountRoot"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "kms:*"
        Resource  = "*"
        Condition = { StringEquals = { "kms:CallerAccount" = data.aws_caller_identity.current.account_id } }
      },
      {
        Sid       = "AllowCloudWatchToPublish"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_sns_topic" "sg_sns_topic" {
  name              = var.sns_topic_name
  kms_master_key_id = aws_kms_key.sg_sns_topic.key_id
}

resource "aws_sns_topic_subscription" "user_updates_sqs_target" {
  for_each   = toset(var.email_list)
  depends_on = [aws_sns_topic.sg_sns_topic]
  topic_arn  = aws_sns_topic.sg_sns_topic.arn
  protocol   = "email"
  endpoint   = each.value
}
