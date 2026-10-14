locals {
  enabled                 = module.this.enabled
  prebuilt_policy_enabled = local.enabled && var.prebuilt_policy.enabled
  name                    = var.fifo_queue_enabled ? format("%s.fifo", module.this.id) : module.this.id
  sqs_queue_arn           = one(aws_sqs_queue.default[*].arn)
  sqs_queue_url           = one(aws_sqs_queue.default[*].url)
}

resource "aws_sqs_queue" "default" {
  count = local.enabled ? 1 : 0

  name                              = local.name
  visibility_timeout_seconds        = var.visibility_timeout_seconds
  message_retention_seconds         = var.message_retention_seconds
  max_message_size                  = var.max_message_size
  delay_seconds                     = var.delay_seconds
  receive_wait_time_seconds         = var.receive_wait_time_seconds
  policy                            = var.policy
  redrive_policy                    = var.redrive_policy
  fifo_queue                        = var.fifo_queue_enabled
  content_based_deduplication       = var.content_based_deduplication_enabled
  kms_master_key_id                 = var.kms_master_key_id
  kms_data_key_reuse_period_seconds = var.kms_data_key_reuse_period_seconds
  deduplication_scope               = var.deduplication_scope
  fifo_throughput_limit             = var.fifo_throughput_limit
  tags                              = module.this.tags
}

data "aws_iam_policy_document" "default" {
  count = local.prebuilt_policy_enabled ? 1 : 0

  statement {
    sid     = var.prebuilt_policy.sid
    actions = var.prebuilt_policy.actions

    resources = [local.sqs_queue_arn]

    principals {
      type        = var.prebuilt_policy.principals.type
      identifiers = var.prebuilt_policy.principals.identifiers
    }

  }
}

resource "aws_sqs_queue_policy" "default" {
  count = local.prebuilt_policy_enabled ? 1 : 0

  queue_url = local.sqs_queue_url
  policy    = one(data.aws_iam_policy_document.default[*].json)
}
