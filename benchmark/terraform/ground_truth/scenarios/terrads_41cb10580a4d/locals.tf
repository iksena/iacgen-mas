locals {
  output_data = {
    default_sender_id_string              = var.default_sender_id_string
    default_sms_type                      = var.default_sms_type
    delivery_status_success_sampling_rate = var.delivery_status_success_sampling_rate
    iam_role_arn_delivery_status          = var.iam_role_arn_delivery_status
    monthly_spend_limit                   = var.monthly_spend_limit
    usage_report_s3_bucket                = var.usage_report_s3_bucket
  }
}
