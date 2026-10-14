output "cloudtrail_id" {
  description = "The name of the trail"
  value       = aws_cloudtrail.main.id
}

output "cloudtrail_arn" {
  description = "The Amazon Resource Name of the trail"
  value       = aws_cloudtrail.main.arn
}

output "s3_bucket_id" {
  description = "The name of the S3 bucket"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "s3_bucket_arn" {
  description = "The ARN of the S3 bucket"
  value       = aws_s3_bucket.cloudtrail_logs.arn
}

output "kms_key_arn" {
  description = "The ARN of the KMS key used for encrypting CloudTrail logs"
  value       = aws_kms_key.cloudtrail.arn
}

output "cloudwatch_log_group_arn" {
  description = "The ARN of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.cloudtrail.arn
}

output "sns_topic_arn" {
  description = "The ARN of the SNS topic used for CloudTrail notifications"
  value       = var.create_sns_topic ? aws_sns_topic.cloudtrail_alerts[0].arn : var.existing_sns_topic_arn
}

output "kms_key_id" {
  description = "The ID of the KMS key used for encrypting CloudTrail logs"
  value       = aws_kms_key.cloudtrail.key_id
}