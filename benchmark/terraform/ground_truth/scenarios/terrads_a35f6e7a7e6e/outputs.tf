output "id" {
  value       = one(aws_sqs_queue.default[*].id)
  description = "The URL for the created Amazon SQS queue."
}

output "arn" {
  value       = local.sqs_queue_arn
  description = "The ARN of the SQS queue."
}

output "url" {
  value       = local.sqs_queue_url
  description = "The URL for the created Amazon SQS queue."
}

output "name" {
  value       = one(aws_sqs_queue.default[*].name)
  description = "The name of Amazon SQS queue."
}
