output "vault_arn" {
  value       = aws_backup_vault.vault.arn
  description = "ARN of the backup vault."
}

output "plan_arn" {
  value       = aws_backup_plan.plan.arn
  description = "ARN of the Backup Plan"
}

output "iam_role_arn" {
  value       = aws_iam_role.iam_role.arn
  description = "ARN of the IAM role created for Backup"
}

output "kms_key_arn" {
  value       = local.create_kms_key ? aws_kms_key.kms_key[0].arn : null
  description = "ARN of the KMS Key if created, otherwise null"
}
