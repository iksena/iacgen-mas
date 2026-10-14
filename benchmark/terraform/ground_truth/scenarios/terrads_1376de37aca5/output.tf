output "group_admin_name" {
  description = "The admin groups name"
  value       = aws_iam_group.admin.name
}

output "group_admin_id" {
  description = "The admin groups ID"
  value       = aws_iam_group.admin.id
}

output "group_admin_arn" {
  description = "The ARN assigned by AWS for the admin group"
  value       = aws_iam_group.admin.arn
}

output "group_admin_path" {
  description = "The path of the admin group in IAM"
  value       = aws_iam_group.admin.path
}

output "group_admin_users" {
  description = "List of IAM User names in the admin group"
  value       = aws_iam_group_membership.admin.*.users
}

output "role_admin_name" {
  description = "The name of the admin role"
  value       = aws_iam_role.admin.name
}

output "role_admin_id" {
  description = "The ID of the admin role"
  value       = aws_iam_role.admin.id
}

output "role_admin_arn" {
  description = "The ARN of the admin role"
  value       = aws_iam_role.admin.arn
}


output "group_other_name" {
  description = "The other groups name"
  value       = aws_iam_group.other.name
}

output "group_other_id" {
  description = "The other groups ID"
  value       = aws_iam_group.other.id
}

output "group_other_arn" {
  description = "The ARN assigned by AWS for the other group"
  value       = aws_iam_group.other.arn
}

output "group_other_path" {
  description = "The path of the other group in IAM"
  value       = aws_iam_group.other.path
}

output "group_other_users" {
  description = "List of IAM User names in the other group"
  value       = aws_iam_group_membership.other.*.users
}
