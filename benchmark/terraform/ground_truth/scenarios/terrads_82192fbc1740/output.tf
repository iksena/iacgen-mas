### EFS 
output "efs_file_system_id" {
  description = "EFS ID"
  value       = try(aws_efs_file_system.efs[*].id, "")
}

output "efs_file_system_arn" {
  description = "EFS ARN"
  value       = try(aws_efs_file_system.efs[*].arn, "")
}

output "efs_mount_target_ids" {
  description = "EFS Mount targets"
  value       = try(values(aws_efs_mount_target.mount_target)[*].id, [])

}

output "efs_mount_target_dns_names" {
  description = "EFS Mount targets DNS name"
  value       = try(values(aws_efs_mount_target.mount_target)[*].dns_name, [])
}

### SFTP 
output "sftp_server_arn" {
  description = "SFTP SERVER ARN"
  value       = aws_transfer_server.sftp_server.arn
}

output "sftp_server_id" {
  description = "SFTP SERVER ID"
  value       = aws_transfer_server.sftp_server.id
}

output "sftp_user_usernames" {
  description = "SFTP SERVER USERS"
  value       = [for user in aws_transfer_user.sftp_user : user.user_name]
}

output "sftp_server_endpoint" {
  description = "SFTP SERVER ENDPOINT"
  value       = try(aws_transfer_server.sftp_server.endpoint, "")
}


### IAM
output "iam_role_arn" {
  description = "IAM ROLE ARN used for SFTP users"
  value       = aws_iam_role.sftp_user_role[0].arn
}

### EIP
output "sftp_elastic_ips" {
  description = "Provisioned Elastic IPs"
  value       = var.is_public ? aws_eip.eip.*.id : null
}


# Security Groups

output "sftp_security_group_id" {
  description = "SFTP Security Group ID"
  value       = try(aws_security_group.sftp[0].id, "")
}

output "efs_security_group_id" {
  description = "EFS Security Group ID"
  value       = try(aws_security_group.efs[0].id, "")
}

output "user_access_points" {
  description = "Information about the user-specific EFS access points"
  value = {
    for user, access_point in aws_efs_access_point.user_access_point : user => {
      id             = access_point.id
      arn            = access_point.arn
      file_system_id = access_point.file_system_id
    }
  }
  sensitive = false
}

output "additional_access_points" {
  description = "Information about the general-use EFS access points"
  value = {
    for name, access_point in aws_efs_access_point.additional_access_point : name => {
      id             = access_point.id
      arn            = access_point.arn
      file_system_id = access_point.file_system_id
    }
  }
  sensitive = false
}
