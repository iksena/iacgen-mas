/**
 * # AWS SFTP with EFS Terraform Module
 *
 * This module set up EFS with AWS Transfer Family for accessing AxeTrading server files for managed service customers.
 *
 * # Connect to sftp server: 
 *
 * sftp -i path-to-private-key sftp-username@sftp-server-address
 *
 * # Mounting instructions:
 *
 * Run the following command to install the amazon-efs-utils package: sudo yum install -y amazon-efs-utils
 *
 * sudo mount -t efs -o tls EFS_ID:/ EFS_ID
 *
 * sudo chown -R ec2-user:ec2-user EFS_ID
 *
 * sudo chmod -R 755 EFS_ID
 */

locals {
  role_arn = var.create_iam_role ? aws_iam_role.sftp_user_role[0].arn : var.provided_iam_role_arn
}

# Create AWS Transfer Family SFTP Server
resource "aws_transfer_server" "sftp_server" {
  lifecycle {
    create_before_destroy = true
  }
  identity_provider_type = var.identity_provider_type
  protocols              = ["SFTP"]
  endpoint_type          = var.vpc_id != null ? "VPC" : "PUBLIC"
  security_policy_name   = var.security_policy_name
  domain                 = var.sftp_domain
  logging_role           = var.logging_enabled ? aws_iam_role.logging[0].arn : null

  dynamic "endpoint_details" {
    for_each = var.vpc_id != null ? [1] : []
    content {
      subnet_ids             = var.subnets
      vpc_id                 = var.vpc_id
      security_group_ids     = var.create_sftp_security_group ? compact(concat([aws_security_group.sftp[0].id], var.sftp_security_group_ids)) : var.sftp_security_group_ids
      address_allocation_ids = var.is_public ? aws_eip.eip.*.id : var.eip_ids
    }
  }
  force_destroy = var.identity_provider_type == "SERVICE_MANAGED" ? true : false
  tags          = merge({ Name = var.sftp_name }, var.tags)
}

# Create AWS Transfer Family SFTP User
resource "aws_transfer_user" "sftp_user" {
  for_each = var.sftp_users

  server_id = aws_transfer_server.sftp_server.id
  user_name = each.key

  home_directory_type = var.home_directory_type
  home_directory      = each.value.home_directory != null ? format("/%s/%s", aws_efs_file_system.efs.id, each.value.home_directory) : format("/%s/%s", aws_efs_file_system.efs.id, each.key)

  dynamic "home_directory_mappings" {
    for_each = each.value.restricted ? [true] : []
    content {
      entry  = "/"
      target = "/${aws_efs_file_system.efs.id}/${each.key}"
    }
  }

  posix_profile {
    uid = each.value.uid
    gid = each.value.gid
  }

  role = local.role_arn

  tags = merge({ Name = each.key }, var.tags)

}

### Asociate SFTP User with his ssh public key
resource "aws_transfer_ssh_key" "sftp_ssh_key" {
  for_each  = var.sftp_users
  server_id = aws_transfer_server.sftp_server.id
  user_name = each.key
  body      = each.value.public_key
  depends_on = [
    aws_transfer_user.sftp_user
  ]
}


