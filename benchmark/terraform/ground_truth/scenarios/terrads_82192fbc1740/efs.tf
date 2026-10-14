resource "aws_efs_file_system" "efs" {
  creation_token                  = var.efs_name
  encrypted                       = var.encrypted
  kms_key_id                      = var.kms_key_id
  performance_mode                = var.performance_mode
  provisioned_throughput_in_mibps = 0
  tags                            = merge({ Name = var.efs_name }, var.tags)
  throughput_mode                 = var.throughput_mode
}

resource "aws_efs_mount_target" "mount_target" {
  for_each        = toset(var.subnets)
  file_system_id  = aws_efs_file_system.efs.id
  subnet_id       = each.value
  security_groups = var.create_efs_security_group ? compact(concat([aws_security_group.efs[0].id], var.security_groups)) : var.security_groups
}

resource "aws_efs_access_point" "user_access_point" {
  for_each = var.enable_user_access_point ? var.sftp_users : {}

  file_system_id = aws_efs_file_system.efs.id

  posix_user {
    uid = each.value.uid
    gid = each.value.gid
  }
  root_directory {
    path = each.value.home_directory != null ? format("/%s", each.value.home_directory) : format("/%s", each.key)
    creation_info {
      owner_uid   = each.value.uid
      owner_gid   = each.value.gid
      permissions = "0755"
    }
  }
  tags = merge({ Name = each.key }, var.tags)
}

resource "aws_efs_access_point" "additional_access_point" {
  for_each = var.additional_access_points

  file_system_id = aws_efs_file_system.efs.id

  posix_user {
    uid = each.value.uid
    gid = each.value.gid
  }
  root_directory {
    path = each.value.path
    creation_info {
      owner_uid   = each.value.uid
      owner_gid   = each.value.gid
      permissions = each.value.permissions
    }
  }
  tags = merge({ Name = each.key }, var.tags)
}
