
resource "aws_security_group" "sftp" {
  count = var.create_sftp_security_group ? 1 : 0

  name        = var.sftp_security_group_name
  description = "Security Group for SFTP Server"
  vpc_id      = var.vpc_id
  tags        = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "this" {
  for_each = { for k, v in var.sftp_security_group_rules : k => v if var.create_sftp_security_group }

  # Required
  security_group_id = aws_security_group.sftp[0].id
  protocol          = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  type              = each.value.type

  # Optional
  description              = try(each.value.description, null)
  cidr_blocks              = try(each.value.cidr_blocks, null)
  ipv6_cidr_blocks         = try(each.value.ipv6_cidr_blocks, null)
  prefix_list_ids          = try(each.value.prefix_list_ids, [])
  self                     = try(each.value.self, null)
  source_security_group_id = try(each.value.source_security_group_id, null)
}