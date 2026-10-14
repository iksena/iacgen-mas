
resource "aws_kms_key" "kms_key" {
  count               = local.create_kms_key ? 1 : 0
  description         = "KMS key for Backup Encryption at rest"
  enable_key_rotation = true

  tags = {
    Name = "${local.name}-backup-encryption-key"
  }
}

resource "aws_backup_vault" "vault" {
  name        = "${local.name}-backup-vault"
  kms_key_arn = local.kms_key_arn
  tags = {
    Name = "${local.name}-backup-vault"
  }
}


resource "aws_backup_plan" "plan" {
  name = "${local.name}-backup-plan"
  tags = {
    Name = "${local.name}-backup-plan"
  }

  rule {
    rule_name         = "${local.name}-backup-rule"
    target_vault_name = aws_backup_vault.vault.name
    schedule          = var.backup_schedule

    dynamic "lifecycle" {
      for_each = var.cold_storage_after != null || var.delete_after != null ? [1] : []
      content {
        cold_storage_after = var.cold_storage_after
        delete_after       = var.delete_after
      }
    }
    dynamic "copy_action" {
      for_each = var.secondary_vault_arn != null ? [1] : []
      content {
        destination_vault_arn = var.secondary_vault_arn
        dynamic "lifecycle" {
          for_each = local.secondary_vault_cold_storage_after != null || local.secondary_vault_delete_after != null ? [1] : []
          content {
            cold_storage_after = local.secondary_vault_cold_storage_after
            delete_after       = local.secondary_vault_delete_after
          }
        }
      }
    }

    recovery_point_tags = {
      Name = "${local.name}-backup-recovery-point"
    }

  }
}

resource "aws_iam_role" "iam_role" {
  name               = "${local.name}-backup-role"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": ["sts:AssumeRole"],
      "Effect": "allow",
      "Principal": {
        "Service": ["backup.amazonaws.com"]
      }
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "iam_role_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
  role       = aws_iam_role.iam_role.name
}


resource "aws_backup_selection" "selection" {
  name         = "${local.name}-backup-selection"
  iam_role_arn = aws_iam_role.iam_role.arn

  plan_id = aws_backup_plan.plan.id

  dynamic "selection_tag" {
    for_each = var.selection_tags
    content {
      type  = lookup(selection_tag.value, "type", "STRINGEQUALS")
      key   = lookup(selection_tag.value, "key", "backup")
      value = lookup(selection_tag.value, "value", "true")
    }
  }
}
