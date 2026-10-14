# ################################################################
# . Author : Ankit Upadhyay
# . Follow me on github for more aws maintainance resources  http://github.com/ankitosh
# 
# ################################################################

resource "aws_backup_vault" "BackupVault_premium" {
  name        = "Premium"
  kms_key_arn = aws_kms_key.backup_key.arn
}

resource "aws_backup_plan" "BackupPlan_premium" {
  name = "Premium"

  rule {
    rule_name         = "Premium_Daily_4Hour_Backup"
    schedule          = "cron(0 0/4 ? * * *)"
    target_vault_name = aws_backup_vault.BackupVault_premium.id
    lifecycle {
      delete_after = 1
    }
  }
  rule {
    rule_name         = "Premium_Daily_Backup"
    schedule          = "cron(0 0 * * ? *)"
    target_vault_name = aws_backup_vault.BackupVault_premium.id
    lifecycle {
      delete_after = 31
    }
  }
  rule {
    rule_name         = "Premium_Monthly"
    schedule          = "cron(0 0 1 1/1 ? *)"
    target_vault_name = aws_backup_vault.BackupVault_premium.id
    lifecycle {
      delete_after       = 365
      cold_storage_after = 15
    }
  }
  rule {
    rule_name         = "Premium_Yearly"
    schedule          = "cron(0 0 31 12 ? *)"
    target_vault_name = aws_backup_vault.BackupVault_premium.id
    lifecycle {
      delete_after       = 2555
      cold_storage_after = 15
    }
  }
}

resource "aws_backup_selection" "BackupResourceSelection_premium" {
  name         = "Premium"
  plan_id      = aws_backup_plan.BackupPlan_premium.id
  iam_role_arn = aws_iam_role.IamRoleForAwsBackup.arn

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "premium"
  }
}
