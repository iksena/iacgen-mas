# ################################################################
# . Author : Ankit Upadhyay
# . Follow me on github for more aws maintainance resources  http://github.com/ankitosh
# 
# ################################################################

resource "aws_backup_vault" "BackupVault_gold" {
  name        = "Gold_Backup_Vault"
  kms_key_arn = aws_kms_key.backup_key.arn
}

resource "aws_backup_plan" "BackupPlan_gold" {
  name = "Gold_Backup"

  rule {
    rule_name         = "Gold_Daily_Backup_Rule"
    schedule          = "cron(0 0 * * ? *)"
    target_vault_name = aws_backup_vault.BackupVault_gold.id
    lifecycle {
      delete_after = 31
    }
  }
  rule {
    rule_name         = "Gold_Monthly_Backup_Rule"
    schedule          = "cron(0 0 1 1/1 ? *)"
    target_vault_name = aws_backup_vault.BackupVault_gold.id
    lifecycle {
      delete_after = 365
    }
  }
  rule {
    rule_name         = "Gold_Yearly_Backup_Rule"
    schedule          = "cron(0 0 31 12 ? *)"
    target_vault_name = aws_backup_vault.BackupVault_gold.id
    lifecycle {
      delete_after = 2555
    }
  }
}

resource "aws_backup_selection" "BackupResourceSelection_gold" {
  name         = "Gold_Backup_Select"
  plan_id      = aws_backup_plan.BackupPlan_gold.id
  iam_role_arn = aws_iam_role.IamRoleForAwsBackup.arn

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "gold"
  }
}
