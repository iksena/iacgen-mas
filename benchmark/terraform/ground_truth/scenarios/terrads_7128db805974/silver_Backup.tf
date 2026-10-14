# ################################################################
# . Author : Ankit Upadhyay
# . Follow me on github for more aws maintainance resources  http://github.com/ankitosh
# 
# ################################################################

resource "aws_backup_vault" "BackupVault_silver" {
  name        = "Silver_Backup_Vault"
  kms_key_arn = aws_kms_key.backup_key.arn
}

resource "aws_backup_plan" "BackupPlan_silver" {
  name = "Silver_Backup_Plan"

  rule {
    rule_name         = "Silver_Backup_Daily"
    schedule          = "cron(0 5 ? * * *)"
    target_vault_name = aws_backup_vault.BackupVault_silver.id
    lifecycle {
      delete_after = 7
    }
  }
}

resource "aws_backup_selection" "BackupResourceSelection_silver" {
  name         = "Silver_Backup_resource"
  plan_id      = aws_backup_plan.BackupPlan_silver.id
  iam_role_arn = aws_iam_role.IamRoleForAwsBackup.arn

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "silver"
  }
}
