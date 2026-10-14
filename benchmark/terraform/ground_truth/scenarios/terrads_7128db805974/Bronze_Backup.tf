# ################################################################
# . Author : Ankit Upadhyay
# . Follow me on github for more aws maintainance resources  http://github.com/ankitosh
# 
# ################################################################

resource "aws_backup_vault" "BackupVault_Bronze" {
  name        = "Bronze_Backup_Vault"
  kms_key_arn = aws_kms_key.backup_key.arn
}

resource "aws_backup_plan" "BackupPlan_Bronze" {
  name = "Bronze_Backup"

  rule {
    rule_name         = "Bronze_Backup_Weekly"
    schedule          = "cron(0 0 ? * FRI *)"
    target_vault_name = aws_backup_vault.BackupVault_Bronze.id
    lifecycle {
      delete_after = 10
    }
  }
}

resource "aws_backup_selection" "BackupResourceSelection_Bronze" {
  name         = "Bronze_Resource_Assignment"
  plan_id      = aws_backup_plan.BackupPlan_Bronze.id
  iam_role_arn = aws_iam_role.IamRoleForAwsBackup.arn

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "bronze"
  }
}
