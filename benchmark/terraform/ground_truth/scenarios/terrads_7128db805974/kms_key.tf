# ################################################################
# . Author : Ankit Upadhyay
# . Follow me on github for more aws maintainance resources  http://github.com/ankitosh
# 
# ################################################################

resource "aws_kms_key" "backup_key" {
  description             = "Backup_Vault_Encryption"
  deletion_window_in_days = 10
  enable_key_rotation      = true
}