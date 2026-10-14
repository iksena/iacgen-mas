output "financial_user" {
  value = {
    "username" = aws_iam_user.billing.name
    "password" = aws_iam_user_login_profile.billing.password
  }
  sensitive = true
}
output "admin_user" {
  value = {
    "username" = aws_iam_user.admin.name
    "password" = aws_iam_user_login_profile.admin.password
  }
  sensitive = true
}
output "maintenance_user" {
  value = {
    "username" = aws_iam_user.suport.name
    "password" = aws_iam_user_login_profile.suport.password
  }
  sensitive = true
}

