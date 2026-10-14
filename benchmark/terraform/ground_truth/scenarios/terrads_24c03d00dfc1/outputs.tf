output "current_user" {
  value = data.aws_caller_identity.current.account_id
}

output "dev_user_name" {
    value = aws_iam_user.dev.name
}
output "dev_user_unique_id" {
    value = aws_iam_user.dev.unique_id
}
output "test" {
    value = aws_iam_user.test.name
}
output "test_user_unique_id" {
    value = aws_iam_user.test.unique_id
}
output "prod_user_name" {
    value = aws_iam_user.prod.name
}
output "prod_user_unique_id" {
    value = aws_iam_user.prod.unique_id
}