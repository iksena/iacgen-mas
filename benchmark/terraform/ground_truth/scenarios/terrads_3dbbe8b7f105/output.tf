output user_arn {
  value = aws_iam_user.user.arn
}

output user_id {
  value = aws_iam_user.user.unique_id
}
