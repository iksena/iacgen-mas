locals {
  tags = {
    Name       = "rwwise.dev Infrastructure Setup"
    Repository = "https://github.com/zangrum/setup.inf.rwwise.dev"
    Account    = data.aws_caller_identity.current.account_id
    User       = data.aws_caller_identity.current.user_id
  }
}