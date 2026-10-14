data "aws_iam_policy_document" "billing" {
  statement {
    actions = [
    "aws-portal:ViewBilling",
    "aws-portal:ViewAccount",
    "aws-portal:ViewUsage",
    "aws-portal:ViewPaymentMethods",
    "awsbillingconsole:ViewBilling",
    "awsbillingconsole:ViewAccount",
    "awsbillingconsole:ViewUsage",
    "awsbillingconsole:ViewPaymentMethods",
    "budgets:ViewBudget",
    "cur:DescribeReportDefinitions",
    "pricing:DescribeServices",
    "pricing:GetAttributeValues",
    "pricing:GetProducts",
    "ce:GetCostAndUsage"
    ]
    resources = ["*"]
    effect = "Allow"
  }
}

data "aws_iam_policy_document" "suport" {
  statement{
    actions = [
      "ec2:Describe*",
      "ec2:Get*",
      "ec2:List*"
    ]
    resources = [
      "*",
    ]
    effect = "Allow"
  }
  statement{
    actions = [
      "s3:Get*",
      "s3:List*"
    ]
    resources = [
      "*",
    ]
    effect = "Allow"
  }
  statement{
    actions = [
      "cloudwatch:Describe*",
      "cloudwatch:Get*",
      "cloudwatch:List*"
    ]
    resources = [
      "*",
    ]
    effect = "Allow"
  }
  statement {
    actions = [
      "rds:Describe*",
      "rds:List*"
    ]
    resources = [
      "*",
    ]
    effect = "Allow"
  }
}
