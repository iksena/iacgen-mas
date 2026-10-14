resource "aws_iam_user" "dev" {
  name = "DevUser-rwwise.dev"
  path = "/system/"

  tags = local.tags
}

resource "aws_iam_access_key" "dev" {
  user = aws_iam_user.dev.name
}

data "aws_iam_policy_document" "dev" {
  statement {
    effect = "Allow"
    actions = ["codebuild:BatchGet*",
      "codebuild:GetResourcePolicy",
      "codebuild:List*",
      "codebuild:DescribeTestCases",
      "codebuild:DescribeCodeCoverages",
      "codecommit:GetBranch",
      "codecommit:GetCommit",
      "codecommit:GetRepository",
      "cloudwatch:GetMetricStatistics",
      "events:DescribeRule",
      "events:ListTargetsByRule",
      "events:ListRuleNamesByTarget",
    "logs:GetLogEvents"]
    resources = ["*"]
  }
  statement {
    sid    = "CodeStarConnectionsUserAccess"
    effect = "Allow"
    actions = [
      "codestar-connections:ListConnections",
      "codestar-connections:GetConnection"
    ]
    resources = ["arn:aws:codestar-connections:*:*:connection/*"]
  }
  statement {
    sid    = "CodeStarNotificationsPowerUserAccess"
    effect = "Allow"
    actions = [
      "codestar-notifications:DescribeNotificationRule"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "codestar-notifications:NotificationsForResource"
      values   = ["arn:aws:codebuild:*"]
    }
  }
  statement {
    sid    = "CodeStarNotificationsListAccess"
    effect = "Allow"
    actions = ["codestar-notifications:ListNotificationRules",
      "codestar-notifications:ListEventTypes",
    "codestar-notifications:ListTargets"]
    resources = ["*"]
  }
}

resource "aws_iam_user_policy" "dev" {
  name   = "dev_cicd_user_policy"
  user   = aws_iam_user.dev.name
  policy = data.aws_iam_policy_document.dev.json
}