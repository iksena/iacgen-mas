### features
locals {
  custom_bus = local.name != "default" ? true : false
}

### event rules
resource "aws_cloudwatch_event_bus" "bus" {
  for_each          = toset(local.custom_bus ? ["custom"] : [])
  name              = local.name
  tags              = merge(local.default-tags, var.tags)
  event_source_name = lookup(var.bus, "event_source_name", local.default_bus.event_source_name)
}

### event rules
### At least one of `schedule_expression` or `event_pattern` is required.
resource "aws_cloudwatch_event_rule" "rule" {
  for_each            = { for r in var.rules : r.name => r }
  name                = each.key
  tags                = merge(local.default-tags, var.tags)
  description         = lookup(each.value, "description", local.default_rule.description)
  event_bus_name      = local.custom_bus ? aws_cloudwatch_event_bus.bus["custom"].id : null
  event_pattern       = lookup(each.value, "event_pattern", local.default_rule.event_pattern)
  schedule_expression = lookup(each.value, "schedule_expression", local.default_rule.schedule_expression)
}

### security/policy
resource "aws_iam_role" "invoke" {
  name = join("-", [local.name, "invoke"])
  tags = merge(local.default-tags, var.tags)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = format("events.%s", local.aws.dns)
      }
    }]
  })

  inline_policy {
    name = join("-", [local.name, "invoke-targets"])
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Action = [
          "lambda:InvokeFunction",
          "states:StartExecution",
        ]
        Effect   = "Allow"
        Resource = ["*"]
      }]
    })
  }
}

### https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-targets.html
### choreography/route
resource "aws_cloudwatch_event_target" "target" {
  depends_on     = [aws_cloudwatch_event_rule.rule]
  for_each       = { for t in var.targets : t.name => t }
  event_bus_name = local.custom_bus ? aws_cloudwatch_event_bus.bus["custom"].id : null
  rule           = lookup(each.value, "rule")
  arn            = lookup(each.value, "arn")
  role_arn       = strcontains(lookup(each.value, "arn", ""), "stateMachine") ? aws_iam_role.invoke.arn : null
}
