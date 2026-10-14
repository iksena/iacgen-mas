output "bus" {
  description = "The attributes of generated event bridge bus"
  value       = aws_cloudwatch_event_bus.bus
}

output "rules" {
  description = "The attributes of generated event bridge rules"
  value       = aws_cloudwatch_event_rule.rule
}
