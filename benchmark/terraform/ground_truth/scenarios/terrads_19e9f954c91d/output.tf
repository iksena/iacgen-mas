output "vpc_id" {
    value = aws_vpc.main.id
}

output "presentation_subnet_id" {
  value = aws_subnet.presentation.id
}

output "application_subnet_id" {
  value = aws_subnet.application.id
}

output "data_subnet_id" {
  value = aws_subnet.data.id
}
