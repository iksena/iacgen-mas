output "id" {
  value       = aws_vpc.default.id
  description = "VPC id"
}

output "public_subnet_ids" {
  value       = aws_subnet.public.*.id
  description = "List of public subnet IDs"
}

output "cidr_block" {
  value       = var.cidr_block
  description = "The CIDR block associated with the VPC"
}

