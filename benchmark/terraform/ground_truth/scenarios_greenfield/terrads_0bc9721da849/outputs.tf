output "vpc" {
  description = "The dev VPC"
  value       = aws_vpc.dev-vpc
}

output "db_subnet_id_1" {
  description = "The subnet 1 id of the RDS cluster"
  value       = aws_subnet.lambda-rds-db-subnet-1.id
}

output "db_subnet_id_2" {
  description = "The subnet 2 id of the RDS cluster"
  value       = aws_subnet.lambda-rds-db-subnet-2.id
}

output "db_availability_zone" {
  description = "The availability zone id of the RDS cluster"
  value       = local.availability_zone
}

output "db_security_group_id" {
  description = "The security group id of the RDS cluster"
  value       = aws_security_group.postgres-db.id
}

output "bastion_host_subnet_id" {
  description = "The subnet id of the bastion host"
  value       = aws_subnet.lambda-rds-bastion-host-subnet.id
}

output "bastion_host_security_group_id" {
  description = "The security group id of the Bastion Host"
  value       = aws_security_group.bastion-host.id
}

output "lambda_functions_security_group_id" {
  description = "The security group id of the Lambda Functions"
  value       = aws_security_group.lambda-functions.id
}

output "lambda_functions_subnet_id" {
  description = "The subnet id of the Lambda Functions"
  value       = aws_subnet.lambda-rds-dev-lambda-subnet.id
}