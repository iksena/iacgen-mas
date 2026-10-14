output "vpc_arn" {
  description = "value of the arn for the vpc"
  value       = aws_vpc.main-vpc.arn
}

output "vpc_id" {
  description = "value of the id for the vpc"
  value       = aws_vpc.main-vpc.id
}

output "vpc_ip4_cidr_block" {
  description = "value of the cidr block for the vpc"
  value       = aws_vpc.main-vpc.cidr_block
}

output "vpc_ipv6_cidr_block" {
  description = "value of the ipv6 cidr block for the vpc"
  value       = aws_vpc.main-vpc.ipv6_cidr_block
}

output "vpc_default_network_acl_id" {
  description = "value of the default network acl id for the vpc"
  value       = aws_vpc.main-vpc.default_network_acl_id
}

output "web_sg_id" {
  description = "value of the id for the web security group"
  value       = aws_security_group.web_sg.id
}

output "app_sg_id" {
  description = "value of the id for the app security group"
  value       = aws_security_group.app_sg.id
}

output "db_sg_id" {
  description = "value of the id for the db security group"
  value       = aws_security_group.db_sg.id
}

output "subnets_ids" {
  description = "value of the ids for the subnets"
  value = {
    for sn in aws_subnet.vpc_subnets : sn.tags["Name"] => sn.id
  }
}
