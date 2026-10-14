output "vpc" {

  depends_on  = [aws_vpc.vpc]
  value = data.aws_vpc.vpc[0]
  
}

output "vpc_name" {
  depends_on  = [aws_vpc.vpc]
  value= data.aws_vpc.vpc[0].tags["Name"]
}

output "vpc_id" {
  depends_on  = [aws_vpc.vpc]
  value = local.vpc_id
  description = "The id for the vpc network"
}

output "vpc_arn" {
  depends_on  = [aws_vpc.vpc]
  value       = local.arn
  description = "The arn of the vpc"
}

output "default_network_acl_id" {
  depends_on  = [aws_vpc.vpc, data.aws_network_acls.default-vpc-network-acls] 
  value  = local.acl_id
  #value  = ""
  description = "The id for the default network acl"
}

output "default_security_group_id" {
  depends_on  = [aws_vpc.vpc]   
  value       = local.security_group_id
  description = "The id of the default security group."
}

output "default_security_group_arn" {
  depends_on  = [aws_vpc.vpc]   
  value       = local.security_group_arn
  description = "The arn of the default security group."
}

output "vpc_cidr" {
  depends_on  = [aws_vpc.vpc]   
  value = var.internal_cidr
  description = "The internal vpc cidr."
  
}