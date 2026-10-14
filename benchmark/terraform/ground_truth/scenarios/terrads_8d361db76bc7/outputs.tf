output "azs" {
  description = "Number of Availability Zones specified"
  value       = var.zones
}

output "number_azs" {
  description = "Number of Availability Zones specified"
  value       = var.zones
}

output "zones" {
  description = "Number of Availability Zones specified"
  value       = var.zones
}

# --------------------------------------------------------------------------
# VPC
# --------------------------------------------------------------------------
output "vpc_arn" {
  description = "AWS VPC ID ARN"
  value       = aws_vpc.vpc.arn
}

output "vpc_id" {
  description = "AWS VPC ID"
  value       = aws_vpc.vpc.id
}

output "vpc_cidr" {
  description = "AWS VPC IPv4 CIDR"
  value       = aws_vpc.vpc.cidr_block
}

output "vpc_dns" {
  description = "VPC DNS Server IP"
  value       = cidrhost(aws_vpc.vpc.cidr_block, 2)
}


output "vpc_ipv6_cidr" {
  description = "AWS VPC IPv6 CIDR"
  value       = aws_vpc.vpc.ipv6_cidr_block
}

output "vpc_ipv6_association_id" {
  description = "AWS VPC aassociation ID for the IPv6 CIDR block"
  value       = aws_vpc.vpc.ipv6_association_id
}

output "igw_id" {
  description = "Internet Gateway ID"
  value       = aws_internet_gateway.igw.id
}

output "egress_only_internet_gateway_id" {
  description = "ID of IPv6 Egress-Only Internet Gateway"
  value       = var.ipv6 ? aws_egress_only_internet_gateway.ipv6.0.id : null
}


# --------------------------------------------------------------------------
# Cache Subnets
# --------------------------------------------------------------------------
output "cache_azs" {
  description = "Availability Zones for Cache Subnets"
  value       = [for s in aws_subnet.cache : s.availability_zone]
}

output "cache_subnets" {
  description = "Number of Cache Subnet IDs"
  value       = length([for s in aws_subnet.cache : s.id])
}

output "cache_subnet_arns" {
  description = "Cache Subnet ARNs"
  value       = [for s in aws_subnet.cache : s.arn]
}

output "cache_subnet_ids" {
  description = "Number of Cache Subnet IDs"
  value       = [for s in aws_subnet.cache : s.id]
}

output "cache_subnet_cidrs" {
  description = "Cache Subnet CIDRs"
  value       = [for s in aws_subnet.cache : s.cidr_block]
}

output "cache_subnet_ipv6_cidr_blocks" {
  description = "Cache Subnet IPv6 CIDR blocks"
  value       = [for s in aws_subnet.cache : s.ipv6_cidr_block]
}

output "cache_rt_ids" {
  description = "Cache Route Table IDs"
  value       = [for s in aws_route_table.cache : s.id]
}

# --------------------------------------------------------------------------
# Database Subnets
# --------------------------------------------------------------------------
output "db_azs" {
  description = "Availability Zones for Database Subnets"
  value       = [for s in aws_subnet.db : s.availability_zone]
}

output "db_subnets" {
  description = "Number of Database Subnet IDs"
  value       = length([for s in aws_subnet.db : s.id])
}

output "db_subnet_arns" {
  description = "Database Subnet ARNs"
  value       = [for s in aws_subnet.db : s.arn]
}

output "db_subnet_ids" {
  description = "Number of Database Subnet IDs"
  value       = [for s in aws_subnet.db : s.id]
}

output "db_subnet_cidrs" {
  description = "Database Subnet CIDRs"
  value       = [for s in aws_subnet.db : s.cidr_block]
}

output "db_subnet_ipv6_cidr_blocks" {
  description = "Database Subnet IPv6 CIDR blocks"
  value       = [for s in aws_subnet.db : s.ipv6_cidr_block]
}

output "db_rt_ids" {
  description = "Database Route Table IDs"
  value       = [for s in aws_route_table.db : s.id]
}

# --------------------------------------------------------------------------
# Internal Subnets
# --------------------------------------------------------------------------
output "internal_azs" {
  description = "Availability Zones for Internal Subnets"
  value       = [for s in aws_subnet.internal : s.availability_zone]
}

output "internal_subnets" {
  description = "Number of Internal Subnet IDs"
  value       = length([for s in aws_subnet.internal : s.id])
}

output "internal_subnet_arns" {
  description = "Internal Subnet ARNs"
  value       = [for s in aws_subnet.internal : s.arn]
}

output "internal_subnet_ids" {
  description = "Number of Internal Subnet IDs"
  value       = [for s in aws_subnet.internal : s.id]
}

output "internal_subnet_cidrs" {
  description = "Internal Subnet CIDRs"
  value       = [for s in aws_subnet.internal : s.cidr_block]
}

output "internal_subnet_ipv6_cidr_blocks" {
  description = "Internal Subnet IPv6 CIDR blocks"
  value       = [for s in aws_subnet.internal : s.ipv6_cidr_block]
}

output "internal_rt_ids" {
  description = "Internal Route Table IDs"
  value       = [for s in aws_route_table.internal : s.id]
}

# --------------------------------------------------------------------------
# Private Subnets
# --------------------------------------------------------------------------
output "private_azs" {
  description = "Availability Zones for Private Subnets"
  value       = [for s in aws_subnet.private : s.availability_zone]
}

output "private_subnets" {
  description = "Number of Private Subnet IDs"
  value       = length([for s in aws_subnet.private : s.id])
}

output "private_subnet_arns" {
  description = "Private Subnet ARNs"
  value       = [for s in aws_subnet.private : s.arn]
}

output "private_subnet_ids" {
  description = "Number of Private Subnet IDs"
  value       = [for s in aws_subnet.private : s.id]
}

output "private_subnet_cidrs" {
  description = "Private Subnet CIDRs"
  value       = [for s in aws_subnet.private : s.cidr_block]
}

output "private_subnet_ipv6_cidr_blocks" {
  description = "Private Subnet IPv6 CIDR blocks"
  value       = [for s in aws_subnet.private : s.ipv6_cidr_block]
}

output "private_rt_ids" {
  description = "Private Route Table IDs"
  value       = [for s in aws_route_table.private : s.id]
}

output "nat_gateway_count" {
  description = "Number of NAT Gateways"
  value       = length(aws_nat_gateway.natgw.*.id)
}

output "nat_gateway_public_ips" {
  description = "Public IPs of NAT Gateways"
  value       = aws_nat_gateway.natgw.*.public_ip
}

output "eip_public_ips" {
  description = "Public IPv4 of EIP addresses"
  value       = aws_eip.eip.*.public_ip
}

# --------------------------------------------------------------------------
# Public Subnets
# --------------------------------------------------------------------------
output "public_azs" {
  description = "Availability Zones for Public Subnets"
  value       = [for s in aws_subnet.public : s.availability_zone]
}

output "public_subnets" {
  description = "Number of Public Subnets"
  value       = length([for s in aws_subnet.public : s.id])
}

output "public_subnet_arns" {
  description = "Public Subnet ARNs"
  value       = [for s in aws_subnet.public : s.arn]
}

output "public_subnet_ids" {
  description = "Number of Public Subnet IDs"
  value       = [for s in aws_subnet.public : s.id]
}

output "public_subnet_cidrs" {
  description = "Public Subnets CIDRs"
  value       = [for s in aws_subnet.public : s.cidr_block]
}

output "public_subnet_ipv6_cidr_blocks" {
  description = "Public Subnet IPv6 CIDR blocks"
  value       = [for s in aws_subnet.public : s.ipv6_cidr_block]
}

output "public_rt_ids" {
  description = "Public Route Table IDs"
  value       = aws_route_table.public.*.id
}

# --------------------------------------------------------------------------
# VPC Endpoints
# --------------------------------------------------------------------------
output "vpc_endpoint_s3_id" {
  description = "ID of VPC endpoint for S3"
  value       = var.s3_endpoint ? aws_vpc_endpoint.s3.0.id : null
}

output "vpc_endpoint_s3_pl_id" {
  description = "Prefix list ID for the S3 VPC endpoint"
  value       = var.s3_endpoint ? aws_vpc_endpoint.s3.0.prefix_list_id : null
}
