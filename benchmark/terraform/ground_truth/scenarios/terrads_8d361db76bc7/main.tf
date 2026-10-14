# --------------------------------------------------------------------------
# Locals - Tagging
# --------------------------------------------------------------------------
locals {
  cluster_name = substr(lower(var.cluster_name), 0, 99)
  tags = merge(
    var.tags,
    {
      "Name"   = var.name
      "Module" = "terraform-aws-stackx-network"
      "Github" = "https://github.com/ventx/terraform-aws-stackx-network"
    }
  )
  cache_subnet_tags = merge(
    var.tags,
    var.cache_subnet_tags,
  )
  db_subnet_tags = merge(
    var.tags,
    var.db_subnet_tags
  )
  internal_subnet_tags = merge(
    var.tags,
    var.internal_subnet_tags
  )
  private_subnet_tags = merge(
    var.tags,
    var.private_subnet_tags,
    var.k8s ?
    {
      "karpenter.sh/discovery"                      = local.cluster_name
      "kubernetes.io/cluster/${local.cluster_name}" = "shared",
      "kubernetes.io/role/internal-elb"             = "1",
    } : null
  )
  public_subnet_tags = merge(
    var.tags,
    var.public_subnet_tags,
    var.k8s ?
    {
      "kubernetes.io/cluster/${local.cluster_name}" = "shared",
      "kubernetes.io/role/elb"                      = "1",
    } : null
  )
  nat_gateway_count = var.single_nat_gateway ? 1 : var.zones
}


# --------------------------------------------------------------------------
# VPC
# --------------------------------------------------------------------------
resource "aws_vpc" "vpc" {
  cidr_block                       = cidrsubnet("10.0.0.0/8", 8, var.region_number[var.region] + var.vpc_cidr_add)
  enable_dns_support               = true
  enable_dns_hostnames             = true
  assign_generated_ipv6_cidr_block = var.ipv6 ? true : false

  tags = local.tags
}


# --------------------------------------------------------------------------
# Internet Gateway
# --------------------------------------------------------------------------
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = local.tags
}


# --------------------------------------------------------------------------
# EIPs
# --------------------------------------------------------------------------
# Elastic IP addresses (EIP) for NAT Gateways
resource "aws_eip" "eip" {
  count = local.nat_gateway_count

  tags = var.single_nat_gateway ? local.private_subnet_tags : merge(
    local.private_subnet_tags, {
      "Name" = "${var.private_subnet_name}-${data.aws_availability_zones.available.names[count.index]}"
    }
  )
}


# --------------------------------------------------------------------------
# NAT Gateways
# --------------------------------------------------------------------------
resource "aws_nat_gateway" "natgw" {
  count = local.nat_gateway_count

  allocation_id = element(
    aws_eip.eip.*.id,
  var.single_nat_gateway ? 0 : count.index)

  subnet_id = element(
    [for s in aws_subnet.public : s.id],
  var.single_nat_gateway ? 0 : count.index)

  tags = var.single_nat_gateway ? local.private_subnet_tags : merge(
    local.private_subnet_tags, {
      "Name" = "${var.private_subnet_name}-${data.aws_availability_zones.available.names[count.index]}"
    }
  )
}


# --------------------------------------------------------------------------
# IPV6 Egress-only Gateway
# --------------------------------------------------------------------------
resource "aws_egress_only_internet_gateway" "ipv6" {
  count = var.ipv6 ? 1 : 0

  vpc_id = aws_vpc.vpc.id
}
