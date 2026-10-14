resource "aws_vpc" "main-vpc" {
  cidr_block                       = var.vpc_ip4_cidr_block
  assign_generated_ipv6_cidr_block = var.is_ipv6_enabled
  instance_tenancy                 = var.instance_tenancy
  enable_dns_hostnames             = var.enable_dns_hostnames
  enable_dns_support               = var.enable_dns_support

  tags = {
    Name = "main-vpc"
  }
}

resource "aws_internet_gateway" "main-igw" {
  vpc_id = aws_vpc.main-vpc.id

  tags = {
    Name = "main-igw-vpc-${aws_vpc.main-vpc.id}"
  }
}

resource "aws_subnet" "vpc_subnets" {
  for_each = { for sn in var.sn_details : sn.name => sn }

  cidr_block = module.ipv4_subnets.networks[
    index(
      [for network in module.ipv4_subnets.networks : network.name],
      each.value.name
    )
  ].cidr_block

  ipv6_cidr_block = var.is_ipv6_enabled ? module.ipv6_subnets.networks[
    index(
      [for network in module.ipv6_subnets.networks : network.name],
      each.value.name
    )
  ].cidr_block : null

  vpc_id                          = aws_vpc.main-vpc.id
  availability_zone               = each.value.availability_zone
  assign_ipv6_address_on_creation = var.is_ipv6_enabled
  map_public_ip_on_launch         = false

  tags = {
    Name   = each.value.name
    Public = each.value.is_public
  }
}

resource "aws_route_table" "public-rt-web" {
  vpc_id = aws_vpc.main-vpc.id

  # all traffic to the internet gateway
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main-igw.id
  }
  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.main-igw.id
  }

  tags = {
    Name = "public-rt-web"
  }
}

resource "aws_route_table_association" "public-subnet-association" {
  for_each = { for sn in var.sn_details : sn.name => sn if sn.is_public }

  subnet_id      = aws_subnet.vpc_subnets[each.key].id
  route_table_id = aws_route_table.public-rt-web.id
}
