####################################################################
#
# Self-contained network for the cluster (no default VPC is assumed).
# Nodes live in three private subnets and reach the internet through a
# NAT gateway; the private API endpoint needs VPC DNS support.
#
####################################################################

resource "aws_vpc" "eks" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    "Name" = "demo-eks-vpc"
  }
}

resource "aws_internet_gateway" "eks" {
  vpc_id = aws_vpc.eks.id
}

resource "aws_subnet" "nat" {
  vpc_id            = aws_vpc.eks.id
  cidr_block        = "10.0.0.0/24"
  availability_zone = "${var.aws_region}a"
  tags = {
    "Name" = "demo-eks-nat"
  }
}

resource "aws_route_table" "nat" {
  vpc_id = aws_vpc.eks.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.eks.id
  }
}

resource "aws_route_table_association" "nat" {
  subnet_id      = aws_subnet.nat.id
  route_table_id = aws_route_table.nat.id
}

resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "eks" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.nat.id
  depends_on    = [aws_internet_gateway.eks]
}

resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.eks.id
  cidr_block        = "10.0.1${count.index}.0/24"
  availability_zone = "${var.aws_region}${["a", "b", "c"][count.index]}"
  tags = {
    "Name" = "demo-eks-private-${count.index}"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.eks.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.eks.id
  }
}

resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}
