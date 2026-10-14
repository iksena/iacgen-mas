#data
data "aws_availability_zones" "available" {
  state = "available"
}

# Self-contained VPC (replacing the default-VPC/default-subnet dependency --
# AWS-0101).
resource "aws_vpc" "vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "default_private_subnet_1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = element(data.aws_availability_zones.available.names, 0)
}

resource "aws_subnet" "default_private_subnet_2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = element(data.aws_availability_zones.available.names, 1)
}

locals {
  private_subnet_1_id = aws_subnet.default_private_subnet_1.id
  private_subnet_2_id = aws_subnet.default_private_subnet_2.id
  vpc_id              = aws_vpc.vpc.id
}
