# Self-contained VPC/subnet fallback: var.vpc_id/var.subnet had no default in
# the original template (a genuine existing-infra reference), and this
# benchmark's real-AWS test account has no default VPC. Only create real
# infrastructure when the caller hasn't supplied their own.
resource "aws_vpc" "benchmark" {
  count                = var.vpc_id == "" ? 1 : 0
  cidr_block           = "10.70.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name != "" ? var.name : "benchmark"}-vpc"
  }
}

data "aws_availability_zones" "benchmark" {
  state = "available"
}

resource "aws_subnet" "benchmark" {
  count                   = var.vpc_id == "" ? 1 : 0
  vpc_id                  = aws_vpc.benchmark[0].id
  cidr_block              = "10.70.0.0/24"
  availability_zone       = data.aws_availability_zones.benchmark.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.name != "" ? var.name : "benchmark"}-subnet"
  }
}

resource "aws_internet_gateway" "benchmark" {
  count  = var.vpc_id == "" ? 1 : 0
  vpc_id = aws_vpc.benchmark[0].id
}

resource "aws_route_table" "benchmark" {
  count  = var.vpc_id == "" ? 1 : 0
  vpc_id = aws_vpc.benchmark[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.benchmark[0].id
  }
}

resource "aws_route_table_association" "benchmark" {
  count          = var.vpc_id == "" ? 1 : 0
  subnet_id      = aws_subnet.benchmark[0].id
  route_table_id = aws_route_table.benchmark[0].id
}

locals {
  effective_vpc_id    = var.vpc_id != "" ? var.vpc_id : aws_vpc.benchmark[0].id
  effective_subnet_id = var.subnet != "" ? var.subnet : aws_subnet.benchmark[0].id
}

# var.ssh_key_pair had no default in the original template (a real EC2 key
# pair name with no aws_key_pair resource creating it) -- disposable
# self-contained key so instance creation doesn't fail on a missing key pair.
resource "aws_key_pair" "benchmark" {
  key_name   = var.ssh_key_pair
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOCfB2Nzsb+EqPexcxNl/dj1ZHbljsIBLqCZ3tMVgDRvaFmpo5WhFk1WyM/nOuXjiupeqduYczLqs/X4TV2YQfdj5p1N/u+aP6O1wQe606zAa5e3ywnwX4g6lv3XxUwc+bVzSHLbKD7V/F0yXU8EALB+0kVMClaln3+MeFJWTyHB4ApI1Z+nZJhNoeJDTor9AzUqNMr5fIIpMvSogGmbyP/8RzFOwtIfFqou3ejiwaS5FEEdkZhqjkoMfumSGhPQAr7nmFUY5US1u7vkhc8YCuz2xwREG9tY1Wf5YyzFaA600QhKBk4r2o3FPuHNenhXC2QOnbA0b69VoeNvuuZ16P benchmark-disposable-key"
}
