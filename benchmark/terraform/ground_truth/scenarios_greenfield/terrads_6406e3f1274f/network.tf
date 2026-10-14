resource "aws_vpc" "main" {
  cidr_block = "192.168.0.0/16"
}


resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  availability_zone = "${data.aws_region.current.name}b"
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, 0)
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  availability_zone = "${data.aws_region.current.name}b"
  cidr_block        = cidrsubnet(aws_vpc.main.cidr_block, 8, 10)
  # Auto-assign-public-IP left off: the only resource in this subnet is the
  # NAT Gateway below, which gets its public address via an explicit EIP
  # association, not the subnet's own default.
}

resource "aws_security_group" "batch" {
  name        = "${local.common_tags.Name}-batch"
  description = "Allow all egress from batch instances"
  vpc_id      = aws_vpc.main.id
}


resource "aws_security_group_rule" "https_egress" {
  description       = "Allow HTTPS egress from batch instances within the VPC"
  security_group_id = aws_security_group.batch.id
  type              = "egress"
  from_port         = 443
  to_port            = 443
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.main.cidr_block]
}


resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

# The public subnet has an internet gateway to 
# allow the NAT gateway to go out.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

# traffic FROM instance out to internet is run
# through NAT (which will be placed in the public subnet)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.default.id
  }
}

resource "aws_route_table_association" "public" {
  route_table_id = aws_route_table.public.id
  subnet_id      = aws_subnet.public.id
}

resource "aws_route_table_association" "private" {
  route_table_id = aws_route_table.private.id
  subnet_id      = aws_subnet.private.id
}

resource "aws_nat_gateway" "default" {
  connectivity_type = "public"
  allocation_id     = aws_eip.default.id
  subnet_id         = aws_subnet.public.id

  # To ensure proper ordering, it is recommended to add an explicit dependency
  # on the Internet Gateway for the VPC.
  depends_on = [aws_internet_gateway.main]
}

resource "aws_eip" "default" {
  vpc = true
}
