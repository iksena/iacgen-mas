resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.dev-vpc.id

  tags = {
    Name = "lambda-rds-dev-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.dev-vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "lambda-rds-public-subnet"
  }
}

resource "aws_route_table_association" "bastion-host-route-table" {
  subnet_id      = aws_subnet.lambda-rds-bastion-host-subnet.id
  route_table_id = aws_route_table.public.id
}