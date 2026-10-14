
resource "aws_eip" "eip" {
  instance = var.aws_instance_id
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public_subnet" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  #  depends_on = [aws_vpc.main]

}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  #  depends_on = [aws_vpc.main]
}

resource "aws_route_table" "public_rt" {
  vpc_id     = aws_vpc.main.id
  depends_on = [aws_vpc.main]
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "public_rt_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}