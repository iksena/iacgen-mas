provider "aws" {
  region = var.aws_region
}

resource "aws_vpc" "main" {
  cidr_block = "10.16.0.0/16"

  tags = {
    Name = var.vpc_name
  }
}

resource "aws_subnet" "presentation" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.16.0.0/24"

  tags = {
    Name = "presentation-subnet"
  }
}

resource "aws_subnet" "application" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.16.1.0/24"

  tags = {
    Name = "application-subnet"
  }
}

resource "aws_subnet" "data" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.16.2.0/24"

  tags = {
    Name = "data-subnet"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "presentation" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table_association" "presentation" {
  subnet_id = aws_subnet.presentation.id
  route_table_id = aws_route_table.presentation.id
}

resource "aws_route" "internet" {
  route_table_id = aws_route_table.presentation.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.main.id
}
