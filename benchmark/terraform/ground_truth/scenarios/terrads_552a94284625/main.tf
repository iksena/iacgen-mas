provider "aws" {
  shared_config_files      = ["~/.aws/config"]
  shared_credentials_files = ["~/.aws/credentials"]
}

resource "aws_vpc" "fis-vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public_subnet" {
  cidr_block = "10.0.1.0/24"
  vpc_id     = aws_vpc.fis-vpc.id
}

resource "aws_subnet" "private_subnet" {
  cidr_block = "10.0.2.0/24"
  vpc_id     = aws_vpc.fis-vpc.id
}

// Create an internet gateway to allow the VPC to connect to the internet
resource "aws_internet_gateway" "fis_public_internet_gateway" {
  vpc_id = aws_vpc.fis-vpc.id
}

// Create a route table for the public subnet to route traffic to the internet gateway
resource "aws_route_table" "fis_public_subnet_route_table" {
  vpc_id = aws_vpc.fis-vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.fis_public_internet_gateway.id
  }

  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.fis_public_internet_gateway.id
  }
}

// Associate the public subnet with the route table to allow traffic to the internet gateway 
resource "aws_route_table_association" "fis_public_association" {
  route_table_id = aws_route_table.fis_public_subnet_route_table.id
  subnet_id      = aws_subnet.public_subnet.id
}
