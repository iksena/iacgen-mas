provider "aws" {
  region="us-east-1"
  
}

#testing
#Generating of VPC
resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support = true
  
  tags={
    Name="development-be-vpc"
  }
}

#Generating of a Public Subnet
resource "aws_subnet" "public_subnet" {
  
  vpc_id = aws_vpc.main.id
  cidr_block = var.subnet_public_cidrs
  availability_zone = "us-east-1a"
  map_public_ip_on_launch = false
  

  tags={
    Name="development-be-public-subnet"
  }
}

#Generating of Private Subnet
resource "aws_subnet" "private_subnet" {
  
  vpc_id = aws_vpc.main.id
  cidr_block = var.subnet_private_cidrs
   availability_zone = "us-east-1b"
  
  tags={
    Name="development-be-private-subnet"
  }
}

#Generating of public Route Table
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "development-be-public-rt"
  }
  
}

#Association of Route Table with Public Subnet 
resource "aws_route_table_association" "public_subnets_asso" {
  
  subnet_id = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
  
}

#Generating Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags={
    Name="development-be-ig"
  }
  
}

#Generating of SSH and HTTP Secuirty Group
resource "aws_security_group" "sg_grp" {
  vpc_id = aws_vpc.main.id
  name   = "http_access"
  description = "sg for backend development"

  #This is For SSH
  ingress {
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  #This is For Http
  ingress {
    description = "Http Acess"
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  tags = {
    Name= "development-be-sg"
  }

}


