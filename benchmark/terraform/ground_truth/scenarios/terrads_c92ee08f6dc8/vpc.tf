terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "us-east-1"
}

# vpc
resource "aws_vpc" "myvpc" {
  cidr_block       = "10.0.0.0/16" #65536
  instance_tenancy = "default"

  tags = {
    Name = "projectvpc"
  }
}

#pub subnet
resource "aws_subnet" "pubsub" {
  vpc_id     = aws_vpc.myvpc.id
  cidr_block = "10.0.1.0/24" #256
  availability_zone = "us-east-1a"
  tags = {
    Name = "pub-sub"
  }
}
#pvt subnet
resource "aws_subnet" "pvtsub" {
  vpc_id     = aws_vpc.myvpc.id
  cidr_block = "10.0.2.0/24" #256
  availability_zone = "us-east-1b"

  tags = {
    Name = "pub-sub"
  }
}

#IGW
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.myvpc.id

  tags = {
    Name = "main"
  }
}

#Pub Route Table
resource "aws_route_table" "pubrt" {
  vpc_id = aws_vpc.myvpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "RT-PUB"
  }
}
#Pvt Route Table
resource "aws_route_table" "pvtrt" {
  vpc_id = aws_vpc.myvpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "RT-PUB"
  }
}


#Rt-ass
#pub-rt
resource "aws_route_table_association" "pubasc" {
  subnet_id      = aws_subnet.pubsub.id
  route_table_id = aws_route_table.pubrt.id
}
#pvt-rt
resource "aws_route_table_association" "pvtasc" {
  subnet_id      = aws_subnet.pvtsub.id
  route_table_id = aws_route_table.pvtrt.id
}

#Eip
resource "aws_eip" "eip" {
 vpc = true
}

#Natgateway
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.pubsub.id

  tags = {
    Name = "gw NAT"
  }
}


