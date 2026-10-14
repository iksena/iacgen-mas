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
  region = "eu-central-1"
}
# vpc
resource "aws_vpc" "myvpc" {
  cidr_block       = var.cidr_vpc #10.0.0.0/16
  instance_tenancy = "default"

  tags = {
    Name = "project-vpc"
  }
}
# SUBNET
# pub subnet 1
resource "aws_subnet" "pubsub1" {
  vpc_id     = aws_vpc.myvpc.id
  cidr_block = var.subpub1 #10.0.1.0/16
  availability_zone = var.azpub1

  tags = {
    Name = "pub-sub-1"
  }
}
# pub subnet 2
resource "aws_subnet" "pubsub2" {
  vpc_id     = aws_vpc.myvpc.id
  cidr_block = var.subpub2 #10.0.2.0/16
  availability_zone = var.az_sub_pub2

  tags = {
    Name = "pub-sub-2"
  }
}
# pvt subnet 1
resource "aws_subnet" "pvtsub1" {
  vpc_id     = aws_vpc.myvpc.id
  cidr_block = var.subpvt1 #10.0.3.0/16
  availability_zone = var.az_sub_pvt1

  tags = {
    Name = "pvt-sub-1"
  }
}

# pvt subnet 2
resource "aws_subnet" "pvtsub2" {
  vpc_id     = aws_vpc.myvpc.id
  cidr_block = var.subpvt2 #10.0.4.0/16
  availability_zone = var.az_sub_pvt2

  tags = {
    Name = "pvt-sub-2"
  }
}

# igw
resource "aws_internet_gateway" "tigw" {
  vpc_id = aws_vpc.myvpc.id

  tags = {
    Name = "T-igw"
  }
}

# ROUTE TABLE
# PUB-RT-1
resource "aws_route_table" "pubrt1" {
  vpc_id = aws_vpc.myvpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.tigw.id
  }
  tags = {
    Name = "RT_PUBRT-1"
  }
}

# PUB-RT-2
resource "aws_route_table" "pubrt2" {
  vpc_id = aws_vpc.myvpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.tigw.id
  }
  tags = {
    Name = "RT_PUBRT-2"
  }
}

# PVT-RT-1
resource "aws_route_table" "pvtrt1" {
  vpc_id = aws_vpc.myvpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.pvtnat1.id
  }
  tags = {
    Name = "RT_PVTRT-1"
  }
}
# PVT-RT-2
resource "aws_route_table" "pvtrt2" {
  vpc_id = aws_vpc.myvpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.pvtnat1.id
  }
  tags = {
    Name = "RT_PVTRT-2"
  }
}

# ROUTE TABLE ASC
# ASCPUB SUB 1
resource "aws_route_table_association" "pubasc1" {
  subnet_id      = aws_subnet.pubsub1.id
  route_table_id = aws_route_table.pubrt1.id
}

# ASCPUB SUB 2
resource "aws_route_table_association" "pubasc2" {
  subnet_id      = aws_subnet.pubsub2.id
  route_table_id = aws_route_table.pubrt2.id
}
# ASCPVT SUB 1
resource "aws_route_table_association" "pvtasc1" {
  subnet_id      = aws_subnet.pvtsub1.id
  route_table_id = aws_route_table.pvtrt1.id
}

# ASCPVT SUB 2
resource "aws_route_table_association" "pvtasc2" {
  subnet_id      = aws_subnet.pvtsub2.id
  route_table_id = aws_route_table.pvtrt2.id
}

#EIP -1
resource "aws_eip" "eip1" {
  vpc = "true"
}

# EIP-2
resource "aws_eip" "eip2" {
  vpc   = "true"
}

# NAT-1
resource "aws_nat_gateway" "pvtnat1" {
  allocation_id = aws_eip.eip1.id
  subnet_id     = aws_subnet.pubsub1.id

  tags = {
    Name = "T-NAT1"
  }
}

# NAT -2
resource "aws_nat_gateway" "pvtnat2" {
  allocation_id = aws_eip.eip2.id
  subnet_id     = aws_subnet.pubsub2.id

  tags = {
    Name = "T-NAT1"
  }
}

# PUb-SEG
resource "aws_security_group" "pub_sec" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.myvpc.id

  ingress {
    description      = "https"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }
  ingress {
    description      = "ssh"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    # Placeholder admin source (RFC 5737 documentation range) -- override with your
    # real source IP/CIDR, not left open to the world.
    cidr_blocks      = ["203.0.113.0/24"]
  }
  ingress {
    description      = "http"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = [aws_vpc.myvpc.cidr_block]
  }

  tags = {
    Name = "pub-seg"
  }
}

#pvt-seg

resource "aws_security_group" "pvt_sec" {
  name        = "pvt-seg"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.myvpc.id

  ingress {
    description      = "https"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    security_groups = [aws_security_group.pub_sec.id]
  }
  ingress {
    description      = "ssh"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    security_groups = [aws_security_group.pub_sec.id]
  }
  ingress {
    description      = "http"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    security_groups = [aws_security_group.pub_sec.id]
  }
  ingress {
    description      = "postgres"
    from_port        = 5432
    to_port          = 5432
    protocol         = "tcp"
    security_groups = [aws_security_group.pub_sec.id]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    security_groups = [aws_security_group.pub_sec.id]
    
  }

  tags = {
    Name = "pvt-seg"
  }
}