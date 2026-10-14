# Self-contained VPC (no default VPC is assumed)
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "alb-ec2-vpc"
  }
}

# Security Groups ALB
resource "aws_security_group" "alb" {
  name        = "alb"
  description = "Allow HTTP inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP Inbound"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  tags = {
    Name = "alb"
  }
}

# Security Groups EC2
resource "aws_security_group" "allow_alb" {
  name        = "allow_alb"
  description = "Allow ALB inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP Inbound"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  tags = {
    Name = "allow_alb"
  }
}