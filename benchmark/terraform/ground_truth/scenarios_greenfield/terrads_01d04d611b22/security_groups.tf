# WEB TIER
resource "aws_security_group" "web_sg" {
  name        = "web_sg"
  description = "Allow TLS and SSH inbound traffic to the web tier"
  vpc_id      = aws_vpc.main-vpc.id

  tags = {
    Name = "web_sg"
    Tier = "web"
  }
}

## Rules for the web security group
resource "aws_vpc_security_group_ingress_rule" "internet_to_web_tls" {
  security_group_id = aws_security_group.web_sg.id

  cidr_ipv4 = "0.0.0.0/0"

  from_port   = 443
  ip_protocol = "tcp"
  to_port     = 443
}

resource "aws_vpc_security_group_ingress_rule" "internet_to_web_ssh" {
  security_group_id = aws_security_group.web_sg.id

  cidr_ipv4 = var.vpc_ip4_cidr_block

  from_port   = 22
  ip_protocol = "tcp"
  to_port     = 22
}

resource "aws_vpc_security_group_egress_rule" "web_to_app_tls" {
  security_group_id = aws_security_group.web_sg.id

  referenced_security_group_id = aws_security_group.app_sg.id

  from_port   = 443
  ip_protocol = "tcp"
  to_port     = 443
}

# APP TIER
resource "aws_security_group" "app_sg" {
  name        = "app_sg"
  description = "Allow TLS inbound traffic and outbound traffic between web and app tiers"
  vpc_id      = aws_vpc.main-vpc.id

  tags = {
    Name = "app_sg"
    Tier = "app"
  }
}

## Rules for the app security group
resource "aws_vpc_security_group_ingress_rule" "web_to_app_tls" {
  security_group_id = aws_security_group.app_sg.id

  referenced_security_group_id = aws_security_group.web_sg.id

  from_port   = 443
  ip_protocol = "tcp"
  to_port     = 443
}

resource "aws_vpc_security_group_egress_rule" "app_to_db_tls" {
  security_group_id = aws_security_group.app_sg.id

  referenced_security_group_id = aws_security_group.db_sg.id

  from_port   = 443
  ip_protocol = "tcp"
  to_port     = 443
}

# DB TIER
resource "aws_security_group" "db_sg" {
  name        = "db_sg"
  description = "Allow TLS inbound and outbount traffic between app and db tiers"
  vpc_id      = aws_vpc.main-vpc.id

  tags = {
    Name = "db_sg"
    Tier = "db"
  }
}

## Rules for the db security group
resource "aws_vpc_security_group_ingress_rule" "app_to_db_tls" {
  security_group_id = aws_security_group.db_sg.id

  referenced_security_group_id = aws_security_group.app_sg.id

  from_port   = 443
  ip_protocol = "tcp"
  to_port     = 443
}
