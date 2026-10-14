data "aws_ami" "latest_amazon_linux" {
  owners      = ["amazon"]
  most_recent = true
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Self-contained VPC (replacing the default-VPC dependency -- AWS-0101).
resource "aws_vpc" "web" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "web" {
  vpc_id                  = aws_vpc.web.id
  cidr_block              = "10.0.0.0/24"
  availability_zone       = element(data.aws_availability_zones.available.names, 0)
  map_public_ip_on_launch = false
}

resource "aws_internet_gateway" "web" {
  vpc_id = aws_vpc.web.id
}

resource "aws_route_table" "web" {
  vpc_id = aws_vpc.web.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.web.id
  }
}

resource "aws_route_table_association" "web" {
  subnet_id      = aws_subnet.web.id
  route_table_id = aws_route_table.web.id
}

resource "aws_instance" "web" {
  ami                         = data.aws_ami.latest_amazon_linux.id
  instance_type               = var.server_size
  subnet_id                   = aws_subnet.web.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = true
  user_data                   = <<EOF
#!/bin/bash
yum -y update
yum -y install httpd
myip=`curl http://169.254.169.254/latest/meta-data/local-ipv4`
echo "<h2>${var.server_name}-WebServer with IP: $myip</h2><br>Build by Terraform!"  >  /var/www/html/index.html
sudo service httpd start
chkconfig httpd on
EOF

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name  = "${var.server_name}-WebServer"
    Owner = "Denis Astahov"
  }
}

resource "aws_security_group" "web" {
  name_prefix = "${var.server_name}-WebServer-SG"
  vpc_id      = aws_vpc.web.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.web.cidr_block]
  }

  tags = {
    Name  = "${var.server_name}-WebServer SecurityGroup"
    Owner = "Denis Astahov"
  }
}

resource "aws_eip" "web" {
 domain    = "vpc" # Need to add in new AWS Provider version
  instance = aws_instance.web.id
  tags = {
    Name  = "${var.server_name}-WebServer-IP"
    Owner = "Denis Astahov"
  }
}
