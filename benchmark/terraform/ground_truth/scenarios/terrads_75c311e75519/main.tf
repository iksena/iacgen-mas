locals {  
  resource_group_name = var.resource_group_name != "" && var.resource_group_name != null ? var.resource_group_name : "default"
  prefix_name     = var.name_prefix != "" && var.name_prefix != null ? var.name_prefix : local.resource_group_name
  vpc_name        = var.name != "" ? var.name : "${local.prefix_name}-vpc"
  vpc_id          = var.provision ? data.aws_vpc.vpc[0].id : ""
  cidr_block      = var.provision ? data.aws_vpc.vpc[0].cidr_block : ""
  arn             = var.provision ? data.aws_vpc.vpc[0].arn : ""
  security_group_id  = length(data.aws_security_group.default_aws_security_group) > 0 ? data.aws_security_group.default_aws_security_group[0].id : ""
  security_group_arn = length(data.aws_security_group.default_aws_security_group) > 0 ? data.aws_security_group.default_aws_security_group[0].arn : ""
  
  acl_id          = var.provision && data.aws_network_acls.default-vpc-network-acls != null && length(tolist(data.aws_network_acls.default-vpc-network-acls[0].ids))>0 ? tolist(data.aws_network_acls.default-vpc-network-acls[0].ids)[0] : ""
}

# Create a VPC
resource "aws_vpc" "vpc" {
  count                = var.provision ? 1 : 0
  
  cidr_block           = var.internal_cidr
  instance_tenancy     = var.instance_tenancy
  enable_dns_support   = var.enable_dns_support
  enable_dns_hostnames = var.enable_dns_hostnames

  tags = {
    Name = local.vpc_name
    ResourceGroup = local.resource_group_name
  }
}

data "aws_vpc" "vpc" {
  depends_on = [aws_vpc.vpc]
  count = var.provision ? 1 : 0

  tags = {
    Name = local.vpc_name
  }
}

data "aws_network_acls" "default-vpc-network-acls" {
  depends_on = [aws_vpc.vpc]  
  count = var.provision ? 1 : 0

  #count = var.provision && var._count > 0 ?  1 : 0
  vpc_id = local.vpc_id

  filter {
    name   = "default"
    values = ["true"]
  }
}

resource "aws_default_network_acl" "default" {

  depends_on = [aws_vpc.vpc, data.aws_network_acls.default-vpc-network-acls]
  count = var.provision ? 1 : 0
  #count = var.provision && var._count > 0 ?  1 : 0
  default_network_acl_id = local.acl_id

  # if no rules defined, deny all traffic in this ACL
  egress {          #allow_internal_egress
    protocol   = -1 # -1 'all' protocol
    rule_no    = 100
    action     = "allow"
    cidr_block = local.cidr_block
    from_port  = 0
    to_port    = 0
  }

  ingress {         #allow_internal_ingress
    protocol   = -1 #-1 'all' protocol 
    rule_no    = 200
    action     = "allow"
    cidr_block = local.cidr_block
    from_port  = 0
    to_port    = 0
  }

  ingress {            #deny_external_ssh
    protocol   = "tcp" #-1 'all' protocol 
    rule_no    = 300
    action     = "deny"
    cidr_block = var.external_cidr //"0.0.0.0/0"
    from_port  = 22
    to_port    = 22
  }

  ingress {            #deny_external_rdp
    protocol   = "tcp" # -1 'all' protocol
    rule_no    = 400
    action     = "deny"
    cidr_block = var.external_cidr //"0.0.0.0/0"
    from_port  = 3389
    to_port    = 3389
  }

  tags = {
    Name = "${local.vpc_name}-default_acl"
    ResourceGroup = local.resource_group_name
  }
}

resource "aws_default_security_group" "default_security_group" {
  count = var.provision  ? 1 : 0
  
  vpc_id = local.vpc_id

  tags = {
    Name = "${local.vpc_name}-default_sg"
    ResourceGroup = local.resource_group_name
  }
}

resource "aws_security_group_rule" "default_inbound_ping" {
  count = var.provision  ? 1 : 0
  

  type              = "ingress"
  from_port         = 8
  to_port           = 8
  protocol          = "icmp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = element(aws_default_security_group.default_security_group.*, 0).id
}

resource "aws_security_group_rule" "default_inbound_http" {
  count = var.provision  ? 1 : 0
  
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = element(aws_default_security_group.default_security_group.*, 0).id
}

data "aws_security_group" "default_aws_security_group" {
  count = var.provision ? 1 : 0
  
  vpc_id = local.vpc_id

  filter {
    name   = "group-name"
    values = ["default"]
  }
}