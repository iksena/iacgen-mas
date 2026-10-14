resource "aws_eip" "eip" {
  count = var.is_public ? length(var.subnets) : 0

  domain = "vpc"

  tags = var.tags
}