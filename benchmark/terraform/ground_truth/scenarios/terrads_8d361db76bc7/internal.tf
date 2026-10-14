# --------------------------------------------------------------------------
# internal Subnets
# --------------------------------------------------------------------------
resource "aws_subnet" "internal" {
  for_each = var.internal ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  availability_zone = "${data.aws_region.current.name}${each.key}"
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(aws_vpc.vpc.cidr_block, var.k8s ? 6 : 4, ((var.k8s ? 17 : 2) * var.zones) + index(keys(var.az_number), each.key))


  tags = merge(local.internal_subnet_tags, {
    "Name" = "${var.internal_subnet_name}-${data.aws_region.current.name}${each.key}"
    }
  )

  timeouts {
    delete = "30m"
  }
}


# --------------------------------------------------------------------------
# Route Table
# --------------------------------------------------------------------------
resource "aws_route_table" "internal" {
  count = var.internal ? 1 : 0

  vpc_id = aws_vpc.vpc.id

  tags = local.internal_subnet_tags

  lifecycle {
    ignore_changes = [
      route
    ]
  }
}


# --------------------------------------------------------------------------
# Associate Route Table to Internal Subnets
# --------------------------------------------------------------------------
resource "aws_route_table_association" "internal" {
  for_each = var.internal ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  subnet_id      = element([for s in aws_subnet.internal : s.id], index(keys(var.az_number), each.key))
  route_table_id = aws_route_table.internal.0.id
}
