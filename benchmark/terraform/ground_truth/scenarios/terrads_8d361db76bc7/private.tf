# --------------------------------------------------------------------------
# Private Subnets
# --------------------------------------------------------------------------
resource "aws_subnet" "private" {
  for_each = var.private ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  availability_zone = "${data.aws_region.current.name}${each.key}"
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(aws_vpc.vpc.cidr_block, var.k8s ? 2 : 4, (0 * var.zones) + index(keys(var.az_number), each.key))


  tags = merge(local.private_subnet_tags, {
    "Name" = "${var.private_subnet_name}-${data.aws_region.current.name}${each.key}"
    }
  )

  timeouts {
    delete = "30m"
  }
}


# --------------------------------------------------------------------------
# Route Table
# --------------------------------------------------------------------------
resource "aws_route_table" "private" {
  for_each = var.private ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  vpc_id = aws_vpc.vpc.id

  tags = var.single_nat_gateway ? local.private_subnet_tags : merge(
    local.private_subnet_tags, {
      "Name" = "${var.private_subnet_name}-${data.aws_availability_zones.available.names[index(keys(var.az_number), each.key)]}"
    }
  )

  lifecycle {
    ignore_changes = [
      route
    ]
  }
}


# --------------------------------------------------------------------------
# NAT Gateway route
# --------------------------------------------------------------------------
resource "aws_route" "private_nat_gateway" {
  count = var.private ? local.nat_gateway_count : 0

  route_table_id         = element([for s in aws_route_table.private : s.id], count.index)
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = element([for s in aws_nat_gateway.natgw : s.id], count.index)

  timeouts {
    create = "5m"
  }
}


# --------------------------------------------------------------------------
# IPv6 Route
# --------------------------------------------------------------------------
resource "aws_route" "private_ipv6_egress" {
  for_each = var.private && var.ipv6 ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  route_table_id              = element([for s in aws_route_table.private : s.id], index(keys(var.az_number), each.key))
  destination_ipv6_cidr_block = "::/0"
  egress_only_gateway_id      = aws_egress_only_internet_gateway.ipv6.0.id
}


# --------------------------------------------------------------------------
# Associate Route Table to Private Subnets
# --------------------------------------------------------------------------
resource "aws_route_table_association" "private" {
  for_each = var.private ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  subnet_id      = element([for s in aws_subnet.private : s.id], index(keys(var.az_number), each.key))
  route_table_id = element([for s in aws_route_table.private : s.id], var.single_nat_gateway ? 0 : index(keys(var.az_number), each.key))
}
