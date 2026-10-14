# --------------------------------------------------------------------------
# Public Subnets
# --------------------------------------------------------------------------
resource "aws_subnet" "public" {
  for_each = var.public ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  availability_zone = "${data.aws_region.current.name}${each.key}"
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(aws_vpc.vpc.cidr_block, var.k8s ? 6 : 4, ((var.k8s ? 16 : 1) * var.zones) + index(keys(var.az_number), each.key))

  tags = merge(local.public_subnet_tags, {
    "Name" = "${var.public_subnet_name}-${data.aws_region.current.name}${each.key}"
    }
  )

  timeouts {
    delete = "30m"
  }
}


# --------------------------------------------------------------------------
# Route Table
# --------------------------------------------------------------------------
resource "aws_route_table" "public" {
  count = var.public ? 1 : 0

  vpc_id = aws_vpc.vpc.id

  tags = local.public_subnet_tags

  lifecycle {
    ignore_changes = [route]
  }
}


# --------------------------------------------------------------------------
# Internet Gateway Route
# --------------------------------------------------------------------------
resource "aws_route" "public_internet_gateway" {
  count                  = var.public ? 1 : 0
  route_table_id         = aws_route_table.public.0.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id

  timeouts {
    create = "5m"
  }
}


# --------------------------------------------------------------------------
# IPv6 Route
# --------------------------------------------------------------------------
resource "aws_route" "public_internet_gateway_ipv6" {
  for_each = var.public && var.ipv6 ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  route_table_id              = aws_route_table.public.0.id
  destination_ipv6_cidr_block = "::/0"
  egress_only_gateway_id      = aws_egress_only_internet_gateway.ipv6.0.id
}


# --------------------------------------------------------------------------
# Associate Route Table to Private Subnets
# --------------------------------------------------------------------------
resource "aws_route_table_association" "public" {
  for_each = var.public ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  subnet_id      = element([for s in aws_subnet.public : s.id], index(keys(var.az_number), each.key))
  route_table_id = aws_route_table.public.0.id
}
