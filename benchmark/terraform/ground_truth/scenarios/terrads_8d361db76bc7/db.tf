# --------------------------------------------------------------------------
# Database Subnets
# --------------------------------------------------------------------------
resource "aws_subnet" "db" {
  for_each = var.db ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  availability_zone = "${data.aws_region.current.name}${each.key}"
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(aws_vpc.vpc.cidr_block, var.k8s ? 6 : 4, ((var.k8s ? 18 : 3) * var.zones) + index(keys(var.az_number), each.key))


  tags = merge(local.db_subnet_tags, {
    "Name" = "${var.db_subnet_name}-${data.aws_region.current.name}${each.key}"
    }
  )

  timeouts {
    delete = "30m"
  }
}


# --------------------------------------------------------------------------
# Route Table
# --------------------------------------------------------------------------
resource "aws_route_table" "db" {
  count = var.db ? 1 : 0

  vpc_id = aws_vpc.vpc.id

  tags = local.db_subnet_tags

  lifecycle {
    ignore_changes = [
      route
    ]
  }
}


# --------------------------------------------------------------------------
# Associate Route Table to Database Subnets
# --------------------------------------------------------------------------
resource "aws_route_table_association" "db" {
  for_each = var.db ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  subnet_id      = element([for s in aws_subnet.db : s.id], index(keys(var.az_number), each.key))
  route_table_id = aws_route_table.db.0.id
}


# --------------------------------------------------------------------------
# RDS Database Subnet Group
# --------------------------------------------------------------------------
resource "aws_db_subnet_group" "db" {
  count = var.db == true ? 1 : 0

  name       = "${var.name}-db"
  subnet_ids = [for s in aws_subnet.db : s.id]

  tags = local.db_subnet_tags
}
