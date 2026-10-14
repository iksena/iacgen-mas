# --------------------------------------------------------------------------
# Cache Subnets
# --------------------------------------------------------------------------
resource "aws_subnet" "cache" {
  for_each = var.cache ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  availability_zone = "${data.aws_region.current.name}${each.key}"
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(aws_vpc.vpc.cidr_block, var.k8s ? 6 : 4, ((var.k8s ? 19 : 4) * var.zones) + index(keys(var.az_number), each.key))


  tags = merge(local.cache_subnet_tags, {
    "Name" = "${var.cache_subnet_name}-${data.aws_region.current.name}${each.key}"
    }
  )

  timeouts {
    delete = "30m"
  }
}


# --------------------------------------------------------------------------
# Route Table
# --------------------------------------------------------------------------
resource "aws_route_table" "cache" {
  count = var.cache ? 1 : 0

  vpc_id = aws_vpc.vpc.id

  tags = local.cache_subnet_tags

  lifecycle {
    ignore_changes = [
      route
    ]
  }
}


# --------------------------------------------------------------------------
# Associate Route Table with Cache Subnets
# --------------------------------------------------------------------------
resource "aws_route_table_association" "cache" {
  for_each = var.cache ? toset(slice(keys(var.az_number), 0, var.zones)) : toset([])

  subnet_id      = element([for s in aws_subnet.cache : s.id], index(keys(var.az_number), each.key))
  route_table_id = aws_route_table.cache.0.id
}


# --------------------------------------------------------------------------
# ElastiCache Cache Subnet Group
# --------------------------------------------------------------------------
resource "aws_elasticache_subnet_group" "cache" {
  count = var.cache ? 1 : 0

  name        = "${var.name}-elasticache"
  description = "ElastiCache subnet group for ${var.name}"
  subnet_ids  = [for s in aws_subnet.cache : s.id]
}
