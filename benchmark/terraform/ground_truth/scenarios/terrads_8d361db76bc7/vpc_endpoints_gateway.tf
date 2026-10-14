# --------------------------------------------------------------------------
# VPC Endpoint (Gateway) - S3
# --------------------------------------------------------------------------
resource "aws_vpc_endpoint" "s3" {
  count = var.s3_endpoint ? 1 : 0

  vpc_id       = aws_vpc.vpc.id
  service_name = "com.amazonaws.${data.aws_region.current.name}.s3"

  tags = merge(
    local.tags,
    tomap({
      "Name" = "${var.name}-s3"
    })
  )

}

resource "aws_vpc_endpoint_route_table_association" "private_s3" {
  count = var.s3_endpoint && var.private_endpoints ? var.zones : 0

  vpc_endpoint_id = aws_vpc_endpoint.s3.0.id
  route_table_id  = element([for s in aws_route_table.private : s.id], count.index)
}

resource "aws_vpc_endpoint_route_table_association" "public_s3" {
  count = var.s3_endpoint && var.public_endpoints ? 1 : 0

  vpc_endpoint_id = aws_vpc_endpoint.s3.0.id
  route_table_id  = aws_route_table.public.0.id
}

resource "aws_vpc_endpoint_route_table_association" "internal_s3" {
  count = var.s3_endpoint && var.internal_endpoints ? 1 : 0

  vpc_endpoint_id = aws_vpc_endpoint.s3.0.id
  route_table_id  = aws_route_table.internal.0.id
}

resource "aws_vpc_endpoint_route_table_association" "db_s3" {
  count = var.s3_endpoint && var.db_endpoints ? 1 : 0

  vpc_endpoint_id = aws_vpc_endpoint.s3[0].id
  route_table_id  = aws_route_table.db[0].id
}

resource "aws_vpc_endpoint_route_table_association" "cache_s3" {
  count = var.s3_endpoint && var.cache_endpoints ? 1 : 0

  vpc_endpoint_id = aws_vpc_endpoint.s3[0].id
  route_table_id  = aws_route_table.cache[0].id
}
