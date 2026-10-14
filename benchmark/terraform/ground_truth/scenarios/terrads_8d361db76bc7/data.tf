# --------------------------------------------------------------------------
# Locals - Data Sources
# --------------------------------------------------------------------------

# Determine all of the available availability zones in the
# current AWS region.
data "aws_availability_zones" "available" {
  state = "available"
}

# This additional data source determines some additional
# details about each VPC, including its suffix letter.
data "aws_availability_zone" "all" {
  count = var.zones

  name = data.aws_availability_zones.available.names[count.index]
}

# Get the current AWS region name
data "aws_region" "current" {}
