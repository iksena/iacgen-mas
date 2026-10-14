locals {
  availability_zone           = data.aws_availability_zones.available.names[0]
  secondary_availability_zone = data.aws_availability_zones.available.names[1]
  vpc_cidr_block              = "10.32.0.0/20"
}