resource "aws_subnet" "lambda-rds-db-subnet-1" {
  vpc_id            = aws_vpc.dev-vpc.id
  availability_zone = local.availability_zone
  cidr_block        = "10.32.0.0/28"

  tags = {
    Name = "lambda-rds-db-subnet-1"
  }
}

resource "aws_subnet" "lambda-rds-db-subnet-2" {
  vpc_id            = aws_vpc.dev-vpc.id
  availability_zone = local.secondary_availability_zone
  cidr_block        = "10.32.0.16/28"

  tags = {
    Name = "lambda-rds-db-subnet-2"
  }
}

resource "aws_subnet" "lambda-rds-dev-lambda-subnet" {
  vpc_id            = aws_vpc.dev-vpc.id
  availability_zone = local.availability_zone
  cidr_block        = "10.32.1.0/24"

  tags = {
    Name = "lambda-rds-dev-lambda-subnet"
  }
}

resource "aws_subnet" "lambda-rds-bastion-host-subnet" {
  vpc_id                  = aws_vpc.dev-vpc.id
  availability_zone       = local.availability_zone
  cidr_block              = "10.32.15.0/24"

  tags = {
    Name = "lambda-rds-bastion-host-subnet"
  }
}