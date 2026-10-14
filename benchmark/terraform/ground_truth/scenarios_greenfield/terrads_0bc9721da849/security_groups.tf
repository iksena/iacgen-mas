resource "aws_security_group" "postgres-db" {
  description = "RDS PostgreSQL on dev VPC"
  name        = "lambda-rds-dev-postgres-db"
  vpc_id      = aws_vpc.dev-vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = [
      local.vpc_cidr_block,
    ]
  }
}

resource "aws_security_group_rule" "postgres-db-ingress-bastion-rule" {
  security_group_id        = aws_security_group.postgres-db.id
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  type                     = "ingress"
  source_security_group_id = aws_security_group.bastion-host.id
}

resource "aws_security_group_rule" "postgres-db-ingress-lambda-rule" {
  security_group_id        = aws_security_group.postgres-db.id
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  type                     = "ingress"
  source_security_group_id = aws_security_group.lambda-functions.id
}

resource "aws_security_group" "lambda-functions" {
  description = "Lambda functions running on the dev VPC"
  name        = "lambda-rds-dev-lambda-functions"
  vpc_id      = aws_vpc.dev-vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = [
      local.vpc_cidr_block,
    ]
  }
}

resource "aws_security_group" "bastion-host" {
  description = "Bastion host to access RDS DB"
  name        = "lambda-rds-dev-bastion-host"
  vpc_id      = aws_vpc.dev-vpc.id

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = -1
    security_groups = [
      aws_security_group.postgres-db.id
    ]
  }

  # SSH reachable from inside the VPC only (use SSM Session Manager or a VPN to reach it).
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [
      aws_vpc.dev-vpc.cidr_block
    ]
  }
}
