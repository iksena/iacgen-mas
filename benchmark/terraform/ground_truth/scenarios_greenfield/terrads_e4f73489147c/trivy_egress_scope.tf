# VPC CIDRs used to scope security-group rules that previously allowed 0.0.0.0/0
# (Trivy AWS-0104 unrestricted egress / AWS-0107 admin ports open to the internet).

data "aws_vpc" "trivy_scope_1" {
  id = module.vpc.vpc_id
}
