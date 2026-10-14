### default values

### aws partitions
module "aws" {
  source = "Young-ook/spinnaker/aws//modules/aws-partitions"
}

locals {
  aws = {
    dns       = module.aws.partition.dns_suffix
    partition = module.aws.partition.partition
    region    = module.aws.region.name
  }
}

locals {
  default_rule = {
    description         = null
    schedule_expression = null
    event_pattern       = null
  }
  default_bus = {
    event_source_name = null
  }
}
