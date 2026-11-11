package intent.tf.row_236

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "aws_vpc"
   ],
   "where": []
  },
  "subnets": {
   "types": [
    "aws_subnet"
   ],
   "where": []
  },
  "sg": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "vpc_endpoint_sg"
    }
   ]
  },
  "iface": {
   "types": [
    "aws_vpc_endpoint"
   ],
   "where": [
    {
     "path": [
      "vpc_endpoint_type"
     ],
     "op": "eq",
     "value": "Interface"
    }
   ]
  },
  "s3ep": {
   "types": [
    "aws_vpc_endpoint"
   ],
   "where": [
    {
     "path": [
      "service_name"
     ],
     "op": "regex",
     "value": "\\.s3$"
    },
    {
     "path": [
      "vpc_endpoint_type"
     ],
     "op": "eq",
     "value": "Gateway"
    }
   ]
  },
  "rt": {
   "types": [
    "aws_route_table"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc_name_var",
   "tier": "core",
   "quote": "a vpc_name variable defaulting to \"benchmark-vpc\"",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "vpc_name"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "benchmark-vpc"
     }
    ]
   }
  },
  {
   "id": "vpc_cidr",
   "tier": "core",
   "quote": "primary IPv4 CIDR defaulting to \"172.16.0.0/16\"",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": [
     {
      "path": [
       "cidr_block"
      ],
      "op": "eq",
      "value": "172.16.0.0/16"
     }
    ]
   }
  },
  {
   "id": "dns_hostnames",
   "tier": "core",
   "quote": "enabling DNS hostnames",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_hostnames"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "no_generated_ipv6",
   "tier": "detail",
   "quote": "disabling generated IPv6 CIDRs",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "assign_generated_ipv6_cidr_block"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "assign_generated_ipv6_cidr_block"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "default_sg_deny_all",
   "tier": "core",
   "quote": "setting default security group rules to deny all traffic",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_default_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ingress"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_default_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ingress"
      ],
      "op": "len_eq",
      "value": 0
     }
    }
   ]
  },
  {
   "id": "default_sg_no_egress",
   "tier": "core",
   "quote": "setting default security group rules to deny all traffic",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_default_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "egress"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_default_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "egress"
      ],
      "op": "len_eq",
      "value": 0
     }
    }
   ]
  },
  {
   "id": "subnets_across_azs",
   "tier": "core",
   "quote": "Subnets must be dynamically provisioned across specified availability zones, defaulting to the first three availability zones in the us-east-1 region",
   "kind": "exists",
   "select": "subnets",
   "distinct_path": [
    "availability_zone"
   ],
   "min": 3,
   "justify": "first three availability zones means three distinct AZs"
  },
  {
   "id": "subnets_in_us_east_1",
   "tier": "detail",
   "quote": "availability zones in the us-east-1 region",
   "kind": "attr",
   "select": "subnets",
   "cond": {
    "path": [
     "availability_zone"
    ],
    "op": "regex",
    "value": "^us-east-1"
   },
   "quantifier": "all"
  },
  {
   "id": "nat_gateway",
   "tier": "core",
   "quote": "enabling NAT gateway support for outbound routing",
   "kind": "exists",
   "select": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   }
  },
  {
   "id": "s3_gateway_endpoint",
   "tier": "core",
   "quote": "an S3 Gateway VPC endpoint",
   "kind": "exists",
   "select": "s3ep"
  },
  {
   "id": "s3_endpoint_route_tables",
   "tier": "detail",
   "quote": "associated with the public, private, and default route tables",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "s3ep",
     "to": "rt"
    },
    {
     "kind": "attr",
     "select": "s3ep",
     "cond": {
      "path": [
       "route_table_ids"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "s3_endpoint_default_route_table",
   "tier": "detail",
   "quote": "public, private, and default route tables",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_vpc_endpoint"
       },
       {
        "path": [
         "properties",
         "service_name"
        ],
        "op": "regex",
        "value": "(?i)s3"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "route_table_ids"
      ],
      "op": "regex",
      "value": "(?i)default|main_route"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_vpc_endpoint_route_table_association"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "route_table_id"
      ],
      "op": "regex",
      "value": "(?i)default|main_route"
     }
    }
   ],
   "justify": "the VPC's default route table is the main route table, referenced as default_route_table_id, main_route_table_id or aws_default_route_table"
  },
  {
   "id": "ecr_dkr_endpoint",
   "tier": "core",
   "quote": "private DNS-enabled Interface VPC endpoints for ECR Docker, ECR API, CloudWatch Logs, SSM, and KMS",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "\\.ecr\\.dkr$"
     },
     {
      "path": [
       "vpc_endpoint_type"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   },
   "justify": "ECR Docker is the ecr.dkr service"
  },
  {
   "id": "ecr_api_endpoint",
   "tier": "core",
   "quote": "private DNS-enabled Interface VPC endpoints for ECR Docker, ECR API, CloudWatch Logs, SSM, and KMS",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "\\.ecr\\.api$"
     },
     {
      "path": [
       "vpc_endpoint_type"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   },
   "justify": "ECR API is the ecr.api service"
  },
  {
   "id": "logs_endpoint",
   "tier": "core",
   "quote": "private DNS-enabled Interface VPC endpoints for ECR Docker, ECR API, CloudWatch Logs, SSM, and KMS",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "\\.logs$"
     },
     {
      "path": [
       "vpc_endpoint_type"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   },
   "justify": "CloudWatch Logs is the logs service"
  },
  {
   "id": "ssm_endpoint",
   "tier": "core",
   "quote": "private DNS-enabled Interface VPC endpoints for ECR Docker, ECR API, CloudWatch Logs, SSM, and KMS",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "\\.ssm$"
     },
     {
      "path": [
       "vpc_endpoint_type"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   }
  },
  {
   "id": "kms_endpoint",
   "tier": "core",
   "quote": "private DNS-enabled Interface VPC endpoints for ECR Docker, ECR API, CloudWatch Logs, SSM, and KMS",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "\\.kms$"
     },
     {
      "path": [
       "vpc_endpoint_type"
      ],
      "op": "eq",
      "value": "Interface"
     }
    ]
   }
  },
  {
   "id": "private_dns",
   "tier": "core",
   "quote": "private DNS-enabled Interface VPC endpoints",
   "kind": "attr",
   "select": "iface",
   "cond": {
    "path": [
     "private_dns_enabled"
    ],
    "op": "truthy"
   },
   "quantifier": "all"
  },
  {
   "id": "endpoints_in_subnets",
   "tier": "detail",
   "quote": "residing in the private subnets",
   "kind": "ref",
   "from": "iface",
   "to": "subnets"
  },
  {
   "id": "endpoint_sg_named",
   "tier": "core",
   "quote": "a dedicated security group named \"vpc_endpoint_sg\"",
   "kind": "exists",
   "select": "sg"
  },
  {
   "id": "endpoints_use_sg",
   "tier": "core",
   "quote": "Access to these interface endpoints must be controlled by a dedicated security group",
   "kind": "ref",
   "from": "iface",
   "to": "sg"
  },
  {
   "id": "sg_ingress_443_self",
   "tier": "core",
   "quote": "self-referencing TCP ingress and egress rules exclusively on port 443",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "self"
        ],
        "op": "truthy"
       }
      ]
     },
     "to": "sg"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "absent"
       },
       {
        "path": [
         "ipv6_cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "sg"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "absent"
       },
       {
        "path": [
         "cidr_ipv6"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "sg"
    },
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "self"
        ],
        "op": "truthy"
       }
      ]
     }
    }
   ],
   "justify": "HTTPS port 443; self-referencing means the rule source is the group itself"
  },
  {
   "id": "sg_egress_443_self",
   "tier": "core",
   "quote": "self-referencing TCP ingress and egress rules exclusively on port 443",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "egress"
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "self"
        ],
        "op": "truthy"
       }
      ]
     },
     "to": "sg"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "egress"
       },
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "absent"
       },
       {
        "path": [
         "ipv6_cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "sg"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "from_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "to_port"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "absent"
       },
       {
        "path": [
         "cidr_ipv6"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "sg"
    },
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "egress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "self"
        ],
        "op": "truthy"
       }
      ]
     }
    }
   ],
   "justify": "HTTPS port 443; self-referencing means the rule destination is the group itself"
  },
  {
   "id": "nat_per_az",
   "tier": "extra",
   "kind": "exists",
   "select": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   },
   "min": 3
  },
  {
   "id": "private_route_via_nat",
   "tier": "extra",
   "kind": "ref",
   "from": {
    "types": [
     "aws_route"
    ],
    "where": [
     {
      "path": [
       "destination_cidr_block"
      ],
      "op": "eq",
      "value": "0.0.0.0/0"
     }
    ]
   },
   "to": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   }
  },
  {
   "id": "vpc_dns_support",
   "tier": "extra",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "extra_type_aws_eip",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_eip"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_internet_gateway",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_network_acl",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_network_acl"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_network_acl_rule",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_network_acl_rule"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_route_table_association",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
