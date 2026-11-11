package intent.tf.row_243

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "vpc",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "quote": "creates a versatile VPC networking and private interface endpoint module"
  },
  {
   "id": "vpc_name",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "benchmark-vpc"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "regex",
      "value": "benchmark-vpc"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags_all",
       "Name"
      ],
      "op": "regex",
      "value": "benchmark-vpc"
     }
    }
   ],
   "quote": "a name variable defaulting to \"benchmark-vpc\""
  },
  {
   "id": "vpc_cidr",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.0.0/16"
   },
   "quote": "primary CIDR \"10.0.0.0/16\""
  },
  {
   "id": "dns_support",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "enabling DNS hostnames and DNS support by default"
  },
  {
   "id": "dns_hostnames",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enable_dns_hostnames"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "enabling DNS hostnames and DNS support by default"
  },
  {
   "id": "region_default",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "us-east-1"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "region"
      ],
      "op": "eq",
      "value": "us-east-1"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_subnet"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "availability_zone"
      ],
      "op": "regex",
      "value": "^us-east-1"
     }
    }
   ],
   "quote": "by default in us-east-1"
  },
  {
   "id": "existing_vpc_param",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "(?i)(^|_)vpc_id$"
   },
   "quote": "unless an existing vpc_id is supplied"
  },
  {
   "id": "existing_vpc_optional",
   "tier": "detail",
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
        "value": "aws_vpc"
       }
      ]
     },
     "cond": {
      "path": [
       "gated"
      ],
      "op": "truthy"
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
        "value": "data.aws_vpc"
       }
      ]
     },
     "cond": {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    }
   ],
   "quote": "either new VPC provisioning or integration with existing infrastructure"
  },
  {
   "id": "subnets",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "min": 6,
   "quote": "private subnets, and database subnets using a default CIDR map across two default availability zones",
   "justify": "public, private and database tiers across two AZs"
  },
  {
   "id": "subnet_azs",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "min": 2,
   "distinct_path": [
    "availability_zone"
   ],
   "quote": "across two default availability zones in the us-east-1 region",
   "max": 2
  },
  {
   "id": "subnets_vpc",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "quote": "private subnets, and database subnets"
  },
  {
   "id": "public_no_map_ip",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "map_public_ip_on_launch"
    ],
    "op": "none_eq",
    "value": true
   },
   "quantifier": "all",
   "quote": "public subnets (not mapping public IPs on launch by default)"
  },
  {
   "id": "db_subnet_group",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_db_subnet_group"
    ],
    "where": []
   },
   "quote": "an RDS database subnet group"
  },
  {
   "id": "db_subnet_group_subnets",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_db_subnet_group"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "an RDS database subnet group"
  },
  {
   "id": "db_subnet_group_name",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_db_subnet_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "benchmark-vpc"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_db_subnet_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^benchmark-vpc"
     }
    }
   ],
   "quote": "named using a lowercased version of the VPC name"
  },
  {
   "id": "igw",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
   },
   "quote": "an Internet Gateway"
  },
  {
   "id": "nat_single",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   },
   "min": 1,
   "max": 1,
   "quote": "a single Elastic IP-backed NAT Gateway",
   "justify": "a single NAT gateway"
  },
  {
   "id": "nat_eip",
   "tier": "core",
   "kind": "ref",
   "from": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_eip"
    ],
    "where": []
   },
   "quote": "Elastic IP-backed NAT Gateway"
  },
  {
   "id": "nat_public_subnet",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "deployed in the first public subnet"
  },
  {
   "id": "nat_private_route",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
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
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": [
       {
        "path": [
         "route",
         "*",
         "cidr_block"
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
     "kind": "ref",
     "from": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_route_table"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "0\\.0\\.0\\.0/0"
       }
      ]
     },
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_nat_gateway"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_route"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "0\\.0\\.0\\.0/0"
       }
      ]
     },
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_nat_gateway"
       }
      ]
     }
    }
   ],
   "quote": "targeting the private route table",
   "justify": "outbound routing through NAT is the default route 0.0.0.0/0"
  },
  {
   "id": "existing_nat_param",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "existing_nat_id"
   },
   "quote": "unless an existing_nat_id is provided"
  },
  {
   "id": "endpoints_interface",
   "tier": "core",
   "kind": "exists",
   "select": {
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
   "min": 7,
   "quote": "interface VPC endpoints",
   "justify": "eight services listed; s3 may legitimately be a gateway endpoint"
  },
  {
   "id": "endpoint_ec2",
   "tier": "core",
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
      "value": "\\.ec2$"
     }
    ]
   },
   "quote": "\"ec2\""
  },
  {
   "id": "endpoint_ecr_api",
   "tier": "core",
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
     }
    ]
   },
   "quote": "\"ecr.api\""
  },
  {
   "id": "endpoint_ecr_dkr",
   "tier": "core",
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
     }
    ]
   },
   "quote": "\"ecr.dkr\""
  },
  {
   "id": "endpoint_s3",
   "tier": "core",
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
      "value": "\\.s3$"
     }
    ]
   },
   "quote": "\"s3\""
  },
  {
   "id": "endpoint_logs",
   "tier": "core",
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
     }
    ]
   },
   "quote": "\"logs\""
  },
  {
   "id": "endpoint_sts",
   "tier": "core",
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
      "value": "\\.sts$"
     }
    ]
   },
   "quote": "\"sts\""
  },
  {
   "id": "endpoint_elb",
   "tier": "core",
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
      "value": "\\.elasticloadbalancing$"
     }
    ]
   },
   "quote": "\"elasticloadbalancing\""
  },
  {
   "id": "endpoint_asg",
   "tier": "core",
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
      "value": "\\.autoscaling$"
     }
    ]
   },
   "quote": "\"autoscaling\""
  },
  {
   "id": "endpoints_private_subnets",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "attached to all private subnets"
  },
  {
   "id": "endpoint_sg_param",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "(?i)(^|_)security_group_id$"
   },
   "quote": "secured either by an existing security_group_id"
  },
  {
   "id": "endpoint_sg",
   "tier": "core",
   "kind": "ref",
   "quote": "secured either by an existing security_group_id or by a newly created endpoint security group",
   "from": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_security_group"
    ],
    "where": []
   }
  },
  {
   "id": "endpoint_sg_name",
   "tier": "detail",
   "kind": "any_of",
   "quote": "named using the VPC's name value followed by the suffix \"-vpc-endpoints\"",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^benchmark-vpc.*-vpc-endpoints$"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name_prefix"
      ],
      "op": "regex",
      "value": "^benchmark-vpc.*-vpc-endpoints"
     }
    }
   ]
  },
  {
   "id": "sg_ingress_https",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     },
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
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
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
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     }
    }
   ],
   "quote": "permits inbound HTTPS port 443 traffic from the VPC CIDR",
   "justify": "HTTPS implies 443/tcp"
  },
  {
   "id": "sg_egress_vpc",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
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
           "cidr_blocks",
           "*"
          ],
          "op": "eq",
          "value": "10.0.0.0/16"
         }
        ]
       },
       {
        "path": [
         "egress",
         "*",
         "ipv6_cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     },
     "cond": {
      "path": [
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "10.0.0.0/16",
      "every": true
     }
    },
    {
     "kind": "attr",
     "quantifier": "all",
     "select": {
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
       }
      ]
     },
     "cond": {
      "path": [
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "10.0.0.0/16",
      "every": true
     }
    },
    {
     "kind": "attr",
     "quantifier": "all",
     "select": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "cidr_ipv4"
      ],
      "op": "eq",
      "value": "10.0.0.0/16"
     }
    }
   ],
   "quote": "outbound traffic only within the VPC CIDR"
  },
  {
   "id": "x_public_route_igw",
   "tier": "extra",
   "kind": "any_of",
   "checks": [
    {
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
       "aws_internet_gateway"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "x_assoc",
   "tier": "extra",
   "kind": "exists",
   "select": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "min": 4
  },
  {
   "id": "x_nat_public",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "connectivity_type"
    ],
    "op": "eq",
    "value": "public"
   }
  },
  {
   "id": "x_endpoint_vpc",
   "tier": "extra",
   "kind": "ref",
   "from": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
