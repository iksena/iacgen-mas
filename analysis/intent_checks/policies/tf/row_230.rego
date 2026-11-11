package intent.tf.row_230

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "quote": "a VPC with DNS hostnames"
  },
  {
   "id": "vpc_dns_hostnames",
   "kind": "attr",
   "tier": "core",
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
    "op": "truthy"
   },
   "quote": "DNS hostnames and DNS support enabled"
  },
  {
   "id": "vpc_dns_support",
   "kind": "attr",
   "tier": "core",
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
    "op": "truthy"
   },
   "quote": "DNS hostnames and DNS support enabled"
  },
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "tier": "core",
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
   "quote": "defaulting to CIDR \"10.0.0.0/16\""
  },
  {
   "id": "vpc_name",
   "kind": "attr",
   "tier": "core",
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
    "op": "eq",
    "value": "DatatogAgentlessScanner"
   },
   "quote": "name tag \"DatatogAgentlessScanner\""
  },
  {
   "id": "tag_datadog",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
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
       "Datadog"
      ],
      "op": "eq",
      "value": "true"
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
       "Datadog"
      ],
      "op": "eq",
      "value": "true"
     }
    }
   ],
   "quote": "\"Datadog\" = \"true\""
  },
  {
   "id": "tag_scanner",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
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
       "DatadogAgentlessScanner"
      ],
      "op": "eq",
      "value": "true"
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
       "DatadogAgentlessScanner"
      ],
      "op": "eq",
      "value": "true"
     }
    }
   ],
   "quote": "\"DatadogAgentlessScanner\" = \"true\""
  },
  {
   "id": "subnets_public_private",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "dynamically compute public and offset private subnets across the availability zones",
   "min": 2,
   "justify": "at least one public and one private subnet"
  },
  {
   "id": "subnets_multi_az",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "across up to 3 available availability zones",
   "min": 2,
   "distinct_path": [
    "availability_zone"
   ],
   "justify": "multi-AZ implied by up to 3 AZs"
  },
  {
   "id": "igw",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
   },
   "quote": "an Internet Gateway"
  },
  {
   "id": "igw_vpc",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_internet_gateway_attachment"
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
   ],
   "quote": "an Internet Gateway"
  },
  {
   "id": "public_default_route",
   "kind": "any_of",
   "tier": "core",
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
       "aws_internet_gateway"
      ],
      "where": []
     }
    }
   ],
   "quote": "a public route table routing 0.0.0.0/0 to the gateway"
  },
  {
   "id": "single_eip",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_eip"
    ],
    "where": []
   },
   "quote": "a single Elastic IP and NAT Gateway",
   "min": 1,
   "max": 1,
   "justify": "single means exactly one"
  },
  {
   "id": "single_nat",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   },
   "quote": "a single Elastic IP and NAT Gateway placed in the first public subnet",
   "min": 1,
   "max": 1,
   "justify": "single means exactly one"
  },
  {
   "id": "nat_uses_eip",
   "kind": "ref",
   "tier": "detail",
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
   "quote": "a single Elastic IP and NAT Gateway"
  },
  {
   "id": "nat_in_subnet",
   "kind": "ref",
   "tier": "core",
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
   "quote": "NAT Gateway placed in the first public subnet"
  },
  {
   "id": "private_default_route_nat",
   "kind": "any_of",
   "tier": "core",
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
    }
   ],
   "quote": "a private route table routing 0.0.0.0/0 to the NAT Gateway"
  },
  {
   "id": "route_tables",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_route_table"
    ],
    "where": []
   },
   "quote": "an Internet Gateway with a public route table routing 0.0.0.0/0 to the gateway",
   "min": 2,
   "justify": "one public and one private route table"
  },
  {
   "id": "s3_gateway_endpoint",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
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
       },
       {
        "path": [
         "vpc_endpoint_type"
        ],
        "op": "eq",
        "value": "Gateway"
       }
      ]
     }
    },
    {
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
       },
       {
        "path": [
         "vpc_endpoint_type"
        ],
        "op": "absent"
       }
      ]
     }
    }
   ],
   "quote": "an S3 Gateway VPC Endpoint"
  },
  {
   "id": "s3_endpoint_route_tables",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
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
     "to": {
      "types": [
       "aws_route_table"
      ],
      "where": []
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_vpc_endpoint_route_table_association"
      ],
      "where": []
     },
     "min": 2
    }
   ],
   "quote": "associated with both route tables"
  },
  {
   "id": "endpoint_sg_443",
   "kind": "any_of",
   "tier": "core",
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
        "op": "regex",
        "value": "^10\\.0\\.0\\.0/16$"
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
        "path": [],
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
          "op": "regex",
          "value": "^10\\.0\\.0\\.0/16$"
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
      ]
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "match",
        "value": [
         {
          "path": [],
          "op": "port_covers",
          "value": 443
         },
         {
          "path": [
           "cidr_ipv4"
          ],
          "op": "regex",
          "value": "^10\\.0\\.0\\.0/16$"
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
      ]
     },
     "to": {
      "types": [
       "aws_security_group"
      ],
      "where": []
     }
    }
   ],
   "quote": "an interface VPC endpoint security group permitting inbound TCP port 443 from the VPC CIDR block",
   "justify": "HTTPS 443 over TCP as stated (an all-protocol rule does not count); the VPC CIDR block defaults to 10.0.0.0/16"
  },
  {
   "id": "lambda_endpoint",
   "kind": "exists",
   "tier": "core",
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
      "value": "\\.lambda$"
     }
    ]
   },
   "quote": "interface VPC endpoints for Lambda and EBS"
  },
  {
   "id": "ebs_endpoint",
   "kind": "exists",
   "tier": "core",
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
      "value": "\\.ebs$"
     }
    ]
   },
   "quote": "interface VPC endpoints for Lambda and EBS"
  },
  {
   "id": "interface_endpoints_type",
   "kind": "attr",
   "tier": "detail",
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
      "value": "\\.(lambda|ebs)$"
     }
    ]
   },
   "cond": {
    "path": [
     "vpc_endpoint_type"
    ],
    "op": "eq",
    "value": "Interface"
   },
   "quote": "interface VPC endpoints for Lambda and EBS",
   "quantifier": "all"
  },
  {
   "id": "interface_private_dns",
   "kind": "attr",
   "tier": "core",
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
      "value": "\\.(lambda|ebs)$"
     }
    ]
   },
   "cond": {
    "path": [
     "private_dns_enabled"
    ],
    "op": "truthy"
   },
   "quote": "with private DNS enabled",
   "quantifier": "all"
  },
  {
   "id": "interface_in_private_subnets",
   "kind": "ref",
   "tier": "core",
   "from": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "\\.(lambda|ebs)$"
     }
    ]
   },
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "deployed across private subnets"
  },
  {
   "id": "interface_uses_sg",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "aws_vpc_endpoint"
    ],
    "where": [
     {
      "path": [
       "service_name"
      ],
      "op": "regex",
      "value": "\\.(lambda|ebs)$"
     }
    ]
   },
   "to": {
    "types": [
     "aws_security_group"
    ],
    "where": []
   },
   "quote": "an interface VPC endpoint security group"
  },
  {
   "id": "ssm_optional_declared",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
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
         "gated"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ssm|ec2messages"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
         "gated"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "gate"
        ],
        "op": "regex",
        "value": "(?i)ssm|ec2messages"
       }
      ]
     }
    }
   ],
   "quote": "optional SSM interface VPC endpoints"
  },
  {
   "id": "ssm_flag",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": false
     },
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)ssm"
     }
    ]
   },
   "quote": "controlled by a boolean flag defaulting to false"
  },
  {
   "id": "x_nat_public_type",
   "kind": "attr",
   "tier": "extra",
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
   "id": "x_assoc",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "min": 4
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
