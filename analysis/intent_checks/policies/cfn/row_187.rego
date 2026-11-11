package intent.cfn.row_187

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "AWS::EC2::VPC"
   ],
   "where": []
  },
  "subnets": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": []
  },
  "igw": {
   "types": [
    "AWS::EC2::InternetGateway"
   ],
   "where": []
  },
  "attach": {
   "types": [
    "AWS::EC2::VPCGatewayAttachment"
   ],
   "where": []
  },
  "nat": {
   "types": [
    "AWS::EC2::NatGateway"
   ],
   "where": []
  },
  "eip": {
   "types": [
    "AWS::EC2::EIP"
   ],
   "where": []
  },
  "rts": {
   "types": [
    "AWS::EC2::RouteTable"
   ],
   "where": []
  },
  "assoc": {
   "types": [
    "AWS::EC2::SubnetRouteTableAssociation"
   ],
   "where": []
  },
  "route_igw": {
   "types": [
    "AWS::EC2::Route"
   ],
   "where": [
    {
     "path": [
      "DestinationCidrBlock"
     ],
     "op": "eq",
     "value": "0.0.0.0/0"
    },
    {
     "path": [
      "GatewayId"
     ],
     "op": "present"
    }
   ]
  },
  "route_nat": {
   "types": [
    "AWS::EC2::Route"
   ],
   "where": [
    {
     "path": [
      "DestinationCidrBlock"
     ],
     "op": "eq",
     "value": "0.0.0.0/0"
    },
    {
     "path": [
      "NatGatewayId"
     ],
     "op": "present"
    }
   ]
  },
  "flow": {
   "types": [
    "AWS::EC2::FlowLog"
   ],
   "where": []
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "frole": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "regex",
     "value": "(?i)^vpc-flow-logs(\\.[a-z0-9-]+)?\\.amazonaws\\.com$"
    }
   ]
  },
  "s3ep": {
   "types": [
    "AWS::EC2::VPCEndpoint"
   ],
   "where": [
    {
     "path": [
      "ServiceName"
     ],
     "op": "regex",
     "value": "(?i)\\.s3$"
    }
   ]
  },
  "ecrapi": {
   "types": [
    "AWS::EC2::VPCEndpoint"
   ],
   "where": [
    {
     "path": [
      "ServiceName"
     ],
     "op": "regex",
     "value": "(?i)\\.ecr\\.api$"
    },
    {
     "path": [
      "VpcEndpointType"
     ],
     "op": "eq",
     "value": "Interface"
    }
   ]
  },
  "ecrdkr": {
   "types": [
    "AWS::EC2::VPCEndpoint"
   ],
   "where": [
    {
     "path": [
      "ServiceName"
     ],
     "op": "regex",
     "value": "(?i)\\.ecr\\.dkr$"
    },
    {
     "path": [
      "VpcEndpointType"
     ],
     "op": "eq",
     "value": "Interface"
    }
   ]
  },
  "ecr": {
   "types": [
    "AWS::EC2::VPCEndpoint"
   ],
   "where": [
    {
     "path": [
      "ServiceName"
     ],
     "op": "regex",
     "value": "(?i)\\.ecr\\.(api|dkr)$"
    },
    {
     "path": [
      "VpcEndpointType"
     ],
     "op": "eq",
     "value": "Interface"
    }
   ]
  },
  "sg": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": []
  },
  "sgegr": {
   "types": [
    "AWS::EC2::SecurityGroupEgress"
   ],
   "where": []
  },
  "outs": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "creates a VPC with managed NAT gateways"
  },
  {
   "id": "four_subnets",
   "kind": "exists",
   "select": "subnets",
   "tier": "core",
   "quote": "two public subnets and two private subnets",
   "justify": "two public plus two private is four",
   "min": 4
  },
  {
   "id": "two_azs",
   "kind": "exists",
   "select": "subnets",
   "tier": "core",
   "quote": "spread across two availability zones appropriate for the deployment region",
   "justify": "two availability zones",
   "min": 2,
   "distinct_path": [
    "AvailabilityZone"
   ]
  },
  {
   "id": "igw",
   "kind": "exists",
   "select": "igw",
   "tier": "core",
   "quote": "an internet gateway attached to the VPC"
  },
  {
   "id": "igw_attached",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "attach",
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": "attach",
     "to": "vpc"
    }
   ],
   "tier": "core",
   "quote": "an internet gateway attached to the VPC"
  },
  {
   "id": "nat_per_public_subnet",
   "kind": "exists",
   "select": "nat",
   "tier": "core",
   "quote": "a NAT gateway, each with its own Elastic IP, in each public subnet",
   "justify": "one NAT gateway in each of the two public subnets",
   "min": 2,
   "distinct_path": [
    "SubnetId",
    "ref"
   ]
  },
  {
   "id": "eip_per_nat",
   "kind": "exists",
   "select": "eip",
   "tier": "core",
   "quote": "a NAT gateway, each with its own Elastic IP, in each public subnet",
   "justify": "each of the two NAT gateways has its own Elastic IP",
   "min": 2
  },
  {
   "id": "nat_distinct_eips",
   "kind": "exists",
   "select": "nat",
   "tier": "detail",
   "quote": "each with its own Elastic IP",
   "justify": "two NAT gateways with distinct allocations",
   "min": 2,
   "distinct_path": [
    "AllocationId",
    "ref"
   ]
  },
  {
   "id": "public_route_igw",
   "kind": "ref",
   "from": "route_igw",
   "to": "igw",
   "tier": "core",
   "quote": "route tables so the public subnets route through the internet gateway",
   "justify": "routing through the internet gateway means a default route 0.0.0.0/0"
  },
  {
   "id": "private_routes_nat",
   "kind": "exists",
   "select": "route_nat",
   "tier": "core",
   "quote": "each private subnet routes outbound traffic through its own availability zone's NAT gateway",
   "justify": "two private subnets each with its own NAT route",
   "min": 2,
   "distinct_path": [
    "RouteTableId",
    "ref"
   ]
  },
  {
   "id": "private_routes_distinct_nat",
   "kind": "exists",
   "select": "route_nat",
   "tier": "core",
   "quote": "through its own availability zone's NAT gateway",
   "justify": "each of the two private subnets uses its own NAT gateway",
   "min": 2,
   "distinct_path": [
    "NatGatewayId",
    "ref"
   ]
  },
  {
   "id": "route_tables",
   "kind": "exists",
   "select": "rts",
   "tier": "detail",
   "quote": "route tables so the public subnets route through the internet gateway",
   "justify": "one public plus one per private subnet",
   "min": 3
  },
  {
   "id": "subnet_associations",
   "kind": "exists",
   "select": "assoc",
   "tier": "detail",
   "quote": "route tables so the public subnets route through the internet gateway",
   "justify": "four subnets associated",
   "min": 4
  },
  {
   "id": "flow_log",
   "kind": "exists",
   "select": "flow",
   "tier": "core",
   "quote": "Enable VPC flow logs"
  },
  {
   "id": "flow_log_vpc",
   "kind": "ref",
   "from": "flow",
   "to": "vpc",
   "tier": "core",
   "quote": "Enable VPC flow logs delivered to a CloudWatch Logs log group"
  },
  {
   "id": "log_group",
   "kind": "exists",
   "select": "lg",
   "tier": "core",
   "quote": "a CloudWatch Logs log group"
  },
  {
   "id": "flow_to_log_group",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "flow",
     "to": "lg"
    },
    {
     "kind": "join",
     "from": "flow",
     "from_path": [
      "LogGroupName"
     ],
     "to": "lg",
     "to_path": [
      "LogGroupName"
     ]
    }
   ],
   "tier": "core",
   "quote": "delivered to a CloudWatch Logs log group"
  },
  {
   "id": "retention_parameter",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with a configurable retention period",
   "checks": [
    {
     "kind": "join",
     "from": "lg",
     "from_path": [
      "RetentionInDays"
     ],
     "to": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "to_path": [
      "default"
     ]
    },
    {
     "kind": "attr",
     "select": "lg",
     "cond": {
      "path": [
       "RetentionInDays"
      ],
      "op": "regex",
      "value": "^<param:"
     }
    }
   ],
   "justify": "configurable means set from a template parameter; <param:...> is how the adapter renders a parameter with no default"
  },
  {
   "id": "retention_set",
   "kind": "attr",
   "select": "lg",
   "cond": {
    "path": [
     "RetentionInDays"
    ],
    "op": "present"
   },
   "tier": "detail",
   "quote": "with a configurable retention period"
  },
  {
   "id": "traffic_type_parameter",
   "kind": "any_of",
   "tier": "detail",
   "quote": "traffic type to capture",
   "checks": [
    {
     "kind": "join",
     "from": "flow",
     "from_path": [
      "TrafficType"
     ],
     "to": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "to_path": [
      "default"
     ]
    },
    {
     "kind": "attr",
     "select": "flow",
     "cond": {
      "path": [
       "TrafficType"
      ],
      "op": "regex",
      "value": "^<param:"
     }
    }
   ],
   "justify": "configurable means set from a template parameter; <param:...> is how the adapter renders a parameter with no default"
  },
  {
   "id": "traffic_type",
   "kind": "attr",
   "select": "flow",
   "cond": {
    "path": [
     "TrafficType"
    ],
    "op": "regex",
    "value": "^(ALL|ACCEPT|REJECT|<param:.*)$"
   },
   "tier": "core",
   "quote": "traffic type to capture",
   "justify": "VPC flow log traffic types are ALL, ACCEPT and REJECT"
  },
  {
   "id": "flow_role",
   "kind": "exists",
   "select": "frole",
   "tier": "core",
   "quote": "through a dedicated IAM role"
  },
  {
   "id": "flow_uses_role",
   "kind": "ref",
   "from": "flow",
   "to": "frole",
   "tier": "core",
   "quote": "through a dedicated IAM role granted permission to write to that log group"
  },
  {
   "id": "role_writes_logs",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "frole",
     "cond": {
      "path": [
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*",
       "Action",
       "*"
      ],
      "op": "glob_covers",
      "value": "logs:PutLogEvents"
     }
    },
    {
     "kind": "attr",
     "select": "frole",
     "cond": {
      "path": [
       "ManagedPolicyArns"
      ],
      "op": "regex",
      "value": "(?i)(flowlog|cloudwatchlogsfullaccess)"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy",
       "AWS::IAM::ManagedPolicy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*",
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "logs:PutLogEvents"
       }
      ]
     },
     "to": "frole",
     "bidirectional": true
    }
   ],
   "tier": "detail",
   "quote": "granted permission to write to that log group",
   "justify": "writing to a log group needs logs:PutLogEvents"
  },
  {
   "id": "s3_endpoint",
   "kind": "exists",
   "select": "s3ep",
   "tier": "core",
   "quote": "Add a gateway VPC endpoint for S3"
  },
  {
   "id": "s3_gateway_type",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "s3ep",
     "cond": {
      "path": [
       "VpcEndpointType"
      ],
      "op": "eq",
      "value": "Gateway"
     }
    },
    {
     "kind": "attr",
     "select": "s3ep",
     "cond": {
      "path": [
       "VpcEndpointType"
      ],
      "op": "absent"
     }
    }
   ],
   "tier": "core",
   "quote": "a gateway VPC endpoint for S3",
   "justify": "Gateway is the default endpoint type"
  },
  {
   "id": "s3_all_route_tables",
   "kind": "attr",
   "select": "s3ep",
   "cond": {
    "path": [
     "RouteTableIds"
    ],
    "op": "len_gte",
    "value": 3
   },
   "tier": "core",
   "quote": "attached to all route tables",
   "justify": "one public route table plus one per private subnet"
  },
  {
   "id": "ecr_api_endpoint",
   "kind": "exists",
   "select": "ecrapi",
   "tier": "core",
   "quote": "interface VPC endpoints for the ECR API and ECR Docker registry services"
  },
  {
   "id": "ecr_dkr_endpoint",
   "kind": "exists",
   "select": "ecrdkr",
   "tier": "core",
   "quote": "interface VPC endpoints for the ECR API and ECR Docker registry services"
  },
  {
   "id": "ecr_private_dns",
   "kind": "attr",
   "select": "ecr",
   "cond": {
    "path": [
     "PrivateDnsEnabled"
    ],
    "op": "eq",
    "value": true
   },
   "tier": "core",
   "quote": "with private DNS enabled",
   "quantifier": "all"
  },
  {
   "id": "ecr_in_private_subnets",
   "kind": "attr",
   "select": "ecr",
   "cond": {
    "path": [
     "SubnetIds"
    ],
    "op": "len_gte",
    "value": 2
   },
   "tier": "detail",
   "quote": "in the private subnets",
   "justify": "two private subnets",
   "quantifier": "all"
  },
  {
   "id": "endpoint_sg",
   "kind": "exists",
   "select": "sg",
   "tier": "core",
   "quote": "protected by a security group"
  },
  {
   "id": "ecr_uses_sg",
   "kind": "ref",
   "from": "ecr",
   "to": "sg",
   "tier": "detail",
   "quote": "protected by a security group"
  },
  {
   "id": "sg_egress_https",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "SecurityGroupEgress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "FromPort"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "ToPort"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "IpProtocol"
        ],
        "op": "regex",
        "value": "(?i)^(tcp|6)$"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "sgegr",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "FromPort"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "ToPort"
        ],
        "op": "eq",
        "value": 443
       },
       {
        "path": [
         "IpProtocol"
        ],
        "op": "regex",
        "value": "(?i)^(tcp|6)$"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "only allows outbound HTTPS traffic",
   "justify": "HTTPS is port 443"
  },
  {
   "id": "sg_egress_vpc_cidr",
   "kind": "any_of",
   "checks": [
    {
     "kind": "join",
     "from": "sg",
     "from_path": [
      "SecurityGroupEgress",
      "*",
      "CidrIp"
     ],
     "to": "vpc",
     "to_path": [
      "CidrBlock"
     ]
    },
    {
     "kind": "join",
     "from": "sgegr",
     "from_path": [
      "CidrIp"
     ],
     "to": "vpc",
     "to_path": [
      "CidrBlock"
     ]
    },
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "SecurityGroupEgress",
       "*",
       "CidrIp"
      ],
      "op": "regex",
      "value": "(?i)cidrblock"
     }
    },
    {
     "kind": "attr",
     "select": "sgegr",
     "cond": {
      "path": [
       "CidrIp"
      ],
      "op": "regex",
      "value": "(?i)cidrblock"
     }
    }
   ],
   "tier": "core",
   "quote": "within the VPC's CIDR range",
   "justify": "the VPC CIDR may be referenced with GetAtt CidrBlock"
  },
  {
   "id": "sg_egress_only_https",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "SecurityGroupEgress",
       "*",
       "FromPort"
      ],
      "op": "eq",
      "value": 443,
      "every": true
     }
    },
    {
     "kind": "attr",
     "select": "sgegr",
     "cond": {
      "path": [
       "FromPort"
      ],
      "op": "eq",
      "value": 443
     },
     "quantifier": "all"
    }
   ],
   "tier": "detail",
   "quote": "only allows outbound HTTPS traffic within the VPC's CIDR range",
   "justify": "HTTPS is port 443"
  },
  {
   "id": "sg_no_open_egress",
   "kind": "any_of",
   "tier": "detail",
   "quote": "only allows outbound HTTPS traffic within the VPC's CIDR range",
   "justify": "traffic limited to the VPC CIDR means no 0.0.0.0/0",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
     "quantifier": "all",
     "cond": {
      "path": [
       "SecurityGroupEgress",
       "*",
       "CidrIp"
      ],
      "op": "neq",
      "value": "0.0.0.0/0",
      "every": true
     }
    },
    {
     "kind": "attr",
     "select": "sgegr",
     "quantifier": "all",
     "cond": {
      "path": [
       "CidrIp"
      ],
      "op": "none_eq",
      "value": "0.0.0.0/0"
     }
    }
   ]
  },
  {
   "id": "output_vpc_id",
   "kind": "ref",
   "tier": "detail",
   "quote": "Export the VPC ID",
   "from": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "value",
       "attr"
      ],
      "op": "absent"
     }
    ]
   },
   "to": "vpc"
  },
  {
   "id": "output_vpc_cidr",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "eq",
        "value": "CidrBlock"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "^[0-9]{1,3}(\\.[0-9]{1,3}){3}/[0-9]+$"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "VPC CIDR"
  },
  {
   "id": "output_zone_names",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "^[a-z]{2}(-[a-z]+)+-[0-9][a-z]$"
       }
      ]
     },
     "min": 2
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "eq",
        "value": "AvailabilityZone"
       }
      ]
     },
     "min": 2
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value"
        ],
        "op": "regex",
        "value": "(?i)(GetAZs|Fn::Select)"
       }
      ]
     },
     "min": 2
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)(az|availabilityzone)"
       }
      ]
     },
     "min": 2
    }
   ],
   "tier": "detail",
   "quote": "both availability zone names",
   "justify": "two zone names"
  },
  {
   "id": "output_subnet_ids",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "value",
         "ref"
        ],
        "op": "present"
       },
       {
        "path": [
         "value",
         "attr"
        ],
        "op": "absent"
       }
      ]
     },
     "min": 6
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)subnet"
       }
      ]
     },
     "min": 4
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "description"
        ],
        "op": "regex",
        "value": "(?i)subnet"
       }
      ]
     },
     "min": 4
    }
   ],
   "tier": "detail",
   "quote": "all four subnet IDs",
   "justify": "four subnets; with the VPC ID and security group ID that is six plain Ref outputs"
  },
  {
   "id": "output_endpoint_sg",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "outs",
     "to": "sg"
    }
   ],
   "tier": "detail",
   "quote": "the endpoint security group ID"
  },
  {
   "id": "exported_for_other_stacks",
   "kind": "exists",
   "select": {
    "types": [
     "__output__"
    ],
    "where": [
     {
      "path": [
       "export"
      ],
      "op": "present"
     }
    ]
   },
   "tier": "detail",
   "quote": "so other stacks can reference this network",
   "justify": "the VPC ID and four subnet IDs are exported",
   "min": 5
  },
  {
   "id": "x_dns_hostnames",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "eq",
    "value": true
   },
   "tier": "extra"
  },
  {
   "id": "x_dns_support",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsSupport"
    ],
    "op": "eq",
    "value": true
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
