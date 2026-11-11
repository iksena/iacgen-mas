package intent.cfn.row_254

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
  "pubsub": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "in",
     "value": [
      "10.0.0.0/24",
      "10.0.1.0/24"
     ]
    }
   ]
  },
  "igw": {
   "types": [
    "AWS::EC2::InternetGateway"
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
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "flow": {
   "types": [
    "AWS::EC2::FlowLog"
   ],
   "where": []
  },
  "pubroute": {
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
  "natroutes": {
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
  "pub_a": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.0.0.0/24"
    }
   ]
  },
  "pub_b": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.0.1.0/24"
    }
   ]
  },
  "priv_a": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.0.2.0/24"
    }
   ]
  },
  "priv_b": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.0.3.0/24"
    }
   ]
  },
  "privsub": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "in",
     "value": [
      "10.0.2.0/24",
      "10.0.3.0/24"
     ]
    }
   ]
  },
  "flowrole": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "vpc-flow-logs.amazonaws.com"
    }
   ]
  },
  "lg7": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": [
    {
     "path": [
      "RetentionInDays"
     ],
     "op": "eq",
     "value": 7
    }
   ]
  },
  "assoc": {
   "types": [
    "AWS::EC2::SubnetRouteTableAssociation"
   ],
   "where": []
  },
  "assocgw": {
   "types": [
    "AWS::EC2::VPCGatewayAttachment"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "tier": "core",
   "quote": "using the 10.0.0.0/16 range",
   "select": "vpc",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "eq",
    "value": "10.0.0.0/16"
   }
  },
  {
   "id": "dns_support",
   "tier": "core",
   "quote": "DNS support and DNS hostnames enabled",
   "justify": "EnableDnsSupport defaults to true, so only an explicit false violates this",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsSupport"
    ],
    "op": "none_eq",
    "value": false
   }
  },
  {
   "id": "dns_hostnames",
   "kind": "attr",
   "tier": "core",
   "quote": "DNS support and DNS hostnames enabled",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "subnet_10_0_0_0_24",
   "kind": "exists",
   "tier": "core",
   "quote": "two public subnets using 10.0.0.0/24 and 10.0.1.0/24 and two private subnets using 10.0.2.0/24 and 10.0.3.0/24",
   "select": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": [
     {
      "path": [
       "CidrBlock"
      ],
      "op": "eq",
      "value": "10.0.0.0/24"
     }
    ]
   }
  },
  {
   "id": "subnet_10_0_1_0_24",
   "kind": "exists",
   "tier": "core",
   "quote": "two public subnets using 10.0.0.0/24 and 10.0.1.0/24 and two private subnets using 10.0.2.0/24 and 10.0.3.0/24",
   "select": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": [
     {
      "path": [
       "CidrBlock"
      ],
      "op": "eq",
      "value": "10.0.1.0/24"
     }
    ]
   }
  },
  {
   "id": "subnet_10_0_2_0_24",
   "kind": "exists",
   "tier": "core",
   "quote": "two public subnets using 10.0.0.0/24 and 10.0.1.0/24 and two private subnets using 10.0.2.0/24 and 10.0.3.0/24",
   "select": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": [
     {
      "path": [
       "CidrBlock"
      ],
      "op": "eq",
      "value": "10.0.2.0/24"
     }
    ]
   }
  },
  {
   "id": "subnet_10_0_3_0_24",
   "kind": "exists",
   "tier": "core",
   "quote": "two public subnets using 10.0.0.0/24 and 10.0.1.0/24 and two private subnets using 10.0.2.0/24 and 10.0.3.0/24",
   "select": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": [
     {
      "path": [
       "CidrBlock"
      ],
      "op": "eq",
      "value": "10.0.3.0/24"
     }
    ]
   }
  },
  {
   "id": "subnets_two_azs",
   "tier": "core",
   "quote": "spread across the first two availability zones in the region",
   "justify": "two public and two private subnets across two zones: each pair spans two zones",
   "kind": "all_of",
   "checks": [
    {
     "kind": "exists",
     "select": "pubsub",
     "min": 2,
     "distinct_path": [
      "AvailabilityZone"
     ]
    },
    {
     "kind": "exists",
     "select": "privsub",
     "min": 2,
     "distinct_path": [
      "AvailabilityZone"
     ]
    }
   ]
  },
  {
   "id": "first_two_azs",
   "kind": "attr",
   "tier": "detail",
   "quote": "spread across the first two availability zones in the region",
   "justify": "the first two zones of a region carry the suffixes a and b, whatever the region",
   "select": "subnets",
   "quantifier": "all",
   "cond": {
    "path": [
     "AvailabilityZone"
    ],
    "op": "regex",
    "value": "^[a-z]+(-[a-z]+)+-[0-9]+[ab]$"
   }
  },
  {
   "id": "subnets_in_vpc",
   "tier": "detail",
   "quote": "two public subnets using 10.0.0.0/24 and 10.0.1.0/24 and two private subnets using 10.0.2.0/24 and 10.0.3.0/24",
   "kind": "ref",
   "from": "subnets",
   "to": "vpc"
  },
  {
   "id": "cidr_params",
   "kind": "exists",
   "tier": "detail",
   "quote": "with each of those four ranges exposed as a parameter defaulting to the value given",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "in",
      "value": [
       "10.0.0.0/24",
       "10.0.1.0/24",
       "10.0.2.0/24",
       "10.0.3.0/24"
      ]
     }
    ]
   },
   "min": 4,
   "distinct_path": [
    "default"
   ]
  },
  {
   "id": "igw",
   "kind": "exists",
   "tier": "core",
   "quote": "an internet gateway shared by the public subnets",
   "select": "igw"
  },
  {
   "id": "igw_attach",
   "tier": "core",
   "quote": "an internet gateway shared by the public subnets",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "assocgw",
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": "assocgw",
     "to": "vpc"
    }
   ]
  },
  {
   "id": "route_via_igw",
   "kind": "ref",
   "tier": "core",
   "quote": "an internet gateway shared by the public subnets",
   "from": "pubroute",
   "to": "igw",
   "justify": "0.0.0.0/0 is the default route to the internet"
  },
  {
   "id": "public_associations",
   "kind": "all_of",
   "tier": "detail",
   "quote": "an internet gateway shared by the public subnets",
   "checks": [
    {
     "kind": "ref",
     "from": "assoc",
     "to": "pub_a"
    },
    {
     "kind": "ref",
     "from": "assoc",
     "to": "pub_b"
    }
   ]
  },
  {
   "id": "nat_gateways",
   "kind": "exists",
   "tier": "core",
   "quote": "a separate NAT gateway with its own elastic IP in each public subnet",
   "select": "nat",
   "min": 2
  },
  {
   "id": "nat_in_public",
   "tier": "core",
   "quote": "a separate NAT gateway with its own elastic IP in each public subnet",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "nat",
     "to": "pub_a"
    },
    {
     "kind": "ref",
     "from": "nat",
     "to": "pub_b"
    }
   ]
  },
  {
   "id": "eips",
   "kind": "exists",
   "tier": "core",
   "quote": "with its own elastic IP in each public subnet",
   "select": "eip",
   "min": 2
  },
  {
   "id": "nat_distinct_eips",
   "kind": "exists",
   "tier": "core",
   "quote": "with its own elastic IP in each public subnet",
   "select": "nat",
   "min": 2,
   "distinct_path": [
    "AllocationId",
    "ref"
   ]
  },
  {
   "id": "private_nat_routes",
   "kind": "exists",
   "tier": "core",
   "quote": "each private subnet routes outbound traffic through the NAT gateway in its own zone",
   "select": "natroutes",
   "min": 2,
   "distinct_path": [
    "NatGatewayId",
    "ref"
   ],
   "justify": "0.0.0.0/0 is the default route to the internet"
  },
  {
   "id": "private_route_tables",
   "kind": "exists",
   "tier": "detail",
   "quote": "each private subnet routes outbound traffic through the NAT gateway in its own zone",
   "select": "natroutes",
   "min": 2,
   "distinct_path": [
    "RouteTableId",
    "ref"
   ],
   "justify": "0.0.0.0/0 is the default route to the internet"
  },
  {
   "id": "private_associations",
   "tier": "detail",
   "quote": "each private subnet routes outbound traffic through the NAT gateway in its own zone",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "assoc",
     "to": "priv_a"
    },
    {
     "kind": "ref",
     "from": "assoc",
     "to": "priv_b"
    }
   ]
  },
  {
   "id": "flow_log",
   "tier": "core",
   "quote": "turn on VPC flow logs",
   "kind": "ref",
   "from": "flow",
   "to": "vpc"
  },
  {
   "id": "flow_all",
   "kind": "attr",
   "tier": "core",
   "quote": "capturing all traffic",
   "select": "flow",
   "cond": {
    "path": [
     "TrafficType"
    ],
    "op": "eq",
    "value": "ALL"
   }
  },
  {
   "id": "log_group",
   "kind": "exists",
   "tier": "core",
   "quote": "a CloudWatch log group that it creates",
   "select": "lg"
  },
  {
   "id": "retention_7",
   "tier": "core",
   "quote": "deliver them to a CloudWatch log group that it creates with a seven day retention period",
   "justify": "seven day retention is 7 days",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "flow",
     "to": "lg7"
    },
    {
     "kind": "join",
     "from": "flow",
     "from_path": [
      "LogGroupName"
     ],
     "to": "lg7",
     "to_path": [
      "LogGroupName"
     ]
    }
   ]
  },
  {
   "id": "flow_to_group",
   "kind": "any_of",
   "tier": "core",
   "quote": "deliver them to a CloudWatch log group that it creates",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::EC2::FlowLog"
      ],
      "where": []
     },
     "to": "lg"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::EC2::FlowLog"
      ],
      "where": []
     },
     "from_path": [
      "LogGroupName"
     ],
     "to": {
      "types": [
       "AWS::Logs::LogGroup"
      ],
      "where": []
     },
     "to_path": [
      "LogGroupName"
     ]
    }
   ]
  },
  {
   "id": "flow_role",
   "tier": "core",
   "quote": "together with the role that flow log delivery requires",
   "kind": "ref",
   "from": "flow",
   "to": "role"
  },
  {
   "id": "flow_role_trust",
   "tier": "detail",
   "quote": "together with the role that flow log delivery requires",
   "justify": "flow log delivery roles are assumed by the VPC flow logs service",
   "kind": "ref",
   "from": "flow",
   "to": "flowrole"
  },
  {
   "id": "flow_role_logs",
   "tier": "detail",
   "quote": "together with the role that flow log delivery requires",
   "justify": "flow log delivery writes log events to CloudWatch Logs",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "flowrole",
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
     "select": "flowrole",
     "cond": {
      "path": [
       "ManagedPolicyArns",
       "*"
      ],
      "op": "regex",
      "value": "(?i)(CloudWatchLogsFullAccess|AdministratorAccess)$"
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
     "to": "flowrole",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "ecs_cluster",
   "kind": "exists",
   "tier": "core",
   "quote": "create an ECS cluster",
   "select": {
    "types": [
     "AWS::ECS::Cluster"
    ],
    "where": []
   }
  },
  {
   "id": "container_insights",
   "kind": "attr",
   "tier": "core",
   "quote": "with Container Insights enabled",
   "justify": "enabled (or the newer enhanced) turns Container Insights on",
   "select": {
    "types": [
     "AWS::ECS::Cluster"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "ClusterSettings",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Name"
      ],
      "op": "eq",
      "value": "containerInsights"
     },
     {
      "path": [
       "Value"
      ],
      "op": "in",
      "value": [
       "enabled",
       "enhanced"
      ]
     }
    ]
   }
  },
  {
   "id": "x_eip_vpc",
   "kind": "attr",
   "tier": "extra",
   "select": "eip",
   "cond": {
    "path": [
     "Domain"
    ],
    "op": "eq",
    "value": "vpc"
   }
  },
  {
   "id": "x_igw_depends",
   "kind": "attr",
   "tier": "extra",
   "select": "pubroute",
   "cond": {
    "path": [
     "__resource__",
     "DependsOn"
    ],
    "op": "present"
   }
  },
  {
   "id": "extra_type_aws_ec2_routetable",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::RouteTable"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
