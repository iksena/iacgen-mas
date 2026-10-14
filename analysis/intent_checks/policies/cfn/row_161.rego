# GENERATED from specs/cfn/row_161.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_161

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
  "nat": {
   "types": [
    "AWS::EC2::NatGateway"
   ],
   "where": []
  },
  "tgw": {
   "types": [
    "AWS::EC2::TransitGateway"
   ],
   "where": []
  },
  "flowlog": {
   "types": [
    "AWS::EC2::FlowLog"
   ],
   "where": []
  },
  "export": {
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
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "select": "vpc",
   "tier": "core",
   "quote": "a VPC CIDR of 10.0.0.0/16",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "eq",
    "value": "10.0.0.0/16"
   }
  },
  {
   "id": "public_subnets",
   "kind": "all_of",
   "tier": "core",
   "quote": "public subnets 10.0.1.0/24 and 10.0.2.0/24",
   "checks": [
    {
     "kind": "exists",
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
     "kind": "exists",
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
    }
   ]
  },
  {
   "id": "private_subnets",
   "kind": "all_of",
   "tier": "core",
   "quote": "private subnets 10.0.10.0/24 and 10.0.11.0/24",
   "checks": [
    {
     "kind": "exists",
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
        "value": "10.0.10.0/24"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "10.0.11.0/24"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "subnets_two_azs",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": []
   },
   "distinct_path": [
    "AvailabilityZone"
   ],
   "min": 2,
   "tier": "detail",
   "quote": "across two AZs",
   "justify": "two AZs means two distinct AvailabilityZone values"
  },
  {
   "id": "nat_in_each_public_subnet",
   "kind": "all_of",
   "tier": "core",
   "quote": "NAT gateways in each public subnet",
   "checks": [
    {
     "kind": "ref",
     "from": "nat",
     "to": {
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
     "kind": "ref",
     "from": "nat",
     "to": {
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
    }
   ]
  },
  {
   "id": "public_route_igw",
   "kind": "ref",
   "tier": "detail",
   "quote": "public and private route tables",
   "from": {
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
     }
    ]
   },
   "to": {
    "types": [
     "AWS::EC2::InternetGateway"
    ],
    "where": []
   },
   "justify": "a public route table routes 0.0.0.0/0 to an internet gateway"
  },
  {
   "id": "private_route_nat",
   "kind": "ref",
   "tier": "detail",
   "quote": "public and private route tables",
   "from": {
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
     }
    ]
   },
   "to": "nat",
   "justify": "private route tables send default traffic through the NAT gateways"
  },
  {
   "id": "route_tables",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::EC2::RouteTable"
    ],
    "where": []
   },
   "min": 2,
   "tier": "detail",
   "quote": "public and private route tables",
   "justify": "at least one public and one private route table"
  },
  {
   "id": "tgw_asn",
   "kind": "attr",
   "select": "tgw",
   "tier": "core",
   "quote": "a Transit Gateway with a private ASN of 64512",
   "cond": {
    "path": [
     "AmazonSideAsn"
    ],
    "op": "eq",
    "value": 64512
   }
  },
  {
   "id": "tgw_dns_ecmp",
   "kind": "attr",
   "select": "tgw",
   "tier": "core",
   "quote": "DNS and VPN ECMP support enabled",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "DnsSupport"
      ],
      "op": "eq",
      "value": "enable"
     },
     {
      "path": [
       "VpnEcmpSupport"
      ],
      "op": "eq",
      "value": "enable"
     }
    ]
   },
   "justify": "enabled is the enum value enable"
  },
  {
   "id": "tgw_vpc_attachment",
   "kind": "all_of",
   "tier": "detail",
   "quote": "a landing zone hub VPC for multi-account spoke attachment",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::EC2::TransitGatewayAttachment",
       "AWS::EC2::TransitGatewayVpcAttachment"
      ],
      "where": []
     },
     "to": "tgw"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::EC2::TransitGatewayAttachment",
       "AWS::EC2::TransitGatewayVpcAttachment"
      ],
      "where": []
     },
     "to": "vpc"
    }
   ]
  },
  {
   "id": "route_10_8_to_tgw",
   "kind": "ref",
   "tier": "core",
   "quote": "private routes that send 10.0.0.0/8 traffic toward the Transit Gateway",
   "from": {
    "types": [
     "AWS::EC2::Route"
    ],
    "where": [
     {
      "path": [
       "DestinationCidrBlock"
      ],
      "op": "eq",
      "value": "10.0.0.0/8"
     }
    ]
   },
   "to": "tgw"
  },
  {
   "id": "flow_log_on_vpc",
   "kind": "ref",
   "from": "flowlog",
   "to": "vpc",
   "tier": "core",
   "quote": "provision VPC flow logs"
  },
  {
   "id": "flow_log_to_cloudwatch",
   "kind": "any_of",
   "tier": "core",
   "quote": "VPC flow logs to CloudWatch",
   "checks": [
    {
     "kind": "attr",
     "select": "flowlog",
     "cond": {
      "path": [
       "LogDestinationType"
      ],
      "op": "eq",
      "value": "cloud-watch-logs"
     }
    },
    {
     "kind": "attr",
     "select": "flowlog",
     "cond": {
      "path": [
       "LogGroupName"
      ],
      "op": "present"
     }
    }
   ],
   "justify": "CloudWatch Logs destination type is cloud-watch-logs"
  },
  {
   "id": "flow_log_iam_role",
   "kind": "ref",
   "tier": "detail",
   "quote": "include the necessary IAM roles",
   "from": "flowlog",
   "to": {
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
   "justify": "flow logs to CloudWatch need a delivery role trusted by vpc-flow-logs.amazonaws.com"
  },
  {
   "id": "endpoint_ssm",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.ssm$"
     }
    ]
   },
   "tier": "core",
   "quote": "VPC endpoints for SSM"
  },
  {
   "id": "endpoint_ec2messages",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.ec2messages$"
     }
    ]
   },
   "tier": "core",
   "quote": "EC2 Messages"
  },
  {
   "id": "endpoint_ssmmessages",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.ssmmessages$"
     }
    ]
   },
   "tier": "core",
   "quote": "SSM Messages"
  },
  {
   "id": "endpoint_logs",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": [
     {
      "path": [
       "ServiceName"
      ],
      "op": "regex",
      "value": "(?i)\\.logs$"
     }
    ]
   },
   "tier": "core",
   "quote": "CloudWatch Logs"
  },
  {
   "id": "endpoint_s3",
   "kind": "exists",
   "select": {
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
   "tier": "core",
   "quote": "and S3 so private subnets can securely reach these services"
  },
  {
   "id": "endpoints_in_vpc",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": []
   },
   "to": "vpc",
   "tier": "detail",
   "quote": "so private subnets can securely reach these services without internet access"
  },
  {
   "id": "endpoint_security_group",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::EC2::VPCEndpoint"
    ],
    "where": []
   },
   "to": {
    "types": [
     "AWS::EC2::SecurityGroup"
    ],
    "where": []
   },
   "tier": "detail",
   "quote": "security groups"
  },
  {
   "id": "env_prefix_param",
   "kind": "exists",
   "tier": "detail",
   "quote": "an environment name prefix defaulting to \"landing-zone\"",
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
      "value": "landing-zone"
     }
    ]
   }
  },
  {
   "id": "resource_tagging",
   "kind": "attr",
   "select": "vpc",
   "tier": "detail",
   "quote": "standard resource tagging",
   "cond": {
    "path": [
     "Tags"
    ],
    "op": "len_gte",
    "value": 1
   }
  },
  {
   "id": "exports_key_ids",
   "kind": "all_of",
   "tier": "detail",
   "quote": "exporting key resource IDs such as the VPC, subnets, and Transit Gateway",
   "checks": [
    {
     "kind": "ref",
     "from": "export",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "export",
     "to": {
      "types": [
       "AWS::EC2::Subnet"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": "export",
     "to": "tgw"
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
