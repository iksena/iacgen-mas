package intent.cfn.row_132

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a private VPC infrastructure",
   "select": {
    "types": [
     "AWS::EC2::VPC"
    ],
    "where": []
   }
  },
  {
   "id": "vpc_dns_support",
   "kind": "attr",
   "tier": "core",
   "quote": "Include DNS support for the VPC",
   "select": {
    "types": [
     "AWS::EC2::VPC"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "EnableDnsSupport"
    ],
    "op": "none_eq",
    "value": false
   }
  },
  {
   "id": "three_subnets",
   "kind": "exists",
   "tier": "core",
   "quote": "three private subnets spanning multiple availability zones",
   "select": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": []
   },
   "min": 3
  },
  {
   "id": "private_subnets",
   "kind": "exists",
   "tier": "core",
   "quote": "three private subnets",
   "select": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": [
     {
      "path": [
       "MapPublicIpOnLaunch"
      ],
      "op": "none_eq",
      "value": true
     },
     {
      "path": [
       "__resource__",
       "Condition"
      ],
      "op": "absent"
     }
    ]
   },
   "min": 3
  },
  {
   "id": "subnets_multi_az",
   "kind": "exists",
   "tier": "core",
   "quote": "spanning multiple availability zones",
   "select": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": [
     {
      "path": [
       "MapPublicIpOnLaunch"
      ],
      "op": "none_eq",
      "value": true
     },
     {
      "path": [
       "__resource__",
       "Condition"
      ],
      "op": "absent"
     }
    ]
   },
   "distinct_path": [
    "AvailabilityZone"
   ],
   "min": 2
  },
  {
   "id": "subnet_cidrs_distinct",
   "kind": "exists",
   "tier": "detail",
   "quote": "use the provided CIDR parameters for the VPC and each subnet",
   "justify": "three separate subnets need three separate CIDRs",
   "select": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": []
   },
   "distinct_path": [
    "CidrBlock"
   ],
   "min": 3
  },
  {
   "id": "cidr_parameters",
   "kind": "exists",
   "tier": "core",
   "quote": "use the provided CIDR parameters for the VPC and each subnet",
   "justify": "one CIDR parameter for the VPC and one for each of the three subnets",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)cidr"
     }
    ]
   },
   "min": 4
  },
  {
   "id": "vpc_cidr_from_param",
   "kind": "join",
   "tier": "detail",
   "quote": "use the provided CIDR parameters for the VPC",
   "from": {
    "types": [
     "AWS::EC2::VPC"
    ],
    "where": []
   },
   "from_path": [
    "CidrBlock"
   ],
   "to": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)cidr"
     }
    ]
   },
   "to_path": [
    "default"
   ]
  },
  {
   "id": "subnet_cidr_from_param",
   "kind": "join",
   "tier": "detail",
   "quote": "use the provided CIDR parameters for the VPC and each subnet",
   "from": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": []
   },
   "from_path": [
    "CidrBlock"
   ],
   "to": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)cidr"
     }
    ]
   },
   "to_path": [
    "default"
   ]
  },
  {
   "id": "nat_gateway",
   "kind": "exists",
   "tier": "core",
   "quote": "optional internet egress via a NAT Gateway",
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
      "value": "AWS::EC2::NatGateway"
     }
    ]
   }
  },
  {
   "id": "nat_toggle_gated",
   "kind": "exists",
   "tier": "detail",
   "quote": "(enabled or disabled by parameter)",
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
      "value": "AWS::EC2::NatGateway"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "nat_toggle_param",
   "kind": "exists",
   "tier": "detail",
   "quote": "(enabled or disabled by parameter)",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)(nat|egress|internet)"
     }
    ]
   }
  },
  {
   "id": "nat_route",
   "kind": "exists",
   "tier": "detail",
   "quote": "optional internet egress via a NAT Gateway",
   "justify": "internet egress through a NAT needs a 0.0.0.0/0 route to it",
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
      "value": "AWS::EC2::Route"
     },
     {
      "path": [
       "properties",
       "DestinationCidrBlock"
      ],
      "op": "eq",
      "value": "0.0.0.0/0"
     },
     {
      "path": [
       "properties",
       "NatGatewayId"
      ],
      "op": "present"
     }
    ]
   }
  },
  {
   "id": "kms_key",
   "kind": "exists",
   "tier": "core",
   "quote": "a customer-managed KMS key for encrypting an artifact storage bucket",
   "select": {
    "types": [
     "AWS::KMS::Key"
    ],
    "where": []
   }
  },
  {
   "id": "kms_retain",
   "kind": "attr",
   "tier": "core",
   "quote": "with a deletion policy set to Retain",
   "select": {
    "types": [
     "AWS::KMS::Key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "__resource__",
     "DeletionPolicy"
    ],
    "op": "eq",
    "value": "Retain"
   }
  },
  {
   "id": "x_key_rotation",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::KMS::Key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "EnableKeyRotation"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_update_retain",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::KMS::Key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "__resource__",
     "UpdateReplacePolicy"
    ],
    "op": "eq",
    "value": "Retain"
   }
  },
  {
   "id": "x_dns_hostnames",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::VPC"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "extra_type_aws_ec2_eip",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::EIP"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_internetgateway",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::InternetGateway"
    ],
    "where": []
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
  },
  {
   "id": "extra_type_aws_ec2_subnetroutetableassociation",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::SubnetRouteTableAssociation"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_ec2_vpcgatewayattachment",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::EC2::VPCGatewayAttachment"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_kms_alias",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::KMS::Alias"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
