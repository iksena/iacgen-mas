package intent.cfn.row_189

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "AWS::EC2::VPC"
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
  "pub1": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.0.0.0/26"
    }
   ]
  },
  "pub2": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.0.0.64/26"
    }
   ]
  },
  "priv1": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.0.0.128/26"
    }
   ]
  },
  "priv2": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.0.0.192/26"
    }
   ]
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
  "assoc": {
   "types": [
    "AWS::EC2::SubnetRouteTableAssociation"
   ],
   "where": []
  },
  "default_route": {
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
  "igw_route": {
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
  "nat_route": {
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
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "fl": {
   "types": [
    "AWS::EC2::FlowLog"
   ],
   "where": []
  },
  "sgs": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": []
  },
  "ep_ssm": {
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
  "ep_ssmm": {
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
  "ep_ec2m": {
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
  "ep_sm": {
   "types": [
    "AWS::EC2::VPCEndpoint"
   ],
   "where": [
    {
     "path": [
      "ServiceName"
     ],
     "op": "regex",
     "value": "(?i)\\.secretsmanager$"
    }
   ]
  },
  "eps": {
   "types": [
    "AWS::EC2::VPCEndpoint"
   ],
   "where": []
  },
  "pub_subnets": {
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
      "10.0.0.0/26",
      "10.0.0.64/26"
     ]
    }
   ]
  },
  "priv_subnets": {
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
      "10.0.0.128/26",
      "10.0.0.192/26"
     ]
    }
   ]
  },
  "igw_attachment": {
   "types": [
    "AWS::EC2::VPCGatewayAttachment"
   ],
   "where": []
  },
  "eps4": {
   "types": [
    "AWS::EC2::VPCEndpoint"
   ],
   "where": [
    {
     "path": [
      "ServiceName"
     ],
     "op": "regex",
     "value": "(?i)\\.(ssm|ssmmessages|ec2messages|secretsmanager)$"
    }
   ]
  },
  "key_rotated": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": [
    {
     "path": [
      "EnableKeyRotation"
     ],
     "op": "eq",
     "value": "true"
    }
   ]
  },
  "lg30": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": [
    {
     "path": [
      "RetentionInDays"
     ],
     "op": "eq",
     "value": "30"
    }
   ]
  },
  "sg_only_in": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": [
    {
     "path": [
      "SecurityGroupIngress",
      "*",
      "IpProtocol"
     ],
     "op": "in",
     "value": [
      "tcp",
      "6"
     ],
     "every": true
    },
    {
     "path": [
      "SecurityGroupIngress",
      "*",
      "FromPort"
     ],
     "op": "eq",
     "value": "443",
     "every": true
    },
    {
     "path": [
      "SecurityGroupIngress",
      "*",
      "ToPort"
     ],
     "op": "eq",
     "value": "443",
     "every": true
    },
    {
     "path": [
      "SecurityGroupIngress",
      "*",
      "CidrIp"
     ],
     "op": "regex",
     "value": "^10\\.0\\.0\\.0/24$|CidrBlock",
     "every": true
    }
   ]
  },
  "sg_only_eg": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": [
    {
     "path": [
      "SecurityGroupEgress",
      "*",
      "IpProtocol"
     ],
     "op": "in",
     "value": [
      "tcp",
      "6"
     ],
     "every": true
    },
    {
     "path": [
      "SecurityGroupEgress",
      "*",
      "FromPort"
     ],
     "op": "eq",
     "value": "443",
     "every": true
    },
    {
     "path": [
      "SecurityGroupEgress",
      "*",
      "ToPort"
     ],
     "op": "eq",
     "value": "443",
     "every": true
    },
    {
     "path": [
      "SecurityGroupEgress",
      "*",
      "CidrIp"
     ],
     "op": "regex",
     "value": "^10\\.0\\.0\\.0/24$|CidrBlock",
     "every": true
    }
   ]
  },
  "sg_has_in": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": [
    {
     "path": [
      "SecurityGroupIngress",
      "*"
     ],
     "op": "match",
     "value": [
      {
       "path": [
        "IpProtocol"
       ],
       "op": "in",
       "value": [
        "tcp",
        "6"
       ]
      },
      {
       "path": [],
       "op": "port_covers",
       "value": 443
      },
      {
       "path": [
        "CidrIp"
       ],
       "op": "regex",
       "value": "^10\\.0\\.0\\.0/24$|CidrBlock"
      }
     ]
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "a 10.0.0.0/24 CIDR"
  },
  {
   "id": "vpc_name_prefix",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::EC2::VPC"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Tags",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "Key"
      ],
      "op": "eq",
      "value": "Name"
     },
     {
      "path": [
       "Value"
      ],
      "op": "regex",
      "value": "(?i)^KerberosEMRonEKS"
     }
    ]
   },
   "tier": "detail",
   "quote": "a VPC named with a \"KerberosEMRonEKS\" prefix"
  },
  {
   "id": "public_subnet_1",
   "kind": "exists",
   "select": "pub1",
   "tier": "core",
   "quote": "10.0.0.0/26"
  },
  {
   "id": "public_subnet_2",
   "kind": "exists",
   "select": "pub2",
   "tier": "core",
   "quote": "10.0.0.64/26"
  },
  {
   "id": "private_subnet_1",
   "kind": "exists",
   "select": "priv1",
   "tier": "core",
   "quote": "10.0.0.128/26"
  },
  {
   "id": "private_subnet_2",
   "kind": "exists",
   "select": "priv2",
   "tier": "core",
   "quote": "10.0.0.192/26"
  },
  {
   "id": "subnets_in_vpc",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "pub1",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "pub2",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "priv1",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "priv2",
     "to": "vpc"
    }
   ],
   "tier": "detail",
   "quote": "split into two public subnets (10.0.0.0/26 and 10.0.0.64/26) and two private subnets (10.0.0.128/26 and 10.0.0.192/26)"
  },
  {
   "id": "subnets_different_azs",
   "tier": "core",
   "quote": "each in a different AZ",
   "kind": "all_of",
   "justify": "each public pair and each private pair spans two AZs; the prompt pairs each private subnet with a NAT in the same AZ, so two AZs in total",
   "checks": [
    {
     "kind": "exists",
     "select": "pub_subnets",
     "distinct_path": [
      "AvailabilityZone"
     ],
     "min": 2
    },
    {
     "kind": "exists",
     "select": "priv_subnets",
     "distinct_path": [
      "AvailabilityZone"
     ],
     "min": 2
    }
   ]
  },
  {
   "id": "internet_gateway",
   "kind": "exists",
   "select": "igw",
   "tier": "core",
   "quote": "an Internet Gateway"
  },
  {
   "id": "igw_attached",
   "tier": "detail",
   "quote": "an Internet Gateway",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "igw_attachment",
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": "igw_attachment",
     "to": "vpc"
    }
   ]
  },
  {
   "id": "nat_gateways",
   "kind": "exists",
   "select": "nat",
   "min": 2,
   "tier": "core",
   "quote": "two NAT Gateways each with an EIP",
   "justify": "two NAT gateways"
  },
  {
   "id": "nat_eips",
   "kind": "exists",
   "select": "eip",
   "min": 2,
   "tier": "core",
   "quote": "two NAT Gateways each with an EIP",
   "justify": "one EIP per NAT gateway"
  },
  {
   "id": "nat_uses_eip",
   "tier": "core",
   "quote": "two NAT Gateways each with an EIP",
   "kind": "all_of",
   "justify": "each NAT gateway has its own EIP, so two distinct allocations",
   "checks": [
    {
     "kind": "ref",
     "from": "nat",
     "to": "eip"
    },
    {
     "kind": "exists",
     "select": "nat",
     "distinct_path": [
      "AllocationId"
     ],
     "min": 2
    }
   ]
  },
  {
   "id": "public_default_route_igw",
   "kind": "ref",
   "to": "igw",
   "tier": "core",
   "quote": "public subnets have default routes to the Internet Gateway",
   "justify": "a default route is destination 0.0.0.0/0",
   "from": "igw_route"
  },
  {
   "id": "public_subnets_associated",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "assoc",
     "to": "pub1"
    },
    {
     "kind": "ref",
     "from": "assoc",
     "to": "pub2"
    }
   ],
   "tier": "detail",
   "quote": "the proper routing so that public subnets have default routes to the Internet Gateway"
  },
  {
   "id": "private_default_routes_nat",
   "kind": "exists",
   "select": "nat_route",
   "min": 2,
   "distinct_path": [
    "NatGatewayId"
   ],
   "tier": "core",
   "quote": "each private subnet has a default route to its respective NAT Gateway",
   "justify": "each of the two private subnets routes to its own NAT gateway"
  },
  {
   "id": "private_subnets_associated",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "assoc",
     "to": "priv1"
    },
    {
     "kind": "ref",
     "from": "assoc",
     "to": "priv2"
    }
   ],
   "tier": "detail",
   "quote": "each private subnet has a default route to its respective NAT Gateway"
  },
  {
   "id": "kms_key_rotation",
   "kind": "attr",
   "select": "key",
   "cond": {
    "path": [
     "EnableKeyRotation"
    ],
    "op": "eq",
    "value": "true"
   },
   "tier": "core",
   "quote": "a KMS key for encrypting VPC flow logs with key rotation enabled",
   "justify": "rotation enabled means EnableKeyRotation true"
  },
  {
   "id": "log_group_encrypted_with_key",
   "tier": "core",
   "quote": "a KMS key for encrypting VPC flow logs",
   "kind": "ref",
   "from": "lg",
   "to": "key_rotated",
   "justify": "the flow-log key has rotation enabled, i.e. EnableKeyRotation true"
  },
  {
   "id": "flow_log_all_traffic",
   "kind": "attr",
   "select": "fl",
   "cond": {
    "path": [
     "TrafficType"
    ],
    "op": "eq",
    "value": "ALL"
   },
   "tier": "core",
   "quote": "a VPC flow log sending all traffic"
  },
  {
   "id": "flow_log_to_log_group",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "fl",
     "to": "lg"
    },
    {
     "kind": "join",
     "from": "fl",
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
   "quote": "a CloudWatch log group"
  },
  {
   "id": "flow_log_for_vpc",
   "kind": "ref",
   "to": "vpc",
   "tier": "detail",
   "quote": "a VPC flow log",
   "from": "fl"
  },
  {
   "id": "log_retention_30",
   "tier": "core",
   "quote": "30-day retention",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "fl",
     "to": "lg30"
    },
    {
     "kind": "join",
     "from": "fl",
     "from_path": [
      "LogGroupName"
     ],
     "to": "lg30",
     "to_path": [
      "LogGroupName"
     ]
    }
   ]
  },
  {
   "id": "endpoint_ssm",
   "kind": "attr",
   "select": "ep_ssm",
   "cond": {
    "path": [
     "VpcEndpointType"
    ],
    "op": "eq",
    "value": "Interface"
   },
   "tier": "core",
   "quote": "VPC interface endpoints in the private subnets for SSM"
  },
  {
   "id": "endpoint_ssm_messages",
   "kind": "attr",
   "select": "ep_ssmm",
   "cond": {
    "path": [
     "VpcEndpointType"
    ],
    "op": "eq",
    "value": "Interface"
   },
   "tier": "core",
   "quote": "SSM Messages"
  },
  {
   "id": "endpoint_ec2_messages",
   "kind": "attr",
   "select": "ep_ec2m",
   "cond": {
    "path": [
     "VpcEndpointType"
    ],
    "op": "eq",
    "value": "Interface"
   },
   "tier": "core",
   "quote": "EC2 Messages"
  },
  {
   "id": "endpoint_secrets_manager",
   "kind": "attr",
   "select": "ep_sm",
   "cond": {
    "path": [
     "VpcEndpointType"
    ],
    "op": "eq",
    "value": "Interface"
   },
   "tier": "core",
   "quote": "Secrets Manager"
  },
  {
   "id": "endpoints_in_private_subnets",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "ep_ssm",
     "to": "priv1"
    },
    {
     "kind": "ref",
     "from": "ep_ssmm",
     "to": "priv1"
    },
    {
     "kind": "ref",
     "from": "ep_ec2m",
     "to": "priv1"
    },
    {
     "kind": "ref",
     "from": "ep_sm",
     "to": "priv1"
    },
    {
     "kind": "ref",
     "from": "ep_ssm",
     "to": "priv2"
    },
    {
     "kind": "ref",
     "from": "ep_ssmm",
     "to": "priv2"
    },
    {
     "kind": "ref",
     "from": "ep_ec2m",
     "to": "priv2"
    },
    {
     "kind": "ref",
     "from": "ep_sm",
     "to": "priv2"
    }
   ],
   "tier": "detail",
   "quote": "VPC interface endpoints in the private subnets",
   "justify": "endpoints sit in the private subnets; both are accepted as the template has two"
  },
  {
   "id": "endpoints_share_security_group",
   "tier": "detail",
   "quote": "all using a shared security group",
   "kind": "all_of",
   "justify": "each of the four endpoints uses a security group",
   "checks": [
    {
     "kind": "ref",
     "from": "ep_ssm",
     "to": "sgs"
    },
    {
     "kind": "ref",
     "from": "ep_ssmm",
     "to": "sgs"
    },
    {
     "kind": "ref",
     "from": "ep_ec2m",
     "to": "sgs"
    },
    {
     "kind": "ref",
     "from": "ep_sm",
     "to": "sgs"
    }
   ]
  },
  {
   "id": "sg_https_ingress_from_vpc_cidr",
   "tier": "core",
   "quote": "restricts inbound and outbound traffic to HTTPS from the VPC CIDR",
   "kind": "any_of",
   "justify": "HTTPS implies TCP port 443; the VPC CIDR is the stated 10.0.0.0/24 or the VPC CidrBlock attribute",
   "checks": [
    {
     "kind": "ref",
     "from": "eps4",
     "to": "sg_has_in"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::EC2::SecurityGroupIngress"
      ],
      "where": [
       {
        "path": [
         "IpProtocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "regex",
        "value": "^10\\.0\\.0\\.0/24$|CidrBlock"
       }
      ]
     },
     "to": "sgs"
    }
   ]
  },
  {
   "id": "sg_ingress_only_https",
   "tier": "core",
   "quote": "restricts inbound and outbound traffic to HTTPS from the VPC CIDR",
   "kind": "any_of",
   "justify": "HTTPS implies TCP port 443; the VPC CIDR is the stated 10.0.0.0/24 or the VPC CidrBlock attribute",
   "checks": [
    {
     "kind": "ref",
     "from": "eps4",
     "to": "sg_only_in"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::EC2::SecurityGroupIngress"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "IpProtocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       },
       {
        "path": [
         "FromPort"
        ],
        "op": "eq",
        "value": "443"
       },
       {
        "path": [
         "ToPort"
        ],
        "op": "eq",
        "value": "443"
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "regex",
        "value": "^10\\.0\\.0\\.0/24$|CidrBlock"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sg_egress_https",
   "tier": "core",
   "quote": "restricts inbound and outbound traffic to HTTPS from the VPC CIDR",
   "kind": "ref",
   "from": "eps4",
   "to": "sg_only_eg",
   "justify": "HTTPS implies TCP port 443; the VPC CIDR is the stated 10.0.0.0/24 or the VPC CidrBlock attribute"
  },
  {
   "id": "x_dns_support",
   "kind": "attr",
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
    "op": "eq",
    "value": "true"
   },
   "tier": "extra"
  },
  {
   "id": "x_dns_hostnames",
   "kind": "attr",
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
    "op": "eq",
    "value": "true"
   },
   "tier": "extra"
  },
  {
   "id": "x_private_dns",
   "kind": "attr",
   "select": "eps",
   "cond": {
    "path": [
     "PrivateDnsEnabled"
    ],
    "op": "eq",
    "value": "true"
   },
   "quantifier": "all",
   "tier": "extra"
  },
  {
   "id": "x_nat_in_public",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "nat",
     "to": "pub1"
    },
    {
     "kind": "ref",
     "from": "nat",
     "to": "pub2"
    }
   ],
   "tier": "extra"
  },
  {
   "id": "x_flowlog_role",
   "kind": "ref",
   "to": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   },
   "tier": "extra",
   "from": "fl"
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
