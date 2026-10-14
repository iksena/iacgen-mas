# GENERATED from specs/cfn/row_120.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_120

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
  "igw": {
   "types": [
    "AWS::EC2::InternetGateway"
   ],
   "where": []
  },
  "igw_attach": {
   "types": [
    "AWS::EC2::VPCGatewayAttachment"
   ],
   "where": []
  },
  "subnet": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": []
  },
  "rt": {
   "types": [
    "AWS::EC2::RouteTable"
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
  "tgw": {
   "types": [
    "AWS::EC2::TransitGateway"
   ],
   "where": []
  },
  "tgw_attach": {
   "types": [
    "AWS::EC2::TransitGatewayAttachment",
    "AWS::EC2::TransitGatewayVpcAttachment"
   ],
   "where": []
  },
  "sg": {
   "types": [
    "AWS::EC2::SecurityGroup"
   ],
   "where": []
  },
  "cgw": {
   "types": [
    "AWS::EC2::CustomerGateway"
   ],
   "where": []
  },
  "vpn": {
   "types": [
    "AWS::EC2::VPNConnection"
   ],
   "where": []
  },
  "flowlog": {
   "types": [
    "AWS::EC2::FlowLog"
   ],
   "where": []
  },
  "loggroup": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "kms": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "eq",
    "value": "10.94.0.0/16"
   },
   "tier": "core",
   "quote": "defaults of 10.94.0.0/16 for the VPC"
  },
  {
   "id": "igw_attached_to_vpc",
   "kind": "all_of",
   "tier": "core",
   "quote": "an internet gateway",
   "checks": [
    {
     "kind": "ref",
     "from": "igw_attach",
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": "igw_attach",
     "to": "vpc"
    }
   ]
  },
  {
   "id": "subnet_cidr_in_vpc",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::EC2::Subnet"
    ],
    "where": [
     {
      "path": [
       "CidrBlock"
      ],
      "op": "eq",
      "value": "10.94.10.0/24"
     }
    ]
   },
   "to": "vpc",
   "tier": "core",
   "quote": "10.94.10.0/24 for the subnet"
  },
  {
   "id": "subnet_private",
   "kind": "attr",
   "select": "subnet",
   "cond": {
    "path": [
     "MapPublicIpOnLaunch"
    ],
    "op": "none_eq",
    "value": true
   },
   "tier": "detail",
   "quote": "a private subnet"
  },
  {
   "id": "subnet_first_az",
   "kind": "attr",
   "select": "subnet",
   "cond": {
    "path": [
     "AvailabilityZone"
    ],
    "op": "eq",
    "value": "us-east-1a"
   },
   "tier": "detail",
   "quote": "in the first available availability zone",
   "justify": "\"first available availability zone\" resolves to us-east-1a (index 0 of GetAZs) under the normaliser region us-east-1"
  },
  {
   "id": "default_route_via_igw",
   "kind": "all_of",
   "tier": "core",
   "quote": "a route table with a default route via the IGW",
   "checks": [
    {
     "kind": "ref",
     "from": "default_route",
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": "default_route",
     "to": "rt"
    }
   ],
   "justify": "\"default route\" means destination 0.0.0.0/0"
  },
  {
   "id": "transit_gateway_vpc_attachment",
   "kind": "all_of",
   "tier": "core",
   "quote": "a transit gateway with a VPC attachment",
   "checks": [
    {
     "kind": "ref",
     "from": "tgw_attach",
     "to": "tgw"
    },
    {
     "kind": "ref",
     "from": "tgw_attach",
     "to": "vpc"
    }
   ]
  },
  {
   "id": "sg_https_ingress_internal",
   "kind": "any_of",
   "tier": "core",
   "quote": "a security group that only allows HTTPS inbound from a configurable internal CIDR range",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "SecurityGroupIngress",
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
         "IpProtocol"
        ],
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "present"
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "neq",
        "value": "0.0.0.0/0"
       }
      ]
     }
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
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "neq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": "sg"
    }
   ],
   "justify": "HTTPS implies tcp/443; \"internal CIDR range\" implies not 0.0.0.0/0"
  },
  {
   "id": "sg_ingress_https_only",
   "kind": "any_of",
   "tier": "detail",
   "quote": "only allows HTTPS inbound from a configurable internal CIDR range",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::EC2::SecurityGroup"
      ],
      "where": [
       {
        "path": [
         "SecurityGroupIngress",
         "*",
         "FromPort"
        ],
        "op": "eq",
        "value": 443,
        "every": true
       },
       {
        "path": [
         "SecurityGroupIngress",
         "*",
         "ToPort"
        ],
        "op": "eq",
        "value": 443,
        "every": true
       },
       {
        "path": [
         "SecurityGroupIngress",
         "*",
         "IpProtocol"
        ],
        "op": "eq",
        "value": "tcp",
        "every": true
       },
       {
        "path": [
         "SecurityGroupIngress",
         "*",
         "CidrIp"
        ],
        "op": "neq",
        "value": "0.0.0.0/0",
        "every": true
       }
      ]
     }
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
        "op": "eq",
        "value": "tcp"
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "neq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ],
   "justify": "\"only allows HTTPS\" implies every ingress rule is tcp/443; \"internal CIDR range\" implies not 0.0.0.0/0"
  },
  {
   "id": "sg_https_egress_to_oci",
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
      "path": [],
      "op": "port_covers",
      "value": 443
     },
     {
      "path": [
       "IpProtocol"
      ],
      "op": "eq",
      "value": "tcp"
     },
     {
      "path": [
       "CidrIp"
      ],
      "op": "present"
     },
     {
      "path": [
       "CidrIp"
      ],
      "op": "neq",
      "value": "0.0.0.0/0"
     }
    ]
   },
   "tier": "core",
   "quote": "only allows HTTPS outbound to the OCI backbone CIDR",
   "justify": "HTTPS implies tcp/443; \"to the OCI backbone CIDR\" implies a specific CIDR, not 0.0.0.0/0"
  },
  {
   "id": "sg_egress_https_only",
   "kind": "exists",
   "tier": "detail",
   "quote": "only allows HTTPS outbound to the OCI backbone CIDR",
   "select": {
    "types": [
     "AWS::EC2::SecurityGroup"
    ],
    "where": [
     {
      "path": [
       "SecurityGroupEgress",
       "*",
       "FromPort"
      ],
      "op": "eq",
      "value": 443,
      "every": true
     },
     {
      "path": [
       "SecurityGroupEgress",
       "*",
       "ToPort"
      ],
      "op": "eq",
      "value": 443,
      "every": true
     },
     {
      "path": [
       "SecurityGroupEgress",
       "*",
       "IpProtocol"
      ],
      "op": "eq",
      "value": "tcp",
      "every": true
     },
     {
      "path": [
       "SecurityGroupEgress",
       "*",
       "CidrIp"
      ],
      "op": "neq",
      "value": "0.0.0.0/0",
      "every": true
     }
    ]
   },
   "justify": "\"only allows HTTPS outbound\" implies every egress rule is tcp/443 to a non-0.0.0.0/0 CIDR"
  },
  {
   "id": "vpn_to_customer_gateway",
   "kind": "all_of",
   "tier": "core",
   "quote": "conditionally create a customer gateway and VPN connection to OCI",
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
        "value": "AWS::EC2::CustomerGateway"
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
        "value": "AWS::EC2::VPNConnection"
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
        "value": "AWS::EC2::VPNConnection"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "CustomerGatewayId"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "vpn_static_routes_only",
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
      "value": "AWS::EC2::VPNConnection"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "StaticRoutesOnly"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "using static routes only"
  },
  {
   "id": "tgw_route_for_oci",
   "kind": "any_of",
   "tier": "core",
   "quote": "define a transit gateway route for OCI traffic",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::EC2::Route"
      ],
      "where": [
       {
        "path": [
         "DestinationCidrBlock"
        ],
        "op": "neq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": "tgw"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::EC2::TransitGatewayRoute"
      ],
      "where": [
       {
        "path": [
         "DestinationCidrBlock"
        ],
        "op": "neq",
        "value": "0.0.0.0/0"
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
        "value": "AWS::EC2::Route"
       },
       {
        "path": [
         "properties",
         "TransitGatewayId"
        ],
        "op": "present"
       },
       {
        "path": [
         "properties",
         "DestinationCidrBlock"
        ],
        "op": "neq",
        "value": "0.0.0.0/0"
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
        "value": "AWS::EC2::TransitGatewayRoute"
       },
       {
        "path": [
         "properties",
         "DestinationCidrBlock"
        ],
        "op": "neq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ],
   "justify": "a route \"for OCI traffic\" targets the OCI CIDR, i.e. not the 0.0.0.0/0 default route"
  },
  {
   "id": "vpc_flow_logs",
   "kind": "ref",
   "from": "flowlog",
   "to": "vpc",
   "tier": "core",
   "quote": "enabling VPC flow logs"
  },
  {
   "id": "flow_logs_to_cloudwatch",
   "kind": "ref",
   "from": "flowlog",
   "to": "loggroup",
   "tier": "detail",
   "quote": "logs stored in CloudWatch"
  },
  {
   "id": "log_group_kms_encrypted",
   "kind": "ref",
   "from": "loggroup",
   "to": "kms",
   "tier": "core",
   "quote": "encrypted with a customer-managed KMS key"
  },
  {
   "id": "kms_key_rotation",
   "kind": "attr",
   "select": "kms",
   "cond": {
    "path": [
     "EnableKeyRotation"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "key rotation enabled"
  },
  {
   "id": "log_retention_30_days",
   "kind": "attr",
   "select": "loggroup",
   "cond": {
    "path": [
     "RetentionInDays"
    ],
    "op": "eq",
    "value": 30
   },
   "tier": "detail",
   "quote": "30-day retention"
  },
  {
   "id": "parameterized_cidrs",
   "kind": "all_of",
   "tier": "detail",
   "quote": "all resources use parameterized CIDRs with defaults of 10.94.0.0/16 for the VPC and 10.94.10.0/24 for the subnet",
   "checks": [
    {
     "kind": "exists",
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
        "value": "10.94.0.0/16"
       }
      ]
     }
    },
    {
     "kind": "exists",
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
        "value": "10.94.10.0/24"
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
