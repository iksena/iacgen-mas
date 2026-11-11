package intent.cfn.row_160

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
     "value": "10.0.0.0/16"
    }
   ]
  },
  "igw": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::EC2::InternetGateway"
    }
   ]
  },
  "rt": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::EC2::RouteTable"
    }
   ]
  },
  "subnet": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::EC2::Subnet"
    },
    {
     "path": [
      "properties",
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.0.1.0/24"
    }
   ]
  },
  "sg": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::EC2::SecurityGroup"
    }
   ]
  },
  "sgi": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::EC2::SecurityGroupIngress"
    }
   ]
  },
  "igw_gated": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::EC2::InternetGateway"
    },
    {
     "path": [
      "gated"
     ],
     "op": "truthy"
    }
   ]
  },
  "rt_gated": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::EC2::RouteTable"
    },
    {
     "path": [
      "gated"
     ],
     "op": "truthy"
    }
   ]
  },
  "subnet_gated": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::EC2::Subnet"
    },
    {
     "path": [
      "gated"
     ],
     "op": "truthy"
    },
    {
     "path": [
      "properties",
      "CidrBlock"
     ],
     "op": "eq",
     "value": "10.0.1.0/24"
    }
   ]
  },
  "sg_gated": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::EC2::SecurityGroup"
    },
    {
     "path": [
      "gated"
     ],
     "op": "truthy"
    }
   ]
  },
  "bool_params": {
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
      "true",
      "false"
     ]
    }
   ]
  },
  "prefix_param": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "default"
     ],
     "op": "eq",
     "value": "SimpleApp1"
    }
   ]
  },
  "src_param": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "default"
     ],
     "op": "eq",
     "value": "0.0.0.0/0"
    }
   ]
  },
  "outs": {
   "types": [
    "__output__"
   ],
   "where": []
  },
  "named": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "properties"
     ],
     "op": "regex",
     "value": "SimpleApp1"
    }
   ]
  },
  "igw_route": {
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
    }
   ]
  },
  "attach": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::EC2::VPCGatewayAttachment"
    }
   ]
  },
  "vpc_id_outs": {
   "types": [
    "__output__"
   ],
   "where": [
    {
     "path": [
      "value",
      "attr"
     ],
     "op": "none_eq",
     "value": "CidrBlock"
    },
    {
     "path": [
      "value",
      "attr"
     ],
     "op": "none_eq",
     "value": "DefaultSecurityGroup"
    },
    {
     "path": [
      "value",
      "attr"
     ],
     "op": "none_eq",
     "value": "DefaultNetworkAcl"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "tier": "core",
   "quote": "a VPC CIDR of 10.0.0.0/16",
   "select": "vpc"
  },
  {
   "id": "igw_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "an optional internet gateway",
   "select": "igw"
  },
  {
   "id": "subnet_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "public subnet CIDR of 10.0.1.0/24",
   "select": "subnet"
  },
  {
   "id": "rt_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "route table",
   "select": "rt"
  },
  {
   "id": "sg_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "security group",
   "select": "sg"
  },
  {
   "id": "igw_optional",
   "kind": "exists",
   "tier": "core",
   "quote": "an optional internet gateway, public subnet, route table, and security group controlled by boolean parameters",
   "select": "igw_gated"
  },
  {
   "id": "subnet_optional",
   "kind": "exists",
   "tier": "core",
   "quote": "an optional internet gateway, public subnet, route table, and security group controlled by boolean parameters",
   "select": "subnet_gated"
  },
  {
   "id": "rt_optional",
   "kind": "exists",
   "tier": "core",
   "quote": "an optional internet gateway, public subnet, route table, and security group controlled by boolean parameters",
   "select": "rt_gated"
  },
  {
   "id": "sg_optional",
   "kind": "exists",
   "tier": "core",
   "quote": "an optional internet gateway, public subnet, route table, and security group controlled by boolean parameters",
   "select": "sg_gated"
  },
  {
   "id": "boolean_params",
   "kind": "exists",
   "tier": "core",
   "quote": "controlled by boolean parameters",
   "justify": "parameters is plural; boolean parameters default to true or false",
   "select": "bool_params",
   "min": 2
  },
  {
   "id": "prefix_param",
   "kind": "exists",
   "tier": "core",
   "quote": "a configurable naming prefix defaulting to \"SimpleApp1\"",
   "select": "prefix_param"
  },
  {
   "id": "prefix_used",
   "kind": "exists",
   "tier": "detail",
   "quote": "a configurable naming prefix defaulting to \"SimpleApp1\"",
   "select": "named"
  },
  {
   "id": "subnet_az",
   "kind": "attr",
   "tier": "detail",
   "quote": "in the first available availability zone in the region",
   "justify": "Fn::Select 0 of Fn::GetAZs resolves to us-east-1a under the adapter region; other indexes resolve to other zones",
   "select": "subnet",
   "cond": {
    "path": [
     "properties",
     "AvailabilityZone"
    ],
    "op": "eq",
    "value": "us-east-1a"
   }
  },
  {
   "id": "sg_http",
   "kind": "any_of",
   "tier": "core",
   "quote": "a security group that allows HTTP and HTTPS traffic from a specified source IP range defaulting to 0.0.0.0/0",
   "justify": "HTTP implies port 80 over TCP, so an all-protocol rule does not count",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "properties",
       "SecurityGroupIngress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "IpProtocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         6
        ]
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "sgi",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "IpProtocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         6
        ]
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sg_https",
   "kind": "any_of",
   "tier": "core",
   "quote": "a security group that allows HTTP and HTTPS traffic from a specified source IP range defaulting to 0.0.0.0/0",
   "justify": "HTTPS implies port 443 over TCP, so an all-protocol rule does not count",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "properties",
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
        "op": "in",
        "value": [
         "tcp",
         6
        ]
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "sgi",
     "cond": {
      "path": [
       "properties"
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
        "op": "in",
        "value": [
         "tcp",
         6
        ]
       },
       {
        "path": [
         "CidrIp"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "source_param",
   "kind": "exists",
   "tier": "detail",
   "quote": "a specified source IP range defaulting to 0.0.0.0/0",
   "select": "src_param"
  },
  {
   "id": "subnet_in_vpc",
   "kind": "ref",
   "tier": "detail",
   "quote": "a public subnet CIDR of 10.0.1.0/24",
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
      "value": "AWS::EC2::Subnet"
     }
    ]
   },
   "to": "vpc"
  },
  {
   "id": "sg_in_vpc",
   "kind": "ref",
   "tier": "detail",
   "quote": "a security group",
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
      "value": "AWS::EC2::SecurityGroup"
     }
    ]
   },
   "to": "vpc"
  },
  {
   "id": "single_output",
   "kind": "exists",
   "tier": "core",
   "quote": "with the only output being the VPC ID",
   "justify": "the only output means exactly one output",
   "select": "outs",
   "max": 1
  },
  {
   "id": "output_vpc",
   "kind": "ref",
   "tier": "core",
   "quote": "the VPC ID",
   "from": "vpc_id_outs",
   "to": "vpc"
  },
  {
   "id": "x_dns_hostnames",
   "kind": "attr",
   "tier": "extra",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_dns_support",
   "kind": "attr",
   "tier": "extra",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsSupport"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_attach_vpc",
   "kind": "ref",
   "tier": "extra",
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
      "value": "AWS::EC2::VPCGatewayAttachment"
     }
    ]
   },
   "to": "vpc"
  },
  {
   "id": "x_route_default",
   "kind": "attr",
   "tier": "extra",
   "select": "igw_route",
   "cond": {
    "path": [
     "properties",
     "GatewayId"
    ],
    "op": "present"
   }
  },
  {
   "id": "x_subnet_nopublic",
   "kind": "attr",
   "tier": "extra",
   "select": "subnet",
   "cond": {
    "path": [
     "properties",
     "MapPublicIpOnLaunch"
    ],
    "op": "none_eq",
    "value": true
   }
  },
  {
   "id": "extra_type_aws_ec2_subnetroutetableassociation",
   "kind": "exists",
   "tier": "extra",
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
      "value": "AWS::EC2::SubnetRouteTableAssociation"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
