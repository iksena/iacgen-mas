package intent.cfn.row_268

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
     "value": "10.0.1.0/24"
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
     "value": "10.0.2.0/24"
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
     "value": "10.0.101.0/24"
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
     "value": "10.0.102.0/24"
    }
   ]
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
  "pubrt": {
   "types": [
    "AWS::EC2::RouteTable"
   ],
   "where": []
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
      "GatewayId",
      "ref"
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
      "NatGatewayId",
      "ref"
     ],
     "op": "present"
    }
   ]
  },
  "assoc": {
   "types": [
    "AWS::EC2::SubnetRouteTableAssociation"
   ],
   "where": []
  },
  "outs": {
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
  "pubs": {
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
      "10.0.1.0/24",
      "10.0.2.0/24"
     ]
    }
   ]
  },
  "privs": {
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
      "10.0.101.0/24",
      "10.0.102.0/24"
     ]
    }
   ]
  },
  "attach": {
   "types": [
    "AWS::EC2::VPCGatewayAttachment"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "tier": "core",
   "quote": "built around a VPC",
   "select": "vpc"
  },
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "tier": "core",
   "quote": "a configurable CIDR that defaults to 10.0.0.0/16",
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
   "id": "vpc_dns",
   "tier": "core",
   "quote": "with DNS support and DNS hostnames enabled",
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
   "id": "vpc_dnshost",
   "kind": "attr",
   "tier": "core",
   "quote": "with DNS support and DNS hostnames enabled",
   "select": "vpc",
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "pub1_subnet",
   "kind": "ref",
   "tier": "core",
   "quote": "two public subnets defaulting to 10.0.1.0/24 and 10.0.2.0/24",
   "from": "pub1",
   "to": "vpc"
  },
  {
   "id": "pub2_subnet",
   "kind": "ref",
   "tier": "core",
   "quote": "two public subnets defaulting to 10.0.1.0/24 and 10.0.2.0/24",
   "from": "pub2",
   "to": "vpc"
  },
  {
   "id": "priv1_subnet",
   "kind": "ref",
   "tier": "core",
   "quote": "two private subnets defaulting to 10.0.101.0/24 and 10.0.102.0/24",
   "from": "priv1",
   "to": "vpc"
  },
  {
   "id": "priv2_subnet",
   "kind": "ref",
   "tier": "core",
   "quote": "two private subnets defaulting to 10.0.101.0/24 and 10.0.102.0/24",
   "from": "priv2",
   "to": "vpc"
  },
  {
   "id": "subnets_azs",
   "tier": "core",
   "quote": "spread across availability zones in the region",
   "justify": "spread across AZs implies each pair of subnets spans at least two zones",
   "kind": "all_of",
   "checks": [
    {
     "kind": "exists",
     "select": "pubs",
     "min": 2,
     "distinct_path": [
      "AvailabilityZone"
     ]
    },
    {
     "kind": "exists",
     "select": "privs",
     "min": 2,
     "distinct_path": [
      "AvailabilityZone"
     ]
    }
   ]
  },
  {
   "id": "cidr_params",
   "tier": "detail",
   "quote": "with every CIDR exposed as its own parameter",
   "justify": "five CIDRs (VPC and four subnets) each its own parameter",
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
      "op": "in",
      "value": [
       "10.0.0.0/16",
       "10.0.1.0/24",
       "10.0.2.0/24",
       "10.0.101.0/24",
       "10.0.102.0/24"
      ]
     }
    ]
   },
   "distinct_path": [
    "default"
   ],
   "min": 5
  },
  {
   "id": "igw",
   "kind": "exists",
   "tier": "core",
   "quote": "An internet gateway attached to the VPC",
   "select": "igw"
  },
  {
   "id": "igw_attach",
   "tier": "core",
   "quote": "An internet gateway attached to the VPC",
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
   ]
  },
  {
   "id": "igw_route",
   "kind": "ref",
   "tier": "core",
   "quote": "sends all outbound traffic from both public subnets to it",
   "from": "igw_route",
   "to": "igw",
   "justify": "all outbound traffic implies 0.0.0.0/0"
  },
  {
   "id": "igw_route_rt",
   "kind": "ref",
   "tier": "core",
   "quote": "a single shared public route table",
   "from": "igw_route",
   "to": "pubrt",
   "justify": "all outbound traffic implies 0.0.0.0/0"
  },
  {
   "id": "shared_public_rt",
   "kind": "exists",
   "tier": "core",
   "quote": "a single shared public route table",
   "select": "assoc",
   "distinct_path": [
    "RouteTableId",
    "ref"
   ],
   "min": 3,
   "max": 3,
   "justify": "four subnet associations onto exactly three tables: one shared public table plus one per private subnet"
  },
  {
   "id": "pub1_assoc",
   "kind": "ref",
   "tier": "core",
   "quote": "from both public subnets",
   "from": "assoc",
   "to": "pub1"
  },
  {
   "id": "pub2_assoc",
   "kind": "ref",
   "tier": "core",
   "quote": "from both public subnets",
   "from": "assoc",
   "to": "pub2"
  },
  {
   "id": "nat_count",
   "kind": "exists",
   "tier": "core",
   "quote": "Each public subnet should also host its own NAT gateway",
   "select": "nat",
   "min": 2
  },
  {
   "id": "nat_pub1",
   "kind": "ref",
   "tier": "core",
   "quote": "Each public subnet should also host its own NAT gateway",
   "from": "nat",
   "to": "pub1"
  },
  {
   "id": "nat_pub2",
   "kind": "ref",
   "tier": "core",
   "quote": "Each public subnet should also host its own NAT gateway",
   "from": "nat",
   "to": "pub2"
  },
  {
   "id": "nat_eip",
   "kind": "exists",
   "tier": "core",
   "quote": "with a dedicated elastic IP",
   "select": "eip",
   "min": 2,
   "justify": "two public subnets each with a dedicated EIP"
  },
  {
   "id": "nat_eip_ref",
   "tier": "core",
   "quote": "with a dedicated elastic IP",
   "justify": "a dedicated elastic IP for each of the two NAT gateways",
   "kind": "exists",
   "select": "nat",
   "min": 2,
   "distinct_path": [
    "AllocationId",
    "ref"
   ]
  },
  {
   "id": "priv_rt",
   "kind": "exists",
   "tier": "core",
   "quote": "each private subnet should get its own route table",
   "select": "pubrt",
   "min": 3,
   "justify": "one public route table plus one per private subnet"
  },
  {
   "id": "priv_nat_routes",
   "kind": "exists",
   "tier": "core",
   "quote": "each private subnet should get its own route table sending outbound traffic to the NAT gateway",
   "select": "nat_route",
   "min": 2,
   "distinct_path": [
    "NatGatewayId",
    "ref"
   ],
   "justify": "outbound traffic implies 0.0.0.0/0; two private subnets each with own route"
  },
  {
   "id": "priv1_assoc",
   "kind": "ref",
   "tier": "core",
   "quote": "each private subnet should get its own route table",
   "from": "assoc",
   "to": "priv1"
  },
  {
   "id": "priv2_assoc",
   "kind": "ref",
   "tier": "core",
   "quote": "each private subnet should get its own route table",
   "from": "assoc",
   "to": "priv2"
  },
  {
   "id": "outs",
   "kind": "exists",
   "tier": "core",
   "quote": "as exported outputs",
   "select": "outs",
   "min": 5,
   "justify": "VPC plus four subnet identifiers"
  },
  {
   "id": "out_vpc",
   "tier": "detail",
   "quote": "publish the VPC and all four subnet identifiers as exported outputs",
   "kind": "ref",
   "from": {
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
   "to": "vpc"
  },
  {
   "id": "out_pub1",
   "kind": "ref",
   "tier": "detail",
   "quote": "all four subnet identifiers",
   "from": {
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
   "to": "pub1"
  },
  {
   "id": "out_pub2",
   "kind": "ref",
   "tier": "detail",
   "quote": "all four subnet identifiers",
   "from": {
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
   "to": "pub2"
  },
  {
   "id": "out_priv1",
   "kind": "ref",
   "tier": "detail",
   "quote": "all four subnet identifiers",
   "from": {
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
   "to": "priv1"
  },
  {
   "id": "out_priv2",
   "kind": "ref",
   "tier": "detail",
   "quote": "all four subnet identifiers",
   "from": {
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
   "to": "priv2"
  },
  {
   "id": "names",
   "tier": "detail",
   "quote": "Name the resources after the stack",
   "justify": "after the stack means the Name tag is built from the stack name, which the adapter renders as stack",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
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
        "value": "(?i)stack"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::EC2::Subnet"
      ],
      "where": []
     },
     "quantifier": "all",
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
        "value": "(?i)stack"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_eip_domain",
   "kind": "attr",
   "tier": "extra",
   "select": "eip",
   "cond": {
    "path": [
     "Domain"
    ],
    "op": "eq",
    "value": "vpc"
   },
   "quantifier": "all"
  },
  {
   "id": "x_route_dep",
   "kind": "attr",
   "tier": "extra",
   "select": "igw_route",
   "cond": {
    "path": [
     "__resource__",
     "DependsOn"
    ],
    "op": "present"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
