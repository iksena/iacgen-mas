package intent.cfn.row_110

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
     "value": "172.18.0.0/16"
    }
   ]
  },
  "pub": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "172.18.0.0/22"
    }
   ]
  },
  "priv": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": [
    {
     "path": [
      "CidrBlock"
     ],
     "op": "eq",
     "value": "172.18.32.0/21"
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
  "att": {
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
  "rt": {
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
  "params": {
   "types": [
    "__parameter__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "The VPC CIDR should default to 172.18.0.0/16"
  },
  {
   "id": "public_subnet_cidr",
   "kind": "exists",
   "select": "pub",
   "tier": "core",
   "quote": "the public subnet to 172.18.0.0/22"
  },
  {
   "id": "private_subnet_cidr",
   "kind": "exists",
   "select": "priv",
   "tier": "core",
   "quote": "the private subnet to 172.18.32.0/21"
  },
  {
   "id": "subnets_in_vpc",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "pub",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "priv",
     "to": "vpc"
    }
   ],
   "tier": "detail",
   "quote": "a VPC with a public and a private subnet"
  },
  {
   "id": "cidr_defaults_as_parameters",
   "kind": "all_of",
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
        "value": "172.18.0.0/16"
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
        "value": "172.18.0.0/22"
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
        "value": "172.18.32.0/21"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "The VPC CIDR should default to 172.18.0.0/16, the public subnet to 172.18.0.0/22, and the private subnet to 172.18.32.0/21"
  },
  {
   "id": "internet_gateway",
   "kind": "exists",
   "select": "igw",
   "tier": "core",
   "quote": "an internet gateway"
  },
  {
   "id": "igw_attached",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "att",
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": "att",
     "to": {
      "types": [
       "AWS::EC2::VPC"
      ],
      "where": []
     }
    }
   ],
   "tier": "detail",
   "quote": "an internet gateway"
  },
  {
   "id": "route_tables",
   "kind": "exists",
   "select": "rt",
   "min": 2,
   "tier": "core",
   "quote": "appropriate route tables and associations",
   "justify": "one route table for the public and one for the private subnet"
  },
  {
   "id": "route_associations",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "assoc",
     "to": "pub"
    },
    {
     "kind": "ref",
     "from": "assoc",
     "to": "priv"
    }
   ],
   "tier": "core",
   "quote": "appropriate route tables and associations"
  },
  {
   "id": "nat_gateway",
   "kind": "exists",
   "select": "nat",
   "tier": "core",
   "quote": "a NAT gateway with an Elastic IP attached to it"
  },
  {
   "id": "elastic_ip",
   "kind": "exists",
   "select": "eip",
   "tier": "core",
   "quote": "a NAT gateway with an Elastic IP attached to it"
  },
  {
   "id": "nat_uses_eip",
   "kind": "ref",
   "from": "nat",
   "to": "eip",
   "tier": "core",
   "quote": "a NAT gateway with an Elastic IP attached to it"
  },
  {
   "id": "nat_in_public_subnet",
   "kind": "ref",
   "from": "nat",
   "to": "pub",
   "tier": "core",
   "quote": "a NAT gateway placed in the public subnet"
  },
  {
   "id": "private_route_via_nat",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": "default_route",
     "to": "nat"
    },
    {
     "kind": "join",
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
       },
       {
        "path": [
         "NatGatewayId"
        ],
        "op": "present"
       }
      ]
     },
     "from_path": [
      "RouteTableId",
      "ref"
     ],
     "to": "assoc",
     "to_path": [
      "RouteTableId",
      "ref"
     ]
    }
   ],
   "tier": "core",
   "quote": "the private subnet instances can access the internet through a NAT gateway",
   "justify": "internet access is the default route 0.0.0.0/0"
  },
  {
   "id": "public_route_via_igw",
   "kind": "ref",
   "from": "default_route",
   "to": "igw",
   "tier": "detail",
   "quote": "appropriate route tables and associations",
   "justify": "internet access is the default route 0.0.0.0/0"
  },
  {
   "id": "no_auto_public_ip",
   "kind": "attr",
   "select": "subnets",
   "cond": {
    "path": [
     "MapPublicIpOnLaunch"
    ],
    "op": "none_eq",
    "value": "true"
   },
   "quantifier": "all",
   "tier": "core",
   "quote": "Neither subnet should auto-assign public IP addresses to launched instances",
   "justify": "not auto-assigning means MapPublicIpOnLaunch is not true"
  },
  {
   "id": "x_eip_vpc_domain",
   "kind": "attr",
   "select": "eip",
   "cond": {
    "path": [
     "Domain"
    ],
    "op": "eq",
    "value": "vpc"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
