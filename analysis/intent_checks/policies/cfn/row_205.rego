package intent.cfn.row_205

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
  "rt": {
   "types": [
    "AWS::EC2::RouteTable"
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
  "nat_routes": {
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
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc",
   "tier": "core",
   "quote": "creates a VPC with a private address range",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "regex",
    "value": "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)"
   },
   "justify": "a private address range means RFC1918"
  },
  {
   "id": "subnets9",
   "tier": "core",
   "quote": "each with one subnet per Availability Zone",
   "kind": "exists",
   "select": "subnets",
   "min": 9,
   "justify": "three tiers x three AZs"
  },
  {
   "id": "three_azs",
   "tier": "core",
   "quote": "spanning three Availability Zones",
   "kind": "exists",
   "select": "subnets",
   "distinct_path": [
    "AvailabilityZone"
   ],
   "min": 3,
   "justify": "three AZs"
  },
  {
   "id": "distinct_cidrs",
   "tier": "core",
   "quote": "using distinct CIDR blocks carved out of the VPC's range",
   "kind": "exists",
   "select": "subnets",
   "distinct_path": [
    "CidrBlock"
   ],
   "min": 9,
   "justify": "nine subnets, each with its own CIDR"
  },
  {
   "id": "igw",
   "tier": "core",
   "quote": "Attach an Internet Gateway to the VPC",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::EC2::VPCGatewayAttachment"
      ],
      "where": []
     },
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::EC2::VPCGatewayAttachment"
      ],
      "where": []
     },
     "to": "vpc"
    }
   ]
  },
  {
   "id": "igw_route",
   "tier": "core",
   "quote": "a single web-tier route table that has a default route to it",
   "kind": "ref",
   "from": "igw_route",
   "to": "igw",
   "justify": "a default route means 0.0.0.0/0"
  },
  {
   "id": "route_tables",
   "tier": "core",
   "quote": "a single web-tier route table that has a default route to it, shared across all three web subnets",
   "kind": "exists",
   "select": "rt",
   "min": 7,
   "justify": "one shared web route table plus six own tables for app and db subnets"
  },
  {
   "id": "web_rt_shared",
   "tier": "core",
   "quote": "a single web-tier route table that has a default route to it, shared across all three web subnets",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::EC2::SubnetRouteTableAssociation"
    ],
    "where": []
   },
   "distinct_path": [
    "RouteTableId"
   ],
   "min": 7,
   "max": 7,
   "justify": "nine subnet associations use exactly seven route tables: one shared by the three web subnets plus one per application and database subnet"
  },
  {
   "id": "assoc",
   "tier": "detail",
   "quote": "shared across all three web subnets",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::EC2::SubnetRouteTableAssociation"
    ],
    "where": []
   },
   "min": 9,
   "justify": "each of the nine subnets is associated with a route table"
  },
  {
   "id": "nat3",
   "tier": "core",
   "quote": "create a NAT Gateway with its own Elastic IP in each web-tier subnet",
   "kind": "exists",
   "select": "nat",
   "min": 3
  },
  {
   "id": "nat_eip",
   "tier": "core",
   "quote": "with its own Elastic IP",
   "kind": "ref",
   "from": "nat",
   "to": "eip"
  },
  {
   "id": "nat_eips3",
   "tier": "detail",
   "quote": "a NAT Gateway with its own Elastic IP",
   "kind": "exists",
   "select": "nat",
   "distinct_path": [
    "AllocationId"
   ],
   "min": 3,
   "justify": "three NAT gateways, each with a different Elastic IP"
  },
  {
   "id": "nat_subnets",
   "tier": "detail",
   "quote": "in each web-tier subnet",
   "kind": "exists",
   "select": "nat",
   "distinct_path": [
    "SubnetId"
   ],
   "min": 3,
   "justify": "one NAT per web subnet, three AZs"
  },
  {
   "id": "tier_routes",
   "tier": "core",
   "quote": "give each application and database subnet its own route table with a default route through the NAT Gateway",
   "kind": "exists",
   "select": "nat_routes",
   "distinct_path": [
    "RouteTableId"
   ],
   "min": 6,
   "justify": "three app + three db subnets; a default route means 0.0.0.0/0"
  },
  {
   "id": "nat_route_ref",
   "tier": "core",
   "quote": "a default route through the NAT Gateway",
   "kind": "ref",
   "from": "nat_routes",
   "to": "nat",
   "justify": "a default route means 0.0.0.0/0"
  },
  {
   "id": "nat_per_az",
   "tier": "core",
   "quote": "a default route through the NAT Gateway in the corresponding Availability Zone",
   "kind": "exists",
   "select": "nat_routes",
   "distinct_path": [
    "NatGatewayId"
   ],
   "min": 3,
   "justify": "each AZ's subnets route through that AZ's NAT gateway, so all three NAT gateways carry routes"
  },
  {
   "id": "out_vpc",
   "tier": "detail",
   "quote": "Expose the VPC ID",
   "kind": "ref",
   "from": "out",
   "to": "vpc"
  },
  {
   "id": "out_subnets",
   "tier": "detail",
   "quote": "the lists of web, application, and database subnet IDs as stack outputs",
   "kind": "ref",
   "from": "out",
   "to": "subnets"
  },
  {
   "id": "out_subnet_lists",
   "tier": "detail",
   "quote": "the lists of web, application, and database subnet IDs as stack outputs",
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
      "value": "(?i)(fn::join|\\$\\{[^}]+\\}\\s*,)"
     }
    ]
   },
   "min": 3,
   "justify": "three subnet-ID lists, each an Fn::Join or a comma-joined Fn::Sub"
  },
  {
   "id": "out_azs",
   "tier": "detail",
   "quote": "the Availability Zones used",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "out",
     "cond": {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "us-east-1[a-f]"
     }
    },
    {
     "kind": "attr",
     "select": "out",
     "cond": {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "(?i)(AvailabilityZone|Fn::GetAZs)"
     }
    }
   ],
   "justify": "Fn::GetAZs and Fn::Select over it resolve to the adapter's us-east-1 AZ names; a GetAtt Subnet.AvailabilityZone also exposes them"
  },
  {
   "id": "x_dnshost",
   "kind": "attr",
   "select": "vpc",
   "tier": "extra",
   "cond": {
    "path": [
     "EnableDnsHostnames"
    ],
    "op": "truthy"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
