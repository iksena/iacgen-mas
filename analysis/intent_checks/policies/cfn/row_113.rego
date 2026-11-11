package intent.cfn.row_113

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
  "subnets": {
   "types": [
    "AWS::EC2::Subnet"
   ],
   "where": []
  },
  "rts": {
   "types": [
    "AWS::EC2::RouteTable"
   ],
   "where": []
  },
  "natroutes": {
   "types": [
    "AWS::EC2::Route"
   ],
   "where": [
    {
     "path": [
      "NatGatewayId"
     ],
     "op": "present"
    }
   ]
  },
  "igwroutes": {
   "types": [
    "AWS::EC2::Route"
   ],
   "where": [
    {
     "path": [
      "GatewayId"
     ],
     "op": "present"
    },
    {
     "path": [
      "DestinationCidrBlock"
     ],
     "op": "eq",
     "value": "0.0.0.0/0"
    }
   ]
  },
  "assoc": {
   "types": [
    "AWS::EC2::SubnetRouteTableAssociation"
   ],
   "where": []
  },
  "att": {
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
   "quote": "The VPC should use a 10.0.0.0/16 CIDR block",
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
   "id": "igw",
   "kind": "exists",
   "tier": "core",
   "quote": "with an internet gateway for public internet access",
   "select": "igw"
  },
  {
   "id": "igw_attached",
   "kind": "any_of",
   "tier": "core",
   "quote": "an internet gateway for public internet access",
   "checks": [
    {
     "kind": "ref",
     "from": "att",
     "to": "igw"
    }
   ]
  },
  {
   "id": "igw_attached_vpc",
   "kind": "ref",
   "tier": "detail",
   "quote": "an internet gateway for public internet access",
   "from": "att",
   "to": "vpc"
  },
  {
   "id": "single_nat",
   "kind": "exists",
   "tier": "core",
   "quote": "a single NAT gateway",
   "select": "nat",
   "min": 1,
   "max": 1,
   "justify": "single means exactly one"
  },
  {
   "id": "nat_eip",
   "kind": "ref",
   "tier": "core",
   "quote": "a single NAT gateway (backed by an Elastic IP)",
   "from": "nat",
   "to": "eip"
  },
  {
   "id": "nine_subnets",
   "kind": "exists",
   "tier": "core",
   "quote": "a public subnet, a private application subnet, and a private database subnet, allocated from nine sequential /24 CIDR blocks",
   "select": "subnets",
   "min": 9,
   "justify": "three AZs x three tiers = nine",
   "max": 9
  },
  {
   "id": "subnet_cidrs",
   "kind": "attr",
   "tier": "core",
   "quote": "nine sequential /24 CIDR blocks within the 10.0.0.0/16 range",
   "select": "subnets",
   "cond": {
    "path": [
     "CidrBlock"
    ],
    "op": "regex",
    "value": "^10\\.0\\.\\d{1,3}\\.0/24$|Fn::Cidr.{0,120}[, ]8\\s*\\]"
   },
   "quantifier": "all",
   "justify": "/24 blocks inside 10.0.0.0/16, as literals or Fn::Cidr with 8 host bits"
  },
  {
   "id": "three_azs",
   "kind": "exists",
   "tier": "core",
   "quote": "three availability zones (the first three available in the region)",
   "select": "subnets",
   "distinct_path": [
    "AvailabilityZone"
   ],
   "min": 3
  },
  {
   "id": "route_tables",
   "kind": "exists",
   "tier": "core",
   "quote": "separate route tables for the public, private application, and private database subnet groups",
   "select": "rts",
   "min": 3,
   "justify": "three subnet groups"
  },
  {
   "id": "public_route_igw",
   "kind": "ref",
   "tier": "core",
   "quote": "routing public subnet traffic to the internet gateway",
   "from": "igwroutes",
   "to": "igw",
   "justify": "public internet access means a default route"
  },
  {
   "id": "private_routes_nat",
   "kind": "exists",
   "tier": "core",
   "quote": "private and database subnet traffic to the NAT gateway",
   "select": "natroutes",
   "min": 2,
   "distinct_path": [
    "RouteTableId"
   ],
   "justify": "private app and database tiers use separate route tables"
  },
  {
   "id": "private_routes_nat_ref",
   "kind": "ref",
   "tier": "detail",
   "quote": "private and database subnet traffic to the NAT gateway",
   "from": "natroutes",
   "to": "nat"
  },
  {
   "id": "private_routes_default",
   "kind": "attr",
   "tier": "detail",
   "quote": "providing outbound internet access for the private tiers",
   "select": "natroutes",
   "cond": {
    "path": [
     "DestinationCidrBlock"
    ],
    "op": "eq",
    "value": "0.0.0.0/0"
   },
   "quantifier": "all",
   "justify": "outbound internet access means a default route"
  },
  {
   "id": "associations",
   "kind": "exists",
   "tier": "detail",
   "quote": "the corresponding subnet-to-route-table associations",
   "select": "assoc",
   "min": 9,
   "justify": "one per subnet"
  },
  {
   "id": "associations_three_tables",
   "kind": "exists",
   "tier": "detail",
   "quote": "the corresponding subnet-to-route-table associations",
   "select": "assoc",
   "distinct_path": [
    "RouteTableId"
   ],
   "min": 3,
   "justify": "public, application and database groups each use their own route table"
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
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
