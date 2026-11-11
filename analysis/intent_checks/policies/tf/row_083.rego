package intent.tf.row_083

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "aws_vpc"
   ],
   "where": []
  },
  "sub": {
   "types": [
    "aws_subnet"
   ],
   "where": []
  },
  "igw": {
   "types": [
    "aws_internet_gateway"
   ],
   "where": []
  },
  "rt": {
   "types": [
    "aws_route_table"
   ],
   "where": []
  },
  "assoc": {
   "types": [
    "aws_route_table_association"
   ],
   "where": []
  },
  "route": {
   "types": [
    "aws_route"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "a multi-tier VPC"
  },
  {
   "id": "vpc_name",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "tags",
     "Name"
    ],
    "op": "eq",
    "value": "ntier primary"
   },
   "tier": "core",
   "quote": "named \"ntier primary\""
  },
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.10.0.0/16"
   },
   "tier": "core",
   "quote": "default CIDR 10.10.0.0/16"
  },
  {
   "id": "subnets7",
   "kind": "exists",
   "select": "sub",
   "tier": "core",
   "min": 7,
   "distinct_path": [
    "cidr_block"
   ],
   "quote": "split into subnets for web, app, database, and management tiers plus a duplicate web/app/database set",
   "justify": "web, app, database, management plus a duplicate web/app/database set is 7 distinct subnets"
  },
  {
   "id": "subnets_in_vpc",
   "kind": "ref",
   "from": "sub",
   "to": "vpc",
   "tier": "detail",
   "quote": "split into subnets for web, app, database, and management tiers"
  },
  {
   "id": "igw",
   "kind": "exists",
   "select": "igw",
   "tier": "core",
   "quote": "an attached internet gateway"
  },
  {
   "id": "igw_vpc",
   "kind": "ref",
   "from": "igw",
   "to": "vpc",
   "tier": "core",
   "quote": "with an attached internet gateway"
  },
  {
   "id": "route_tables",
   "kind": "exists",
   "select": "rt",
   "tier": "core",
   "min": 2,
   "quote": "public and private route tables",
   "justify": "a public and a private route table"
  },
  {
   "id": "route_to_igw",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "rt",
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": "route",
     "to": "igw"
    }
   ],
   "tier": "core",
   "quote": "that both route to the gateway"
  },
  {
   "id": "both_tables_route",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "rt",
     "quantifier": "all",
     "cond": {
      "path": [
       "route"
      ],
      "op": "len_gte",
      "value": 1
     }
    },
    {
     "kind": "exists",
     "select": "route",
     "min": 2
    }
   ],
   "tier": "core",
   "quote": "public and private route tables that both route to the gateway",
   "justify": "both tables carry a route: every route table has an inline route, or there are at least two route resources"
  },
  {
   "id": "assocs",
   "kind": "exists",
   "select": "assoc",
   "tier": "core",
   "min": 7,
   "quote": "putting the web, management, and second web subnets in the public table and the rest in the private table",
   "justify": "all seven subnets are placed in one of the two tables"
  },
  {
   "id": "assoc_subnet",
   "kind": "ref",
   "from": "assoc",
   "to": "sub",
   "tier": "detail",
   "quote": "putting the web, management, and second web subnets in the public table"
  },
  {
   "id": "assoc_rt",
   "kind": "ref",
   "from": "assoc",
   "to": "rt",
   "tier": "detail",
   "quote": "in the public table and the rest in the private table"
  },
  {
   "id": "route_default",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "rt",
     "cond": {
      "path": [
       "route",
       "*",
       "cidr_block"
      ],
      "op": "eq",
      "value": "0.0.0.0/0"
     }
    },
    {
     "kind": "attr",
     "select": "route",
     "cond": {
      "path": [
       "destination_cidr_block"
      ],
      "op": "eq",
      "value": "0.0.0.0/0"
     }
    }
   ],
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
