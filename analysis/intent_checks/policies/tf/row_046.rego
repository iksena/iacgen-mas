package intent.tf.row_046

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "aws_vpc"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "eq",
     "value": "192.168.0.0/16"
    }
   ]
  },
  "subnets": {
   "types": [
    "aws_subnet"
   ],
   "where": []
  },
  "web": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "tags",
      "*"
     ],
     "op": "regex",
     "value": "(?i)(^|[-_ ])web($|[-_ ])"
    }
   ]
  },
  "app": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "tags",
      "*"
     ],
     "op": "regex",
     "value": "(?i)(^|[-_ ])app($|[-_ ])"
    }
   ]
  },
  "db": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "tags",
      "*"
     ],
     "op": "regex",
     "value": "(?i)(^|[-_ ])db($|[-_ ])"
    }
   ]
  },
  "mgmt": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "tags",
      "*"
     ],
     "op": "regex",
     "value": "(?i)(^|[-_ ])mgmt($|[-_ ])"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "tier": "core",
   "quote": "custom VPC with a default CIDR block of 192.168.0.0/16",
   "kind": "exists",
   "select": "vpc"
  },
  {
   "id": "four_subnets",
   "tier": "core",
   "quote": "four subnets",
   "kind": "exists",
   "select": "subnets",
   "min": 4,
   "max": 4
  },
  {
   "id": "subnets_in_vpc",
   "tier": "detail",
   "quote": "a custom VPC with a default CIDR block of 192.168.0.0/16 and four subnets",
   "kind": "ref",
   "from": "subnets",
   "to": "vpc"
  },
  {
   "id": "tag_web",
   "tier": "core",
   "quote": "tagged web, app, db, and mgmt",
   "kind": "exists",
   "select": "web"
  },
  {
   "id": "tag_app",
   "tier": "core",
   "quote": "tagged web, app, db, and mgmt",
   "kind": "exists",
   "select": "app"
  },
  {
   "id": "tag_db",
   "tier": "core",
   "quote": "tagged web, app, db, and mgmt",
   "kind": "exists",
   "select": "db"
  },
  {
   "id": "tag_mgmt",
   "tier": "core",
   "quote": "tagged web, app, db, and mgmt",
   "kind": "exists",
   "select": "mgmt"
  },
  {
   "id": "subnets_24",
   "tier": "core",
   "quote": "each a /24",
   "kind": "attr",
   "select": "subnets",
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "regex",
    "value": "/24$"
   },
   "quantifier": "all"
  },
  {
   "id": "subnets_inside_vpc_range",
   "tier": "detail",
   "quote": "carved sequentially out of the VPC range",
   "kind": "attr",
   "select": "subnets",
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "regex",
    "value": "^192\\.168\\."
   },
   "quantifier": "all",
   "justify": "carved out of the VPC range 192.168.0.0/16 means 192.168.x.x"
  },
  {
   "id": "subnets_distinct_cidrs",
   "tier": "detail",
   "quote": "carved sequentially out of the VPC range",
   "kind": "exists",
   "select": "subnets",
   "min": 4,
   "distinct_path": [
    "cidr_block"
   ],
   "justify": "four sequential non-overlapping /24 blocks"
  },
  {
   "id": "three_azs",
   "tier": "core",
   "quote": "spread across three availability zones",
   "kind": "exists",
   "select": "subnets",
   "min": 3,
   "distinct_path": [
    "availability_zone"
   ],
   "justify": "three availability zones",
   "max": 3
  },
  {
   "id": "web_mgmt_share_az",
   "tier": "detail",
   "quote": "the web and mgmt subnets share the first zone",
   "kind": "join",
   "from": "web",
   "from_path": [
    "availability_zone"
   ],
   "to": "mgmt",
   "to_path": [
    "availability_zone"
   ]
  },
  {
   "id": "vpc_dns_support",
   "tier": "extra",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "eq",
    "value": true
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
