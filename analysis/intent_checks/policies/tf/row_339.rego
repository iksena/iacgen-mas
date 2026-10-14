# GENERATED from specs/tf/row_339.json by intent_checks/build.py -- do not edit.
package intent.tf.row_339

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
     "value": "10.0.0.0/16"
    }
   ]
  },
  "pub_subnet": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "eq",
     "value": "10.0.1.0/24"
    }
   ]
  },
  "priv_subnet": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "eq",
     "value": "10.0.2.0/24"
    }
   ]
  },
  "both_subnets": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "in",
     "value": [
      "10.0.1.0/24",
      "10.0.2.0/24"
     ]
    }
   ]
  },
  "igw": {
   "types": [
    "aws_internet_gateway"
   ],
   "where": []
  },
  "nat": {
   "types": [
    "aws_nat_gateway"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "exists",
   "tier": "core",
   "quote": "a VPC named \"projectvpc\" with CIDR block \"10.0.0.0/16\"",
   "select": "vpc"
  },
  {
   "id": "vpc_name_tag",
   "kind": "attr",
   "tier": "core",
   "quote": "a VPC named \"projectvpc\"",
   "select": "vpc",
   "cond": {
    "path": [
     "tags",
     "Name"
    ],
    "op": "eq",
    "value": "projectvpc"
   },
   "justify": "a VPC 'named' X carries Name tag X"
  },
  {
   "id": "public_subnet",
   "kind": "ref",
   "tier": "core",
   "quote": "a public subnet \"10.0.1.0/24\"",
   "from": "pub_subnet",
   "to": "vpc"
  },
  {
   "id": "private_subnet",
   "kind": "ref",
   "tier": "core",
   "quote": "a private subnet \"10.0.2.0/24\"",
   "from": "priv_subnet",
   "to": "vpc"
  },
  {
   "id": "subnets_in_different_azs",
   "kind": "exists",
   "tier": "core",
   "quote": "in the first availability zone of us-east-1 and a private subnet \"10.0.2.0/24\" in the second availability zone",
   "select": "both_subnets",
   "distinct_path": [
    "availability_zone"
   ],
   "min": 2,
   "justify": "first vs second AZ -> the two subnets sit in two different AZs"
  },
  {
   "id": "public_subnet_first_az",
   "kind": "attr",
   "tier": "detail",
   "quote": "in the first availability zone of us-east-1",
   "select": "pub_subnet",
   "cond": {
    "path": [
     "availability_zone"
    ],
    "op": "regex",
    "value": "^us-east-1a$"
   },
   "justify": "the first availability zone of us-east-1 is us-east-1a"
  },
  {
   "id": "igw_attached",
   "kind": "ref",
   "tier": "detail",
   "quote": "routes to the internet through an Internet Gateway",
   "from": "igw",
   "to": "vpc"
  },
  {
   "id": "public_default_route_via_igw",
   "kind": "any_of",
   "tier": "core",
   "quote": "the public subnet routes to the internet through an Internet Gateway",
   "justify": "'routes to the internet' -> a 0.0.0.0/0 route targeting the IGW (inline route or aws_route)",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": [
       {
        "path": [
         "route",
         "*",
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": [
       {
        "path": [
         "destination_cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": "igw"
    }
   ]
  },
  {
   "id": "public_subnet_associated",
   "kind": "ref",
   "tier": "detail",
   "quote": "the public subnet routes to the internet",
   "from": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "to": "pub_subnet"
  },
  {
   "id": "nat_with_eip",
   "kind": "ref",
   "tier": "core",
   "quote": "a NAT gateway with an Elastic IP",
   "from": "nat",
   "to": {
    "types": [
     "aws_eip"
    ],
    "where": []
   }
  },
  {
   "id": "nat_in_public_subnet",
   "kind": "ref",
   "tier": "core",
   "quote": "placed in the public subnet",
   "from": "nat",
   "to": "pub_subnet"
  },
  {
   "id": "private_default_route_via_nat",
   "kind": "any_of",
   "tier": "core",
   "quote": "the private subnet routes outbound traffic through a NAT gateway",
   "justify": "'routes outbound traffic' -> a 0.0.0.0/0 route targeting the NAT gateway (inline route or aws_route)",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": [
       {
        "path": [
         "route",
         "*",
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": "nat"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": [
       {
        "path": [
         "destination_cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": "nat"
    }
   ]
  },
  {
   "id": "private_subnet_associated",
   "kind": "ref",
   "tier": "detail",
   "quote": "the private subnet routes outbound traffic",
   "from": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "to": "priv_subnet"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
