package intent.tf.row_228

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
  "sub": {
   "types": [
    "aws_subnet"
   ],
   "where": []
  },
  "pres": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "eq",
     "value": "10.16.0.0/24"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "deploy a VPC with CIDR block \"10.16.0.0/16\""
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
    "value": "10.16.0.0/16"
   },
   "tier": "core",
   "quote": "a VPC with CIDR block \"10.16.0.0/16\""
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
    "value": "three-tier-vpc"
   },
   "tier": "core",
   "quote": "a default name variable of \"three-tier-vpc\""
  },
  {
   "id": "param_name",
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
      "value": "three-tier-vpc"
     }
    ]
   },
   "tier": "detail",
   "quote": "a default name variable of \"three-tier-vpc\""
  },
  {
   "id": "param_region",
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
      "value": "us-east-1"
     }
    ]
   },
   "tier": "detail",
   "quote": "defaulting to region \"us-east-1\""
  },
  {
   "id": "sub_pres",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": [
     {
      "path": [
       "cidr_block"
      ],
      "op": "eq",
      "value": "10.16.0.0/24"
     },
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "presentation-subnet"
     }
    ]
   },
   "tier": "core",
   "quote": "a presentation subnet (\"10.16.0.0/24\") named \"presentation-subnet\""
  },
  {
   "id": "sub_app",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": [
     {
      "path": [
       "cidr_block"
      ],
      "op": "eq",
      "value": "10.16.1.0/24"
     },
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "application-subnet"
     }
    ]
   },
   "tier": "core",
   "quote": "an application subnet (\"10.16.1.0/24\") named \"application-subnet\""
  },
  {
   "id": "sub_data",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": [
     {
      "path": [
       "cidr_block"
      ],
      "op": "eq",
      "value": "10.16.2.0/24"
     },
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "data-subnet"
     }
    ]
   },
   "tier": "core",
   "quote": "a data subnet (\"10.16.2.0/24\") named \"data-subnet\""
  },
  {
   "id": "subnets_in_vpc",
   "kind": "ref",
   "from": "sub",
   "to": "vpc",
   "tier": "detail",
   "quote": "three specific subnets"
  },
  {
   "id": "igw",
   "kind": "exists",
   "select": "igw",
   "tier": "core",
   "quote": "connect an internet gateway to the VPC"
  },
  {
   "id": "igw_vpc",
   "kind": "ref",
   "from": "igw",
   "to": "vpc",
   "tier": "core",
   "quote": "connect an internet gateway to the VPC"
  },
  {
   "id": "rt",
   "kind": "exists",
   "select": "rt",
   "tier": "core",
   "quote": "a dedicated route table"
  },
  {
   "id": "assoc_pres",
   "kind": "ref",
   "from": "assoc",
   "to": "pres",
   "tier": "core",
   "quote": "a dedicated route table associated strictly with the presentation subnet"
  },
  {
   "id": "assoc_rt",
   "kind": "ref",
   "from": "assoc",
   "to": "rt",
   "tier": "core",
   "quote": "a dedicated route table associated strictly with the presentation subnet"
  },
  {
   "id": "assoc_only_one",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": "assoc",
     "max": 1
    },
    {
     "kind": "exists",
     "select": "rt",
     "min": 2
    }
   ],
   "tier": "detail",
   "quote": "associated strictly with the presentation subnet",
   "justify": "with a single route table, 'strictly with the presentation subnet' means one association; a second route table (for the other tiers) is allowed"
  },
  {
   "id": "default_route",
   "kind": "any_of",
   "checks": [
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
    },
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
    }
   ],
   "tier": "core",
   "quote": "to direct outbound traffic (\"0.0.0.0/0\") through the internet gateway"
  },
  {
   "id": "vpc_dns_support",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "truthy"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
