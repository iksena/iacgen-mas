package intent.tf.row_340

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "vpc_cidr",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.0.0/16"
   },
   "quote": "a development VPC in us-east-1 named \"demo-vpc\" with CIDR \"10.0.0.0/16\""
  },
  {
   "id": "vpc_name",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "demo-vpc"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags_all",
       "Name"
      ],
      "op": "eq",
      "value": "demo-vpc"
     }
    }
   ],
   "quote": "named \"demo-vpc\""
  },
  {
   "id": "private_cidrs",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
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
        "value": "10.0.11.0/24"
       }
      ]
     }
    },
    {
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
        "value": "10.0.12.0/24"
       }
      ]
     }
    },
    {
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
        "value": "10.0.13.0/24"
       }
      ]
     }
    }
   ],
   "quote": "three private subnets (\"10.0.11.0/24\", \"10.0.12.0/24\", \"10.0.13.0/24\")"
  },
  {
   "id": "public_cidrs",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
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
        "value": "10.0.101.0/24"
       }
      ]
     }
    },
    {
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
        "value": "10.0.102.0/24"
       }
      ]
     }
    },
    {
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
        "value": "10.0.103.0/24"
       }
      ]
     }
    }
   ],
   "quote": "three public subnets (\"10.0.101.0/24\", \"10.0.102.0/24\", \"10.0.103.0/24\")"
  },
  {
   "id": "azs_spread",
   "tier": "detail",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "distinct_path": [
    "availability_zone"
   ],
   "min": 3,
   "quote": "each pair placed in the second, third, and fourth available availability zones",
   "justify": "three distinct zones are needed for the second, third and fourth zone"
  },
  {
   "id": "igw",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
   },
   "quote": "Add an internet gateway"
  },
  {
   "id": "igw_vpc",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_internet_gateway_attachment"
      ],
      "where": []
     }
    }
   ],
   "quote": "Add an internet gateway"
  },
  {
   "id": "public_route_igw",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     }
    }
   ],
   "quote": "an internet gateway with a public route table for the public subnets"
  },
  {
   "id": "route_assocs",
   "tier": "detail",
   "kind": "exists",
   "select": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "min": 6,
   "quote": "a public route table for the public subnets",
   "justify": "six subnets each need a route table association"
  },
  {
   "id": "nat_single",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   },
   "min": 1,
   "max": 1,
   "quote": "a single NAT gateway",
   "justify": "single means exactly one"
  },
  {
   "id": "nat_eip",
   "tier": "core",
   "kind": "ref",
   "from": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_eip"
    ],
    "where": []
   },
   "quote": "a single NAT gateway with an Elastic IP"
  },
  {
   "id": "nat_in_first_public",
   "tier": "core",
   "kind": "ref",
   "from": {
    "types": [
     "aws_nat_gateway"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": [
     {
      "path": [
       "cidr_block"
      ],
      "op": "eq",
      "value": "10.0.101.0/24"
     }
    ]
   },
   "quote": "in the first public subnet",
   "justify": "the first listed public subnet is 10.0.101.0/24"
  },
  {
   "id": "private_route_nat",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_nat_gateway"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_nat_gateway"
      ],
      "where": []
     }
    }
   ],
   "quote": "provides outbound internet access through a private route table shared by the private subnets"
  },
  {
   "id": "x_eip_vpc",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_eip"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "domain"
    ],
    "op": "eq",
    "value": "vpc"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
