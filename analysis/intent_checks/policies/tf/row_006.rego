package intent.tf.row_006

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
  "public_subnet": {
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
  "igw": {
   "types": [
    "aws_internet_gateway"
   ],
   "where": []
  },
  "route_table": {
   "types": [
    "aws_route_table"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "exists",
   "tier": "core",
   "select": "vpc",
   "quote": "a VPC with a CIDR block of 10.0.0.0/16"
  },
  {
   "id": "public_subnet_in_vpc",
   "kind": "ref",
   "tier": "core",
   "from": "public_subnet",
   "to": "vpc",
   "quote": "a public subnet with a CIDR block of 10.0.1.0/24"
  },
  {
   "id": "private_subnet_in_vpc",
   "kind": "ref",
   "tier": "core",
   "from": {
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
   "to": "vpc",
   "quote": "a private subnet with a CIDR block of 10.0.2.0/24"
  },
  {
   "id": "igw_attached",
   "kind": "any_of",
   "tier": "core",
   "quote": "attach an internet gateway to the VPC",
   "checks": [
    {
     "kind": "ref",
     "from": "igw",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_internet_gateway_attachment"
      ],
      "where": []
     },
     "to": "vpc"
    }
   ]
  },
  {
   "id": "public_rt_associated",
   "kind": "ref",
   "tier": "core",
   "from": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "to": "public_subnet",
   "quote": "a public route table associated with the public subnet"
  },
  {
   "id": "ipv4_default_route_to_igw",
   "kind": "any_of",
   "tier": "core",
   "quote": "routes all outbound IPv4 (0.0.0.0/0)",
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
   "id": "ipv6_default_route_to_igw",
   "kind": "any_of",
   "tier": "core",
   "quote": "IPv6 (::/0) traffic directly to the internet gateway",
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
         "ipv6_cidr_block"
        ],
        "op": "eq",
        "value": "::/0"
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
         "destination_ipv6_cidr_block"
        ],
        "op": "eq",
        "value": "::/0"
       }
      ]
     },
     "to": "igw"
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
