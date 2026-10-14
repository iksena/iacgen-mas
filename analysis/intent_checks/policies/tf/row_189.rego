# GENERATED from specs/tf/row_189.json by intent_checks/build.py -- do not edit.
package intent.tf.row_189

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
     "value": "10.0.0.0/18"
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
   "select": "vpc",
   "tier": "core",
   "quote": "The VPC should use a CIDR block of 10.0.0.0/18"
  },
  {
   "id": "subnets_in_vpc",
   "kind": "ref",
   "tier": "core",
   "from": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "to": "vpc",
   "quote": "including public and private subnets"
  },
  {
   "id": "public_and_private_subnets",
   "kind": "exists",
   "tier": "detail",
   "min": 2,
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "including public and private subnets",
   "justify": "'public and private subnets' -> at least one of each (>=2)"
  },
  {
   "id": "internet_gateway",
   "kind": "any_of",
   "tier": "core",
   "quote": "an internet gateway",
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
   "id": "nat_gateway",
   "kind": "ref",
   "tier": "core",
   "from": "nat",
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "a NAT gateway"
  },
  {
   "id": "nat_eip",
   "kind": "ref",
   "tier": "detail",
   "from": "nat",
   "to": {
    "types": [
     "aws_eip"
    ],
    "where": []
   },
   "quote": "All necessary dependencies should be created as part of the stack."
  },
  {
   "id": "public_route_to_igw",
   "kind": "ref",
   "tier": "core",
   "quote": "route tables",
   "from": {
    "types": [
     "aws_route",
     "aws_route_table"
    ],
    "where": []
   },
   "to": "igw"
  },
  {
   "id": "private_route_to_nat",
   "kind": "any_of",
   "tier": "detail",
   "quote": "route tables",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route",
       "aws_route_table"
      ],
      "where": []
     },
     "to": "nat"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_route",
         "aws_route_table"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "aws_nat_gateway"
       }
      ]
     }
    }
   ],
   "justify": "NAT routes are often dynamic/count-gated blocks; the declared route text is read"
  },
  {
   "id": "route_table_associations",
   "kind": "ref",
   "tier": "detail",
   "quote": "route tables",
   "from": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   }
  },
  {
   "id": "network_acls",
   "kind": "any_of",
   "tier": "core",
   "quote": "network ACLs",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_network_acl"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_subnet"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_network_acl_association"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_network_acl"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "subnets_span_all_azs",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_subnet"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_availability_zones"
      ],
      "where": []
     }
    },
    {
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
     "min": 6
    }
   ],
   "quote": "The number of availability zones should be configurable, defaulting to all available AZs in the region.",
   "justify": "'defaulting to all available AZs in the region' -> subnets driven by the availability-zones data source, or spanning all 6 us-east-1 AZs (region stated)"
  },
  {
   "id": "toggle_subnets_and_nat",
   "kind": "all_of",
   "tier": "detail",
   "quote": "allow toggling the creation of public subnets, private subnets, and the NAT gateway via boolean variables",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_nat_gateway"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "min": 2,
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_subnet"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "min": 3,
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
         true,
         false
        ]
       }
      ]
     }
    }
   ],
   "justify": "three boolean toggles stated (public subnets, private subnets, NAT gateway); public and private subnets are both gated"
  },
  {
   "id": "vpc_name_default",
   "kind": "any_of",
   "tier": "detail",
   "quote": "The VPC name should be configurable with a default of \"benchmark-vpc\"",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "benchmark-vpc"
     }
    },
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "tags_all",
       "Name"
      ],
      "op": "eq",
      "value": "benchmark-vpc"
     }
    }
   ]
  },
  {
   "id": "vpc_name_variable",
   "kind": "exists",
   "tier": "detail",
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
      "value": "benchmark-vpc"
     }
    ]
   },
   "quote": "The VPC name should be configurable with a default of \"benchmark-vpc\""
  },
  {
   "id": "region_us_east_1",
   "kind": "any_of",
   "tier": "detail",
   "quote": "The AWS region should default to us-east-1.",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "region"
      ],
      "op": "eq",
      "value": "us-east-1"
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
         "name"
        ],
        "op": "regex",
        "value": "(?i)region"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "us-east-1"
       }
      ]
     }
    }
   ],
   "justify": "\"should default to us-east-1\" -> a region variable defaulting to it"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
