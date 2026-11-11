package intent.tf.row_127

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
  "d_subnet": {
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
    }
   ]
  },
  "d_pub_subnet": {
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
      "properties",
      "map_public_ip_on_launch"
     ],
     "op": "eq",
     "value": true
    }
   ]
  },
  "d_igw": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_internet_gateway"
    }
   ]
  },
  "d_sg": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_security_group"
    }
   ]
  },
  "d_rt": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_route_table"
    }
   ]
  },
  "d_assoc": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_route_table_association"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc_exists",
   "kind": "exists",
   "tier": "core",
   "select": "vpc",
   "quote": "highly dynamic VPC network infrastructure"
  },
  {
   "id": "vpc_cidr",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "cidr_block"
      ],
      "op": "eq",
      "value": "10.0.0.0/16"
     }
    }
   ],
   "quote": "base VPC CIDR block defaulting to \"10.0.0.0/16\""
  },
  {
   "id": "az_data",
   "kind": "exists",
   "tier": "core",
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
      "value": "data.aws_availability_zones"
     }
    ]
   },
   "quote": "across a specified number of available availability zones in the region"
  },
  {
   "id": "az_count_default",
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
      "value": 2
     },
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)(az|zone)"
     }
    ]
   },
   "quote": "which defaults to 2",
   "justify": "the AZ-count variable defaults to the stated 2"
  },
  {
   "id": "subnets_gated",
   "kind": "exists",
   "tier": "core",
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
   },
   "min": 1,
   "quote": "configurable toggles for enabling public, NAT, and private subnet tiers"
  },
  {
   "id": "tier_toggles",
   "kind": "exists",
   "tier": "detail",
   "quote": "configurable toggles for enabling public, NAT, and private subnet tiers",
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
   },
   "min": 3,
   "justify": "one boolean toggle per named tier (public, NAT, private)"
  },
  {
   "id": "subnet_tiers",
   "kind": "exists",
   "tier": "detail",
   "select": "d_subnet",
   "min": 3,
   "quote": "configurable toggles for enabling public, NAT, and private subnet tiers",
   "justify": "the prompt names three tiers (public, NAT, private), each provisioning its own subnet set"
  },
  {
   "id": "subnet_cidr_calc",
   "kind": "attr",
   "tier": "detail",
   "select": "d_subnet",
   "quantifier": "all",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "cidrsubnet|local\\.[A-Za-z0-9_]*(?i:cidr)"
   },
   "quote": "Subnet CIDRs across all enabled tiers must be calculated dynamically"
  },
  {
   "id": "public_subnet_autoip",
   "kind": "exists",
   "tier": "core",
   "select": "d_pub_subnet",
   "quote": "auto-assigning public IP subnets"
  },
  {
   "id": "igw",
   "kind": "exists",
   "tier": "core",
   "select": "d_igw",
   "quote": "an Internet Gateway"
  },
  {
   "id": "igw_vpc",
   "kind": "ref",
   "tier": "detail",
   "from": "d_igw",
   "to": "vpc",
   "quote": "an Internet Gateway"
  },
  {
   "id": "public_sg",
   "kind": "exists",
   "tier": "core",
   "select": "d_sg",
   "quote": "a dedicated security group"
  },
  {
   "id": "sg_egress_all",
   "kind": "any_of",
   "tier": "core",
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
        "value": "aws_security_group_rule"
       },
       {
        "path": [
         "properties",
         "type"
        ],
        "op": "eq",
        "value": "egress"
       },
       {
        "path": [
         "properties",
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "properties",
         "protocol"
        ],
        "op": "in",
        "value": [
         "-1",
         "all"
        ]
       }
      ]
     }
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
        "op": "eq",
        "value": "aws_vpc_security_group_egress_rule"
       },
       {
        "path": [
         "properties",
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "properties",
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "-1",
         "all"
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "d_sg",
     "cond": {
      "path": [
       "properties",
       "egress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "-1",
         "all"
        ]
       }
      ]
     }
    }
   ],
   "quote": "an egress rule allowing all traffic across all protocols to 0.0.0.0/0",
   "justify": "all protocols means protocol -1 / all"
  },
  {
   "id": "public_rt",
   "kind": "exists",
   "tier": "core",
   "select": "d_rt",
   "quote": "a public route table"
  },
  {
   "id": "route_internet",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_route_table"
       },
       {
        "path": [
         "properties",
         "route",
         "*",
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": "d_igw"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_route"
       },
       {
        "path": [
         "properties",
         "destination_cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "to": "d_igw"
    }
   ],
   "quote": "a public route table containing an internet route to 0.0.0.0/0 via the Internet Gateway"
  },
  {
   "id": "rt_assoc_subnets",
   "kind": "ref",
   "tier": "core",
   "from": "d_assoc",
   "to": "d_subnet",
   "quote": "attached to all public subnets"
  },
  {
   "id": "rt_assoc_rt",
   "kind": "ref",
   "tier": "detail",
   "from": "d_assoc",
   "to": "d_rt",
   "quote": "attached to all public subnets"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
