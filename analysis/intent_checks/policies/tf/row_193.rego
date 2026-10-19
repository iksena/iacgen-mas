package intent.tf.row_193

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "vpc": {
   "types": [
    "aws_vpc"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc_cidr_default",
   "kind": "attr",
   "select": "vpc",
   "tier": "core",
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.0.0/16"
   },
   "quote": "a configurable VPC CIDR block defaulting to \"10.0.0.0/16\""
  },
  {
   "id": "vpc_dns_enabled",
   "kind": "all_of",
   "tier": "core",
   "quote": "options to enable DNS hostnames and DNS support (both defaulting to true)",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "enable_dns_hostnames"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "enable_dns_support"
      ],
      "op": "truthy"
     }
    }
   ]
  },
  {
   "id": "vpc_creation_toggle",
   "kind": "exists",
   "tier": "detail",
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
      "value": "aws_vpc"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "a main creation toggle defaulting to true"
  },
  {
   "id": "subnet_tiers_declared",
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
   "quote": "Subnet tiers must support lists of CIDR blocks for public, private, and isolated intra subnets"
  },
  {
   "id": "subnet_az_names_or_ids",
   "kind": "any_of",
   "tier": "detail",
   "quote": "mapped across a provided list of availability zone names or IDs",
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
        "value": "aws_subnet"
       },
       {
        "path": [
         "properties",
         "availability_zone"
        ],
        "op": "present"
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
        "value": "aws_subnet"
       },
       {
        "path": [
         "properties",
         "availability_zone_id"
        ],
        "op": "present"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "tier_suffixes",
   "kind": "all_of",
   "tier": "detail",
   "quote": "configurable tier suffixes (\"public\", \"private\", \"intra\")",
   "checks": [
    {
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
        "value": "public"
       }
      ]
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
         "default"
        ],
        "op": "eq",
        "value": "private"
       }
      ]
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
         "default"
        ],
        "op": "eq",
        "value": "intra"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "map_public_ip_setting",
   "kind": "exists",
   "tier": "detail",
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
       "properties",
       "map_public_ip_on_launch"
      ],
      "op": "present"
     }
    ]
   },
   "quote": "support map public IP on launch toggles (defaulting to false)"
  },
  {
   "id": "igw_conditional",
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
      "value": "aws_internet_gateway"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "conditionally provision an Internet Gateway based on a creation toggle"
  },
  {
   "id": "public_default_route_to_igw",
   "kind": "any_of",
   "tier": "core",
   "quote": "attached to a dedicated public route table with a default 0.0.0.0/0 route",
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
        "value": "aws_route"
       },
       {
        "path": [
         "properties",
         "destination_cidr_block"
        ],
        "op": "contains",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "properties",
         "gateway_id"
        ],
        "op": "contains",
        "value": "aws_internet_gateway"
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
        "value": "aws_route_table"
       },
       {
        "path": [
         "properties",
         "route"
        ],
        "op": "contains",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "properties",
         "route"
        ],
        "op": "contains",
        "value": "aws_internet_gateway"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "nat_eips",
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
      "value": "aws_eip"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "the module must create Elastic IPs and NAT Gateways"
  },
  {
   "id": "nat_gateways",
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
      "value": "aws_nat_gateway"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "the module must create Elastic IPs and NAT Gateways"
  },
  {
   "id": "private_nat_routes",
   "kind": "any_of",
   "tier": "core",
   "quote": "establishing individual private route tables with 0.0.0.0/0 NAT routes",
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
        "value": "aws_route"
       },
       {
        "path": [
         "properties",
         "destination_cidr_block"
        ],
        "op": "contains",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "properties",
         "nat_gateway_id"
        ],
        "op": "contains",
        "value": "aws_nat_gateway"
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
        "value": "aws_route_table"
       },
       {
        "path": [
         "properties",
         "route"
        ],
        "op": "contains",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "properties",
         "route"
        ],
        "op": "contains",
        "value": "aws_nat_gateway"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "subnet_route_associations",
   "kind": "exists",
   "tier": "detail",
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
      "value": "aws_route_table_association"
     }
    ]
   },
   "quote": "associated with each private subnet"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
