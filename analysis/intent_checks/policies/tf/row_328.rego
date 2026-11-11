package intent.tf.row_328

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
  "decl_vpc": {
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
    }
   ]
  },
  "decl_igw": {
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
  "decl_nat": {
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
    }
   ]
  },
  "decl_subnet": {
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
  }
 },
 "checks": [
  {
   "id": "vpc_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "provisions a single VPC",
   "select": "vpc",
   "min": 1,
   "max": 1,
   "justify": "\"a single VPC\" means exactly one"
  },
  {
   "id": "vpc_name_main",
   "kind": "any_of",
   "tier": "core",
   "quote": "named \"main\"",
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
      "value": "main"
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
      "value": "main"
     }
    }
   ]
  },
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "tier": "core",
   "quote": "the CIDR block 10.0.0.0/16",
   "select": "vpc",
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.0.0/16"
   }
  },
  {
   "id": "vpc_tenancy_default",
   "kind": "attr",
   "tier": "core",
   "quote": "default instance tenancy",
   "select": "vpc",
   "cond": {
    "path": [
     "instance_tenancy"
    ],
    "op": "eq",
    "value": "default"
   }
  },
  {
   "id": "vpc_dns_support",
   "kind": "attr",
   "tier": "core",
   "quote": "DNS support enabled",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "vpc_dns_hostnames_off",
   "kind": "attr",
   "tier": "core",
   "quote": "DNS hostnames disabled",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_hostnames"
    ],
    "op": "none_eq",
    "value": true
   }
  },
  {
   "id": "vpc_no_ipv6",
   "kind": "attr",
   "tier": "core",
   "quote": "no IPv6 CIDR block",
   "select": "vpc",
   "cond": {
    "path": [
     "assign_generated_ipv6_cidr_block"
    ],
    "op": "none_eq",
    "value": true
   }
  },
  {
   "id": "subnets_declared",
   "kind": "all_of",
   "tier": "core",
   "quote": "accept an optional list of subnet definitions",
   "checks": [
    {
     "kind": "exists",
     "select": "decl_subnet"
    },
    {
     "kind": "attr",
     "select": "decl_subnet",
     "cond": {
      "path": [
       "properties",
       "cidr_block"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "decl_subnet",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)availability_zone"
     }
    }
   ]
  },
  {
   "id": "intra_class_supported",
   "kind": "attr",
   "tier": "detail",
   "quote": "class (public, private, or intra)",
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
       "aws_subnet",
       "aws_route_table",
       "aws_route_table_association"
      ]
     }
    ]
   },
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)intra"
   }
  },
  {
   "id": "db_subnet_group_declared",
   "kind": "exists",
   "tier": "detail",
   "quote": "optionally register them in database and ElastiCache subnet groups",
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
      "value": "aws_db_subnet_group"
     }
    ]
   }
  },
  {
   "id": "elasticache_subnet_group_declared",
   "kind": "exists",
   "tier": "detail",
   "quote": "optionally register them in database and ElastiCache subnet groups",
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
      "value": "aws_elasticache_subnet_group"
     }
    ]
   }
  },
  {
   "id": "igw_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "public subnets routed through an internet gateway",
   "select": "decl_igw"
  },
  {
   "id": "public_route_to_igw",
   "kind": "any_of",
   "tier": "core",
   "quote": "public subnets routed through an internet gateway",
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
        "value": "aws_route"
       }
      ]
     },
     "to": "decl_igw"
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
        "value": "aws_route_table"
       }
      ]
     },
     "to": "decl_igw"
    }
   ]
  },
  {
   "id": "nat_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "private subnets routed through NAT gateways",
   "select": "decl_nat"
  },
  {
   "id": "private_route_to_nat",
   "kind": "any_of",
   "tier": "core",
   "quote": "private subnets routed through NAT gateways",
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
        "value": "aws_route"
       }
      ]
     },
     "to": "decl_nat"
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
        "value": "aws_route_table"
       }
      ]
     },
     "to": "decl_nat"
    }
   ]
  },
  {
   "id": "route_tables_declared",
   "kind": "exists",
   "tier": "detail",
   "quote": "public subnets routed through an internet gateway and private subnets routed through NAT gateways",
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
     }
    ]
   }
  },
  {
   "id": "nothing_but_vpc_by_default",
   "kind": "exists",
   "tier": "core",
   "quote": "no subnets, gateways, route tables, or subnet groups should be created unless subnet definitions are supplied",
   "justify": "with the empty default subnet list the only resource of these types is the single VPC",
   "select": {
    "types": [
     "aws_vpc",
     "aws_subnet",
     "aws_internet_gateway",
     "aws_egress_only_internet_gateway",
     "aws_nat_gateway",
     "aws_eip",
     "aws_route_table",
     "aws_route",
     "aws_route_table_association",
     "aws_db_subnet_group",
     "aws_elasticache_subnet_group"
    ],
    "where": []
   },
   "min": 1,
   "max": 1
  },
  {
   "id": "module_toggle_gates_vpc",
   "kind": "attr",
   "tier": "core",
   "quote": "a module-level toggle should allow disabling all resource creation",
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
   "cond": {
    "path": [
     "gate"
    ],
    "op": "regex",
    "value": "var\\."
   },
   "justify": "a module-level toggle is a variable that gates the resource's count/for_each"
  },
  {
   "id": "x_nat_eip",
   "kind": "exists",
   "tier": "extra",
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
     }
    ]
   }
  },
  {
   "id": "extra_type_aws_route_table_association",
   "kind": "exists",
   "tier": "extra",
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
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
