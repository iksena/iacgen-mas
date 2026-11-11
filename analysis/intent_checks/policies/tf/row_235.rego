package intent.tf.row_235

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
  "subnets": {
   "types": [
    "aws_subnet"
   ],
   "where": []
  },
  "pub": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "regex",
     "value": "^10\\.0\\.(12|16|20)\\.0/22$"
    }
   ]
  },
  "pri": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "regex",
     "value": "^10\\.0\\.(0|4|8)\\.0/22$"
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
  },
  "eip": {
   "types": [
    "aws_eip"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "cluster_name_var",
   "tier": "core",
   "quote": "accept a cluster_name variable defaulting to \"benchmark\"",
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
      "op": "eq",
      "value": "cluster_name"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "benchmark"
     }
    ]
   }
  },
  {
   "id": "octets_var",
   "tier": "core",
   "quote": "a vpc_cidr_network_octets string defaulting to \"10.0\"",
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
      "op": "eq",
      "value": "vpc_cidr_network_octets"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "10.0"
     }
    ]
   }
  },
  {
   "id": "default_tags_var",
   "tier": "detail",
   "quote": "a default_tags map defaulting to an empty map",
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
      "op": "eq",
      "value": "default_tags"
     },
     {
      "path": [
       "default"
      ],
      "op": "len_eq",
      "value": 0
     }
    ]
   }
  },
  {
   "id": "ecs_cluster_name",
   "tier": "core",
   "quote": "Provision an ECS cluster named with a \"dit-paas-\" prefix, followed by the cluster name value, and a \"-cluster\" suffix",
   "kind": "exists",
   "select": {
    "types": [
     "aws_ecs_cluster"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "dit-paas-benchmark-cluster"
     }
    ]
   },
   "justify": "prefix + default cluster name 'benchmark' + suffix"
  },
  {
   "id": "vpc_cidr",
   "tier": "core",
   "quote": "a VPC configured with a CIDR block formed from the vpc_cidr_network_octets value followed by \".0.0/16\"",
   "kind": "exists",
   "select": {
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
   "justify": "default octets 10.0 + .0.0/16"
  },
  {
   "id": "vpc_cidr_from_octets_var",
   "tier": "detail",
   "quote": "a CIDR block formed from the vpc_cidr_network_octets value",
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
      "value": "aws_vpc"
     },
     {
      "path": [
       "properties",
       "cidr_block"
      ],
      "op": "regex",
      "value": "\\$\\{.*(var\\.vpc_cidr_network_octets|local\\.)"
     }
    ]
   }
  },
  {
   "id": "vpc_dns_hostnames_off",
   "tier": "detail",
   "quote": "DNS hostnames disabled",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "enable_dns_hostnames"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "enable_dns_hostnames"
      ],
      "op": "absent"
     }
    }
   ]
  },
  {
   "id": "public_subnets",
   "tier": "core",
   "quote": "configure three public subnets using /22 CIDR allocations formed from the vpc_cidr_network_octets value followed by \".12.0/22\", \".16.0/22\", and \".20.0/22\" respectively",
   "kind": "exists",
   "select": "pub",
   "min": 3,
   "justify": "default octets 10.0 + the stated suffixes"
  },
  {
   "id": "private_subnets",
   "tier": "core",
   "quote": "three private subnets using /22 CIDR allocations formed from the same vpc_cidr_network_octets value followed by \".0.0/22\", \".4.0/22\", and \".8.0/22\" respectively",
   "kind": "exists",
   "select": "pri",
   "min": 3,
   "justify": "default octets 10.0 + the stated suffixes"
  },
  {
   "id": "three_azs",
   "tier": "core",
   "quote": "Across the first three availability zones (a, b, and c)",
   "kind": "exists",
   "select": "subnets",
   "distinct_path": [
    "availability_zone"
   ],
   "min": 3,
   "justify": "three AZs means three distinct availability zones"
  },
  {
   "id": "subnet_az_pairing",
   "tier": "detail",
   "quote": "Across the first three availability zones (a, b, and c), configure three public subnets using /22 CIDR allocations formed from the vpc_cidr_network_octets value followed by \".12.0/22\", \".16.0/22\", and \".20.0/22\" respectively",
   "justify": "region default us-east-1 with zones a, b, c, and the stated CIDR suffixes on the default octets 10.0, paired respectively",
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
        "value": "10.0.12.0/22"
       },
       {
        "path": [
         "availability_zone"
        ],
        "op": "eq",
        "value": "us-east-1a"
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
        "value": "10.0.16.0/22"
       },
       {
        "path": [
         "availability_zone"
        ],
        "op": "eq",
        "value": "us-east-1b"
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
        "value": "10.0.20.0/22"
       },
       {
        "path": [
         "availability_zone"
        ],
        "op": "eq",
        "value": "us-east-1c"
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
        "value": "10.0.0.0/22"
       },
       {
        "path": [
         "availability_zone"
        ],
        "op": "eq",
        "value": "us-east-1a"
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
        "value": "10.0.4.0/22"
       },
       {
        "path": [
         "availability_zone"
        ],
        "op": "eq",
        "value": "us-east-1b"
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
        "value": "10.0.8.0/22"
       },
       {
        "path": [
         "availability_zone"
        ],
        "op": "eq",
        "value": "us-east-1c"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "subnets_in_vpc",
   "tier": "detail",
   "quote": "Across the first three availability zones (a, b, and c), configure three public subnets",
   "kind": "ref",
   "from": "subnets",
   "to": "vpc"
  },
  {
   "id": "igw_attached",
   "tier": "core",
   "quote": "Internet access must be handled via an Internet Gateway",
   "kind": "ref",
   "from": "igw",
   "to": "vpc",
   "bidirectional": true
  },
  {
   "id": "igw_named",
   "tier": "detail",
   "quote": "an Internet Gateway named with the cluster name value followed by \"-ig\"",
   "kind": "attr",
   "select": "igw",
   "cond": {
    "path": [
     "tags",
     "Name"
    ],
    "op": "eq",
    "value": "benchmark-ig"
   },
   "justify": "default cluster name benchmark + -ig"
  },
  {
   "id": "public_default_route_igw",
   "tier": "core",
   "quote": "a shared public route table that directs \"0.0.0.0/0\" traffic to the gateway for all public subnets",
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
         "aws_route_table"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "0\\.0\\.0\\.0/0"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)internet_gateway"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "public_subnets_associated",
   "tier": "detail",
   "quote": "a shared public route table that directs \"0.0.0.0/0\" traffic to the gateway for all public subnets",
   "kind": "ref",
   "from": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "to": "pub"
  },
  {
   "id": "route_tables",
   "tier": "core",
   "quote": "pairing each NAT Gateway with a dedicated private route table for its corresponding private subnet",
   "kind": "exists",
   "select": {
    "types": [
     "aws_route_table"
    ],
    "where": []
   },
   "min": 4,
   "justify": "one shared public table plus three dedicated private tables"
  },
  {
   "id": "private_subnets_associated",
   "tier": "detail",
   "quote": "a dedicated private route table for its corresponding private subnet",
   "kind": "ref",
   "from": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "to": "pri"
  },
  {
   "id": "eips",
   "tier": "core",
   "quote": "instantiate an Elastic IP and public NAT Gateway in each of the three public subnets",
   "kind": "exists",
   "select": "eip",
   "min": 3,
   "justify": "one Elastic IP per public subnet"
  },
  {
   "id": "nat_gateways",
   "tier": "core",
   "quote": "instantiate an Elastic IP and public NAT Gateway in each of the three public subnets",
   "kind": "exists",
   "select": "nat",
   "min": 3,
   "justify": "one NAT gateway per public subnet"
  },
  {
   "id": "nat_public",
   "tier": "detail",
   "quote": "public NAT Gateway",
   "kind": "attr",
   "select": "nat",
   "cond": {
    "path": [
     "connectivity_type"
    ],
    "op": "eq",
    "value": "public"
   },
   "quantifier": "all"
  },
  {
   "id": "nat_uses_eip",
   "tier": "core",
   "quote": "instantiate an Elastic IP and public NAT Gateway",
   "kind": "ref",
   "from": "nat",
   "to": "eip"
  },
  {
   "id": "nat_in_public_subnet",
   "tier": "core",
   "quote": "public NAT Gateway in each of the three public subnets",
   "kind": "ref",
   "from": "nat",
   "to": "pub"
  },
  {
   "id": "private_routes_via_nat",
   "tier": "core",
   "quote": "route outbound \"0.0.0.0/0\" traffic",
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
         "aws_route_table"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "0\\.0\\.0\\.0/0"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)nat_gateway"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "eip_domain_vpc",
   "tier": "extra",
   "kind": "attr",
   "select": "eip",
   "cond": {
    "path": [
     "domain"
    ],
    "op": "eq",
    "value": "vpc"
   },
   "quantifier": "all"
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
    "op": "truthy"
   }
  },
  {
   "id": "private_subnets_no_public_ip",
   "tier": "extra",
   "kind": "attr",
   "select": "pri",
   "cond": {
    "path": [
     "map_public_ip_on_launch"
    ],
    "op": "falsy"
   },
   "quantifier": "all"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
