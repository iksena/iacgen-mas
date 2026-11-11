package intent.tf.row_366

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
  "pub": {
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
      "10.0.10.0/24",
      "10.0.20.0/24",
      "10.0.30.0/24"
     ]
    }
   ]
  },
  "priv": {
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
      "10.0.11.0/24",
      "10.0.22.0/24",
      "10.0.33.0/24"
     ]
    }
   ]
  },
  "pub1": {
   "types": [
    "aws_subnet"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "eq",
     "value": "10.0.10.0/24"
    }
   ]
  },
  "six": {
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
      "10.0.10.0/24",
      "10.0.20.0/24",
      "10.0.30.0/24",
      "10.0.11.0/24",
      "10.0.22.0/24",
      "10.0.33.0/24"
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
   "id": "vpc",
   "kind": "exists",
   "tier": "core",
   "select": "vpc",
   "quote": "with CIDR 10.0.0.0/16"
  },
  {
   "id": "vpc_name",
   "kind": "any_of",
   "tier": "core",
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
      "value": "vpc-terraform-testing"
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
      "value": "vpc-terraform-testing"
     }
    }
   ],
   "quote": "named \"vpc-terraform-testing\""
  },
  {
   "id": "dns_hostnames_off",
   "kind": "any_of",
   "tier": "detail",
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
   ],
   "quote": "DNS hostnames disabled"
  },
  {
   "id": "ipv6_off",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "assign_generated_ipv6_cidr_block"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": "vpc",
     "cond": {
      "path": [
       "assign_generated_ipv6_cidr_block"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "IPv6 off by default"
  },
  {
   "id": "pub_subnets",
   "kind": "exists",
   "tier": "core",
   "select": "pub",
   "min": 3,
   "quote": "using the public CIDRs 10.0.10.0/24, 10.0.20.0/24, and 10.0.30.0/24 and the private CIDRs 10.0.11.0/24, 10.0.22.0/24, and 10.0.33.0/24"
  },
  {
   "id": "priv_subnets",
   "kind": "exists",
   "tier": "core",
   "select": "priv",
   "min": 3,
   "quote": "using the public CIDRs 10.0.10.0/24, 10.0.20.0/24, and 10.0.30.0/24 and the private CIDRs 10.0.11.0/24, 10.0.22.0/24, and 10.0.33.0/24"
  },
  {
   "id": "three_azs",
   "kind": "exists",
   "tier": "core",
   "select": "six",
   "min": 3,
   "distinct_path": [
    "availability_zone"
   ],
   "quote": "Spread it across three availability zones in the region"
  },
  {
   "id": "pub_azs",
   "kind": "exists",
   "tier": "detail",
   "select": "pub",
   "min": 3,
   "distinct_path": [
    "availability_zone"
   ],
   "quote": "one public and one private subnet per zone"
  },
  {
   "id": "priv_azs",
   "kind": "exists",
   "tier": "detail",
   "select": "priv",
   "min": 3,
   "distinct_path": [
    "availability_zone"
   ],
   "quote": "one public and one private subnet per zone"
  },
  {
   "id": "tag_app",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc",
       "aws_subnet"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags",
       "*"
      ],
      "op": "eq",
      "value": "terraform"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc",
       "aws_subnet"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags_all",
       "*"
      ],
      "op": "eq",
      "value": "terraform"
     },
     "quantifier": "all"
    }
   ],
   "quote": "tagging subnets and other resources with the app name and environment",
   "justify": "the stated app name \"terraform\" appears as a tag value"
  },
  {
   "id": "tag_env",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc",
       "aws_subnet"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags",
       "*"
      ],
      "op": "eq",
      "value": "testing"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc",
       "aws_subnet"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags_all",
       "*"
      ],
      "op": "eq",
      "value": "testing"
     },
     "quantifier": "all"
    }
   ],
   "quote": "tagging subnets and other resources with the app name and environment",
   "justify": "the stated environment \"testing\" appears as a tag value"
  },
  {
   "id": "igw",
   "kind": "exists",
   "tier": "core",
   "select": "igw",
   "quote": "Attach an internet gateway"
  },
  {
   "id": "igw_vpc",
   "kind": "ref",
   "tier": "detail",
   "from": "igw",
   "to": "vpc",
   "quote": "Attach an internet gateway"
  },
  {
   "id": "public_route",
   "kind": "any_of",
   "tier": "core",
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
      "where": []
     },
     "to": "igw"
    }
   ],
   "quote": "a public route table that sends internet traffic from the public subnets through it",
   "justify": "internet traffic means the 0.0.0.0/0 route"
  },
  {
   "id": "public_assoc",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "to": "pub",
   "quote": "from the public subnets"
  },
  {
   "id": "eip",
   "kind": "exists",
   "tier": "core",
   "select": "eip",
   "quote": "create an Elastic IP"
  },
  {
   "id": "nat",
   "kind": "exists",
   "tier": "core",
   "select": "nat",
   "max": 1,
   "quote": "a single NAT gateway",
   "justify": "a single NAT gateway means exactly one"
  },
  {
   "id": "nat_eip",
   "kind": "ref",
   "tier": "core",
   "from": "nat",
   "to": "eip",
   "quote": "create an Elastic IP and a single NAT gateway"
  },
  {
   "id": "nat_public",
   "kind": "ref",
   "tier": "core",
   "from": "nat",
   "to": "pub1",
   "quote": "in the first public subnet"
  },
  {
   "id": "private_route",
   "kind": "any_of",
   "tier": "core",
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
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table"
      ],
      "where": []
     },
     "to": "nat"
    }
   ],
   "quote": "a shared private route table sends the private subnets' outbound traffic through the NAT",
   "justify": "outbound traffic means the 0.0.0.0/0 route"
  },
  {
   "id": "private_assoc",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "to": "priv",
   "quote": "the private subnets' outbound traffic"
  },
  {
   "id": "private_rt_shared",
   "kind": "exists",
   "tier": "detail",
   "select": {
    "types": [
     "aws_route_table"
    ],
    "where": []
   },
   "min": 1,
   "max": 2,
   "quote": "a shared private route table sends the private subnets' outbound traffic through the NAT",
   "justify": "one public route table plus one shared private route table is at most two route tables (per-zone private tables would exceed it)"
  },
  {
   "id": "db_subnet_group",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_db_subnet_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "db-subnet-terraform-testing"
     }
    ]
   },
   "quote": "create a DB subnet group named \"db-subnet-terraform-testing\""
  },
  {
   "id": "db_subnets",
   "kind": "ref",
   "tier": "core",
   "from": {
    "types": [
     "aws_db_subnet_group"
    ],
    "where": []
   },
   "to": "priv",
   "quote": "spanning the private subnets"
  },
  {
   "id": "out_vpc",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": "vpc",
   "quote": "output the VPC, subnet, default security group, and NAT gateway details"
  },
  {
   "id": "out_subnet",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "quote": "output the VPC, subnet, default security group, and NAT gateway details"
  },
  {
   "id": "out_nat",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": "nat",
   "quote": "output the VPC, subnet, default security group, and NAT gateway details"
  },
  {
   "id": "out_default_sg",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_security_group",
       "aws_default_security_group"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__output__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)default.?(sg|security.?group)"
     }
    }
   ],
   "quote": "output the VPC, subnet, default security group, and NAT gateway details"
  },
  {
   "id": "tgw_optional",
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
      "value": "aws_ec2_transit_gateway_vpc_attachment"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "transit gateway attachment and IPv6 egress routing should be optional and disabled by default"
  },
  {
   "id": "ipv6_egress_optional",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "aws_egress_only_internet_gateway"
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
         "destination_ipv6_cidr_block"
        ],
        "op": "present"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    }
   ],
   "quote": "IPv6 egress routing should be optional and disabled by default"
  },
  {
   "id": "x_priv_no_pubip",
   "kind": "attr",
   "tier": "extra",
   "select": {
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
       "10.0.11.0/24",
       "10.0.22.0/24",
       "10.0.33.0/24"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "map_public_ip_on_launch"
    ],
    "op": "falsy"
   },
   "quantifier": "all"
  },
  {
   "id": "x_nat_igw",
   "kind": "ref",
   "tier": "extra",
   "from": "nat",
   "to": "igw"
  },
  {
   "id": "x_dns_support",
   "kind": "attr",
   "tier": "extra",
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
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "truthy"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
