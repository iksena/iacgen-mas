package intent.tf.row_119

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "vpc",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "quote": "Provision a main VPC"
  },
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
    "value": "10.14.0.0/16"
   },
   "quote": "a CIDR block of \"10.14.0.0/16\""
  },
  {
   "id": "vpc_tenancy",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "instance_tenancy"
    ],
    "op": "eq",
    "value": "default"
   },
   "quote": "default instance tenancy"
  },
  {
   "id": "vpc_dns_support",
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
     "enable_dns_support"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "enabled DNS support"
  },
  {
   "id": "vpc_dns_hostnames",
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
     "enable_dns_hostnames"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "enabled DNS hostnames"
  },
  {
   "id": "vpc_name",
   "tier": "detail",
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
    "op": "regex",
    "value": "(?i)(tf-eks-jofo.*dev|dev.*tf-eks-jofo)"
   },
   "quote": "named according to the project and environment tags",
   "justify": "the name is built from the Project and Environment values tf-eks-jofo and dev"
  },
  {
   "id": "var_default_tags",
   "tier": "detail",
   "kind": "all_of",
   "quote": "a default_tags map variable containing keys for Project (\"tf-eks-jofo\"), Owner (\"Jovan Zelincevic\"), Compliance (\"Nothing\"), Environment (\"dev\"), and Provider (\"Terraform\")",
   "checks": [
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "\"Project\": \"tf-eks-jofo\""
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "\"Owner\": \"Jovan Zelincevic\""
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "\"Compliance\": \"Nothing\""
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "\"Environment\": \"dev\""
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "\"Provider\": \"Terraform\""
     }
    }
   ]
  },
  {
   "id": "default_tags",
   "tier": "core",
   "kind": "all_of",
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
       "tags_all",
       "Project"
      ],
      "op": "eq",
      "value": "tf-eks-jofo"
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
       "Owner"
      ],
      "op": "eq",
      "value": "Jovan Zelincevic"
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
       "Compliance"
      ],
      "op": "eq",
      "value": "Nothing"
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
       "Environment"
      ],
      "op": "eq",
      "value": "dev"
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
       "Provider"
      ],
      "op": "eq",
      "value": "Terraform"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_subnet"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags_all",
       "Project"
      ],
      "op": "eq",
      "value": "tf-eks-jofo"
     },
     "quantifier": "all"
    }
   ],
   "quote": "apply provider-level default tags using a default_tags map variable containing keys for Project (\"tf-eks-jofo\"), Owner (\"Jovan Zelincevic\"), Compliance (\"Nothing\"), Environment (\"dev\"), and Provider (\"Terraform\")"
  },
  {
   "id": "six_subnets",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "min": 6,
   "quote": "create three public subnets",
   "justify": "three public plus three private subnets"
  },
  {
   "id": "three_azs",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "min": 3,
   "distinct_path": [
    "availability_zone"
   ],
   "quote": "Across the first three available availability zones in the region",
   "justify": "the same first three AZs means exactly three distinct AZ values among the six subnets",
   "max": 3
  },
  {
   "id": "subnet_cidrs",
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
        "value": "10.14.0.0/20"
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
        "value": "10.14.16.0/20"
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
        "value": "10.14.32.0/20"
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
        "value": "10.14.48.0/20"
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
        "value": "10.14.64.0/20"
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
        "value": "10.14.80.0/20"
       }
      ]
     }
    }
   ],
   "quote": "three public subnets with public IP mapping disabled using calculated /20 CIDR blocks starting at index 0",
   "justify": "/20 blocks of 10.14.0.0/16 from index 0, then consecutive blocks for private"
  },
  {
   "id": "subnets_20",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "regex",
    "value": "/20$"
   },
   "quantifier": "all",
   "quote": "calculated /20 CIDR blocks"
  },
  {
   "id": "subnets_in_vpc",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "quote": "create three public subnets"
  },
  {
   "id": "public_ip_off",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "map_public_ip_on_launch"
    ],
    "op": "eq",
    "value": false
   },
   "quantifier": "all",
   "quote": "public IP mapping disabled"
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
   "quote": "an internet gateway route"
  },
  {
   "id": "igw_vpc",
   "tier": "detail",
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
   },
   "quote": "an internet gateway route"
  },
  {
   "id": "public_default_route",
   "tier": "core",
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
     "to": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     }
    }
   ],
   "quote": "configured with an internet gateway route for \"0.0.0.0/0\""
  },
  {
   "id": "route_tables",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_route_table"
    ],
    "where": []
   },
   "min": 2,
   "quote": "a dedicated public route table",
   "justify": "a public and a private route table"
  },
  {
   "id": "associations",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "min": 6,
   "quote": "associated with a dedicated public route table",
   "justify": "each of the six subnets is associated with a route table"
  },
  {
   "id": "assoc_subnets",
   "tier": "detail",
   "kind": "ref",
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
   },
   "quote": "associated with a dedicated public route table"
  },
  {
   "id": "assoc_rt",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_route_table"
    ],
    "where": []
   },
   "quote": "associated with a dedicated public route table"
  },
  {
   "id": "nat",
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
   "quote": "with an allocated Elastic IP"
  },
  {
   "id": "nat_subnet",
   "tier": "detail",
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
    "where": []
   },
   "quote": "deployed in the first public subnet"
  },
  {
   "id": "private_nat_route",
   "tier": "core",
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
     "to": {
      "types": [
       "aws_nat_gateway"
      ],
      "where": []
     }
    }
   ],
   "quote": "routing \"0.0.0.0/0\" traffic through a single NAT gateway"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
