package intent.tf.row_062

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "vpc_named",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "ansible-vpc"
     }
    ]
   },
   "quote": "custom VPC infrastructure named \"ansible-vpc\""
  },
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "ansible-vpc"
     }
    ]
   },
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.0.0/16"
   },
   "quote": "with a CIDR block of 10.0.0.0/16"
  },
  {
   "id": "vpc_dns_support",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "ansible-vpc"
     }
    ]
   },
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "truthy"
   },
   "quote": "enabling both DNS support and DNS hostnames"
  },
  {
   "id": "vpc_dns_hostnames",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "ansible-vpc"
     }
    ]
   },
   "cond": {
    "path": [
     "enable_dns_hostnames"
    ],
    "op": "truthy"
   },
   "quote": "enabling both DNS support and DNS hostnames"
  },
  {
   "id": "private_subnet_cidr",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "ansible-vpc-private-subnet-1"
     }
    ]
   },
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.0.0/24"
   },
   "quote": "a private subnet with a CIDR block of 10.0.0.0/24 named \"ansible-vpc-private-subnet-1\""
  },
  {
   "id": "public_subnet_cidr",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "ansible-vpc-public-subnet-1"
     }
    ]
   },
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.1.0/24"
   },
   "quote": "a public subnet with a CIDR block of 10.0.1.0/24 named \"ansible-vpc-public-subnet-1\""
  },
  {
   "id": "public_subnet_no_auto_ip",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc-public-subnet-1"
       }
      ]
     },
     "cond": {
      "path": [
       "map_public_ip_on_launch"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc-public-subnet-1"
       }
      ]
     },
     "cond": {
      "path": [
       "map_public_ip_on_launch"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "that does not auto-assign public IP addresses on launch"
  },
  {
   "id": "subnets_in_vpc",
   "kind": "all_of",
   "tier": "detail",
   "quote": "The network layout must feature a private subnet",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc-private-subnet-1"
       }
      ]
     },
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc-public-subnet-1"
       }
      ]
     },
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "igw_named",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "ansible-vpc-igw"
     }
    ]
   },
   "quote": "provision an Internet Gateway named \"ansible-vpc-igw\""
  },
  {
   "id": "igw_in_vpc",
   "kind": "any_of",
   "tier": "detail",
   "quote": "provision an Internet Gateway named \"ansible-vpc-igw\"",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc-igw"
       }
      ]
     },
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_internet_gateway_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc-igw"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "public_rt_named",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_route_table"
    ],
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "ansible-vpc-public-rt"
     }
    ]
   },
   "quote": "a public route table named \"ansible-vpc-public-rt\""
  },
  {
   "id": "public_default_route",
   "kind": "any_of",
   "tier": "core",
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
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc-public-rt"
       },
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
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc-igw"
       }
      ]
     }
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
     "to": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc-igw"
       }
      ]
     }
    }
   ],
   "quote": "with a default route sending 0.0.0.0/0 traffic to the Internet Gateway"
  },
  {
   "id": "public_rt_associated",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
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
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc-public-subnet-1"
       }
      ]
     }
    }
   ],
   "quote": "attached to the public subnet"
  },
  {
   "id": "public_assoc_rt",
   "kind": "ref",
   "tier": "detail",
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
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "ansible-vpc-public-rt"
     }
    ]
   },
   "quote": "attached to the public subnet"
  },
  {
   "id": "private_rt_named",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_route_table"
    ],
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "ansible-vpc-private-rt"
     }
    ]
   },
   "quote": "a private route table named \"ansible-vpc-private-rt\""
  },
  {
   "id": "private_rt_no_internet",
   "kind": "any_of",
   "tier": "core",
   "quote": "without outbound internet routes",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_route_table"
      ],
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc-private-rt"
       }
      ]
     },
     "cond": {
      "path": [
       "route"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_route_table"
      ],
      "where": [
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "ansible-vpc-private-rt"
       }
      ]
     },
     "cond": {
      "path": [
       "route"
      ],
      "op": "len_eq",
      "value": 0
     }
    }
   ]
  },
  {
   "id": "private_assoc_subnet",
   "kind": "ref",
   "tier": "core",
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
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "ansible-vpc-private-subnet-1"
     }
    ]
   },
   "quote": "attached to the private subnet"
  },
  {
   "id": "private_assoc_rt",
   "kind": "ref",
   "tier": "detail",
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
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "ansible-vpc-private-rt"
     }
    ]
   },
   "quote": "attached to the private subnet"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
