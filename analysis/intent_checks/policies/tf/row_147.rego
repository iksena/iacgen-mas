package intent.tf.row_147

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
  "allow": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "allow_tls"
    }
   ]
  },
  "pvt": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "pvt-seg"
    }
   ]
  },
  "pubsub": {
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
      "10.0.1.0/24",
      "10.0.2.0/24"
     ]
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "exists",
   "tier": "core",
   "select": "vpc",
   "quote": "default CIDR block of \"10.0.0.0/16\""
  },
  {
   "id": "vpc_name",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
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
        "value": "project-vpc"
       },
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_vpc"
      ],
      "where": [
       {
        "path": [
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "project-vpc"
       },
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     }
    }
   ],
   "quote": "named \"project-vpc\""
  },
  {
   "id": "subnet_pub_sub_1",
   "kind": "any_of",
   "tier": "core",
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
        "value": "10.0.1.0/24"
       },
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "pub-sub-1"
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
        "value": "10.0.1.0/24"
       },
       {
        "path": [
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "pub-sub-1"
       }
      ]
     }
    }
   ],
   "quote": "\"pub-sub-1\" with default CIDR \"10.0.1.0/24\""
  },
  {
   "id": "subnet_pub_sub_2",
   "kind": "any_of",
   "tier": "core",
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
        "value": "10.0.2.0/24"
       },
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "pub-sub-2"
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
        "value": "10.0.2.0/24"
       },
       {
        "path": [
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "pub-sub-2"
       }
      ]
     }
    }
   ],
   "quote": "\"pub-sub-2\" with default CIDR \"10.0.2.0/24\""
  },
  {
   "id": "subnet_pvt_sub_1",
   "kind": "any_of",
   "tier": "core",
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
        "value": "10.0.3.0/24"
       },
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "pvt-sub-1"
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
        "value": "10.0.3.0/24"
       },
       {
        "path": [
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "pvt-sub-1"
       }
      ]
     }
    }
   ],
   "quote": "\"pvt-sub-1\" with default CIDR \"10.0.3.0/24\""
  },
  {
   "id": "subnet_pvt_sub_2",
   "kind": "any_of",
   "tier": "core",
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
        "value": "10.0.4.0/24"
       },
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "pvt-sub-2"
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
        "value": "10.0.4.0/24"
       },
       {
        "path": [
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "pvt-sub-2"
       }
      ]
     }
    }
   ],
   "quote": "\"pvt-sub-2\" with default CIDR \"10.0.4.0/24\""
  },
  {
   "id": "subnet_azs",
   "kind": "exists",
   "tier": "core",
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
       "10.0.1.0/24",
       "10.0.2.0/24",
       "10.0.3.0/24",
       "10.0.4.0/24"
      ]
     }
    ]
   },
   "quote": "across two availability zones",
   "min": 2,
   "distinct_path": [
    "availability_zone"
   ],
   "justify": "two availability zones means two distinct zones"
  },
  {
   "id": "igw_named",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
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
        "value": "T-igw"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": [
       {
        "path": [
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "T-igw"
       }
      ]
     }
    }
   ],
   "quote": "An Internet Gateway named \"T-igw\""
  },
  {
   "id": "pub_rt1",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
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
        "value": "RT_PUBRT-1"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_route_table"
      ],
      "where": [
       {
        "path": [
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "RT_PUBRT-1"
       }
      ]
     }
    }
   ],
   "quote": "two dedicated public route tables (\"RT_PUBRT-1\" and \"RT_PUBRT-2\")"
  },
  {
   "id": "pub_rt1_default_route",
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
        "value": "RT_PUBRT-1"
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
     "to": "igw"
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
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "RT_PUBRT-1"
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
   ],
   "quote": "routing default outbound traffic (\"0.0.0.0/0\") for each public subnet"
  },
  {
   "id": "pub_rt2",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
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
        "value": "RT_PUBRT-2"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_route_table"
      ],
      "where": [
       {
        "path": [
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "RT_PUBRT-2"
       }
      ]
     }
    }
   ],
   "quote": "two dedicated public route tables (\"RT_PUBRT-1\" and \"RT_PUBRT-2\")"
  },
  {
   "id": "pub_rt2_default_route",
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
        "value": "RT_PUBRT-2"
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
     "to": "igw"
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
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "RT_PUBRT-2"
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
   ],
   "quote": "routing default outbound traffic (\"0.0.0.0/0\") for each public subnet"
  },
  {
   "id": "pvt_rt1",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
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
        "value": "RT_PVTRT-1"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_route_table"
      ],
      "where": [
       {
        "path": [
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "RT_PVTRT-1"
       }
      ]
     }
    }
   ],
   "quote": "dedicated private route tables (\"RT_PVTRT-1\" and \"RT_PVTRT-2\")"
  },
  {
   "id": "pvt_rt1_via_nat",
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
        "value": "RT_PVTRT-1"
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
     "to": "nat"
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
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "RT_PVTRT-1"
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
     "to": "nat"
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
     "to": "nat"
    }
   ],
   "quote": "that route default outbound traffic (\"0.0.0.0/0\") through the first NAT Gateway"
  },
  {
   "id": "pvt_rt2",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
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
        "value": "RT_PVTRT-2"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_route_table"
      ],
      "where": [
       {
        "path": [
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "RT_PVTRT-2"
       }
      ]
     }
    }
   ],
   "quote": "dedicated private route tables (\"RT_PVTRT-1\" and \"RT_PVTRT-2\")"
  },
  {
   "id": "pvt_rt2_via_nat",
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
        "value": "RT_PVTRT-2"
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
     "to": "nat"
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
         "tags_all",
         "Name"
        ],
        "op": "eq",
        "value": "RT_PVTRT-2"
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
     "to": "nat"
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
     "to": "nat"
    }
   ],
   "quote": "that route default outbound traffic (\"0.0.0.0/0\") through the first NAT Gateway"
  },
  {
   "id": "eips",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_eip"
    ],
    "where": []
   },
   "quote": "Provision two Elastic IPs and two NAT Gateways",
   "min": 2,
   "justify": "two Elastic IPs"
  },
  {
   "id": "nat_gateways",
   "kind": "exists",
   "tier": "core",
   "select": "nat",
   "quote": "Provision two Elastic IPs and two NAT Gateways",
   "min": 2,
   "justify": "two NAT gateways"
  },
  {
   "id": "nat_tags",
   "kind": "attr",
   "tier": "detail",
   "select": "nat",
   "cond": {
    "path": [
     "tags",
     "Name"
    ],
    "op": "eq",
    "value": "T-NAT1"
   },
   "quote": "(both tagged \"T-NAT1\")",
   "quantifier": "all"
  },
  {
   "id": "nat_in_pub1",
   "kind": "ref",
   "tier": "core",
   "from": "nat",
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
      "value": "10.0.1.0/24"
     }
    ]
   },
   "quote": "in the respective public subnets"
  },
  {
   "id": "nat_in_pub2",
   "kind": "ref",
   "tier": "core",
   "from": "nat",
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
      "value": "10.0.2.0/24"
     }
    ]
   },
   "quote": "in the respective public subnets"
  },
  {
   "id": "nat_uses_eip",
   "kind": "ref",
   "tier": "detail",
   "from": "nat",
   "to": {
    "types": [
     "aws_eip"
    ],
    "where": []
   },
   "quote": "Provision two Elastic IPs and two NAT Gateways"
  },
  {
   "id": "associations",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   },
   "quote": "both private subnets must associate with dedicated private route tables",
   "min": 4,
   "justify": "four subnets each associated with a route table"
  },
  {
   "id": "sg_allow_tls",
   "kind": "exists",
   "tier": "core",
   "select": "allow",
   "quote": "a public security group named \"allow_tls\""
  },
  {
   "id": "allow_http",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "allow",
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
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
         "tcp",
         "6"
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
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
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "allow"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "allow"
    }
   ],
   "quote": "permitting inbound HTTP (port 80) and HTTPS (port 443) from everywhere (\"0.0.0.0/0\")"
  },
  {
   "id": "allow_https",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "allow",
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
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
         "tcp",
         "6"
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
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
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "allow"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "allow"
    }
   ],
   "quote": "permitting inbound HTTP (port 80) and HTTPS (port 443) from everywhere (\"0.0.0.0/0\")"
  },
  {
   "id": "allow_ssh_admin",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "allow",
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "203.0.113.0/24"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "203.0.113.0/24"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "allow"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "203.0.113.0/24"
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "allow"
    }
   ],
   "quote": "SSH (port 22) only from the placeholder admin range \"203.0.113.0/24\""
  },
  {
   "id": "allow_egress_vpc",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "allow",
     "cond": {
      "path": [
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "10.0.0.0/16",
      "every": true
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "egress"
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     },
     "to": "allow"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": [
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
       }
      ]
     },
     "to": "allow"
    }
   ],
   "quote": "with egress limited to the VPC CIDR"
  },
  {
   "id": "sg_pvt_seg",
   "kind": "exists",
   "tier": "core",
   "select": "pvt",
   "quote": "a private security group named \"pvt-seg\""
  },
  {
   "id": "pvt_ingress_80",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "pvt",
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "pvt"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 80
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "pvt"
    }
   ],
   "quote": "permitting inbound HTTP, HTTPS, SSH, and PostgreSQL (port 5432) traffic exclusively from the public security group"
  },
  {
   "id": "pvt_ingress_443",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "pvt",
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "pvt"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "pvt"
    }
   ],
   "quote": "permitting inbound HTTP, HTTPS, SSH, and PostgreSQL (port 5432) traffic exclusively from the public security group"
  },
  {
   "id": "pvt_ingress_22",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "pvt",
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "pvt"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "pvt"
    }
   ],
   "quote": "permitting inbound HTTP, HTTPS, SSH, and PostgreSQL (port 5432) traffic exclusively from the public security group"
  },
  {
   "id": "pvt_ingress_5432",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "pvt",
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 5432
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 5432
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "pvt"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [],
        "op": "port_covers",
        "value": 5432
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "tcp",
         "6"
        ]
       }
      ]
     },
     "to": "pvt"
    }
   ],
   "quote": "permitting inbound HTTP, HTTPS, SSH, and PostgreSQL (port 5432) traffic exclusively from the public security group"
  },
  {
   "id": "pvt_from_public_sg",
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
        "value": "aws_security_group"
       },
       {
        "path": [
         "properties",
         "ingress",
         "*",
         "security_groups",
         "*"
        ],
        "op": "regex",
        "value": "aws_security_group\\."
       }
      ]
     },
     "to": "allow"
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
        "value": "aws_security_group_rule"
       },
       {
        "path": [
         "properties",
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       },
       {
        "path": [
         "properties",
         "source_security_group_id"
        ],
        "op": "regex",
        "value": "aws_security_group\\."
       }
      ]
     },
     "to": "allow"
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
        "value": "aws_vpc_security_group_ingress_rule"
       },
       {
        "path": [
         "properties",
         "referenced_security_group_id"
        ],
        "op": "regex",
        "value": "aws_security_group\\."
       }
      ]
     },
     "to": "allow"
    }
   ],
   "quote": "traffic exclusively from the public security group",
   "justify": "permitting inbound traffic from the public group is an ingress rule"
  },
  {
   "id": "pvt_no_open_cidr",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": "pvt",
     "cond": {
      "path": [
       "ingress",
       "*",
       "cidr_blocks"
      ],
      "op": "len_eq",
      "value": 0,
      "every": true
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "ingress"
       }
      ]
     },
     "cond": {
      "path": [
       "cidr_blocks",
       "*"
      ],
      "op": "none_eq",
      "value": "0.0.0.0/0"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": "pvt",
     "cond": {
      "path": [
       "ingress"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "exclusively from the public security group"
  },
  {
   "id": "pvt_egress_public_sg",
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
        "value": "aws_security_group"
       },
       {
        "path": [
         "properties",
         "egress",
         "*",
         "security_groups",
         "*"
        ],
        "op": "regex",
        "value": "aws_security_group\\."
       },
       {
        "path": [
         "properties",
         "egress",
         "*",
         "cidr_blocks",
         "*"
        ],
        "op": "absent"
       }
      ]
     },
     "to": "allow"
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
         "source_security_group_id"
        ],
        "op": "regex",
        "value": "aws_security_group\\."
       }
      ]
     },
     "to": "allow"
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
        "value": "aws_vpc_security_group_egress_rule"
       },
       {
        "path": [
         "properties",
         "referenced_security_group_id"
        ],
        "op": "regex",
        "value": "aws_security_group\\."
       }
      ]
     },
     "to": "allow"
    }
   ],
   "quote": "restricting egress exclusively to the public security group"
  },
  {
   "kind": "ref",
   "from": "igw",
   "to": "vpc",
   "id": "igw_attached_to_vpc",
   "tier": "extra"
  },
  {
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "eq",
    "value": true
   },
   "id": "vpc_dns_support",
   "tier": "extra"
  },
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
     "aws_route_table"
    ],
    "where": []
   },
   "id": "assoc_to_route_tables",
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
