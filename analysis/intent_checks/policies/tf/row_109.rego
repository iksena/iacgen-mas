package intent.tf.row_109

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
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "development-be-vpc"
     }
    ]
   },
   "quote": "named \"development-be-vpc\""
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
    "value": "10.0.0.0/16"
   },
   "quote": "The VPC should use the CIDR block \"10.0.0.0/16\""
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
   "quote": "with DNS hostnames and DNS support enabled"
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
   "quote": "with DNS hostnames and DNS support enabled"
  },
  {
   "id": "var_cidrs",
   "tier": "detail",
   "kind": "all_of",
   "quote": "(configurable, as are the subnet CIDRs)",
   "justify": "configurable CIDR implies a variable holding the stated default",
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
        "op": "contains",
        "value": "10.0.0.0/16"
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
        "op": "contains",
        "value": "10.0.1.0/24"
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
        "op": "contains",
        "value": "10.0.2.0/24"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "pub_subnet",
   "tier": "core",
   "kind": "exists",
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
      "value": "development-be-public-subnet"
     }
    ]
   },
   "quote": "a public subnet named \"development-be-public-subnet\""
  },
  {
   "id": "pub_cidr",
   "tier": "core",
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
      "value": "development-be-public-subnet"
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
   "quote": "with CIDR \"10.0.1.0/24\""
  },
  {
   "id": "pub_no_autoip",
   "tier": "core",
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
      "value": "development-be-public-subnet"
     }
    ]
   },
   "cond": {
    "path": [
     "map_public_ip_on_launch"
    ],
    "op": "eq",
    "value": false
   },
   "quote": "does not auto-assign public IPs on launch"
  },
  {
   "id": "prv_subnet",
   "tier": "core",
   "kind": "exists",
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
      "value": "development-be-private-subnet"
     }
    ]
   },
   "quote": "a private subnet named \"development-be-private-subnet\""
  },
  {
   "id": "prv_cidr",
   "tier": "core",
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
      "value": "development-be-private-subnet"
     }
    ]
   },
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.2.0/24"
   },
   "quote": "with CIDR \"10.0.2.0/24\""
  },
  {
   "id": "two_azs",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_subnet"
    ],
    "where": []
   },
   "min": 2,
   "distinct_path": [
    "availability_zone"
   ],
   "quote": "in the first availability zone",
   "justify": "first and second availability zone means at least two different AZs"
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
   "quote": "contain a public subnet"
  },
  {
   "id": "igw",
   "tier": "core",
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
      "value": "development-be-ig"
     }
    ]
   },
   "quote": "Provision an internet gateway named \"development-be-ig\""
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
   "quote": "Provision an internet gateway"
  },
  {
   "id": "rt",
   "tier": "core",
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
      "value": "development-be-public-rt"
     }
    ]
   },
   "quote": "a public route table named \"development-be-public-rt\""
  },
  {
   "id": "rt_default_route",
   "tier": "core",
   "kind": "any_of",
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
        "value": "development-be-public-rt"
       }
      ]
     },
     "cond": {
      "path": [
       "route",
       "*",
       "cidr_block"
      ],
      "op": "eq",
      "value": "0.0.0.0/0"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_route"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "destination_cidr_block"
      ],
      "op": "eq",
      "value": "0.0.0.0/0"
     }
    }
   ],
   "quote": "sends internet-bound traffic",
   "justify": "internet-bound traffic means the default route 0.0.0.0/0"
  },
  {
   "id": "rt_igw",
   "tier": "core",
   "kind": "any_of",
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
        "value": "development-be-public-rt"
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
       "aws_route"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_internet_gateway"
      ],
      "where": []
     }
    }
   ],
   "quote": "sends internet-bound traffic through the gateway"
  },
  {
   "id": "assoc_pub",
   "tier": "core",
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
      "value": "development-be-public-subnet"
     }
    ]
   },
   "quote": "is associated only with the public subnet"
  },
  {
   "id": "assoc_rt",
   "tier": "core",
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
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "development-be-public-rt"
     }
    ]
   },
   "quote": "associated only with the public subnet"
  },
  {
   "id": "sg",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_security_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "http_access"
     }
    ]
   },
   "quote": "a security group named \"http_access\""
  },
  {
   "id": "sg_tag",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_security_group"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "http_access"
     }
    ]
   },
   "cond": {
    "path": [
     "tags",
     "Name"
    ],
    "op": "eq",
    "value": "development-be-sg"
   },
   "quote": "(tagged \"development-be-sg\")"
  },
  {
   "id": "sg_ssh",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "http_access"
       }
      ]
     },
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
        "value": "10.0.0.0/16"
       }
      ]
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
      "path": [],
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
        "value": "10.0.0.0/16"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "match",
      "value": [
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
        "value": "10.0.0.0/16"
       }
      ]
     }
    }
   ],
   "quote": "allows SSH only from within the VPC CIDR",
   "justify": "within the VPC CIDR is the stated VPC CIDR 10.0.0.0/16"
  },
  {
   "id": "sg_ssh_only",
   "tier": "core",
   "kind": "any_of",
   "quote": "allows SSH only from within the VPC CIDR",
   "justify": "within the VPC CIDR is the stated VPC CIDR 10.0.0.0/16; every ingress rule covering port 22 must use only it",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "http_access"
       }
      ]
     },
     "cond": {
      "path": [
       "ingress"
      ],
      "op": "regex",
      "value": "^\\[\\{[^{}]*(\"cidr_blocks\": (null|\\[(\"10\\.0\\.0\\.0/16\")?\\])[^{}]*\"ipv6_cidr_blocks\": (null|\\[\\])|\"from_port\": (2[3-9]|[3-9][0-9]|[1-9][0-9]{2,}),[^{}]*\"protocol\": \"(tcp|udp|icmp|icmpv6|6|17|1|58)\"|\"protocol\": \"(tcp|udp|icmp|icmpv6|6|17|1|58)\"[^{}]*\"to_port\": (-1|[0-9]|1[0-9]|2[01])[,}]|\"protocol\": \"(icmp|icmpv6|1|58)\")[^{}]*\\}(, \\{[^{}]*(\"cidr_blocks\": (null|\\[(\"10\\.0\\.0\\.0/16\")?\\])[^{}]*\"ipv6_cidr_blocks\": (null|\\[\\])|\"from_port\": (2[3-9]|[3-9][0-9]|[1-9][0-9]{2,}),[^{}]*\"protocol\": \"(tcp|udp|icmp|icmpv6|6|17|1|58)\"|\"protocol\": \"(tcp|udp|icmp|icmpv6|6|17|1|58)\"[^{}]*\"to_port\": (-1|[0-9]|1[0-9]|2[01])[,}]|\"protocol\": \"(icmp|icmpv6|1|58)\")[^{}]*\\})*\\]$"
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
      "path": [],
      "op": "regex",
      "value": "^\\{[^{}]*(\"cidr_blocks\": (null|\\[(\"10\\.0\\.0\\.0/16\")?\\])[^{}]*\"ipv6_cidr_blocks\": (null|\\[\\])|\"from_port\": (2[3-9]|[3-9][0-9]|[1-9][0-9]{2,}),[^{}]*\"protocol\": \"(tcp|udp|icmp|icmpv6|6|17|1|58)\"|\"protocol\": \"(tcp|udp|icmp|icmpv6|6|17|1|58)\"[^{}]*\"to_port\": (-1|[0-9]|1[0-9]|2[01])[,}]|\"protocol\": \"(icmp|icmpv6|1|58)\")[^{}]*\\}$"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "regex",
      "value": "^\\{[^{}]*(\"cidr_ipv4\": (null|\"10\\.0\\.0\\.0/16\"), \"cidr_ipv6\": null|\"from_port\": (2[3-9]|[3-9][0-9]|[1-9][0-9]{2,}),[^{}]*\"ip_protocol\": \"(tcp|udp|icmp|icmpv6|6|17|1|58)\"|\"ip_protocol\": \"(tcp|udp|icmp|icmpv6|6|17|1|58)\"[^{}]*\"to_port\": (-1|[0-9]|1[0-9]|2[01])[,}])[^{}]*\\}$"
     },
     "quantifier": "all"
    }
   ]
  },
  {
   "id": "sg_http",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "http_access"
       }
      ]
     },
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
       }
      ]
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
      "path": [],
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
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": []
     },
     "cond": {
      "path": [],
      "op": "match",
      "value": [
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
       }
      ]
     }
    }
   ],
   "quote": "allows HTTP on port 80 from anywhere",
   "justify": "from anywhere means 0.0.0.0/0"
  },
  {
   "id": "sg_egress",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "http_access"
       }
      ]
     },
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
        "value": "egress"
       }
      ]
     },
     "cond": {
      "path": [
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "10.0.0.0/16",
      "every": true
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "cidr_ipv4"
      ],
      "op": "eq",
      "value": "10.0.0.0/16"
     },
     "quantifier": "all"
    }
   ],
   "quote": "restricts all outbound traffic to the VPC CIDR",
   "justify": "the VPC CIDR is 10.0.0.0/16"
  },
  {
   "id": "out_vpc",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "__output__"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "quote": "output the VPC and both subnet IDs"
  },
  {
   "id": "out_pub",
   "tier": "detail",
   "kind": "ref",
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
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "development-be-public-subnet"
     }
    ]
   },
   "quote": "output the VPC and both subnet IDs"
  },
  {
   "id": "out_prv",
   "tier": "detail",
   "kind": "ref",
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
    "where": [
     {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "development-be-private-subnet"
     }
    ]
   },
   "quote": "output the VPC and both subnet IDs"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
