package intent.tf.row_212

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
     "value": "172.69.0.0/16"
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
     "op": "eq",
     "value": "172.69.1.0/24"
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
     "op": "eq",
     "value": "172.69.2.0/24"
    }
   ]
  },
  "igw": {
   "types": [
    "aws_internet_gateway"
   ],
   "where": []
  },
  "rt": {
   "types": [
    "aws_route_table"
   ],
   "where": []
  },
  "assoc": {
   "types": [
    "aws_route_table_association"
   ],
   "where": []
  },
  "web_sg": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "tags",
      "Name"
     ],
     "op": "eq",
     "value": "web-server_security_group"
    }
   ]
  },
  "web_sg_decl": {
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
      "name"
     ],
     "op": "contains",
     "value": "webserver-sg"
    }
   ]
  },
  "db_sg_decl": {
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
      "name"
     ],
     "op": "contains",
     "value": "database-sg"
    }
   ]
  },
  "db_sg": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "ingress",
      "*"
     ],
     "op": "port_covers",
     "value": 3306
    }
   ]
  },
  "web_sg_all": {
   "types": [
    "aws_security_group"
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
   "quote": "a VPC defaulting to CIDR block \"172.69.0.0/16\""
  },
  {
   "id": "vpc_tag",
   "kind": "attr",
   "select": "vpc",
   "tier": "detail",
   "quote": "tagged \"vpc_name\"",
   "cond": {
    "path": [
     "tags",
     "*"
    ],
    "op": "eq",
    "value": "vpc_name"
   }
  },
  {
   "id": "pub_subnet",
   "kind": "exists",
   "select": "pub",
   "tier": "core",
   "quote": "a public subnet defaulting to \"172.69.1.0/24\""
  },
  {
   "id": "pub_subnet_tag",
   "kind": "attr",
   "select": "pub",
   "tier": "detail",
   "quote": "tagged \"public_subnet\"",
   "cond": {
    "path": [
     "tags",
     "*"
    ],
    "op": "eq",
    "value": "public_subnet"
   }
  },
  {
   "id": "priv_subnet",
   "kind": "exists",
   "select": "priv",
   "tier": "core",
   "quote": "a private subnet defaulting to \"172.69.2.0/24\""
  },
  {
   "id": "priv_subnet_tag",
   "kind": "attr",
   "select": "priv",
   "tier": "detail",
   "quote": "tagged \"private_subnet\"",
   "cond": {
    "path": [
     "tags",
     "*"
    ],
    "op": "eq",
    "value": "private_subnet"
   }
  },
  {
   "id": "subnets_in_vpc",
   "kind": "all_of",
   "tier": "detail",
   "quote": "containing a public subnet",
   "checks": [
    {
     "kind": "ref",
     "from": "pub",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "priv",
     "to": "vpc"
    }
   ]
  },
  {
   "id": "igw_attached",
   "kind": "ref",
   "from": "igw",
   "to": "vpc",
   "tier": "core",
   "quote": "Connect the VPC to an internet gateway"
  },
  {
   "id": "igw_tag",
   "kind": "attr",
   "select": "igw",
   "tier": "detail",
   "quote": "internet gateway tagged \"igw_tag\"",
   "cond": {
    "path": [
     "tags",
     "*"
    ],
    "op": "eq",
    "value": "igw_tag"
   }
  },
  {
   "id": "rt_tag",
   "kind": "attr",
   "select": "rt",
   "tier": "detail",
   "quote": "public route table tagged \"rtb_tag\"",
   "cond": {
    "path": [
     "tags",
     "*"
    ],
    "op": "eq",
    "value": "rtb_tag"
   }
  },
  {
   "id": "default_route_igw",
   "kind": "any_of",
   "tier": "core",
   "quote": "routes \"0.0.0.0/0\" traffic to the internet gateway",
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
         "route",
         "*",
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
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
   ]
  },
  {
   "id": "route_to_igw_ref",
   "kind": "any_of",
   "tier": "core",
   "quote": "routes \"0.0.0.0/0\" traffic to the internet gateway",
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
   ]
  },
  {
   "id": "rt_assoc_public",
   "kind": "all_of",
   "tier": "core",
   "quote": "associates directly with the public subnet",
   "checks": [
    {
     "kind": "ref",
     "from": "assoc",
     "to": "pub"
    },
    {
     "kind": "ref",
     "from": "assoc",
     "to": "rt"
    }
   ]
  },
  {
   "id": "web_sg_exists",
   "kind": "any_of",
   "tier": "core",
   "quote": "a web server security group named \"webserver-sg_<vpc_id>\"",
   "justify": "name is built from the VPC id, so it is unknown at plan time; the declared name text carries the stated prefix",
   "checks": [
    {
     "kind": "attr",
     "select": "web_sg_all",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^webserver-sg_"
     }
    },
    {
     "kind": "exists",
     "select": "web_sg_decl"
    }
   ]
  },
  {
   "id": "web_sg_tag",
   "kind": "attr",
   "select": "web_sg_all",
   "tier": "detail",
   "quote": "tagged \"web-server_security_group\"",
   "cond": {
    "path": [
     "tags",
     "*"
    ],
    "op": "eq",
    "value": "web-server_security_group"
   }
  },
  {
   "id": "web_sg_dynamic_ingress",
   "kind": "any_of",
   "tier": "detail",
   "quote": "supporting dynamic ingress rules",
   "checks": [
    {
     "kind": "attr",
     "select": "web_sg_decl",
     "cond": {
      "path": [
       "properties",
       "dynamic",
       "ingress"
      ],
      "op": "present"
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
        "op": "in",
        "value": [
         "aws_security_group_rule",
         "aws_vpc_security_group_ingress_rule"
        ]
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
   ]
  },
  {
   "id": "web_sg_http",
   "kind": "any_of",
   "tier": "core",
   "quote": "TCP port 80 open to \"0.0.0.0/0\"",
   "justify": "HTTP rule is the stated TCP port 80 from the stated 0.0.0.0/0; declared dynamic-block branch pairs them",
   "checks": [
    {
     "kind": "attr",
     "select": "web_sg",
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
     "to": "web_sg"
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
     "to": "web_sg"
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
     "to": "web_sg_decl"
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
     "to": "web_sg_decl"
    },
    {
     "kind": "attr",
     "select": "web_sg_decl",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?s)\\b80\\b.{0,300}0\\.0\\.0\\.0/0"
     }
    }
   ]
  },
  {
   "id": "web_sg_ssh_vpc",
   "kind": "any_of",
   "tier": "core",
   "quote": "port 22 restricted to the VPC CIDR \"172.69.0.0/16\"",
   "checks": [
    {
     "kind": "attr",
     "select": "web_sg",
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
        "value": "172.69.0.0/16"
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
        "value": "172.69.0.0/16"
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
     "to": "web_sg"
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
        "value": "172.69.0.0/16"
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
     "to": "web_sg"
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
        "value": "172.69.0.0/16"
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
     "to": "web_sg_decl"
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
        "value": "172.69.0.0/16"
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
     "to": "web_sg_decl"
    },
    {
     "kind": "attr",
     "select": "web_sg_decl",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?s)\\b22\\b.{0,300}172\\.69\\.0\\.0/16"
     }
    }
   ],
   "justify": "port 22 is listed with TCP port 80 in the same default rule list; CIDR is the stated VPC CIDR"
  },
  {
   "id": "web_sg_egress_vpc",
   "kind": "any_of",
   "tier": "core",
   "quote": "outbound egress limited to the VPC CIDR",
   "checks": [
    {
     "kind": "attr",
     "select": "web_sg",
     "cond": {
      "path": [
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "eq",
      "value": "172.69.0.0/16",
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
        "value": "172.69.0.0/16",
        "every": true
       }
      ]
     },
     "to": "web_sg"
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
        "value": "172.69.0.0/16",
        "every": true
       }
      ]
     },
     "to": "web_sg_decl"
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
        "value": "172.69.0.0/16"
       }
      ]
     },
     "to": "web_sg"
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
        "value": "172.69.0.0/16"
       }
      ]
     },
     "to": "web_sg_decl"
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
        "value": "aws_security_group"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "contains",
        "value": "webserver-sg"
       },
       {
        "path": [
         "properties",
         "egress"
        ],
        "op": "regex",
        "value": "172\\.69\\.0\\.0/16|aws_vpc\\.[A-Za-z0-9_-]+\\.cidr_block"
       },
       {
        "path": [
         "properties",
         "egress",
         "*",
         "cidr_blocks",
         "*"
        ],
        "op": "none_eq",
        "value": "0.0.0.0/0"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "web_sg_in_vpc",
   "kind": "ref",
   "from": "web_sg_all",
   "to": "vpc",
   "tier": "detail",
   "quote": "provision a web server security group"
  },
  {
   "id": "db_sg_exists",
   "kind": "any_of",
   "tier": "core",
   "quote": "a database security group named \"database-sg_<vpc_id>\"",
   "justify": "name is built from the VPC id, so it is unknown at plan time; the declared name text carries the stated prefix",
   "checks": [
    {
     "kind": "attr",
     "select": "web_sg_all",
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^database-sg_"
     }
    },
    {
     "kind": "exists",
     "select": "db_sg_decl"
    }
   ]
  },
  {
   "id": "db_sg_mysql",
   "kind": "any_of",
   "tier": "core",
   "quote": "permits TCP ingress on port 3306",
   "checks": [
    {
     "kind": "attr",
     "select": "db_sg_decl",
     "cond": {
      "path": [
       "properties",
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "port_covers",
        "value": 3306
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
     "kind": "attr",
     "select": {
      "types": [
       "aws_security_group"
      ],
      "where": [
       {
        "path": [
         "tags",
         "*"
        ],
        "op": "none_eq",
        "value": "web-server_security_group"
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
        "value": 3306
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
        "value": 3306
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
     "to": "db_sg_decl"
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
        "value": 3306
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
     "to": "db_sg_decl"
    }
   ]
  },
  {
   "id": "defaults_in_variables",
   "kind": "all_of",
   "tier": "detail",
   "quote": "a VPC defaulting to CIDR block \"172.69.0.0/16\"",
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
        "value": "172.69.0.0/16"
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
        "value": "172.69.1.0/24"
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
        "value": "172.69.2.0/24"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_dns_support",
   "kind": "attr",
   "select": "vpc",
   "tier": "extra",
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
