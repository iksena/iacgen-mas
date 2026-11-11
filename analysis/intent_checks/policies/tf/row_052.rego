package intent.tf.row_052

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
      "tags",
      "*"
     ],
     "op": "regex",
     "value": "(?i)public"
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
      "tags",
      "*"
     ],
     "op": "regex",
     "value": "(?i)private"
    }
   ]
  },
  "nat": {
   "types": [
    "aws_nat_gateway"
   ],
   "where": []
  },
  "sg": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "allow-ssh"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc_named",
   "tier": "core",
   "quote": "VPC network named \"trade-tariff-development-vpc\"",
   "kind": "any_of",
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
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "trade-tariff-development-vpc"
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
       "tags",
       "*"
      ],
      "op": "eq",
      "value": "trade-tariff-development-vpc"
     }
    }
   ]
  },
  {
   "id": "public_subnets",
   "tier": "core",
   "quote": "public and private subnets",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": "pub"
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
         "map_public_ip_on_launch"
        ],
        "op": "eq",
        "value": true
       }
      ]
     }
    }
   ]
  },
  {
   "id": "private_subnets",
   "tier": "core",
   "quote": "public and private subnets",
   "kind": "exists",
   "select": "priv"
  },
  {
   "id": "two_azs",
   "tier": "core",
   "quote": "public and private subnets across two availability zones",
   "kind": "all_of",
   "justify": "two availability zones per subnet tier",
   "checks": [
    {
     "kind": "exists",
     "select": "pub",
     "min": 2,
     "max": 2,
     "distinct_path": [
      "availability_zone"
     ]
    },
    {
     "kind": "exists",
     "select": "priv",
     "min": 2,
     "max": 2,
     "distinct_path": [
      "availability_zone"
     ]
    }
   ]
  },
  {
   "id": "nat_gateway",
   "tier": "core",
   "quote": "NAT gateway access",
   "kind": "exists",
   "select": "nat"
  },
  {
   "id": "nat_route",
   "tier": "detail",
   "quote": "NAT gateway access",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": []
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
   ]
  },
  {
   "id": "sg_named",
   "tier": "core",
   "quote": "a security group named \"allow-ssh\"",
   "kind": "exists",
   "select": "sg"
  },
  {
   "id": "ssh_inbound",
   "tier": "core",
   "quote": "allows inbound SSH",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "sg",
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
     "to": "sg"
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
     "to": "sg"
    }
   ],
   "justify": "SSH implies TCP port 22"
  },
  {
   "id": "egress_only_vpc",
   "tier": "core",
   "quote": "outbound traffic only within the VPC CIDR",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
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
       }
      ]
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "properties",
       "cidr_ipv4"
      ],
      "op": "regex",
      "value": "^\\$\\{|/([1-9]|[12][0-9]|3[0-2])$",
      "every": true
     }
    },
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "regex",
      "value": "/([1-9]|[12][0-9]|3[0-2])$",
      "every": true
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "egress",
       "*",
       "cidr_blocks",
       "*"
      ],
      "op": "regex",
      "value": "^\\$\\{|/([1-9]|[12][0-9]|3[0-2])$",
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
     "quantifier": "all",
     "cond": {
      "path": [
       "cidr_blocks",
       "*"
      ],
      "op": "regex",
      "value": "/([1-9]|[12][0-9]|3[0-2])$",
      "every": true
     }
    },
    {
     "kind": "attr",
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
       }
      ]
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "properties",
       "cidr_blocks",
       "*"
      ],
      "op": "regex",
      "value": "^\\$\\{|/([1-9]|[12][0-9]|3[0-2])$",
      "every": true
     }
    }
   ],
   "justify": "anywhere (a /0 range) is outside the VPC CIDR"
  },
  {
   "id": "egress_vpc_cidr",
   "tier": "core",
   "quote": "outbound traffic only within the VPC CIDR",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_vpc",
       "data.aws_vpc"
      ],
      "where": []
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
       }
      ]
     },
     "to": {
      "types": [
       "aws_vpc",
       "data.aws_vpc"
      ],
      "where": []
     }
    },
    {
     "kind": "join",
     "from": "sg",
     "from_path": [
      "egress",
      "*",
      "cidr_blocks",
      "*"
     ],
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "to_path": [
      "cidr_block"
     ]
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "aws_vpc_security_group_egress_rule"
      ],
      "where": []
     },
     "from_path": [
      "cidr_ipv4"
     ],
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "to_path": [
      "cidr_block"
     ]
    },
    {
     "kind": "join",
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
       }
      ]
     },
     "from_path": [
      "cidr_blocks",
      "*"
     ],
     "to": {
      "types": [
       "aws_vpc"
      ],
      "where": []
     },
     "to_path": [
      "cidr_block"
     ]
    }
   ]
  },
  {
   "id": "vpc_dns_hostnames",
   "tier": "extra",
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
   }
  },
  {
   "id": "nat_in_public_subnet",
   "tier": "extra",
   "kind": "ref",
   "from": "nat",
   "to": "subnets"
  },
  {
   "id": "extra_type_aws_default_network_acl",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_default_network_acl"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_default_route_table",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_default_route_table"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_default_security_group",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_default_security_group"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_eip",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_eip"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_internet_gateway",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_route_table_association",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_route_table_association"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
