package intent.tf.row_185

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "vpc_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a highly modular AWS VPC infrastructure module",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   }
  },
  {
   "id": "create_vpc_var",
   "kind": "attr",
   "tier": "core",
   "quote": "The primary VPC creation must be controlled by a create_vpc boolean variable defaulting to true",
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
      "value": "create_vpc"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "vpc_cidr_default",
   "kind": "attr",
   "tier": "core",
   "quote": "accepting an IPv4 CIDR block defaulting to \"10.0.0.0/16\"",
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
   "justify": "explicit default"
  },
  {
   "id": "vpc_cidr_var_default",
   "kind": "attr",
   "tier": "detail",
   "quote": "accepting an IPv4 CIDR block defaulting to \"10.0.0.0/16\"",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "10.0.0.0/16"
   },
   "justify": "explicit default value stated in the prompt"
  },
  {
   "id": "ipam_support",
   "kind": "attr",
   "tier": "core",
   "quote": "(or utilizing an IPAM pool via ipv4_ipam_pool_id and ipv4_netmask_length)",
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
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "ipv4_ipam_pool_id"
    ],
    "op": "present"
   }
  },
  {
   "id": "ipam_netmask",
   "kind": "attr",
   "tier": "detail",
   "quote": "(or utilizing an IPAM pool via ipv4_ipam_pool_id and ipv4_netmask_length)",
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
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "ipv4_netmask_length"
    ],
    "op": "present"
   }
  },
  {
   "id": "secondary_cidr",
   "kind": "exists",
   "tier": "core",
   "quote": "supporting secondary IPv4 CIDR block associations",
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
      "value": "aws_vpc_ipv4_cidr_block_association"
     }
    ]
   }
  },
  {
   "id": "dns_hostnames",
   "kind": "attr",
   "tier": "core",
   "quote": "enabling DNS hostnames and DNS support by default",
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
   "id": "dns_support",
   "kind": "attr",
   "tier": "core",
   "quote": "enabling DNS hostnames and DNS support by default",
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
   }
  },
  {
   "id": "public_subnets",
   "kind": "exists",
   "tier": "core",
   "quote": "Public and private subnet tiers must be defined via flexible map structures accepting explicit CIDR blocks, availability zone assignments, and IPv6 parameters",
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
       "for_each"
      ],
      "op": "present"
     }
    ]
   },
   "min": 2,
   "justify": "public and private tiers are separate subnet groups; map structures implies for_each"
  },
  {
   "id": "subnet_az_declared",
   "kind": "any_of",
   "tier": "detail",
   "quote": "availability zone assignments",
   "checks": [
    {
     "kind": "attr",
     "quantifier": "all",
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "availability_zone"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "quantifier": "all",
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "availability_zone_id"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "subnet_ipv6_declared",
   "kind": "any_of",
   "tier": "detail",
   "quote": "IPv6 parameters",
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
        "value": "aws_subnet"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "ipv6_cidr_block"
      ],
      "op": "present"
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
        "value": "aws_subnet"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assign_ipv6_address_on_creation"
      ],
      "op": "present"
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
        "value": "aws_subnet"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "ipv6_native"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "route_tables",
   "kind": "exists",
   "tier": "core",
   "quote": "alongside dedicated route table definitions",
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
   "id": "public_route",
   "kind": "ref",
   "tier": "core",
   "quote": "map public subnet traffic through a conditionally created Internet Gateway",
   "from": {
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
       "aws_route",
       "aws_route_table"
      ]
     }
    ]
   },
   "to": {
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
   }
  },
  {
   "id": "private_nat_route",
   "kind": "ref",
   "tier": "core",
   "quote": "private subnet traffic through mapped NAT Gateways",
   "from": {
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
       "aws_route",
       "aws_route_table"
      ]
     }
    ]
   },
   "to": {
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
   }
  },
  {
   "id": "igw",
   "kind": "exists",
   "tier": "core",
   "quote": "a conditionally created Internet Gateway (create_igw defaulting to true)",
   "select": {
    "types": [
     "aws_internet_gateway"
    ],
    "where": []
   }
  },
  {
   "id": "create_igw_var",
   "kind": "attr",
   "tier": "detail",
   "quote": "(create_igw defaulting to true)",
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
      "value": "create_igw"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "nat_gateway",
   "kind": "exists",
   "tier": "core",
   "quote": "private subnet traffic through mapped NAT Gateways deployed with Elastic IPs",
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
     }
    ]
   }
  },
  {
   "id": "nat_eip",
   "kind": "ref",
   "tier": "core",
   "quote": "NAT Gateways deployed with Elastic IPs",
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
      "value": "aws_nat_gateway"
     }
    ]
   },
   "to": {
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
   "id": "egress_only_igw",
   "kind": "exists",
   "tier": "core",
   "quote": "optional egress-only internet gateways for IPv6",
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
     }
    ]
   }
  },
  {
   "id": "network_acl",
   "kind": "exists",
   "tier": "core",
   "quote": "customizable network ACLs",
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
      "value": "aws_network_acl"
     }
    ]
   }
  },
  {
   "id": "private_acl_allow_inbound",
   "kind": "any_of",
   "tier": "core",
   "quote": "dedicated ACLs with default allow-all inbound and outbound rules",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_network_acl_rule"
      ],
      "where": [
       {
        "path": [
         "rule_action"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "regex",
        "value": "(?i)^(\\$\\{)?(-1|all)\\}?$"
       }
      ]
     },
     "cond": {
      "path": [
       "egress"
      ],
      "op": "eq",
      "value": false
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
        "value": "aws_network_acl_rule"
       },
       {
        "path": [
         "properties",
         "rule_action"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "properties",
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "properties",
         "protocol"
        ],
        "op": "regex",
        "value": "(?i)^(\\$\\{)?(-1|all)\\}?$"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "egress"
      ],
      "op": "eq",
      "value": false
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_network_acl"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "action"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "regex",
        "value": "(?i)^(\\$\\{)?(-1|all)\\}?$"
       }
      ]
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
        "value": "aws_network_acl"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "ingress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "action"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "regex",
        "value": "(?i)^(\\$\\{)?(-1|all)\\}?$"
       }
      ]
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
        "op": "regex",
        "value": "(?i)private.*(inbound|ingress)|(inbound|ingress).*private"
       },
       {
        "path": [
         "default"
        ],
        "op": "contains",
        "value": "allow"
       },
       {
        "path": [
         "default"
        ],
        "op": "contains",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "contains",
      "value": "-1"
     }
    }
   ],
   "justify": "allow-all implies action allow, 0.0.0.0/0 and all protocols (-1)"
  },
  {
   "id": "private_acl_allow_outbound",
   "kind": "any_of",
   "tier": "core",
   "quote": "dedicated ACLs with default allow-all inbound and outbound rules",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_network_acl_rule"
      ],
      "where": [
       {
        "path": [
         "rule_action"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "regex",
        "value": "(?i)^(\\$\\{)?(-1|all)\\}?$"
       }
      ]
     },
     "cond": {
      "path": [
       "egress"
      ],
      "op": "eq",
      "value": true
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
        "value": "aws_network_acl_rule"
       },
       {
        "path": [
         "properties",
         "rule_action"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "properties",
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "properties",
         "protocol"
        ],
        "op": "regex",
        "value": "(?i)^(\\$\\{)?(-1|all)\\}?$"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "egress"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_network_acl"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "egress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "action"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "regex",
        "value": "(?i)^(\\$\\{)?(-1|all)\\}?$"
       }
      ]
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
        "value": "aws_network_acl"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "egress",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "action"
        ],
        "op": "eq",
        "value": "allow"
       },
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "protocol"
        ],
        "op": "regex",
        "value": "(?i)^(\\$\\{)?(-1|all)\\}?$"
       }
      ]
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
        "op": "regex",
        "value": "(?i)private.*(outbound|egress)|(outbound|egress).*private"
       },
       {
        "path": [
         "default"
        ],
        "op": "contains",
        "value": "allow"
       },
       {
        "path": [
         "default"
        ],
        "op": "contains",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "contains",
      "value": "-1"
     }
    }
   ],
   "justify": "allow-all implies action allow, 0.0.0.0/0 and all protocols (-1)"
  },
  {
   "id": "dhcp_options",
   "kind": "exists",
   "tier": "core",
   "quote": "conditionally created DHCP option sets and associations",
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
      "value": "aws_vpc_dhcp_options"
     }
    ]
   }
  },
  {
   "id": "dhcp_assoc",
   "kind": "ref",
   "tier": "core",
   "quote": "conditionally created DHCP option sets and associations",
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
      "value": "aws_vpc_dhcp_options_association"
     }
    ]
   },
   "to": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_vpc_dhcp_options"
     }
    ]
   }
  },
  {
   "id": "flow_log",
   "kind": "exists",
   "tier": "core",
   "quote": "VPC flow logs configured across log destinations with custom formatting and aggregation intervals",
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
      "value": "aws_flow_log"
     }
    ]
   }
  },
  {
   "id": "flow_log_format",
   "kind": "attr",
   "tier": "detail",
   "quote": "custom formatting",
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
      "value": "aws_flow_log"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "log_format"
    ],
    "op": "present"
   }
  },
  {
   "id": "flow_log_interval",
   "kind": "attr",
   "tier": "detail",
   "quote": "aggregation intervals",
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
      "value": "aws_flow_log"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "max_aggregation_interval"
    ],
    "op": "present"
   }
  },
  {
   "id": "flow_log_destination",
   "kind": "any_of",
   "tier": "detail",
   "quote": "configured across log destinations",
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
        "value": "aws_flow_log"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "log_destination"
      ],
      "op": "present"
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
        "value": "aws_flow_log"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "log_group_name"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "default_sg",
   "kind": "exists",
   "tier": "core",
   "quote": "the default security group (manage_default_security_group defaulting to false)",
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
      "value": "aws_default_security_group"
     }
    ]
   }
  },
  {
   "id": "manage_default_sg_var",
   "kind": "attr",
   "tier": "detail",
   "quote": "manage_default_security_group defaulting to false",
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
      "value": "manage_default_security_group"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": false
   }
  },
  {
   "id": "default_nacl",
   "kind": "exists",
   "tier": "core",
   "quote": "default network ACL (manage_default_network_acl defaulting to false with default allow rules for IPv4/IPv6)",
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
      "value": "aws_default_network_acl"
     }
    ]
   }
  },
  {
   "id": "manage_default_nacl_var",
   "kind": "attr",
   "tier": "detail",
   "quote": "manage_default_network_acl defaulting to false",
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
      "value": "manage_default_network_acl"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": false
   }
  },
  {
   "id": "default_rt",
   "kind": "exists",
   "tier": "core",
   "quote": "default route table (manage_default_route_table defaulting to false)",
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
      "value": "aws_default_route_table"
     }
    ]
   }
  },
  {
   "id": "manage_default_rt_var",
   "kind": "attr",
   "tier": "detail",
   "quote": "manage_default_route_table defaulting to false",
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
      "value": "manage_default_route_table"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": false
   }
  },
  {
   "id": "default_nacl_allow_rules",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with default allow rules for IPv4/IPv6",
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
        "value": "aws_default_network_acl"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "allow"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "::/0"
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
        "op": "regex",
        "value": "(?i)default.*(acl|nacl)"
       },
       {
        "path": [
         "default"
        ],
        "op": "contains",
        "value": "allow"
       },
       {
        "path": [
         "default"
        ],
        "op": "contains",
        "value": "0.0.0.0/0"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "contains",
      "value": "::/0"
     }
    }
   ],
   "justify": "IPv4/IPv6 allow rules mean 0.0.0.0/0 and ::/0"
  },
  {
   "id": "x_tenancy",
   "kind": "attr",
   "tier": "extra",
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
      "value": "instance_tenancy"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "default"
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
