package intent.tf.row_080

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
  "subnet": {
   "types": [
    "aws_subnet"
   ],
   "where": []
  },
  "igw": {
   "types": [
    "aws_internet_gateway"
   ],
   "where": []
  },
  "eip": {
   "types": [
    "aws_eip"
   ],
   "where": []
  },
  "dhcp": {
   "types": [
    "aws_vpc_dhcp_options"
   ],
   "where": []
  },
  "assoc": {
   "types": [
    "aws_vpc_dhcp_options_association"
   ],
   "where": []
  },
  "dsg": {
   "types": [
    "aws_default_security_group"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "vpc",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "a custom test VPC with a 10.0.0.0/16 CIDR block"
  },
  {
   "id": "vpc_cidr",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.0.0/16"
   },
   "tier": "core",
   "quote": "a 10.0.0.0/16 CIDR block"
  },
  {
   "id": "subnet_cidr",
   "kind": "attr",
   "select": "subnet",
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "eq",
    "value": "10.0.1.0/24"
   },
   "tier": "core",
   "quote": "a single 10.0.1.0/24 subnet"
  },
  {
   "id": "subnet_single",
   "kind": "exists",
   "select": "subnet",
   "tier": "detail",
   "max": 1,
   "quote": "a single 10.0.1.0/24 subnet"
  },
  {
   "id": "subnet_in_vpc",
   "kind": "ref",
   "from": "subnet",
   "to": "vpc",
   "tier": "detail",
   "quote": "a single 10.0.1.0/24 subnet"
  },
  {
   "id": "subnet_no_public_ip",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "subnet",
     "cond": {
      "path": [
       "map_public_ip_on_launch"
      ],
      "op": "falsy"
     }
    },
    {
     "kind": "attr",
     "select": "subnet",
     "cond": {
      "path": [
       "map_public_ip_on_launch"
      ],
      "op": "absent"
     }
    }
   ],
   "tier": "core",
   "quote": "does not auto-assign public IPs"
  },
  {
   "id": "igw",
   "kind": "exists",
   "select": "igw",
   "tier": "core",
   "quote": "an internet gateway"
  },
  {
   "id": "igw_vpc",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "igw",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_internet_gateway_attachment"
      ],
      "where": []
     },
     "to": "vpc"
    }
   ],
   "tier": "detail",
   "quote": "an internet gateway"
  },
  {
   "id": "eip",
   "kind": "exists",
   "select": "eip",
   "tier": "core",
   "quote": "an Elastic IP"
  },
  {
   "id": "dhcp",
   "kind": "exists",
   "select": "dhcp",
   "tier": "core",
   "quote": "a custom DHCP options set"
  },
  {
   "id": "dhcp_public_dns",
   "kind": "attr",
   "select": "dhcp",
   "cond": {
    "path": [
     "domain_name_servers",
     "*"
    ],
    "op": "regex",
    "value": "^(8\\.8\\.8\\.8|8\\.8\\.4\\.4|1\\.1\\.1\\.1|1\\.0\\.0\\.1|9\\.9\\.9\\.9|149\\.112\\.112\\.112|208\\.67\\.222\\.222|208\\.67\\.220\\.220)$"
   },
   "tier": "core",
   "quote": "using standard public DNS servers",
   "justify": "well-known public resolvers (Google, Cloudflare, Quad9, OpenDNS) are the standard public DNS servers"
  },
  {
   "id": "dhcp_assoc_vpc",
   "kind": "ref",
   "from": "assoc",
   "to": "vpc",
   "tier": "core",
   "quote": "associated with the VPC"
  },
  {
   "id": "dhcp_assoc_dhcp",
   "kind": "ref",
   "from": "assoc",
   "to": "dhcp",
   "tier": "core",
   "quote": "a custom DHCP options set (using standard public DNS servers) associated with the VPC"
  },
  {
   "id": "default_sg",
   "kind": "exists",
   "select": "dsg",
   "tier": "core",
   "quote": "The VPC's default security group"
  },
  {
   "id": "default_sg_vpc",
   "kind": "ref",
   "from": "dsg",
   "to": "vpc",
   "tier": "detail",
   "quote": "The VPC's default security group"
  },
  {
   "id": "in_http",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "dsg",
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
        "value": "10.0.0.0/16"
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
        "value": "10.0.0.0/16"
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
        "value": "10.0.0.0/16"
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
     }
    }
   ],
   "tier": "core",
   "quote": "should allow HTTP, HTTPS, and SSH only from within the VPC CIDR",
   "justify": "HTTP implies TCP port 80"
  },
  {
   "id": "in_https",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "dsg",
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
        "value": "10.0.0.0/16"
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
        "value": 443
       },
       {
        "path": [
         "cidr_blocks",
         "*"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
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
        "value": 443
       },
       {
        "path": [
         "cidr_ipv4"
        ],
        "op": "eq",
        "value": "10.0.0.0/16"
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
     }
    }
   ],
   "tier": "core",
   "quote": "should allow HTTP, HTTPS, and SSH only from within the VPC CIDR",
   "justify": "HTTPS implies TCP port 443"
  },
  {
   "id": "in_ssh",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "dsg",
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
     }
    }
   ],
   "tier": "core",
   "quote": "should allow HTTP, HTTPS, and SSH only from within the VPC CIDR",
   "justify": "SSH implies TCP port 22"
  },
  {
   "id": "in_only_vpc",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "dsg",
     "cond": {
      "path": [
       "ingress",
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
        "value": "ingress"
       }
      ]
     },
     "quantifier": "all",
     "cond": {
      "path": [
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
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "cidr_ipv4"
      ],
      "op": "eq",
      "value": "10.0.0.0/16"
     }
    }
   ],
   "tier": "core",
   "quote": "only from within the VPC CIDR",
   "justify": "only from within the VPC CIDR: every ingress source CIDR is the VPC's 10.0.0.0/16"
  },
  {
   "id": "egress_vpc",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "dsg",
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
   "tier": "core",
   "quote": "restrict egress to the VPC CIDR as well"
  },
  {
   "id": "vpc_dns_support",
   "kind": "attr",
   "select": "vpc",
   "cond": {
    "path": [
     "enable_dns_support"
    ],
    "op": "truthy"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
