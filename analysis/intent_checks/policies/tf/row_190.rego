package intent.tf.row_190

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
     "value": "10.16.0.0/16"
    }
   ]
  },
  "igw": {
   "types": [
    "aws_internet_gateway"
   ],
   "where": []
  },
  "subnets": {
   "types": [
    "aws_subnet"
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
      "name"
     ],
     "op": "regex",
     "value": "(?i)web[-_ ]?sg"
    }
   ]
  },
  "app_sg": {
   "types": [
    "aws_security_group"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "regex",
     "value": "(?i)app[-_ ]?sg"
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
      "name"
     ],
     "op": "regex",
     "value": "(?i)(db|database)[-_ ]?sg"
    }
   ]
  },
  "sg_egress_443_sgref": {
   "types": [
    "aws_security_group_rule",
    "aws_vpc_security_group_egress_rule"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "none_eq",
     "value": "ingress"
    },
    {
     "path": [],
     "op": "port_covers",
     "value": 443
    },
    {
     "path": [
      "cidr_blocks"
     ],
     "op": "absent"
    },
    {
     "path": [
      "cidr_ipv4"
     ],
     "op": "absent"
    }
   ]
  },
  "sg_ingress_443_sgref": {
   "types": [
    "aws_security_group_rule",
    "aws_vpc_security_group_ingress_rule"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "none_eq",
     "value": "egress"
    },
    {
     "path": [],
     "op": "port_covers",
     "value": 443
    },
    {
     "path": [
      "cidr_blocks"
     ],
     "op": "absent"
    },
    {
     "path": [
      "cidr_ipv4"
     ],
     "op": "absent"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "vpc_cidr",
   "kind": "exists",
   "tier": "core",
   "quote": "a default IPv4 CIDR block of \"10.16.0.0/16\"",
   "select": "vpc"
  },
  {
   "id": "vpc_name_tag",
   "kind": "attr",
   "tier": "core",
   "quote": "a VPC tagged \"main-vpc\"",
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
    "value": "main-vpc"
   },
   "justify": "'tagged \"main-vpc\"' -> Name tag main-vpc"
  },
  {
   "id": "vpc_ipv6",
   "kind": "attr",
   "tier": "core",
   "quote": "Amazon-provided IPv6 CIDR assignment enabled",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "assign_generated_ipv6_cidr_block"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "ipv6_toggle_variable",
   "kind": "exists",
   "tier": "detail",
   "quote": "controlled by is_ipv6_enabled defaulting to true",
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
      "value": "is_ipv6_enabled"
     },
     {
      "path": [
       "default"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "vpc_tenancy_dns",
   "kind": "exists",
   "tier": "detail",
   "quote": "default instance tenancy, and both DNS hostnames and DNS support enabled by default",
   "select": {
    "types": [
     "aws_vpc"
    ],
    "where": [
     {
      "path": [
       "instance_tenancy"
      ],
      "op": "eq",
      "value": "default"
     },
     {
      "path": [
       "enable_dns_hostnames"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "enable_dns_support"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "twelve_subnets",
   "kind": "exists",
   "tier": "core",
   "quote": "defaulting to 12 subnets across three availability zones",
   "select": "subnets",
   "min": 12
  },
  {
   "id": "subnets_three_azs",
   "kind": "exists",
   "tier": "detail",
   "quote": "defaulting to 12 subnets across three availability zones",
   "select": "subnets",
   "distinct_path": [
    "availability_zone"
   ],
   "min": 3
  },
  {
   "id": "ipv4_slash20_subnets",
   "kind": "attr",
   "tier": "core",
   "quote": "IPv4 subnets using 4 additional bits (/20 subnets)",
   "select": "subnets",
   "quantifier": "all",
   "cond": {
    "path": [
     "cidr_block"
    ],
    "op": "regex",
    "value": "^10\\.16\\.[0-9]+\\.[0-9]+/20$"
   },
   "justify": "/16 + 4 bits -> /20 subnets inside 10.16.0.0/16"
  },
  {
   "id": "ipv6_subnets",
   "kind": "exists",
   "tier": "detail",
   "quote": "IPv6 subnets using 8 additional bits (/64 subnets)",
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
       "ipv6_cidr_block"
      ],
      "op": "present"
     }
    ]
   }
  },
  {
   "id": "sn_details_variable",
   "kind": "exists",
   "tier": "detail",
   "quote": "a list of subnet objects (sn_details)",
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
      "value": "sn_details"
     }
    ]
   }
  },
  {
   "id": "igw_attached",
   "kind": "ref",
   "tier": "detail",
   "quote": "An Internet Gateway",
   "from": "igw",
   "to": "vpc"
  },
  {
   "id": "igw_name_prefix",
   "kind": "any_of",
   "tier": "detail",
   "quote": "tagged with a name prefixed by \"main-igw-vpc-\"",
   "checks": [
    {
     "kind": "attr",
     "select": "igw",
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "regex",
      "value": "^main-igw-vpc-"
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
        "value": "aws_internet_gateway"
       },
       {
        "path": [
         "properties",
         "tags"
        ],
        "op": "regex",
        "value": "main-igw-vpc-"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "public_rt_tag",
   "kind": "attr",
   "tier": "detail",
   "quote": "a public route table tagged \"public-rt-web\"",
   "select": {
    "types": [
     "aws_route_table"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "tags",
     "Name"
    ],
    "op": "eq",
    "value": "public-rt-web"
   }
  },
  {
   "id": "ipv4_default_route_igw",
   "kind": "any_of",
   "tier": "core",
   "quote": "routing all IPv4 (\"0.0.0.0/0\")",
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
   "id": "ipv6_default_route_igw",
   "kind": "any_of",
   "tier": "core",
   "quote": "IPv6 (\"::/0\") traffic to the Internet Gateway",
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
         "ipv6_cidr_block"
        ],
        "op": "eq",
        "value": "::/0"
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
         "destination_ipv6_cidr_block"
        ],
        "op": "eq",
        "value": "::/0"
       }
      ]
     },
     "to": "igw"
    }
   ]
  },
  {
   "id": "public_rt_associated",
   "kind": "ref",
   "tier": "detail",
   "quote": "associated exclusively with all subnets marked as public",
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
      "value": "public-rt-web"
     }
    ]
   }
  },
  {
   "id": "three_tier_sgs",
   "kind": "all_of",
   "tier": "core",
   "quote": "security groups must be provisioned for each tier",
   "checks": [
    {
     "kind": "ref",
     "from": "web_sg",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "app_sg",
     "to": "vpc"
    },
    {
     "kind": "ref",
     "from": "db_sg",
     "to": "vpc"
    }
   ]
  },
  {
   "id": "web_ingress_443_anywhere",
   "kind": "any_of",
   "tier": "core",
   "quote": "a \"web_sg\" permitting ingress port 443 (TLS) from \"0.0.0.0/0\"",
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
        "value": 443
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
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule",
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "none_eq",
        "value": "egress"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 443
       },
       {
        "path": [],
        "op": "regex",
        "value": "0\\.0\\.0\\.0/0"
       }
      ]
     },
     "to": "web_sg"
    }
   ]
  },
  {
   "id": "web_ssh_from_vpc_cidr",
   "kind": "any_of",
   "tier": "core",
   "quote": "port 22 (SSH) only from the VPC IPv4 CIDR block",
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
        "value": "10.16.0.0/16"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_security_group_rule",
       "aws_vpc_security_group_ingress_rule"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "none_eq",
        "value": "egress"
       },
       {
        "path": [],
        "op": "port_covers",
        "value": 22
       },
       {
        "path": [],
        "op": "regex",
        "value": "10\\.16\\.0\\.0/16"
       }
      ]
     },
     "to": "web_sg"
    }
   ],
   "justify": "the VPC IPv4 CIDR block is the stated 10.16.0.0/16"
  },
  {
   "id": "web_egress_443_to_app",
   "kind": "all_of",
   "tier": "core",
   "quote": "egress port 443 to \"app_sg\"",
   "checks": [
    {
     "kind": "ref",
     "from": "sg_egress_443_sgref",
     "to": "web_sg"
    },
    {
     "kind": "ref",
     "from": "sg_egress_443_sgref",
     "to": "app_sg"
    }
   ]
  },
  {
   "id": "app_ingress_443_from_web",
   "kind": "all_of",
   "tier": "core",
   "quote": "an \"app_sg\" permitting ingress port 443 from \"web_sg\"",
   "checks": [
    {
     "kind": "ref",
     "from": "sg_ingress_443_sgref",
     "to": "app_sg"
    },
    {
     "kind": "ref",
     "from": "sg_ingress_443_sgref",
     "to": "web_sg"
    }
   ]
  },
  {
   "id": "app_egress_443_to_db",
   "kind": "all_of",
   "tier": "core",
   "quote": "egress port 443 to \"db_sg\"",
   "checks": [
    {
     "kind": "ref",
     "from": "sg_egress_443_sgref",
     "to": "app_sg"
    },
    {
     "kind": "ref",
     "from": "sg_egress_443_sgref",
     "to": "db_sg"
    }
   ]
  },
  {
   "id": "db_ingress_443_from_app",
   "kind": "all_of",
   "tier": "core",
   "quote": "a \"db_sg\" permitting ingress port 443 from \"app_sg\"",
   "checks": [
    {
     "kind": "ref",
     "from": "sg_ingress_443_sgref",
     "to": "db_sg"
    },
    {
     "kind": "ref",
     "from": "sg_ingress_443_sgref",
     "to": "app_sg"
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
