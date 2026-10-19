package intent.tf.row_155

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "ext_vpc": {
   "types": [
    "aws_vpc"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "eq",
     "value": "10.41.0.0/16"
    }
   ]
  },
  "int_vpc": {
   "types": [
    "aws_vpc"
   ],
   "where": [
    {
     "path": [
      "cidr_block"
     ],
     "op": "eq",
     "value": "10.40.0.0/16"
    }
   ]
  },
  "igw": {
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
     "value": "External GW"
    }
   ]
  },
  "rtb": {
   "types": [
    "aws_route_table"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "ext_vpc_cidr",
   "kind": "exists",
   "select": "ext_vpc",
   "tier": "core",
   "quote": "The external VPC must be configured with CIDR block \"10.41.0.0/16\""
  },
  {
   "id": "ext_vpc_dns",
   "kind": "all_of",
   "tier": "core",
   "quote": "enable DNS support and DNS hostnames",
   "checks": [
    {
     "kind": "attr",
     "select": "ext_vpc",
     "cond": {
      "path": [
       "enable_dns_support"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "ext_vpc",
     "cond": {
      "path": [
       "enable_dns_hostnames"
      ],
      "op": "truthy"
     }
    }
   ]
  },
  {
   "id": "ext_vpc_tags",
   "kind": "all_of",
   "tier": "detail",
   "quote": "apply tags for Name (\"Production External\"), purpose (\"Production External VPC\"), and environment (\"prod\")",
   "checks": [
    {
     "kind": "attr",
     "select": "ext_vpc",
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "Production External"
     }
    },
    {
     "kind": "attr",
     "select": "ext_vpc",
     "cond": {
      "path": [
       "tags",
       "purpose"
      ],
      "op": "eq",
      "value": "Production External VPC"
     }
    },
    {
     "kind": "attr",
     "select": "ext_vpc",
     "cond": {
      "path": [
       "tags_all",
       "environment"
      ],
      "op": "eq",
      "value": "prod"
     }
    }
   ]
  },
  {
   "id": "ext_default_sg_no_rules",
   "kind": "ref",
   "tier": "detail",
   "to": "ext_vpc",
   "from": {
    "types": [
     "aws_default_security_group"
    ],
    "where": [
     {
      "path": [
       "ingress",
       "*"
      ],
      "op": "absent"
     },
     {
      "path": [
       "egress",
       "*"
      ],
      "op": "absent"
     }
    ]
   },
   "quote": "manage its default security group with no ingress or egress rules"
  },
  {
   "id": "ext_subnets",
   "kind": "all_of",
   "tier": "core",
   "quote": "Four subnets must be provisioned in the external VPC",
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
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.41.0.0/24"
       }
      ]
     },
     "to": "ext_vpc"
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
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.41.1.0/24"
       }
      ]
     },
     "to": "ext_vpc"
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
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.41.2.0/24"
       }
      ]
     },
     "to": "ext_vpc"
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
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.41.3.0/24"
       }
      ]
     },
     "to": "ext_vpc"
    }
   ]
  },
  {
   "id": "ext_subnet_names",
   "kind": "all_of",
   "tier": "detail",
   "quote": "\"10.41.0.0/24\" (\"Subnet0-1a\"), \"10.41.1.0/24\" (\"Subnet1-1b\"), \"10.41.2.0/24\" (\"Subnet2-1c\"), and \"10.41.3.0/24\" (\"Subnet3-1d\")",
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
        "value": "10.41.0.0/24"
       },
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "Subnet0-1a"
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
        "value": "10.41.1.0/24"
       },
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "Subnet1-1b"
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
        "value": "10.41.2.0/24"
       },
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "Subnet2-1c"
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
        "value": "10.41.3.0/24"
       },
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "Subnet3-1d"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "subnets_first_four_azs",
   "kind": "all_of",
   "tier": "detail",
   "quote": "across the first four availability zones in the region",
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
        "op": "regex",
        "value": "^10\\.41\\."
       }
      ]
     },
     "distinct_path": [
      "availability_zone"
     ],
     "min": 4
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
        "op": "regex",
        "value": "^10\\.40\\."
       }
      ]
     },
     "distinct_path": [
      "availability_zone"
     ],
     "min": 4
    }
   ],
   "justify": "'first four availability zones' -> four distinct AZs per VPC (AZ names not pinned)"
  },
  {
   "id": "igw_external_gw",
   "kind": "ref",
   "from": "igw",
   "to": "ext_vpc",
   "tier": "core",
   "quote": "an Internet Gateway named \"External GW\""
  },
  {
   "id": "route_to_igw",
   "kind": "any_of",
   "tier": "core",
   "quote": "attached to an Internet Gateway named \"External GW\" via a custom route table",
   "checks": [
    {
     "kind": "ref",
     "from": "rtb",
     "to": "igw"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route"
      ],
      "where": []
     },
     "to": "igw"
    }
   ]
  },
  {
   "id": "rtb_main_association",
   "kind": "all_of",
   "tier": "core",
   "quote": "set as the main route table association for the VPC",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_main_route_table_association"
      ],
      "where": []
     },
     "to": "rtb"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_main_route_table_association"
      ],
      "where": []
     },
     "to": "ext_vpc"
    }
   ]
  },
  {
   "id": "rtb_subnet_associations",
   "kind": "all_of",
   "tier": "detail",
   "quote": "associated with all four subnets",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_route_table_association"
      ],
      "where": []
     },
     "min": 4
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_route_table_association"
      ],
      "where": []
     },
     "to": "rtb"
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
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.41.0.0/24"
       }
      ]
     }
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
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.41.1.0/24"
       }
      ]
     }
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
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.41.2.0/24"
       }
      ]
     }
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
       "aws_subnet"
      ],
      "where": [
       {
        "path": [
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.41.3.0/24"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ext_nacl_icmp_egress",
   "kind": "any_of",
   "tier": "core",
   "quote": "ICMP egress (rule 100 allow)",
   "checks": [
    {
     "kind": "ref",
     "to": "ext_vpc",
     "from": {
      "types": [
       "aws_default_network_acl"
      ],
      "where": [
       {
        "path": [
         "egress",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "rule_no"
          ],
          "op": "eq",
          "value": 100
         },
         {
          "path": [
           "protocol"
          ],
          "op": "in",
          "value": [
           "icmp",
           "1"
          ]
         },
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
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "ext_vpc",
     "from": {
      "types": [
       "aws_network_acl_rule"
      ],
      "where": [
       {
        "path": [
         "egress"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "rule_number"
        ],
        "op": "eq",
        "value": 100
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "icmp",
         "1"
        ]
       },
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
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ext_nacl_all_egress",
   "kind": "any_of",
   "tier": "core",
   "quote": "all-traffic egress (rule 150 allow)",
   "checks": [
    {
     "kind": "ref",
     "to": "ext_vpc",
     "from": {
      "types": [
       "aws_default_network_acl"
      ],
      "where": [
       {
        "path": [
         "egress",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "rule_no"
          ],
          "op": "eq",
          "value": 150
         },
         {
          "path": [
           "protocol"
          ],
          "op": "in",
          "value": [
           "-1",
           "all"
          ]
         },
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
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "ext_vpc",
     "from": {
      "types": [
       "aws_network_acl_rule"
      ],
      "where": [
       {
        "path": [
         "egress"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "rule_number"
        ],
        "op": "eq",
        "value": 150
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "-1",
         "all"
        ]
       },
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
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ext_nacl_all_ingress",
   "kind": "any_of",
   "tier": "core",
   "quote": "all-traffic ingress (rule 100 allow) from \"0.0.0.0/0\"",
   "checks": [
    {
     "kind": "ref",
     "to": "ext_vpc",
     "from": {
      "types": [
       "aws_default_network_acl"
      ],
      "where": [
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "rule_no"
          ],
          "op": "eq",
          "value": 100
         },
         {
          "path": [
           "protocol"
          ],
          "op": "in",
          "value": [
           "-1",
           "all"
          ]
         },
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
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "ext_vpc",
     "from": {
      "types": [
       "aws_network_acl_rule"
      ],
      "where": [
       {
        "path": [
         "egress"
        ],
        "op": "falsy"
       },
       {
        "path": [
         "rule_number"
        ],
        "op": "eq",
        "value": 100
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "-1",
         "all"
        ]
       },
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
       }
      ]
     }
    }
   ]
  },
  {
   "id": "int_vpc_cidr_tenancy",
   "kind": "attr",
   "select": "int_vpc",
   "tier": "core",
   "cond": {
    "path": [
     "instance_tenancy"
    ],
    "op": "eq",
    "value": "default"
   },
   "quote": "The internal VPC must be created with CIDR block \"10.40.0.0/16\", default tenancy"
  },
  {
   "id": "int_vpc_tags",
   "kind": "all_of",
   "tier": "detail",
   "quote": "tags for Name (\"Production Internal\"), purpose (\"Production Internal VPC\"), and environment (\"prod\")",
   "checks": [
    {
     "kind": "attr",
     "select": "int_vpc",
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "Production Internal"
     }
    },
    {
     "kind": "attr",
     "select": "int_vpc",
     "cond": {
      "path": [
       "tags",
       "purpose"
      ],
      "op": "eq",
      "value": "Production Internal VPC"
     }
    },
    {
     "kind": "attr",
     "select": "int_vpc",
     "cond": {
      "path": [
       "tags_all",
       "environment"
      ],
      "op": "eq",
      "value": "prod"
     }
    }
   ]
  },
  {
   "id": "int_default_sg_no_rules",
   "kind": "ref",
   "tier": "detail",
   "to": "int_vpc",
   "from": {
    "types": [
     "aws_default_security_group"
    ],
    "where": [
     {
      "path": [
       "ingress",
       "*"
      ],
      "op": "absent"
     },
     {
      "path": [
       "egress",
       "*"
      ],
      "op": "absent"
     }
    ]
   },
   "quote": "managing its default security group with no ingress or egress rules"
  },
  {
   "id": "int_subnets",
   "kind": "all_of",
   "tier": "core",
   "quote": "Four internal subnets must be created in the internal VPC",
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
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.40.0.0/24"
       }
      ]
     },
     "to": "int_vpc"
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
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.40.1.0/24"
       }
      ]
     },
     "to": "int_vpc"
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
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.40.2.0/24"
       }
      ]
     },
     "to": "int_vpc"
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
         "cidr_block"
        ],
        "op": "eq",
        "value": "10.40.3.0/24"
       }
      ]
     },
     "to": "int_vpc"
    }
   ]
  },
  {
   "id": "int_subnet_names",
   "kind": "all_of",
   "tier": "detail",
   "quote": "\"10.40.0.0/24\" (\"Subnet0-1a\"), \"10.40.1.0/24\" (\"Subnet1-1b\"), \"10.40.2.0/24\" (\"Subnet2-1c\"), and \"10.40.3.0/24\" (\"Subnet3-1d\")",
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
        "value": "10.40.0.0/24"
       },
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "Subnet0-1a"
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
        "value": "10.40.1.0/24"
       },
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "Subnet1-1b"
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
        "value": "10.40.2.0/24"
       },
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "Subnet2-1c"
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
        "value": "10.40.3.0/24"
       },
       {
        "path": [
         "tags",
         "Name"
        ],
        "op": "eq",
        "value": "Subnet3-1d"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "int_nacl_icmp_egress",
   "kind": "any_of",
   "tier": "core",
   "quote": "ICMP egress (rule 100 allow)",
   "checks": [
    {
     "kind": "ref",
     "to": "int_vpc",
     "from": {
      "types": [
       "aws_default_network_acl"
      ],
      "where": [
       {
        "path": [
         "egress",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "rule_no"
          ],
          "op": "eq",
          "value": 100
         },
         {
          "path": [
           "protocol"
          ],
          "op": "in",
          "value": [
           "icmp",
           "1"
          ]
         },
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
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "int_vpc",
     "from": {
      "types": [
       "aws_network_acl_rule"
      ],
      "where": [
       {
        "path": [
         "egress"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "rule_number"
        ],
        "op": "eq",
        "value": 100
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "icmp",
         "1"
        ]
       },
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
       }
      ]
     }
    }
   ]
  },
  {
   "id": "int_nacl_all_egress",
   "kind": "any_of",
   "tier": "core",
   "quote": "all-traffic egress (rule 150 allow)",
   "checks": [
    {
     "kind": "ref",
     "to": "int_vpc",
     "from": {
      "types": [
       "aws_default_network_acl"
      ],
      "where": [
       {
        "path": [
         "egress",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "rule_no"
          ],
          "op": "eq",
          "value": 150
         },
         {
          "path": [
           "protocol"
          ],
          "op": "in",
          "value": [
           "-1",
           "all"
          ]
         },
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
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "int_vpc",
     "from": {
      "types": [
       "aws_network_acl_rule"
      ],
      "where": [
       {
        "path": [
         "egress"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "rule_number"
        ],
        "op": "eq",
        "value": 150
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "-1",
         "all"
        ]
       },
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
       }
      ]
     }
    }
   ]
  },
  {
   "id": "int_nacl_icmp_ingress",
   "kind": "any_of",
   "tier": "core",
   "quote": "ICMP ingress (rule 100 allow) from \"0.0.0.0/0\"",
   "checks": [
    {
     "kind": "ref",
     "to": "int_vpc",
     "from": {
      "types": [
       "aws_default_network_acl"
      ],
      "where": [
       {
        "path": [
         "ingress",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "rule_no"
          ],
          "op": "eq",
          "value": 100
         },
         {
          "path": [
           "protocol"
          ],
          "op": "in",
          "value": [
           "icmp",
           "1"
          ]
         },
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
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "int_vpc",
     "from": {
      "types": [
       "aws_network_acl_rule"
      ],
      "where": [
       {
        "path": [
         "egress"
        ],
        "op": "falsy"
       },
       {
        "path": [
         "rule_number"
        ],
        "op": "eq",
        "value": 100
       },
       {
        "path": [
         "protocol"
        ],
        "op": "in",
        "value": [
         "icmp",
         "1"
        ]
       },
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
       }
      ]
     }
    }
   ]
  },
  {
   "id": "int_nacl_no_all_ingress",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "aws_default_network_acl"
    ],
    "where": [
     {
      "path": [
       "ingress",
       "*",
       "protocol"
      ],
      "op": "in",
      "value": [
       "icmp",
       "1"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "ingress",
     "*",
     "protocol"
    ],
    "op": "none_eq",
    "value": "-1"
   },
   "quote": "explicitly restricts rules to ICMP egress (rule 100 allow), all-traffic egress (rule 150 allow), and ICMP ingress (rule 100 allow)"
  },
  {
   "id": "int_subnets_bound_to_nacl",
   "kind": "any_of",
   "tier": "detail",
   "quote": "bound to a default network ACL",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_default_network_acl"
      ],
      "where": [
       {
        "path": [
         "ingress",
         "*",
         "protocol"
        ],
        "op": "in",
        "value": [
         "icmp",
         "1"
        ]
       }
      ]
     },
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
        "value": "10.40.0.0/24"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_default_network_acl"
      ],
      "where": [
       {
        "path": [
         "ingress",
         "*",
         "protocol"
        ],
        "op": "in",
        "value": [
         "icmp",
         "1"
        ]
       }
      ]
     },
     "to": "int_vpc"
    }
   ],
   "justify": "subnets are implicitly associated with their VPC's default network ACL; explicit subnet_ids optional"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
