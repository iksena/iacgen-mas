package intent.tf.row_172

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "sg": {
   "types": [
    "aws_security_group"
   ],
   "where": []
  },
  "pl": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_ec2_managed_prefix_list"
    },
    {
     "path": [
      "gated"
     ],
     "op": "eq",
     "value": true
    }
   ]
  },
  "existing": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "data.aws_security_group"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "sg_created_by_default",
   "kind": "exists",
   "tier": "core",
   "quote": "When new_sg is true (defaulting to true), provision a new security group",
   "select": "sg"
  },
  {
   "id": "sg_name_suffix",
   "kind": "attr",
   "tier": "detail",
   "quote": "named with a -sg suffix based on the module label ID",
   "select": "sg",
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "-sg$"
   }
  },
  {
   "id": "sg_create_before_destroy",
   "kind": "any_of",
   "tier": "detail",
   "quote": "setting create_before_destroy lifecycle behavior",
   "checks": [
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
         "lifecycle",
         "*",
         "create_before_destroy"
        ],
        "op": "eq",
        "value": true
       }
      ]
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
        "value": "aws_security_group"
       },
       {
        "path": [
         "properties",
         "lifecycle"
        ],
        "op": "regex",
        "value": "create_before_destroy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sg_vpc_variable",
   "kind": "exists",
   "tier": "detail",
   "quote": "in the specified vpc_id",
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
      "value": "vpc_id"
     }
    ]
   }
  },
  {
   "id": "prefix_list_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "conditionally create an EC2 managed prefix list",
   "select": "pl"
  },
  {
   "id": "prefix_list_name",
   "kind": "exists",
   "tier": "detail",
   "quote": "named with a -prefix-list suffix",
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
      "value": "aws_ec2_managed_prefix_list"
     },
     {
      "path": [
       "properties",
       "name"
      ],
      "op": "regex",
      "value": "prefix-list"
     }
    ]
   }
  },
  {
   "id": "prefix_list_family",
   "kind": "any_of",
   "tier": "core",
   "quote": "configured with address family \"IPv4\" (overridable via prefix_list_address_family)",
   "checks": [
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
        "value": "aws_ec2_managed_prefix_list"
       },
       {
        "path": [
         "properties",
         "address_family"
        ],
        "op": "regex",
        "value": "(?i)ipv4"
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
         "name"
        ],
        "op": "eq",
        "value": "prefix_list_address_family"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": "IPv4"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "prefix_list_max_entries",
   "kind": "any_of",
   "tier": "core",
   "quote": "max_entries defaulting to 5",
   "checks": [
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
        "value": "aws_ec2_managed_prefix_list"
       },
       {
        "path": [
         "properties",
         "max_entries"
        ],
        "op": "eq",
        "value": 5
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
         "name"
        ],
        "op": "eq",
        "value": "max_entries"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": 5
       }
      ]
     }
    }
   ]
  },
  {
   "id": "prefix_list_entries",
   "kind": "any_of",
   "tier": "detail",
   "quote": "dynamic entries populated from an entry list",
   "checks": [
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
        "value": "aws_ec2_managed_prefix_list"
       },
       {
        "path": [
         "properties",
         "dynamic",
         "entry"
        ],
        "op": "present"
       }
      ]
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
        "value": "aws_ec2_managed_prefix_list"
       },
       {
        "path": [
         "properties",
         "entry"
        ],
        "op": "present"
       }
      ]
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
        "value": "aws_ec2_managed_prefix_list_entry"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "prefix_list_enabled_flag",
   "kind": "exists",
   "tier": "detail",
   "quote": "When prefix_list_enabled is true (defaulting to false)",
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
      "value": "prefix_list_enabled"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": false
     }
    ]
   }
  },
  {
   "id": "prefix_list_ids_variable",
   "kind": "exists",
   "tier": "detail",
   "quote": "no external prefix_list_ids are supplied",
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
      "value": "prefix_list_ids"
     }
    ]
   }
  },
  {
   "id": "enable_flag",
   "kind": "exists",
   "tier": "detail",
   "quote": "Module execution must be governed by an enable boolean flag defaulting to true",
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
      "value": "enable"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": true
     }
    ]
   }
  },
  {
   "id": "new_sg_flag",
   "kind": "exists",
   "tier": "detail",
   "quote": "When new_sg is true (defaulting to true)",
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
      "value": "new_sg"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": true
     }
    ]
   }
  },
  {
   "id": "managedby_default",
   "kind": "exists",
   "tier": "detail",
   "quote": "managedby (defaulting to \"opsstation\")",
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
      "value": "managedby"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "opsstation"
     }
    ]
   }
  },
  {
   "id": "label_order_default",
   "kind": "exists",
   "tier": "detail",
   "quote": "label_order (defaulting to [\"name\", \"environment\"])",
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
      "value": "label_order"
     },
     {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "name.*environment"
     }
    ]
   }
  },
  {
   "id": "repository_default",
   "kind": "exists",
   "tier": "detail",
   "quote": "repository URL (https://github.com/opsstation/terraform-aws-security_group)",
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
      "value": "repository"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "https://github.com/opsstation/terraform-aws-security_group"
     }
    ]
   }
  },
  {
   "id": "name_environment_vars",
   "kind": "all_of",
   "tier": "detail",
   "quote": "driven by variables for name, environment",
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
         "name"
        ],
        "op": "eq",
        "value": "name"
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
         "name"
        ],
        "op": "eq",
        "value": "environment"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "existing_sg_supported",
   "kind": "any_of",
   "tier": "core",
   "quote": "or an existing security group (referenced via existing_sg_id when supplied)",
   "checks": [
    {
     "kind": "exists",
     "select": "existing"
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
         "name"
        ],
        "op": "eq",
        "value": "existing_sg_id"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "existing_sg_variable",
   "kind": "exists",
   "tier": "detail",
   "quote": "referenced via existing_sg_id when supplied",
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
      "value": "existing_sg_id"
     }
    ]
   }
  },
  {
   "id": "ingress_cidr",
   "kind": "any_of",
   "tier": "core",
   "quote": "across four distinct rule target types: CIDR blocks (supporting IPv4/IPv6), self-referencing rules, source security group IDs, and managed prefix list IDs",
   "checks": [
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
         "properties"
        ],
        "op": "regex",
        "value": "cidr_blocks"
       }
      ]
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
        "value": "aws_vpc_security_group_ingress_rule"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "cidr_ipv4"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ingress_self",
   "kind": "any_of",
   "tier": "core",
   "quote": "across four distinct rule target types: CIDR blocks (supporting IPv4/IPv6), self-referencing rules, source security group IDs, and managed prefix list IDs",
   "checks": [
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
         "properties"
        ],
        "op": "regex",
        "value": "(?i)\\bself\\W{1,4}(true|[$])"
       }
      ]
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
        "value": "aws_vpc_security_group_ingress_rule"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "referenced_security_group_id\": [^,]{0,200}(\\bself\\b|aws_security_group\\.|local\\.[A-Za-z_]*sg_id)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ingress_src",
   "kind": "any_of",
   "tier": "core",
   "quote": "across four distinct rule target types: CIDR blocks (supporting IPv4/IPv6), self-referencing rules, source security group IDs, and managed prefix list IDs",
   "checks": [
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
         "properties"
        ],
        "op": "regex",
        "value": "source_security_group_id"
       }
      ]
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
        "value": "aws_vpc_security_group_ingress_rule"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "referenced_security_group_id"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ingress_pl",
   "kind": "any_of",
   "tier": "core",
   "quote": "across four distinct rule target types: CIDR blocks (supporting IPv4/IPv6), self-referencing rules, source security group IDs, and managed prefix list IDs",
   "checks": [
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
         "properties"
        ],
        "op": "regex",
        "value": "prefix_list_ids"
       }
      ]
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
        "value": "aws_vpc_security_group_ingress_rule"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "prefix_list_id"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "egress_cidr",
   "kind": "any_of",
   "tier": "core",
   "quote": "across four distinct rule target types: CIDR blocks (supporting IPv4/IPv6), self-referencing rules, source security group IDs, and managed prefix list IDs",
   "checks": [
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
         "properties"
        ],
        "op": "regex",
        "value": "cidr_blocks"
       }
      ]
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
        "value": "aws_vpc_security_group_egress_rule"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "cidr_ipv4"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "egress_self",
   "kind": "any_of",
   "tier": "core",
   "quote": "across four distinct rule target types: CIDR blocks (supporting IPv4/IPv6), self-referencing rules, source security group IDs, and managed prefix list IDs",
   "checks": [
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
         "properties"
        ],
        "op": "regex",
        "value": "(?i)\\bself\\W{1,4}(true|[$])"
       }
      ]
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
        "value": "aws_vpc_security_group_egress_rule"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "referenced_security_group_id\": [^,]{0,200}(\\bself\\b|aws_security_group\\.|local\\.[A-Za-z_]*sg_id)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "egress_src",
   "kind": "any_of",
   "tier": "core",
   "quote": "across four distinct rule target types: CIDR blocks (supporting IPv4/IPv6), self-referencing rules, source security group IDs, and managed prefix list IDs",
   "checks": [
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
         "properties"
        ],
        "op": "regex",
        "value": "source_security_group_id"
       }
      ]
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
        "value": "aws_vpc_security_group_egress_rule"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "referenced_security_group_id"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "egress_pl",
   "kind": "any_of",
   "tier": "core",
   "quote": "across four distinct rule target types: CIDR blocks (supporting IPv4/IPv6), self-referencing rules, source security group IDs, and managed prefix list IDs",
   "checks": [
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
         "properties"
        ],
        "op": "regex",
        "value": "prefix_list_ids"
       }
      ]
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
        "value": "aws_vpc_security_group_egress_rule"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "prefix_list_id"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cidr_rules_ipv6",
   "kind": "exists",
   "tier": "detail",
   "quote": "CIDR blocks (supporting IPv4/IPv6)",
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
       "aws_vpc_security_group_ingress_rule",
       "aws_vpc_security_group_egress_rule"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "ipv6_cidr_blocks|cidr_ipv6"
     }
    ]
   }
  },
  {
   "id": "prefix_list_rules_default",
   "kind": "ref",
   "tier": "detail",
   "quote": "managed prefix list IDs (defaulting to the created prefix list ID if none is specified)",
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
       "aws_security_group_rule",
       "aws_vpc_security_group_ingress_rule",
       "aws_vpc_security_group_egress_rule"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "prefix_list_id"
     }
    ]
   },
   "to": "pl"
  },
  {
   "id": "x_sg_tags",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_security_group"
    ],
    "where": [
     {
      "path": [
       "tags",
       "Repository"
      ],
      "op": "present"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
