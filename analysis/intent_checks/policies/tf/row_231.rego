package intent.tf.row_231

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
  "sg": {
   "types": [
    "aws_security_group"
   ],
   "where": []
  },
  "decl_pl": {
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
    }
   ]
  },
  "decl_rule": {
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
      "aws_vpc_security_group_egress_rule",
      "aws_security_group"
     ]
    }
   ]
  }
 },
 "checks": [
  {
   "id": "new_sg_by_default",
   "kind": "exists",
   "select": "sg",
   "tier": "core",
   "quote": "creating a new security group"
  },
  {
   "id": "fallback_vpc_cidr",
   "kind": "exists",
   "select": "vpc",
   "tier": "core",
   "quote": "automatically provision a fallback VPC with CIDR 10.0.0.0/16"
  },
  {
   "id": "sg_in_fallback_vpc",
   "kind": "ref",
   "from": "sg",
   "to": "vpc",
   "tier": "core",
   "quote": "to host the security group"
  },
  {
   "id": "fallback_vpc_conditional",
   "kind": "exists",
   "tier": "core",
   "quote": "If a new security group is requested and no VPC ID is supplied",
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
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "properties",
       "cidr_block"
      ],
      "op": "contains",
      "value": "10.0.0.0/16"
     }
    ]
   }
  },
  {
   "id": "sg_creation_toggle",
   "kind": "exists",
   "tier": "core",
   "quote": "allow toggling between creating a new security group or attaching rules to an existing security group",
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
       "gated"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "existing_sg_rules",
   "kind": "exists",
   "tier": "core",
   "quote": "attaching rules to an existing security group",
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
       "properties",
       "security_group_id"
      ],
      "op": "regex",
      "value": "(var|data|local)\\."
     }
    ]
   },
   "justify": "an \"existing security group\" is referenced by an input/lookup ID, not a new resource"
  },
  {
   "id": "enable_toggle",
   "kind": "exists",
   "tier": "core",
   "quote": "a main enable toggle (defaulting to true)",
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
      "value": "(?i)enable"
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
   "id": "sg_name_suffix",
   "kind": "attr",
   "select": "sg",
   "tier": "detail",
   "quote": "appending -sg for new security groups",
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "-sg$"
   }
  },
  {
   "id": "sg_tagged_by_label",
   "kind": "attr",
   "select": "sg",
   "tier": "detail",
   "quote": "Resource naming and tagging must integrate with the git-based label module",
   "cond": {
    "path": [
     "tags"
    ],
    "op": "len_gte",
    "value": 1
   }
  },
  {
   "id": "prefix_list_optional",
   "kind": "exists",
   "tier": "core",
   "quote": "support optional managed prefix list creation",
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
       "gated"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "prefix_list_name_suffix",
   "kind": "attr",
   "select": "decl_pl",
   "tier": "detail",
   "quote": "-prefix-list for managed prefix lists",
   "cond": {
    "path": [
     "properties",
     "name"
    ],
    "op": "regex",
    "value": "(?i)prefix[-_]list"
   }
  },
  {
   "id": "prefix_list_ipv4",
   "kind": "any_of",
   "tier": "detail",
   "quote": "defaulting to IPv4 address family",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_pl",
     "cond": {
      "path": [
       "properties",
       "address_family"
      ],
      "op": "contains",
      "value": "ipv4"
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
        "op": "regex",
        "value": "(?i)address_family"
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
   "id": "prefix_list_max_5",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a maximum of 5 entries",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_pl",
     "cond": {
      "path": [
       "properties",
       "max_entries"
      ],
      "op": "regex",
      "value": "(^|[^0-9])5([^0-9]|$)"
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
        "op": "regex",
        "value": "(?i)max_entries"
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
   "id": "rules_ingress_inputs",
   "kind": "any_of",
   "tier": "core",
   "quote": "separate categorized rule inputs for ingress and egress",
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
        "op": "in",
        "value": [
         "aws_security_group_rule",
         "aws_vpc_security_group_ingress_rule"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "ingress"
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
         "properties"
        ],
        "op": "regex",
        "value": "ingress"
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
        "op": "regex",
        "value": "(?i)ingress"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "rules_egress_inputs",
   "kind": "any_of",
   "tier": "core",
   "quote": "separate categorized rule inputs for ingress and egress",
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
        "op": "in",
        "value": [
         "aws_security_group_rule",
         "aws_vpc_security_group_egress_rule"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "egress"
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
         "properties"
        ],
        "op": "regex",
        "value": "egress"
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
        "op": "regex",
        "value": "(?i)egress"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "rules_cidr_category",
   "kind": "attr",
   "select": "decl_rule",
   "tier": "detail",
   "quote": "based on CIDR blocks",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "cidr_blocks|cidr_ipv4"
   }
  },
  {
   "id": "rules_self_category",
   "kind": "attr",
   "select": "decl_rule",
   "tier": "detail",
   "quote": "self-referencing rules",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "\\bself\\b"
   }
  },
  {
   "id": "rules_source_sg_category",
   "kind": "attr",
   "select": "decl_rule",
   "tier": "detail",
   "quote": "source security group IDs",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "source_security_group_id|referenced_security_group_id|security_groups"
   }
  },
  {
   "id": "rules_prefix_list_default_new",
   "kind": "any_of",
   "tier": "detail",
   "quote": "prefix lists (defaulting to the newly created prefix list when unspecified)",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_rule",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "prefix_list_ids?\\W[^\\]]*(aws_ec2_managed_prefix_list|local\\.\\w*prefix_list)"
     }
    },
    {
     "kind": "ref",
     "from": "decl_rule",
     "to": "decl_pl"
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
