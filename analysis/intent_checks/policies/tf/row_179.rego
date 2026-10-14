# GENERATED from specs/tf/row_179.json by intent_checks/build.py -- do not edit.
package intent.tf.row_179

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
  "decl_sg": {
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
      "aws_security_group"
     ]
    }
   ]
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
     "op": "in",
     "value": [
      "aws_ec2_managed_prefix_list"
     ]
    }
   ]
  }
 },
 "checks": [
  {
   "id": "new_sg_created_by_default",
   "kind": "exists",
   "select": "sg",
   "tier": "core",
   "quote": "supporting either a newly created security group"
  },
  {
   "id": "default_allow_all_ipv4_egress",
   "kind": "any_of",
   "tier": "core",
   "quote": "defaulting to allowing all outbound IPv4 traffic",
   "checks": [
    {
     "kind": "ref",
     "to": "sg",
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
        "value": "0.0.0.0/0"
       },
       {
        "path": [
         "ip_protocol"
        ],
        "op": "in",
        "value": [
         "-1",
         "all"
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "sg",
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
        "value": "0.0.0.0/0"
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
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "sg",
     "cond": {
      "path": [
       "egress",
       "*"
      ],
      "op": "match",
      "value": [
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
         "-1",
         "all"
        ]
       }
      ]
     }
    }
   ],
   "justify": "'all outbound IPv4 traffic' -> 0.0.0.0/0 with all protocols"
  },
  {
   "id": "sg_creation_toggled",
   "kind": "exists",
   "tier": "detail",
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
       "aws_security_group"
      ]
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "controlled by toggles for overall module creation and whether to create a new group"
  },
  {
   "id": "separate_ingress_rule_resources",
   "kind": "exists",
   "tier": "core",
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
       "aws_vpc_security_group_ingress_rule",
       "aws_security_group_rule"
      ]
     }
    ]
   },
   "quote": "adding rules to an existing security group supplied as an input parameter"
  },
  {
   "id": "separate_egress_rule_resources",
   "kind": "exists",
   "tier": "core",
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
       "aws_vpc_security_group_egress_rule",
       "aws_security_group_rule"
      ]
     }
    ]
   },
   "quote": "separate, flexible lists of ingress and egress rule objects"
  },
  {
   "id": "rules_support_cidr",
   "kind": "all_of",
   "tier": "detail",
   "quote": "an IPv4 or IPv6 CIDR block",
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
         "aws_vpc_security_group_ingress_rule",
         "aws_vpc_security_group_egress_rule",
         "aws_security_group_rule",
         "aws_security_group"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "cidr_ipv4|cidr_blocks"
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
        "op": "in",
        "value": [
         "aws_vpc_security_group_ingress_rule",
         "aws_vpc_security_group_egress_rule",
         "aws_security_group_rule",
         "aws_security_group"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "cidr_ipv6|ipv6_cidr_blocks"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "rules_support_source_sg",
   "kind": "exists",
   "tier": "detail",
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
       "aws_vpc_security_group_ingress_rule",
       "aws_vpc_security_group_egress_rule",
       "aws_security_group_rule"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "referenced_security_group_id|source_security_group_id"
     }
    ]
   },
   "quote": "a referenced security group ID"
  },
  {
   "id": "rules_support_prefix_list",
   "kind": "exists",
   "tier": "detail",
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
       "aws_vpc_security_group_ingress_rule",
       "aws_vpc_security_group_egress_rule",
       "aws_security_group_rule"
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
   "quote": "a managed prefix list ID"
  },
  {
   "id": "sg_create_before_destroy",
   "kind": "attr",
   "select": "decl_sg",
   "tier": "detail",
   "cond": {
    "path": [
     "properties",
     "lifecycle",
     "*",
     "create_before_destroy"
    ],
    "op": "present"
   },
   "quote": "a configurable create-before-destroy lifecycle"
  },
  {
   "id": "sg_revoke_rules_on_delete",
   "kind": "attr",
   "select": "decl_sg",
   "tier": "detail",
   "cond": {
    "path": [
     "properties",
     "revoke_rules_on_delete"
    ],
    "op": "present"
   },
   "quote": "rule-revocation-on-delete behavior"
  },
  {
   "id": "prefix_list_capability",
   "kind": "exists",
   "tier": "core",
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
       "aws_ec2_managed_prefix_list"
      ]
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "optionally create a customer-managed EC2 prefix list"
  },
  {
   "id": "prefix_list_config",
   "kind": "all_of",
   "tier": "detail",
   "quote": "with a configurable address family and maximum entry count",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_pl",
     "cond": {
      "path": [
       "properties",
       "address_family"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "decl_pl",
     "cond": {
      "path": [
       "properties",
       "max_entries"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "prefix_list_entries",
   "kind": "any_of",
   "tier": "detail",
   "quote": "populated from a list of CIDR entries",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_pl",
     "cond": {
      "path": [
       "properties",
       "dynamic",
       "entry"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "decl_pl",
     "cond": {
      "path": [
       "properties",
       "entry"
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
         "aws_ec2_managed_prefix_list_entry"
        ]
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
