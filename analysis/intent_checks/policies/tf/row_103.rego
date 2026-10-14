# GENERATED from specs/tf/row_103.json by intent_checks/build.py -- do not edit.
package intent.tf.row_103

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "tgw": {
   "types": [
    "aws_ec2_transit_gateway"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "tgw_created_by_default",
   "kind": "exists",
   "select": "tgw",
   "tier": "core",
   "quote": "a create boolean variable defaulting to true to toggle between provisioning a new Transit Gateway"
  },
  {
   "id": "tgw_default_rt_assoc_disabled",
   "kind": "attr",
   "select": "tgw",
   "tier": "core",
   "cond": {
    "path": [
     "default_route_table_association"
    ],
    "op": "eq",
    "value": "disable"
   },
   "quote": "both default route table association and default route table propagation must be explicitly disabled"
  },
  {
   "id": "tgw_default_rt_prop_disabled",
   "kind": "attr",
   "select": "tgw",
   "tier": "core",
   "cond": {
    "path": [
     "default_route_table_propagation"
    ],
    "op": "eq",
    "value": "disable"
   },
   "quote": "both default route table association and default route table propagation must be explicitly disabled"
  },
  {
   "id": "tgw_asn_65200",
   "kind": "attr",
   "select": "tgw",
   "tier": "core",
   "cond": {
    "path": [
     "amazon_side_asn"
    ],
    "op": "eq",
    "value": 65200
   },
   "quote": "BGP ASN defaulting to 65200"
  },
  {
   "id": "tgw_create_toggle",
   "kind": "all_of",
   "tier": "detail",
   "quote": "a create boolean variable defaulting to true",
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
        "value": "create"
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
        "value": "aws_ec2_transit_gateway"
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
   "id": "existing_tgw_id_var",
   "kind": "exists",
   "tier": "detail",
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
      "value": "id"
     },
     {
      "path": [
       "default"
      ],
      "op": "absent"
     }
    ]
   },
   "quote": "via an id variable defaulting to null"
  },
  {
   "id": "tgw_config_vars",
   "kind": "all_of",
   "tier": "detail",
   "quote": "allowing configuration of BGP ASN defaulting to 65200, auto_accept_shared_attachments, dns_support, vpn_ecmp_support, and transit_gateway_cidr_blocks",
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
        "op": "contains",
        "value": "auto_accept_shared_attachments"
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
        "op": "contains",
        "value": "dns_support"
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
        "op": "contains",
        "value": "vpn_ecmp_support"
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
        "op": "contains",
        "value": "cidr_blocks"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "route_tables_capability",
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
      "op": "eq",
      "value": "aws_ec2_transit_gateway_route_table"
     }
    ]
   },
   "quote": "each item conditionally creates a new Transit Gateway route table"
  },
  {
   "id": "route_tables_var",
   "kind": "exists",
   "tier": "detail",
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
      "value": "route_tables"
     }
    ]
   },
   "quote": "process a map of route_tables"
  },
  {
   "id": "ram_share_capability",
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
      "op": "eq",
      "value": "aws_ram_resource_share"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "if a shared_principals map variable contains entries, provision an AWS RAM resource share"
  },
  {
   "id": "ram_tgw_association_capability",
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
      "op": "eq",
      "value": "aws_ram_resource_association"
     }
    ]
   },
   "quote": "associate the Transit Gateway to the share"
  },
  {
   "id": "ram_principal_association_capability",
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
      "op": "eq",
      "value": "aws_ram_principal_association"
     }
    ]
   },
   "quote": "attach each principal specified in the map"
  },
  {
   "id": "shared_principals_var",
   "kind": "exists",
   "tier": "detail",
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
      "value": "shared_principals"
     }
    ]
   },
   "quote": "a shared_principals map variable"
  },
  {
   "id": "ram_share_name_var",
   "kind": "exists",
   "tier": "detail",
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
      "value": "ram_resource_share_name"
     }
    ]
   },
   "quote": "an explicit ram_resource_share_name variable"
  },
  {
   "id": "ram_share_allows_external",
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
      "op": "eq",
      "value": "aws_ram_resource_share"
     },
     {
      "path": [
       "properties",
       "allow_external_principals"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "provision an AWS RAM resource share that permits external principals"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
