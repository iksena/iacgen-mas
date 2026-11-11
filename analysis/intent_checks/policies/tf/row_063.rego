package intent.tf.row_063

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "tgw",
   "kind": "any_of",
   "tier": "core",
   "quote": "creates or attaches to an AWS Transit Gateway",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_ec2_transit_gateway"
      ],
      "where": []
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
        "value": "data.aws_ec2_transit_gateway"
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
        "value": "aws_ec2_transit_gateway_vpc_attachment"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "transit_gateway_id"
      ],
      "op": "regex",
      "value": "var\\."
     }
    }
   ],
   "justify": "'creates or attaches to': a created TGW, a looked-up existing TGW, or a TGW id supplied by a variable"
  },
  {
   "id": "tgw_attach_existing",
   "kind": "any_of",
   "tier": "detail",
   "quote": "creates or attaches to an AWS Transit Gateway",
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
        "value": "data.aws_ec2_transit_gateway"
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
        "value": "(?i)(existing|transit_gateway_id|tgw_id)"
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
        "value": "aws_ec2_transit_gateway_vpc_attachment"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "transit_gateway_id"
      ],
      "op": "regex",
      "value": "var\\."
     }
    }
   ],
   "justify": "attaching to an existing TGW: a data-source lookup or a variable holding its id"
  },
  {
   "id": "vpc_attachment",
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
      "value": "aws_ec2_transit_gateway_vpc_attachment"
     }
    ]
   },
   "quote": "connecting one or more VPCs to it"
  },
  {
   "id": "attachment_on_tgw",
   "kind": "any_of",
   "tier": "core",
   "quote": "connecting one or more VPCs to it",
   "checks": [
    {
     "kind": "ref",
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
        "value": "aws_ec2_transit_gateway_vpc_attachment"
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
        "value": "aws_ec2_transit_gateway"
       }
      ]
     }
    },
    {
     "kind": "ref",
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
        "value": "aws_ec2_transit_gateway_vpc_attachment"
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
        "value": "data.aws_ec2_transit_gateway"
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
        "value": "aws_ec2_transit_gateway_vpc_attachment"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "transit_gateway_id"
      ],
      "op": "regex",
      "value": "(?i)(var|local)\\.\\w*(tgw|transit)"
     }
    }
   ],
   "justify": "the attachment's transit_gateway_id is the created/looked-up TGW, or a variable/local named for it (locals are invisible)"
  },
  {
   "id": "attachment_for_each",
   "kind": "attr",
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
      "value": "aws_ec2_transit_gateway_vpc_attachment"
     }
    ]
   },
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quote": "connecting one or more VPCs",
   "justify": "one or more VPCs means attachments are created per map entry"
  },
  {
   "id": "attachment_subnet_ids",
   "kind": "attr",
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
      "value": "aws_ec2_transit_gateway_vpc_attachment"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "subnet_ids"
    ],
    "op": "present"
   },
   "quote": "via a map of subnet IDs"
  },
  {
   "id": "attachment_vpc_id",
   "kind": "attr",
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
      "value": "aws_ec2_transit_gateway_vpc_attachment"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "vpc_id"
    ],
    "op": "present"
   },
   "quote": "connecting one or more VPCs to it"
  },
  {
   "id": "tgw_dns_support",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_ec2_transit_gateway"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "dns_support"
    ],
    "op": "eq",
    "value": "enable"
   }
  },
  {
   "id": "tgw_default_assoc",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_ec2_transit_gateway"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default_route_table_association"
    ],
    "op": "eq",
    "value": "enable"
   }
  },
  {
   "id": "tgw_default_prop",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_ec2_transit_gateway"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default_route_table_propagation"
    ],
    "op": "eq",
    "value": "enable"
   }
  },
  {
   "id": "tgw_auto_accept",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_ec2_transit_gateway"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "auto_accept_shared_attachments"
    ],
    "op": "eq",
    "value": "disable"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
