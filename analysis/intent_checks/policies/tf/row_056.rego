package intent.tf.row_056

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "cluster",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_dsql_cluster"
    ],
    "where": []
   },
   "quote": "creates an Amazon Aurora DSQL cluster"
  },
  {
   "id": "multi_region",
   "kind": "any_of",
   "tier": "core",
   "quote": "optional multi-region support",
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
        "value": "aws_dsql_cluster"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "multi_region_properties"
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
        "value": "aws_dsql_cluster"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "dynamic",
       "multi_region_properties"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "peering_declared",
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
      "value": "aws_dsql_cluster_peering"
     }
    ]
   },
   "quote": "an optional cluster peering relationship to other DSQL clusters"
  },
  {
   "id": "creation_controlled",
   "kind": "any_of",
   "tier": "detail",
   "quote": "The cluster's creation",
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
        "value": "aws_dsql_cluster"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "count"
      ],
      "op": "regex",
      "value": "var\\.|local\\."
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
        "value": "aws_dsql_cluster"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "for_each"
      ],
      "op": "regex",
      "value": "var\\.|local\\."
     }
    }
   ],
   "justify": "creation controlled by an input variable means a count/for_each driven by a variable"
  },
  {
   "id": "deletion_protection_var",
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
      "value": "aws_dsql_cluster"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "deletion_protection_enabled"
    ],
    "op": "regex",
    "value": "var\\.|local\\."
   },
   "quote": "deletion protection"
  },
  {
   "id": "kms_key_var",
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
      "value": "aws_dsql_cluster"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "kms_encryption_key"
    ],
    "op": "regex",
    "value": "var\\.|local\\."
   },
   "quote": "KMS encryption key"
  },
  {
   "id": "force_destroy_var",
   "kind": "attr",
   "tier": "detail",
   "quote": "force-destroy behavior",
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
      "value": "aws_dsql_cluster"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "force_destroy"
    ],
    "op": "regex",
    "value": "var\\.|local\\."
   }
  },
  {
   "id": "peering_gated",
   "kind": "any_of",
   "tier": "core",
   "quote": "should only be provisioned when explicitly enabled",
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
        "value": "aws_dsql_cluster_peering"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "count"
      ],
      "op": "regex",
      "value": "var\\.|local\\."
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
        "value": "aws_dsql_cluster_peering"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "for_each"
      ],
      "op": "regex",
      "value": "var\\.|local\\."
     }
    }
   ]
  },
  {
   "id": "peering_clusters",
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
      "value": "aws_dsql_cluster_peering"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "clusters"
    ],
    "op": "present"
   },
   "quote": "alongside a list of clusters to peer with"
  },
  {
   "id": "peering_witness",
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
      "value": "aws_dsql_cluster_peering"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "witness_region"
    ],
    "op": "present"
   },
   "quote": "including its own optional witness region"
  },
  {
   "id": "peering_timeout",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a configurable timeout for the create operation",
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
        "value": "aws_dsql_cluster_peering"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "timeouts",
       "*",
       "create"
      ],
      "op": "regex",
      "value": "var\\.|local\\."
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
        "value": "aws_dsql_cluster_peering"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "dynamic",
       "timeouts",
       "content",
       "*",
       "create"
      ],
      "op": "present"
     }
    }
   ],
   "justify": "configurable create timeout = a timeouts block whose create value comes from an input (variable/local or a dynamic block over one)"
  },
  {
   "id": "peering_uses_cluster",
   "kind": "ref",
   "tier": "extra",
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
      "value": "aws_dsql_cluster_peering"
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
      "value": "aws_dsql_cluster"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
