# GENERATED from specs/tf/row_139.json by intent_checks/build.py -- do not edit.
package intent.tf.row_139

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "queue": {
   "types": [
    "aws_sqs_queue"
   ],
   "where": []
  },
  "queue_decl": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_sqs_queue"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "primary_queue_created",
   "kind": "exists",
   "select": "queue",
   "tier": "core",
   "quote": "Primary queue creation must be controlled by a boolean variable create defaulting to true"
  },
  {
   "id": "standard_queue_by_default",
   "kind": "attr",
   "select": "queue",
   "tier": "core",
   "quote": "fifo_queue defaulting to false",
   "cond": {
    "path": [
     "fifo_queue"
    ],
    "op": "falsy"
   }
  },
  {
   "id": "sqs_managed_sse_default",
   "kind": "attr",
   "select": "queue",
   "tier": "core",
   "quote": "SQS managed server-side encryption (sqs_managed_sse_enabled defaulting to true)",
   "cond": {
    "path": [
     "sqs_managed_sse_enabled"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "queue_policy_declared",
   "kind": "exists",
   "tier": "core",
   "quote": "custom queue policies",
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
      "value": "aws_sqs_queue_policy"
     }
    ]
   },
   "justify": "'custom queue policies' -> aws_sqs_queue_policy"
  },
  {
   "id": "dlq_declared",
   "kind": "exists",
   "tier": "core",
   "min": 2,
   "quote": "provision a corresponding dead-letter queue",
   "select": "queue_decl",
   "justify": "a dead-letter queue is a second aws_sqs_queue alongside the primary queue"
  },
  {
   "id": "redrive_policy_on_main_queue",
   "kind": "any_of",
   "tier": "core",
   "quote": "attach a redrive policy to the main queue setting maxReceiveCount to 5",
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
        "value": "aws_sqs_queue_redrive_policy"
       },
       {
        "path": [
         "properties",
         "redrive_policy"
        ],
        "op": "contains",
        "value": "maxReceiveCount"
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
        "value": "aws_sqs_queue"
       },
       {
        "path": [
         "properties",
         "redrive_policy"
        ],
        "op": "contains",
        "value": "maxReceiveCount"
       }
      ]
     }
    }
   ],
   "justify": "redrive policy -> aws_sqs_queue_redrive_policy or the queue's redrive_policy (maxReceiveCount is the redrive policy key)"
  },
  {
   "id": "redrive_max_receive_5",
   "kind": "any_of",
   "tier": "detail",
   "quote": "setting maxReceiveCount to 5",
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
        "value": "aws_sqs_queue_redrive_policy"
       },
       {
        "path": [
         "properties",
         "redrive_policy"
        ],
        "op": "regex",
        "value": "(?i)maxReceiveCount\\W{0,4}5([^0-9]|$)"
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
        "value": "aws_sqs_queue"
       },
       {
        "path": [
         "properties",
         "redrive_policy"
        ],
        "op": "regex",
        "value": "(?i)maxReceiveCount\\W{0,4}5([^0-9]|$)"
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
        "value": "(?i)receive"
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
   ],
   "justify": "maxReceiveCount 5 stated in prompt; literal or a receive-count variable defaulting to 5"
  },
  {
   "id": "redrive_allow_by_queue",
   "kind": "any_of",
   "tier": "core",
   "quote": "attach a redrive allow policy to the dead-letter queue restricting redrive permissions byQueue to the main queue ARN",
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
        "value": "aws_sqs_queue_redrive_allow_policy"
       },
       {
        "path": [
         "properties",
         "redrive_allow_policy"
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
        "value": "aws_sqs_queue"
       },
       {
        "path": [
         "properties",
         "redrive_allow_policy"
        ],
        "op": "present"
       }
      ]
     }
    }
   ],
   "justify": "redrive allow policy -> aws_sqs_queue_redrive_allow_policy or the queue's redrive_allow_policy; content often built in a local, which is not resolved"
  },
  {
   "id": "sse_fallback_when_no_kms",
   "kind": "any_of",
   "tier": "detail",
   "quote": "must apply automatically whenever a custom KMS master key ID is omitted",
   "checks": [
    {
     "kind": "attr",
     "select": "queue_decl",
     "cond": {
      "path": [
       "properties",
       "sqs_managed_sse_enabled"
      ],
      "op": "regex",
      "value": "(?i)kms|\\?"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_sqs_queue"
      ],
      "where": [
       {
        "path": [
         "sqs_managed_sse_enabled"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "kms_master_key_id"
        ],
        "op": "absent"
       }
      ]
     }
    }
   ],
   "justify": "SSE setting must be conditional (on the KMS key input, directly or via a local) per prompt; under defaults (no KMS key supplied) SQS-managed SSE being on is the stated outcome"
  },
  {
   "id": "fifo_suffix_handling",
   "kind": "attr",
   "select": "queue_decl",
   "tier": "detail",
   "quote": "automatically managing the .fifo suffix for FIFO queues",
   "cond": {
    "path": [
     "properties",
     "name"
    ],
    "op": "regex",
    "value": "(?i)fifo|local\\."
   },
   "justify": "name must handle the .fifo suffix inline, or delegate to a local (locals are not resolved)"
  },
  {
   "id": "name_prefix_supported",
   "kind": "attr",
   "select": "queue_decl",
   "tier": "detail",
   "quote": "handling name or name_prefix patterns",
   "cond": {
    "path": [
     "properties",
     "name_prefix"
    ],
    "op": "present"
   },
   "justify": "selects the SQS queue type; name_prefix from prompt"
  },
  {
   "id": "param_create",
   "kind": "exists",
   "tier": "detail",
   "quote": "a boolean variable create defaulting to true",
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
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "param_fifo_queue",
   "kind": "exists",
   "tier": "detail",
   "quote": "fifo_queue defaulting to false",
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
      "value": "fifo_queue"
     },
     {
      "path": [
       "default"
      ],
      "op": "falsy"
     }
    ]
   }
  },
  {
   "id": "param_sqs_managed_sse_enabled",
   "kind": "exists",
   "tier": "detail",
   "quote": "sqs_managed_sse_enabled defaulting to true",
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
      "value": "sqs_managed_sse_enabled"
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
   "id": "param_create_queue_policy",
   "kind": "exists",
   "tier": "detail",
   "quote": "create_queue_policy flag defaulting to false",
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
      "value": "create_queue_policy"
     },
     {
      "path": [
       "default"
      ],
      "op": "falsy"
     }
    ]
   }
  },
  {
   "id": "param_create_dlq",
   "kind": "exists",
   "tier": "detail",
   "quote": "create_dlq (defaulting to false)",
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
      "value": "create_dlq"
     },
     {
      "path": [
       "default"
      ],
      "op": "falsy"
     }
    ]
   }
  },
  {
   "id": "param_create_dlq_redrive_allow_policy",
   "kind": "exists",
   "tier": "detail",
   "quote": "create_dlq_redrive_allow_policy is true (defaulting to true)",
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
      "value": "create_dlq_redrive_allow_policy"
     },
     {
      "path": [
       "default"
      ],
      "op": "truthy"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
