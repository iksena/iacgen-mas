package intent.tf.row_030

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "queue_1",
   "tier": "core",
   "quote": "two Amazon SQS queues named \"test-sqs\"",
   "kind": "exists",
   "select": {
    "types": [
     "aws_sqs_queue"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "test-sqs"
     }
    ]
   }
  },
  {
   "id": "queue_2",
   "tier": "core",
   "quote": "\"test-sqs1\"",
   "kind": "exists",
   "select": {
    "types": [
     "aws_sqs_queue"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "test-sqs1"
     }
    ]
   }
  },
  {
   "id": "delay",
   "tier": "core",
   "quote": "a message delivery delay of 90 seconds",
   "kind": "attr",
   "select": {
    "types": [
     "aws_sqs_queue"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "in",
      "value": [
       "test-sqs",
       "test-sqs1"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "delay_seconds"
    ],
    "op": "eq",
    "value": 90
   },
   "quantifier": "all"
  },
  {
   "id": "max_size",
   "tier": "core",
   "quote": "a maximum message size of 2048 bytes",
   "kind": "attr",
   "select": {
    "types": [
     "aws_sqs_queue"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "in",
      "value": [
       "test-sqs",
       "test-sqs1"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "max_message_size"
    ],
    "op": "eq",
    "value": 2048
   },
   "quantifier": "all"
  },
  {
   "id": "retention",
   "tier": "core",
   "quote": "a message retention period of 86400 seconds",
   "kind": "attr",
   "select": {
    "types": [
     "aws_sqs_queue"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "in",
      "value": [
       "test-sqs",
       "test-sqs1"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "message_retention_seconds"
    ],
    "op": "eq",
    "value": 86400
   },
   "quantifier": "all"
  },
  {
   "id": "wait",
   "tier": "core",
   "quote": "a receive wait time of 10 seconds",
   "kind": "attr",
   "select": {
    "types": [
     "aws_sqs_queue"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "in",
      "value": [
       "test-sqs",
       "test-sqs1"
      ]
     }
    ]
   },
   "cond": {
    "path": [
     "receive_wait_time_seconds"
    ],
    "op": "eq",
    "value": 10
   },
   "quantifier": "all"
  },
  {
   "id": "env_tag",
   "tier": "detail",
   "quote": "an Environment tag set to \"production\"",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_sqs_queue"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "in",
        "value": [
         "test-sqs",
         "test-sqs1"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "tags",
       "Environment"
      ],
      "op": "eq",
      "value": "production"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_sqs_queue"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "in",
        "value": [
         "test-sqs",
         "test-sqs1"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "tags_all",
       "Environment"
      ],
      "op": "eq",
      "value": "production"
     },
     "quantifier": "all"
    }
   ]
  },
  {
   "id": "kms_key",
   "tier": "core",
   "quote": "a dedicated customer-managed KMS key",
   "kind": "exists",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   }
  },
  {
   "id": "kms_rotation",
   "tier": "core",
   "quote": "a dedicated customer-managed KMS key with automatic key rotation enabled",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sqs_queue"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "in",
        "value": [
         "test-sqs",
         "test-sqs1"
        ]
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "enable_key_rotation"
        ],
        "op": "truthy"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_alias"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "enable_key_rotation"
        ],
        "op": "truthy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "kms_queue_1",
   "tier": "core",
   "quote": "server-side encryption using a dedicated customer-managed KMS key",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sqs_queue"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "test-sqs"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sqs_queue"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "test-sqs"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_alias"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "kms_queue_2",
   "tier": "core",
   "quote": "server-side encryption using a dedicated customer-managed KMS key",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sqs_queue"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "test-sqs1"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sqs_queue"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "test-sqs1"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_alias"
      ],
      "where": []
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
