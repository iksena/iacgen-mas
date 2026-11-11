package intent.tf.row_000

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "queue": {
   "types": [
    "aws_sqs_queue"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "notificationQueue"
    }
   ]
  },
  "queue_any": {
   "types": [
    "aws_sqs_queue"
   ],
   "where": []
  },
  "kms": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "queue_named",
   "kind": "exists",
   "tier": "core",
   "select": "queue",
   "quote": "creates an Amazon SQS queue named \"notificationQueue\""
  },
  {
   "id": "queue_delay",
   "kind": "attr",
   "tier": "core",
   "select": "queue_any",
   "cond": {
    "path": [
     "delay_seconds"
    ],
    "op": "eq",
    "value": 0
   },
   "quote": "a zero-second delivery delay",
   "justify": "zero-second delay means 0"
  },
  {
   "id": "queue_max_size",
   "kind": "attr",
   "tier": "core",
   "select": "queue_any",
   "cond": {
    "path": [
     "max_message_size"
    ],
    "op": "eq",
    "value": 2048
   },
   "quote": "a maximum message size of 2048 bytes"
  },
  {
   "id": "queue_visibility",
   "kind": "attr",
   "tier": "core",
   "select": "queue_any",
   "cond": {
    "path": [
     "visibility_timeout_seconds"
    ],
    "op": "eq",
    "value": 30
   },
   "quote": "a visibility timeout of 30 seconds"
  },
  {
   "id": "queue_retention",
   "kind": "attr",
   "tier": "core",
   "select": "queue_any",
   "cond": {
    "path": [
     "message_retention_seconds"
    ],
    "op": "eq",
    "value": 345600
   },
   "quote": "a message retention period of 345600 seconds"
  },
  {
   "id": "queue_uses_cmk",
   "kind": "any_of",
   "tier": "core",
   "quote": "encrypted with a new customer-managed KMS key",
   "checks": [
    {
     "kind": "ref",
     "from": "queue_any",
     "to": "kms"
    },
    {
     "kind": "ref",
     "from": "queue_any",
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
   "id": "kms_rotation",
   "kind": "attr",
   "tier": "core",
   "select": "kms",
   "cond": {
    "path": [
     "enable_key_rotation"
    ],
    "op": "truthy"
   },
   "quote": "key rotation enabled"
  },
  {
   "id": "queue_policy_exists",
   "kind": "any_of",
   "tier": "core",
   "quote": "attach a resource-based queue policy",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sqs_queue_policy"
      ],
      "where": []
     },
     "to": "queue_any"
    },
    {
     "kind": "attr",
     "select": "queue_any",
     "cond": {
      "path": [
       "policy"
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
        "value": "aws_sqs_queue"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "policy_send",
   "kind": "any_of",
   "tier": "core",
   "quote": "send, receive, and delete messages and read queue attributes",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sqs_queue_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "actions",
           "*"
          ],
          "op": "glob_covers",
          "value": "sqs:SendMessage"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_sqs_queue_policy",
       "aws_sqs_queue"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\"(sqs:(sendmessage|send\\*|\\*))\""
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
        "op": "in",
        "value": [
         "aws_sqs_queue_policy",
         "aws_sqs_queue"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)'sqs:(sendmessage|send\\*|\\*)'"
     }
    }
   ]
  },
  {
   "id": "policy_receive",
   "kind": "any_of",
   "tier": "core",
   "quote": "send, receive, and delete messages and read queue attributes",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sqs_queue_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "actions",
           "*"
          ],
          "op": "glob_covers",
          "value": "sqs:ReceiveMessage"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_sqs_queue_policy",
       "aws_sqs_queue"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\"(sqs:(receivemessage|receive\\*|\\*))\""
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
        "op": "in",
        "value": [
         "aws_sqs_queue_policy",
         "aws_sqs_queue"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)'sqs:(receivemessage|receive\\*|\\*)'"
     }
    }
   ]
  },
  {
   "id": "policy_delete",
   "kind": "any_of",
   "tier": "core",
   "quote": "send, receive, and delete messages and read queue attributes",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sqs_queue_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "actions",
           "*"
          ],
          "op": "glob_covers",
          "value": "sqs:DeleteMessage"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_sqs_queue_policy",
       "aws_sqs_queue"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\"(sqs:(deletemessage|delete\\*|\\*))\""
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
        "op": "in",
        "value": [
         "aws_sqs_queue_policy",
         "aws_sqs_queue"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)'sqs:(deletemessage|delete\\*|\\*)'"
     }
    }
   ]
  },
  {
   "id": "policy_get_attrs",
   "kind": "any_of",
   "tier": "core",
   "quote": "send, receive, and delete messages and read queue attributes",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sqs_queue_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "actions",
           "*"
          ],
          "op": "glob_covers",
          "value": "sqs:GetQueueAttributes"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_sqs_queue_policy",
       "aws_sqs_queue"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\"(sqs:(getqueueattributes|get\\*|getqueue\\*|\\*))\""
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
        "op": "in",
        "value": [
         "aws_sqs_queue_policy",
         "aws_sqs_queue"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)'sqs:(getqueueattributes|get\\*|getqueue\\*|\\*)'"
     }
    }
   ]
  },
  {
   "id": "policy_current_account",
   "kind": "any_of",
   "tier": "core",
   "quote": "allows only the current AWS account",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sqs_queue_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "regex",
          "value": "^(arn:aws[a-z-]*:iam::\\d{12}:root|\\d{12})$"
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "none_eq",
          "value": "*"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_sqs_queue_policy",
       "aws_sqs_queue"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)\"principal\":\\s*\\{\\s*\"aws\":\\s*\\[?\\s*\"(arn:aws[a-z-]*:iam::\\d{12}:root|\\d{12})\"\\s*\\]?\\s*\\}"
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
        "op": "in",
        "value": [
         "aws_sqs_queue_policy",
         "aws_sqs_queue"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)'principal':\\s*\\{'aws':\\s*\\[?'([^']*(caller_identity|account|:root)[^']*|\\d{12})'\\]?\\}"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
