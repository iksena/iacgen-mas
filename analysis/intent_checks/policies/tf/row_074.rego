package intent.tf.row_074

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "topic1",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_sns_topic"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "my-topic-with-policy"
     }
    ]
   },
   "quote": "two topics named \"my-topic-with-policy\" and \"my-topic-with-policy2\""
  },
  {
   "id": "topic2",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_sns_topic"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "my-topic-with-policy2"
     }
    ]
   },
   "quote": "two topics named \"my-topic-with-policy\" and \"my-topic-with-policy2\""
  },
  {
   "id": "topic3",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_sns_topic"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "user-updates-topic"
     }
    ]
   },
   "quote": "a third topic named \"user-updates-topic\""
  },
  {
   "id": "topic_policy",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_sns_topic_policy"
    ],
    "where": []
   },
   "quote": "sharing a topic policy"
  },
  {
   "id": "policy_on_topic1",
   "kind": "ref",
   "tier": "core",
   "from": {
    "types": [
     "aws_sns_topic_policy"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_sns_topic"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "my-topic-with-policy"
     }
    ]
   },
   "quote": "a topic policy that allows all AWS principals full SNS actions on the first topic"
  },
  {
   "id": "policy_on_topic2",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "aws_sns_topic_policy"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_sns_topic"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "my-topic-with-policy2"
     }
    ]
   },
   "quote": "sharing a topic policy"
  },
  {
   "id": "policy_all_principals",
   "kind": "any_of",
   "tier": "core",
   "quote": "allows all AWS principals",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sns_topic_policy"
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
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "*"
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
        "value": "aws_sns_topic_policy"
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "\"identifiers\": \\[\"\\*\"\\]"
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
        "value": "aws_sns_topic_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?s)jsonencode.*Principal.{0,30}['\"]\\*['\"]"
     }
    }
   ],
   "justify": "all AWS principals means the wildcard principal, in the document the topic policy uses"
  },
  {
   "id": "policy_full_actions",
   "kind": "any_of",
   "tier": "core",
   "quote": "full SNS actions",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sns_topic_policy"
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
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "sns:DeleteTopic"
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
        "value": "aws_sns_topic_policy"
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)\"sns:(\\*|DeleteTopic)\""
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
        "value": "aws_sns_topic_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)jsonencode.*sns:(\\*|DeleteTopic)"
     }
    }
   ],
   "justify": "full SNS actions covers administrative actions such as DeleteTopic, not just Publish"
  },
  {
   "id": "policy_allows",
   "kind": "any_of",
   "tier": "detail",
   "quote": "allows all AWS principals full SNS actions",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sns_topic_policy"
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
         "*",
         "effect"
        ],
        "op": "eq",
        "value": "Allow"
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
        "value": "aws_sns_topic_policy"
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)\"effect\": \"allow\""
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
        "value": "aws_sns_topic_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)jsonencode.*Effect.{0,10}Allow"
     }
    }
   ],
   "justify": "the statement effect is Allow, in the document the topic policy uses"
  },
  {
   "id": "policy_resource_first_topic",
   "kind": "any_of",
   "tier": "detail",
   "quote": "on the first topic",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "my-topic-with-policy"
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "to": {
      "types": [
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "my-topic-with-policy"
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
        "value": "aws_sns_topic_policy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "regex",
        "value": "jsonencode"
       }
      ]
     },
     "to": {
      "types": [
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "my-topic-with-policy"
       }
      ]
     }
    }
   ],
   "justify": "an inline jsonencode() topic policy on the first topic is an equivalent encoding of the policy document"
  },
  {
   "id": "topic3_delivery_policy",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "user-updates-topic"
       }
      ]
     },
     "cond": {
      "path": [
       "delivery_policy"
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
        "value": "aws_sns_topic"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "user-updates-topic"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "delivery_policy"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "configured with a custom delivery policy"
  },
  {
   "id": "delivery_retry",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "user-updates-topic"
       }
      ]
     },
     "cond": {
      "path": [
       "delivery_policy"
      ],
      "op": "regex",
      "value": "(?i)retry"
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
        "value": "aws_sns_topic"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "user-updates-topic"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "delivery_policy"
      ],
      "op": "regex",
      "value": "(?i)retry"
     }
    }
   ],
   "quote": "custom delivery policy for retry and throttling behavior",
   "justify": "retry behaviour appears as a retry policy in the delivery policy"
  },
  {
   "id": "delivery_throttle",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "user-updates-topic"
       }
      ]
     },
     "cond": {
      "path": [
       "delivery_policy"
      ],
      "op": "regex",
      "value": "(?i)throttle"
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
        "value": "aws_sns_topic"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "user-updates-topic"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "delivery_policy"
      ],
      "op": "regex",
      "value": "(?i)throttle"
     }
    }
   ],
   "quote": "custom delivery policy for retry and throttling behavior",
   "justify": "throttling behaviour appears as a throttle policy in the delivery policy"
  },
  {
   "id": "kms",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "quote": "encrypted using a customer-managed KMS key with rotation enabled"
  },
  {
   "id": "kms_rotation",
   "kind": "ref",
   "tier": "core",
   "quote": "with rotation enabled",
   "from": {
    "types": [
     "aws_sns_topic"
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
  },
  {
   "id": "topic1_cmk",
   "kind": "any_of",
   "tier": "core",
   "quote": "all three topics encrypted using a customer-managed KMS key",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "my-topic-with-policy"
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
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "my-topic-with-policy"
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
   "id": "topic2_cmk",
   "kind": "any_of",
   "tier": "core",
   "quote": "all three topics encrypted using a customer-managed KMS key",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "my-topic-with-policy2"
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
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "my-topic-with-policy2"
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
   "id": "topic3_cmk",
   "kind": "any_of",
   "tier": "core",
   "quote": "all three topics encrypted using a customer-managed KMS key",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "user-updates-topic"
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
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "user-updates-topic"
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
