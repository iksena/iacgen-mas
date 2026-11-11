package intent.tf.row_061

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "topic",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_sns_topic"
    ],
    "where": []
   },
   "quote": "creates a versatile Amazon SNS topic module"
  },
  {
   "id": "topic_gated",
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
      "value": "aws_sns_topic"
     }
    ]
   },
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quote": "conditional creation of all resources using a main toggle variable",
   "justify": "conditional creation via a toggle means count/for_each gated"
  },
  {
   "id": "policy_gated",
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
      "value": "aws_sns_topic_policy"
     }
    ]
   },
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quote": "conditional creation of all resources using a main toggle variable",
   "justify": "conditional creation via a toggle means count/for_each gated"
  },
  {
   "id": "name_or_prefix",
   "kind": "any_of",
   "tier": "detail",
   "quote": "setting the topic name or name prefix",
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
        "value": "aws_sns_topic"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "name"
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
        "value": "aws_sns_topic"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "name_prefix"
      ],
      "op": "regex",
      "value": "var\\.|local\\."
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
        "value": "(?i)^(topic_)?name(_prefix)?$"
       }
      ]
     }
    }
   ],
   "justify": "'allowing setting X' means X comes from an input: a var/local reference or a variable named for it; a variable with a non-null default resolves to a literal in the declared name, so a variable named for the setting is also accepted"
  },
  {
   "id": "display_name",
   "kind": "any_of",
   "tier": "detail",
   "quote": "display name",
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
        "value": "aws_sns_topic"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "display_name"
      ],
      "op": "regex",
      "value": "var\\.|local\\."
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
        "value": "(?i)display_?name"
       }
      ]
     }
    }
   ],
   "justify": "'allowing setting X' means X comes from an input: a var/local reference or a variable named for it"
  },
  {
   "id": "fifo",
   "kind": "any_of",
   "tier": "detail",
   "quote": "FIFO configurations",
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
        "value": "aws_sns_topic"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "fifo_topic"
      ],
      "op": "regex",
      "value": "var\\.|local\\."
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
        "value": "(?i)fifo"
       }
      ]
     }
    }
   ],
   "justify": "'allowing setting X' means X comes from an input: a var/local reference or a variable named for it"
  },
  {
   "id": "fifo_dedup",
   "kind": "any_of",
   "tier": "detail",
   "quote": "content-based deduplication",
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
        "value": "aws_sns_topic"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "content_based_deduplication"
      ],
      "op": "regex",
      "value": "var\\.|local\\."
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
        "value": "(?i)dedup"
       }
      ]
     }
    }
   ],
   "justify": "'allowing setting X' means X comes from an input: a var/local reference or a variable named for it"
  },
  {
   "id": "kms",
   "kind": "any_of",
   "tier": "detail",
   "quote": "KMS master key IDs",
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
        "value": "aws_sns_topic"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "kms_master_key_id"
      ],
      "op": "regex",
      "value": "var\\.|local\\."
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
        "value": "(?i)kms"
       }
      ]
     }
    }
   ],
   "justify": "'allowing setting X' means X comes from an input: a var/local reference or a variable named for it"
  },
  {
   "id": "feedback",
   "kind": "all_of",
   "tier": "detail",
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
        "value": "aws_sns_topic"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "sqs_(success|failure)_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "lambda_(success|failure)_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "http_(success|failure)_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "firehose_(success|failure)_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "application_(success|failure)_feedback_role_arn"
     }
    }
   ],
   "quote": "protocol-specific feedback configurations for SQS, Lambda, HTTP, Firehose, and application targets"
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
   "quote": "managed IAM topic policies for message publishing and event notifications"
  },
  {
   "id": "policy_on_topic",
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
    "where": []
   },
   "quote": "managed IAM topic policies"
  },
  {
   "id": "policy_document",
   "kind": "any_of",
   "tier": "core",
   "quote": "constructing an IAM topic policy",
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
      "where": []
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
      "value": "jsonencode|local\\.\\w*policy"
     }
    }
   ],
   "justify": "the topic policy is built in-template: a policy document it references, an inline jsonencode(), or a local named for the policy (locals are invisible)"
  },
  {
   "id": "owner_access",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a default owner-access statement",
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
         "statement"
        ],
        "op": "regex",
        "value": "(?i)SourceOwner|SourceAccount|:root"
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
        "value": "(?i)SourceOwner|SourceAccount|:root"
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
      "value": "(?is)jsonencode.*(SourceOwner|SourceAccount|:root)"
     }
    }
   ],
   "justify": "the default owner-access statement scopes access to the owning account (AWS:SourceOwner/SourceAccount condition or the account root principal)"
  },
  {
   "id": "policy_source_override",
   "kind": "any_of",
   "tier": "detail",
   "quote": "custom source, override, or user-defined policy statements",
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
        "value": "source_policy_documents|override_policy_documents|source_json|override_json|\"dynamic\": \\{\"statement\""
       }
      ]
     }
    }
   ]
  },
  {
   "id": "subscription",
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
      "value": "aws_sns_topic_subscription"
     }
    ]
   },
   "quote": "dynamically creating a map of topic subscriptions"
  },
  {
   "id": "subscription_dynamic",
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
      "value": "aws_sns_topic_subscription"
     }
    ]
   },
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "quote": "dynamically creating a map of topic subscriptions"
  },
  {
   "id": "subscription_on_topic",
   "kind": "ref",
   "tier": "detail",
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
      "value": "aws_sns_topic_subscription"
     }
    ]
   },
   "to": {
    "types": [
     "aws_sns_topic"
    ],
    "where": []
   },
   "quote": "topic subscriptions"
  },
  {
   "id": "subscription_fields",
   "kind": "all_of",
   "tier": "detail",
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
        "value": "aws_sns_topic_subscription"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "protocol"
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
        "value": "aws_sns_topic_subscription"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "endpoint"
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
        "value": "aws_sns_topic_subscription"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "filter_policy"
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
        "value": "aws_sns_topic_subscription"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "endpoint_auto_confirms"
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
        "value": "aws_sns_topic_subscription"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "delivery_policy|raw_message_delivery|redrive_policy"
     }
    }
   ],
   "quote": "with protocol, endpoint, filter policy, auto-confirmation, and delivery settings"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
