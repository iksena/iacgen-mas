package intent.tf.row_111

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "topic",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_sns_topic"
    ],
    "where": []
   },
   "quote": "creates a feature-rich, production-grade Amazon SNS topic module"
  },
  {
   "id": "create_toggle",
   "tier": "core",
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
     "gate"
    ],
    "op": "regex",
    "value": "create"
   },
   "quote": "Entire stack deployment must be toggled via a create boolean variable defaulting to true"
  },
  {
   "id": "params_true",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
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
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
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
        "value": "create_topic_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
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
        "value": "enable_default_topic_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
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
        "value": "create_subscription"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": true
     }
    }
   ],
   "quote": "a create boolean variable defaulting to true"
  },
  {
   "id": "params_false",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
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
        "value": "use_name_prefix"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": false
     }
    },
    {
     "kind": "attr",
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
        "value": "content_based_deduplication"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": false
     }
    },
    {
     "kind": "attr",
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
        "value": "fifo_topic"
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": false
     }
    }
   ],
   "quote": "a use_name_prefix boolean (defaulting to false)"
  },
  {
   "id": "name_or_prefix",
   "tier": "core",
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
    "op": "present"
   },
   "quote": "a name string variable (defaulting to null) and a use_name_prefix boolean (defaulting to false) to set either name or name_prefix"
  },
  {
   "id": "name_var_null",
   "tier": "detail",
   "kind": "attr",
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
      "value": "name"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "absent"
   },
   "quote": "a name string variable (defaulting to null)"
  },
  {
   "id": "topic_name",
   "tier": "detail",
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
    "op": "present"
   },
   "quote": "to set either name or name_prefix"
  },
  {
   "id": "dedup",
   "tier": "detail",
   "kind": "attr",
   "quote": "content-based deduplication (defaulting to false)",
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
    "op": "present"
   }
  },
  {
   "id": "delivery_policy",
   "tier": "detail",
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
     "delivery_policy"
    ],
    "op": "present"
   },
   "quote": "delivery policy"
  },
  {
   "id": "display_name",
   "tier": "detail",
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
    "op": "present"
   },
   "quote": "display name"
  },
  {
   "id": "kms",
   "tier": "detail",
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
    "op": "present"
   },
   "quote": "KMS encryption key ID"
  },
  {
   "id": "signature_version",
   "tier": "detail",
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
     "signature_version"
    ],
    "op": "regex",
    "value": "fifo_topic|local\\.[a-z_]*signature"
   },
   "quote": "signature version (set to null if fifo_topic is true)"
  },
  {
   "id": "tracing",
   "tier": "detail",
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
     "tracing_config"
    ],
    "op": "present"
   },
   "quote": "tracing configuration"
  },
  {
   "id": "fifo",
   "tier": "detail",
   "kind": "attr",
   "quote": "FIFO enablement (defaulting to false)",
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
    "op": "present"
   }
  },
  {
   "id": "fb_application",
   "tier": "core",
   "kind": "all_of",
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
       "application_failure_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "application_success_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "application_success_feedback_sample_rate"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "feedback configuration maps for application, Firehose, HTTP, Lambda, and SQS protocols containing failure_role_arn, success_role_arn, and success_sample_rate settings"
  },
  {
   "id": "fb_firehose",
   "tier": "core",
   "kind": "all_of",
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
       "firehose_failure_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "firehose_success_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "firehose_success_feedback_sample_rate"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "feedback configuration maps for application, Firehose, HTTP, Lambda, and SQS protocols"
  },
  {
   "id": "fb_http",
   "tier": "core",
   "kind": "all_of",
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
       "http_failure_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "http_success_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "http_success_feedback_sample_rate"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "feedback configuration maps for application, Firehose, HTTP, Lambda, and SQS protocols"
  },
  {
   "id": "fb_lambda",
   "tier": "core",
   "kind": "all_of",
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
       "lambda_failure_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "lambda_success_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "lambda_success_feedback_sample_rate"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "feedback configuration maps for application, Firehose, HTTP, Lambda, and SQS protocols"
  },
  {
   "id": "fb_sqs",
   "tier": "core",
   "kind": "all_of",
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
       "sqs_failure_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "sqs_success_feedback_role_arn"
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
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "sqs_success_feedback_sample_rate"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "feedback configuration maps for application, Firehose, HTTP, Lambda, and SQS protocols"
  },
  {
   "id": "topic_policy",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_sns_topic_policy"
    ],
    "where": []
   },
   "quote": "Topic policy creation must be managed by a create_topic_policy flag defaulting to true"
  },
  {
   "id": "topic_policy_flag",
   "tier": "core",
   "kind": "any_of",
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
        "value": "aws_sns_topic_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "gate"
      ],
      "op": "regex",
      "value": "create_topic_policy"
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
      "value": "create_topic_policy"
     }
    }
   ],
   "quote": "Topic policy creation must be managed by a create_topic_policy flag"
  },
  {
   "id": "topic_policy_topic",
   "tier": "detail",
   "kind": "ref",
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
   "quote": "Topic policy creation"
  },
  {
   "id": "topic_policy_fallback",
   "tier": "detail",
   "kind": "any_of",
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
       "policy"
      ],
      "op": "regex",
      "value": "var\\.topic_policy"
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
      "value": "var\\.topic_policy"
     }
    }
   ],
   "quote": "falling back to an external topic_policy string if false"
  },
  {
   "id": "policy_doc",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "data.aws_iam_policy_document"
    ],
    "where": []
   },
   "quote": "constructs an IAM policy combining source and override policy documents, custom statement maps"
  },
  {
   "id": "policy_doc_source",
   "tier": "detail",
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
      "value": "data.aws_iam_policy_document"
     }
    ]
   },
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "source_policy_documents"
   },
   "quote": "combining source and override policy documents"
  },
  {
   "id": "policy_doc_override",
   "tier": "detail",
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
      "value": "data.aws_iam_policy_document"
     }
    ]
   },
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "override_policy_documents"
   },
   "quote": "combining source and override policy documents"
  },
  {
   "id": "policy_doc_statements",
   "tier": "detail",
   "kind": "any_of",
   "quote": "custom statement maps",
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
        "op": "regex",
        "value": "(?i)statement"
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "dynamic",
       "statement",
       "for_each"
      ],
      "op": "regex",
      "value": "(?i)statement"
     }
    }
   ]
  },
  {
   "id": "policy_doc_attached",
   "tier": "detail",
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
   },
   "quote": "constructs an IAM policy"
  },
  {
   "id": "default_stmt",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "*"
       },
       {
        "path": [
         "condition",
         "*",
         "variable"
        ],
        "op": "in",
        "value": [
         "aws:SourceOwner",
         "aws:SourceAccount",
         "aws:PrincipalAccount"
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_sns_topic_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)aws:(SourceOwner|SourceAccount|PrincipalAccount)"
     }
    }
   ],
   "quote": "an optional default policy statement (controlled by enable_default_topic_policy defaulting to true) that grants standard SNS topic actions to all AWS principals conditioned on matching the account owner ID",
   "justify": "matching the account owner ID is a condition on the caller's or source's account: aws:SourceOwner, aws:SourceAccount or aws:PrincipalAccount"
  },
  {
   "id": "default_stmt_actions",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "data.aws_iam_policy_document"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "statement",
     "*",
     "actions",
     "*"
    ],
    "op": "glob_covers",
    "value": "sns:Publish"
   },
   "quote": "grants standard SNS topic actions"
  },
  {
   "id": "subscription",
   "tier": "core",
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
      "value": "aws_sns_topic_subscription"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "Topic subscriptions must be conditionally generated from a map variable"
  },
  {
   "id": "subscription_gate",
   "tier": "core",
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
     "gate"
    ],
    "op": "regex",
    "value": "(?s)create.*create_subscription|create_subscription.*create"
   },
   "quote": "when both create and create_subscription (defaulting to true) are true"
  },
  {
   "id": "subscription_topic",
   "tier": "detail",
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
   "quote": "Topic subscriptions"
  },
  {
   "id": "subscription_attrs_a",
   "tier": "detail",
   "kind": "all_of",
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
       "confirmation_timeout_in_minutes"
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
       "properties",
       "filter_policy"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "mapping confirmation timeouts, delivery policies, endpoints, auto-confirm flags, filter policies"
  },
  {
   "id": "subscription_attrs_b",
   "tier": "detail",
   "kind": "all_of",
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
       "filter_policy_scope"
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
       "raw_message_delivery"
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
       "redrive_policy"
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
       "subscription_role_arn"
      ],
      "op": "present"
     }
    }
   ],
   "quote": "filter policy scopes, protocols, raw message delivery flags, redrive policies, and subscription role ARNs"
  },
  {
   "id": "data_protection",
   "tier": "core",
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
      "value": "aws_sns_topic_data_protection_policy"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "conditionally provision a topic data protection policy from a JSON policy string variable when data_protection_policy is set"
  },
  {
   "id": "data_protection_gate",
   "tier": "core",
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
      "value": "aws_sns_topic_data_protection_policy"
     }
    ]
   },
   "cond": {
    "path": [
     "gate"
    ],
    "op": "regex",
    "value": "(?s)data_protection_policy.*fifo_topic|fifo_topic.*data_protection_policy"
   },
   "quote": "when data_protection_policy is set and fifo_topic is false"
  },
  {
   "id": "data_protection_topic",
   "tier": "detail",
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
      "value": "aws_sns_topic_data_protection_policy"
     }
    ]
   },
   "to": {
    "types": [
     "aws_sns_topic"
    ],
    "where": []
   },
   "quote": "topic data protection policy"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
