package intent.tf.row_034

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "topic": {
   "types": [
    "aws_sns_topic"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "incident-response"
    }
   ]
  },
  "key": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "tpol": {
   "types": [
    "aws_sns_topic_policy"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "topic_named",
   "tier": "core",
   "quote": "creates an Amazon SNS topic named \"incident-response\"",
   "kind": "exists",
   "select": "topic"
  },
  {
   "id": "kms_key_created",
   "tier": "core",
   "quote": "dedicated customer-managed KMS key",
   "kind": "exists",
   "select": "key"
  },
  {
   "id": "kms_rotation",
   "tier": "core",
   "quote": "automatic key rotation enabled",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "topic",
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "enable_key_rotation"
        ],
        "op": "eq",
        "value": true
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "key",
     "quantifier": "all",
     "cond": {
      "path": [
       "enable_key_rotation"
      ],
      "op": "eq",
      "value": true
     }
    }
   ]
  },
  {
   "id": "topic_uses_key",
   "tier": "core",
   "quote": "encrypted with a dedicated customer-managed KMS key",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "topic",
     "to": "key"
    },
    {
     "kind": "ref",
     "from": "topic",
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
   "id": "topic_policy_attached",
   "tier": "core",
   "quote": "along with an attached topic policy",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "tpol",
     "to": "topic"
    },
    {
     "kind": "attr",
     "select": "topic",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "present",
      "value": null
     }
    }
   ]
  },
  {
   "id": "policy_id",
   "tier": "core",
   "quote": "policy ID \"__default_policy_ID\"",
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
       "policy_id"
      ],
      "op": "eq",
      "value": "__default_policy_ID"
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
         "data.aws_iam_policy_document",
         "aws_sns_topic_policy",
         "aws_sns_topic"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "__default_policy_ID"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "stmt1_sid",
   "tier": "core",
   "quote": "with SID \"__default_statement_ID\"",
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
       "*",
       "sid"
      ],
      "op": "eq",
      "value": "__default_statement_ID"
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
         "data.aws_iam_policy_document",
         "aws_sns_topic_policy",
         "aws_sns_topic"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "__default_statement_ID"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "stmt2_sid",
   "tier": "core",
   "quote": "with SID \"AllowAWSEvents\"",
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
       "*",
       "sid"
      ],
      "op": "eq",
      "value": "AllowAWSEvents"
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
         "data.aws_iam_policy_document",
         "aws_sns_topic_policy",
         "aws_sns_topic"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "AllowAWSEvents"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "stmt1_actions",
   "tier": "core",
   "quote": "Subscribe, SetTopicAttributes, RemovePermission, Receive, Publish, ListSubscriptionsByTopic, GetTopicAttributes, DeleteTopic, and AddPermission",
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
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "SNS:Subscribe"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "SNS:SetTopicAttributes"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "SNS:RemovePermission"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "SNS:Receive"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "SNS:Publish"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "SNS:ListSubscriptionsByTopic"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "SNS:GetTopicAttributes"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "SNS:DeleteTopic"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "SNS:AddPermission"
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
         "data.aws_iam_policy_document",
         "aws_sns_topic_policy",
         "aws_sns_topic"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)Subscribe"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)SetTopicAttributes"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)RemovePermission"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)Receive"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)Publish"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)ListSubscriptionsByTopic"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)GetTopicAttributes"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)DeleteTopic"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)AddPermission"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "stmt1_all_aws_principals",
   "tier": "core",
   "quote": "must allow all AWS principals",
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
         "sid"
        ],
        "op": "eq",
        "value": "__default_statement_ID"
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
         "data.aws_iam_policy_document",
         "aws_sns_topic_policy",
         "aws_sns_topic"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(\"identifiers\": \\[\"\\*\"\\]|[\"']AWS[\"']\\s*:\\s*\\[?\\s*[\"']\\*[\"']|[\"']Principal[\"']\\s*:\\s*[\"']\\*[\"'])"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "__default_statement_ID"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "stmt1_sourceowner",
   "tier": "core",
   "quote": "constrained by a StringEquals condition requiring the AWS:SourceOwner",
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
       "*",
       "condition",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "test"
        ],
        "op": "eq",
        "value": "StringEquals"
       },
       {
        "path": [
         "variable"
        ],
        "op": "eq",
        "value": "AWS:SourceOwner"
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
         "data.aws_iam_policy_document",
         "aws_sns_topic_policy",
         "aws_sns_topic"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)StringEquals"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)AWS:SourceOwner"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "stmt1_account_id",
   "tier": "detail",
   "quote": "to match the current AWS account ID",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "condition",
         "*",
         "variable"
        ],
        "op": "eq",
        "value": "AWS:SourceOwner"
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
        "value": "data.aws_caller_identity"
       }
      ]
     }
    },
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
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_caller_identity"
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
         "data.aws_iam_policy_document",
         "aws_sns_topic_policy",
         "aws_sns_topic"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)AWS:SourceOwner"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)account_id|caller_identity|AccountId"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "stmt2_events_publish",
   "tier": "core",
   "quote": "must explicitly allow the Amazon EventBridge service principal (events.amazonaws.com) to perform the sns:Publish action",
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
        "value": "events.amazonaws.com"
       },
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "sns:Publish"
       },
       {
        "path": [
         "effect"
        ],
        "op": "eq",
        "value": "Allow"
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
         "data.aws_iam_policy_document",
         "aws_sns_topic_policy",
         "aws_sns_topic"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "events\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)sns:Publish"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_doc_refs_topic",
   "tier": "extra",
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
    "where": []
   }
  },
  {
   "id": "policy_attached_to_topic_via_doc",
   "tier": "extra",
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
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
