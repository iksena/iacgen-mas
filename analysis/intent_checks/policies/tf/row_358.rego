package intent.tf.row_358

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "detector",
   "kind": "exists",
   "select": {
    "types": [
     "aws_guardduty_detector"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "creates an enabled Amazon GuardDuty detector"
  },
  {
   "id": "detector_enabled",
   "kind": "attr",
   "select": {
    "types": [
     "aws_guardduty_detector"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enable"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "creates an enabled Amazon GuardDuty detector"
  },
  {
   "id": "detector_frequency",
   "kind": "attr",
   "select": {
    "types": [
     "aws_guardduty_detector"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "finding_publishing_frequency"
    ],
    "op": "eq",
    "value": "FIFTEEN_MINUTES"
   },
   "tier": "core",
   "quote": "publishes findings every fifteen minutes",
   "justify": "fifteen minutes is the FIFTEEN_MINUTES enum"
  },
  {
   "id": "kms_key",
   "kind": "exists",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "a customer-managed KMS key"
  },
  {
   "id": "kms_rotation",
   "kind": "attr",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "enable_key_rotation"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "with automatic rotation"
  },
  {
   "id": "kms_deletion_window",
   "kind": "attr",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "deletion_window_in_days"
    ],
    "op": "eq",
    "value": 30
   },
   "tier": "core",
   "quote": "a 30-day deletion window"
  },
  {
   "id": "kms_alias",
   "kind": "exists",
   "select": {
    "types": [
     "aws_kms_alias"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "alias/guardduty"
     }
    ]
   },
   "tier": "core",
   "quote": "aliased \"alias/guardduty\""
  },
  {
   "id": "alias_for_key",
   "kind": "ref",
   "from": {
    "types": [
     "aws_kms_alias"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "alias/guardduty"
     }
    ]
   },
   "to": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "tier": "detail",
   "quote": "aliased \"alias/guardduty\""
  },
  {
   "id": "key_policy_admin",
   "kind": "any_of",
   "tier": "core",
   "quote": "whose key policy grants the account full administration",
   "justify": "full administration is kms:* (or *) in one statement whose principal is the account (root ARN or account ID)",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*[\"']Action[\"']\\s*:\\s*\\[?[^\\]{}]*?[\"'](kms:)?\\*[\"'](?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\{(?:[^{}]|\\$\\{[^{}]*\\})*?(:root|[\"']\\d{12})[\"'](?:[^{}]|\\$\\{[^{}]*\\})*\\}(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\}|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\{(?:[^{}]|\\$\\{[^{}]*\\})*?(:root|[\"']\\d{12})[\"'](?:[^{}]|\\$\\{[^{}]*\\})*\\}(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*[\"']Action[\"']\\s*:\\s*\\[?[^\\]{}]*?[\"'](kms:)?\\*[\"'](?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\}"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_kms_key_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*[\"']Action[\"']\\s*:\\s*\\[?[^\\]{}]*?[\"'](kms:)?\\*[\"'](?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\{(?:[^{}]|\\$\\{[^{}]*\\})*?(:root|[\"']\\d{12})[\"'](?:[^{}]|\\$\\{[^{}]*\\})*\\}(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\}|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\{(?:[^{}]|\\$\\{[^{}]*\\})*?(:root|[\"']\\d{12})[\"'](?:[^{}]|\\$\\{[^{}]*\\})*\\}(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*[\"']Action[\"']\\s*:\\s*\\[?[^\\]{}]*?[\"'](kms:)?\\*[\"'](?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\}"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_key"
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
           "actions",
           "*"
          ],
          "op": "in",
          "value": [
           "kms:*",
           "*"
          ]
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "regex",
          "value": "(:root|^[0-9]{12}$|account_id)"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_key"
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
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
          "op": "in",
          "value": [
           "kms:*",
           "*"
          ]
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "regex",
          "value": "(:root|^[0-9]{12}$|account_id)"
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
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_kms_key",
         "aws_kms_key_policy"
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
      "value": "\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*[\"']Action[\"']\\s*:\\s*\\[?[^\\]{}]*?[\"'](kms:)?\\*[\"'](?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\{(?:[^{}]|\\$\\{[^{}]*\\})*?(:root|[\"']\\d{12})[\"'](?:[^{}]|\\$\\{[^{}]*\\})*\\}(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\}|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\{(?:[^{}]|\\$\\{[^{}]*\\})*?(:root|[\"']\\d{12})[\"'](?:[^{}]|\\$\\{[^{}]*\\})*\\}(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*[\"']Action[\"']\\s*:\\s*\\[?[^\\]{}]*?[\"'](kms:)?\\*[\"'](?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\}"
     }
    }
   ]
  },
  {
   "id": "key_policy_generate_data_key",
   "kind": "any_of",
   "tier": "core",
   "quote": "allows the GuardDuty service to generate data keys",
   "justify": "generate data keys is kms:GenerateDataKey (or a wildcard covering it) in one statement whose principal is guardduty.amazonaws.com",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*[\"']Action[\"']\\s*:\\s*\\[?[^\\]{}]*?[\"']kms:(GenerateDataKey[A-Za-z*]*|Generate\\*|\\*)[\"'](?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\{(?:[^{}]|\\$\\{[^{}]*\\})*?[\"']guardduty\\.amazonaws\\.com[\"'](?:[^{}]|\\$\\{[^{}]*\\})*\\}(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\}|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\{(?:[^{}]|\\$\\{[^{}]*\\})*?[\"']guardduty\\.amazonaws\\.com[\"'](?:[^{}]|\\$\\{[^{}]*\\})*\\}(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*[\"']Action[\"']\\s*:\\s*\\[?[^\\]{}]*?[\"']kms:(GenerateDataKey[A-Za-z*]*|Generate\\*|\\*)[\"'](?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\}"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_kms_key_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*[\"']Action[\"']\\s*:\\s*\\[?[^\\]{}]*?[\"']kms:(GenerateDataKey[A-Za-z*]*|Generate\\*|\\*)[\"'](?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\{(?:[^{}]|\\$\\{[^{}]*\\})*?[\"']guardduty\\.amazonaws\\.com[\"'](?:[^{}]|\\$\\{[^{}]*\\})*\\}(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\}|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\{(?:[^{}]|\\$\\{[^{}]*\\})*?[\"']guardduty\\.amazonaws\\.com[\"'](?:[^{}]|\\$\\{[^{}]*\\})*\\}(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*[\"']Action[\"']\\s*:\\s*\\[?[^\\]{}]*?[\"']kms:(GenerateDataKey[A-Za-z*]*|Generate\\*|\\*)[\"'](?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\}"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_key"
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
           "actions",
           "*"
          ],
          "op": "glob_covers",
          "value": "kms:GenerateDataKey"
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "eq",
          "value": "guardduty.amazonaws.com"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_key"
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties",
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
          "value": "kms:GenerateDataKey"
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "eq",
          "value": "guardduty.amazonaws.com"
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
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "in",
        "value": [
         "aws_kms_key",
         "aws_kms_key_policy"
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
      "value": "\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*[\"']Action[\"']\\s*:\\s*\\[?[^\\]{}]*?[\"']kms:(GenerateDataKey[A-Za-z*]*|Generate\\*|\\*)[\"'](?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\{(?:[^{}]|\\$\\{[^{}]*\\})*?[\"']guardduty\\.amazonaws\\.com[\"'](?:[^{}]|\\$\\{[^{}]*\\})*\\}(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\}|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\{(?:[^{}]|\\$\\{[^{}]*\\})*?[\"']guardduty\\.amazonaws\\.com[\"'](?:[^{}]|\\$\\{[^{}]*\\})*\\}(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*[\"']Action[\"']\\s*:\\s*\\[?[^\\]{}]*?[\"']kms:(GenerateDataKey[A-Za-z*]*|Generate\\*|\\*)[\"'](?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:(?:[^{}]|\\$\\{[^{}]*\\})|\\{(?:[^{}]|\\$\\{[^{}]*\\})*\\})*\\})*\\}"
     }
    }
   ]
  },
  {
   "id": "event_rule",
   "kind": "exists",
   "select": {
    "types": [
     "aws_cloudwatch_event_rule"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "guardduty-finding-events"
     }
    ]
   },
   "tier": "core",
   "quote": "an EventBridge rule named \"guardduty-finding-events\""
  },
  {
   "id": "event_rule_pattern",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudwatch_event_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "guardduty-finding-events"
       }
      ]
     },
     "cond": {
      "path": [
       "event_pattern"
      ],
      "op": "regex",
      "value": "GuardDuty Finding"
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
        "value": "aws_cloudwatch_event_rule"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "guardduty-finding-events"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "event_pattern"
      ],
      "op": "regex",
      "value": "GuardDuty Finding"
     }
    }
   ],
   "tier": "core",
   "quote": "matches GuardDuty Finding events"
  },
  {
   "id": "event_rule_source",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudwatch_event_rule"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "guardduty-finding-events"
       }
      ]
     },
     "cond": {
      "path": [
       "event_pattern"
      ],
      "op": "regex",
      "value": "aws\\.guardduty"
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
        "value": "aws_cloudwatch_event_rule"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "guardduty-finding-events"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "event_pattern"
      ],
      "op": "regex",
      "value": "aws\\.guardduty"
     }
    }
   ],
   "tier": "detail",
   "quote": "matches GuardDuty Finding events",
   "justify": "GuardDuty events come from source aws.guardduty"
  },
  {
   "id": "s3_export_declared",
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
      "value": "aws_guardduty_publishing_destination"
     }
    ]
   },
   "tier": "core",
   "quote": "exporting findings to an S3 bucket should be optional"
  },
  {
   "id": "s3_export_optional",
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
      "value": "aws_guardduty_publishing_destination"
     }
    ]
   },
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "optional and disabled by default",
   "justify": "disabled by default means conditionally created"
  },
  {
   "id": "x_pd_kms",
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
      "value": "aws_guardduty_publishing_destination"
     }
    ]
   },
   "to": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "tier": "extra"
  },
  {
   "id": "x_detector_pd",
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
      "value": "aws_guardduty_publishing_destination"
     }
    ]
   },
   "to": {
    "types": [
     "aws_guardduty_detector"
    ],
    "where": []
   },
   "tier": "extra"
  },
  {
   "id": "extra_type_aws_s3_bucket_object",
   "kind": "exists",
   "tier": "extra",
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
      "value": "aws_s3_bucket_object"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
