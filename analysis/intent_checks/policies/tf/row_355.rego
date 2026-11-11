package intent.tf.row_355

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "detector_exists",
   "kind": "exists",
   "select": {
    "types": [
     "aws_guardduty_detector"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "creates and enables an Amazon GuardDuty detector"
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
   "quote": "creates and enables an Amazon GuardDuty detector"
  },
  {
   "id": "detector_region",
   "kind": "any_of",
   "tier": "detail",
   "quote": "for the account in us-east-1",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_guardduty_detector"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "region"
      ],
      "op": "eq",
      "value": "us-east-1"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_guardduty_detector"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "region"
      ],
      "op": "absent"
     }
    }
   ],
   "justify": "when the planned detector carries no region attribute it deploys to the configured provider region, which the plan does not expose"
  },
  {
   "id": "s3_protection_off",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_guardduty_detector"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "datasources",
       "*",
       "s3_logs",
       "*",
       "enable"
      ],
      "op": "eq",
      "value": "false"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_guardduty_detector_feature"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "S3_DATA_EVENTS"
       }
      ]
     },
     "cond": {
      "path": [
       "status"
      ],
      "op": "eq",
      "value": "DISABLED"
     }
    }
   ],
   "tier": "core",
   "quote": "with S3 protection turned off",
   "justify": "turned off means enable false or feature DISABLED"
  },
  {
   "id": "publishing_frequency_default",
   "kind": "any_of",
   "checks": [
    {
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
      "op": "absent"
     }
    },
    {
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
      "value": "SIX_HOURS"
     }
    }
   ],
   "tier": "detail",
   "quote": "the finding publishing frequency left at the service default",
   "justify": "service default is SIX_HOURS; unset also accepted"
  },
  {
   "id": "cloud_posse_label_inputs",
   "kind": "any_of",
   "tier": "detail",
   "quote": "using Cloud Posse label conventions for naming",
   "justify": "Cloud Posse label conventions use namespace/stage/tenant/context inputs and emit Namespace/Stage tags",
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
        "op": "in",
        "value": [
         "namespace",
         "stage",
         "tenant",
         "context"
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_guardduty_detector"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags",
       "Namespace"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_guardduty_detector"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "tags",
       "Stage"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "eventbridge_rule_declared",
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
      "value": "aws_cloudwatch_event_rule"
     }
    ]
   },
   "tier": "core",
   "quote": "Optional EventBridge rules"
  },
  {
   "id": "eventbridge_rule_optional",
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
   "quote": "Optional EventBridge rules and SNS topic notifications for findings should be supported but disabled by default",
   "justify": "disabled by default means conditionally created",
   "quantifier": "all"
  },
  {
   "id": "sns_notifications_declared",
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
       "aws_sns_topic",
       "aws_sns_topic_policy",
       "aws_sns_topic_subscription"
      ]
     }
    ]
   },
   "tier": "core",
   "quote": "SNS topic notifications for findings should be supported"
  },
  {
   "id": "sns_optional",
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
       "aws_sns_topic",
       "aws_sns_topic_policy"
      ]
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
   "quantifier": "all",
   "quote": "supported but disabled by default, so no topic, topic policy, or event rule is created",
   "justify": "disabled by default means conditionally created"
  },
  {
   "id": "x_target_to_rule",
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
      "value": "aws_cloudwatch_event_target"
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
      "value": "aws_cloudwatch_event_rule"
     }
    ]
   },
   "tier": "extra"
  },
  {
   "id": "x_sns_publish",
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
     "statement",
     "*",
     "actions",
     "*"
    ],
    "op": "eq",
    "value": "sns:Publish"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
