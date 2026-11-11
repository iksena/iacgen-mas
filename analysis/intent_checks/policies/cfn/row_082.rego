package intent.cfn.row_082

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "budget": {
   "types": [
    "AWS::Budgets::Budget"
   ],
   "where": []
  },
  "topic": {
   "types": [
    "AWS::SNS::Topic"
   ],
   "where": []
  },
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "alias": {
   "types": [
    "AWS::KMS::Alias"
   ],
   "where": []
  },
  "sub": {
   "types": [
    "AWS::SNS::Subscription"
   ],
   "where": []
  },
  "tpol": {
   "types": [
    "AWS::SNS::TopicPolicy"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "budget",
   "kind": "exists",
   "tier": "core",
   "quote": "a monthly budget",
   "select": "budget"
  },
  {
   "id": "monthly",
   "kind": "attr",
   "tier": "core",
   "quote": "a monthly budget",
   "select": "budget",
   "cond": {
    "path": [
     "Budget",
     "TimeUnit"
    ],
    "op": "eq",
    "value": "MONTHLY"
   }
  },
  {
   "id": "limit",
   "kind": "attr",
   "tier": "core",
   "quote": "a configurable limit defaulting to $100 USD",
   "select": "budget",
   "cond": {
    "path": [
     "Budget",
     "BudgetLimit",
     "Amount"
    ],
    "op": "eq",
    "value": 100
   }
  },
  {
   "id": "unit",
   "kind": "attr",
   "tier": "core",
   "quote": "$100 USD",
   "select": "budget",
   "cond": {
    "path": [
     "Budget",
     "BudgetLimit",
     "Unit"
    ],
    "op": "eq",
    "value": "USD"
   }
  },
  {
   "id": "limit_param",
   "kind": "attr",
   "tier": "detail",
   "quote": "a configurable limit defaulting to $100 USD",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": 100
   }
  },
  {
   "id": "thresholds",
   "kind": "all_of",
   "tier": "core",
   "quote": "when actual costs exceed 80% and 99% of the budget",
   "justify": "exceed means GREATER_THAN, actual means ACTUAL",
   "checks": [
    {
     "kind": "attr",
     "select": "budget",
     "cond": {
      "path": [
       "NotificationsWithSubscribers",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Notification",
         "Threshold"
        ],
        "op": "eq",
        "value": 80
       },
       {
        "path": [
         "Notification",
         "NotificationType"
        ],
        "op": "eq",
        "value": "ACTUAL"
       },
       {
        "path": [
         "Notification",
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GREATER_THAN"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "budget",
     "cond": {
      "path": [
       "NotificationsWithSubscribers",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Notification",
         "Threshold"
        ],
        "op": "eq",
        "value": 99
       },
       {
        "path": [
         "Notification",
         "NotificationType"
        ],
        "op": "eq",
        "value": "ACTUAL"
       },
       {
        "path": [
         "Notification",
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GREATER_THAN"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "percent",
   "kind": "attr",
   "tier": "detail",
   "quote": "80% and 99% of the budget",
   "select": "budget",
   "justify": "80% and 99% are percentage thresholds; PERCENTAGE is also the default, so only an absolute threshold violates this",
   "cond": {
    "path": [
     "NotificationsWithSubscribers",
     "*",
     "Notification",
     "ThresholdType"
    ],
    "op": "none_eq",
    "value": "ABSOLUTE_VALUE"
   }
  },
  {
   "id": "topic",
   "kind": "exists",
   "tier": "core",
   "quote": "encrypt the SNS topic",
   "select": "topic"
  },
  {
   "id": "budget_notifies",
   "kind": "ref",
   "tier": "core",
   "quote": "notifications sent via SMS or email",
   "from": "budget",
   "to": "topic"
  },
  {
   "id": "sub_sms",
   "kind": "attr",
   "tier": "core",
   "quote": "defaulting to SMS with country code +61",
   "select": "sub",
   "cond": {
    "path": [
     "Protocol"
    ],
    "op": "eq",
    "value": "sms"
   }
  },
  {
   "id": "sub_endpoint",
   "kind": "attr",
   "tier": "core",
   "quote": "country code +61",
   "select": "sub",
   "cond": {
    "path": [
     "Endpoint"
    ],
    "op": "contains",
    "value": "+61"
   }
  },
  {
   "id": "sub_topic",
   "kind": "ref",
   "tier": "detail",
   "quote": "notifications sent via SMS or email",
   "from": "sub",
   "to": "topic"
  },
  {
   "id": "method_param",
   "kind": "attr",
   "tier": "detail",
   "quote": "the notification method and endpoint parameterized (defaulting to SMS",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "sms"
   }
  },
  {
   "id": "endpoint_param",
   "kind": "attr",
   "tier": "detail",
   "quote": "the notification method and endpoint parameterized (defaulting to SMS with country code +61)",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "regex",
    "value": "^\\+61"
   }
  },
  {
   "id": "key",
   "kind": "exists",
   "tier": "core",
   "quote": "using a KMS key",
   "select": "key"
  },
  {
   "id": "alias",
   "kind": "attr",
   "tier": "core",
   "quote": "a KMS key with alias \"billing-topic-key\"",
   "select": "alias",
   "cond": {
    "path": [
     "AliasName"
    ],
    "op": "eq",
    "value": "alias/billing-topic-key"
   }
  },
  {
   "id": "alias_key",
   "kind": "ref",
   "tier": "detail",
   "quote": "a KMS key with alias \"billing-topic-key\"",
   "from": "alias",
   "to": "key"
  },
  {
   "id": "topic_encrypted",
   "kind": "any_of",
   "tier": "core",
   "quote": "to encrypt the SNS topic",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::SNS::Topic"
      ],
      "where": [
       {
        "path": [
         "KmsMasterKeyId"
        ],
        "op": "present"
       }
      ]
     },
     "to": "key"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::SNS::Topic"
      ],
      "where": [
       {
        "path": [
         "KmsMasterKeyId"
        ],
        "op": "present"
       }
      ]
     },
     "to": "alias"
    },
    {
     "kind": "attr",
     "select": "topic",
     "cond": {
      "path": [
       "KmsMasterKeyId"
      ],
      "op": "contains",
      "value": "billing-topic-key"
     }
    }
   ]
  },
  {
   "id": "x_rotation",
   "kind": "attr",
   "tier": "extra",
   "select": "key",
   "cond": {
    "path": [
     "EnableKeyRotation"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "x_topic_policy",
   "kind": "attr",
   "tier": "extra",
   "select": "tpol",
   "cond": {
    "path": [
     "PolicyDocument",
     "Statement",
     "*",
     "Principal",
     "Service",
     "*"
    ],
    "op": "eq",
    "value": "budgets.amazonaws.com"
   }
  },
  {
   "id": "x_publish",
   "kind": "attr",
   "tier": "extra",
   "select": "tpol",
   "cond": {
    "path": [
     "PolicyDocument",
     "Statement",
     "*",
     "Action",
     "*"
    ],
    "op": "glob_covers",
    "value": "sns:Publish"
   }
  },
  {
   "id": "budget_type_cost",
   "kind": "attr",
   "tier": "detail",
   "quote": "when actual costs exceed",
   "select": "budget",
   "justify": "a limit in USD on actual costs is a cost budget",
   "cond": {
    "path": [
     "Budget",
     "BudgetType"
    ],
    "op": "eq",
    "value": "COST"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
