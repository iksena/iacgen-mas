package intent.cfn.row_141

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "table": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": []
  },
  "decl_alarms": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::CloudWatch::Alarm"
    }
   ]
  },
  "decl_table": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::DynamoDB::Table"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "table_exists",
   "kind": "exists",
   "select": "table",
   "tier": "core",
   "quote": "creates a DynamoDB table"
  },
  {
   "id": "partition_key_id",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "KeySchema",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "KeyType"
        ],
        "op": "eq",
        "value": "HASH"
       },
       {
        "path": [
         "AttributeName"
        ],
        "op": "eq",
        "value": "id"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "AttributeDefinitions",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "AttributeName"
        ],
        "op": "eq",
        "value": "id"
       },
       {
        "path": [
         "AttributeType"
        ],
        "op": "eq",
        "value": "S"
       }
      ]
     }
    }
   ],
   "tier": "core",
   "quote": "partition key (defaulting to type String S and name 'id')",
   "justify": "partition key is the HASH key"
  },
  {
   "id": "partition_key_configurable",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "id"
     }
    ]
   },
   "tier": "detail",
   "quote": "a configurable partition key"
  },
  {
   "id": "sort_key_default_number",
   "tier": "detail",
   "quote": "an optional sort key (defaulting to type Number N)",
   "kind": "any_of",
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
         "default"
        ],
        "op": "eq",
        "value": "N"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "AttributeDefinitions",
       "*",
       "AttributeType"
      ],
      "op": "eq",
      "value": "N"
     }
    }
   ]
  },
  {
   "id": "billing_provisioned_default",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "BillingMode"
      ],
      "op": "eq",
      "value": "PROVISIONED"
     }
    },
    {
     "kind": "attr",
     "select": "table",
     "cond": {
      "path": [
       "ProvisionedThroughput",
       "ReadCapacityUnits"
      ],
      "op": "present"
     }
    }
   ],
   "tier": "core",
   "quote": "using PROVISIONED billing by default"
  },
  {
   "id": "billing_switchable",
   "kind": "any_of",
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
         "allowed_values",
         "*"
        ],
        "op": "regex",
        "value": "(?i)^(on[- _]?demand|pay[-_ ]?per[-_ ]?request)$"
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
         "default"
        ],
        "op": "regex",
        "value": "(?i)^provisioned$"
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
        "value": "(?i)on.?demand|pay.?per.?request"
       }
      ]
     }
    }
   ],
   "tier": "detail",
   "quote": "with the ability to switch to on-demand"
  },
  {
   "id": "pitr_enabled",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "PointInTimeRecoverySpecification",
     "PointInTimeRecoveryEnabled"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "enabling point-in-time recovery by default"
  },
  {
   "id": "encryption_off_by_default",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "SSESpecification",
     "SSEEnabled"
    ],
    "op": "none_eq",
    "value": true
   },
   "tier": "core",
   "quote": "both should be off by default"
  },
  {
   "id": "encryption_optional_cmk",
   "tier": "core",
   "quote": "Support optional server-side encryption using a customer-managed KMS key",
   "kind": "any_of",
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
        "value": "(?i:kms|encrypt|cmk)|SSE|Sse"
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
        "value": "AWS::KMS::Key"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "gate"
        ],
        "op": "regex",
        "value": "(?i:kms|encrypt|cmk)|SSE|Sse"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "alarms_declared",
   "kind": "exists",
   "select": "decl_alarms",
   "min": 2,
   "tier": "core",
   "quote": "optional CloudWatch alarms (for throttling and error rates)",
   "justify": "throttling alarms and error-rate alarms are two groups"
  },
  {
   "id": "alarm_throttle_metric",
   "tier": "detail",
   "quote": "throttling",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_alarms",
     "cond": {
      "path": [
       "properties",
       "MetricName"
      ],
      "op": "regex",
      "value": "(?i)throttl"
     }
    },
    {
     "kind": "attr",
     "select": "decl_alarms",
     "cond": {
      "path": [
       "properties",
       "Metrics",
       "*",
       "MetricStat",
       "Metric",
       "MetricName"
      ],
      "op": "regex",
      "value": "(?i)throttl"
     }
    }
   ]
  },
  {
   "id": "alarm_error_metric",
   "tier": "detail",
   "quote": "error rates",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_alarms",
     "cond": {
      "path": [
       "properties",
       "MetricName"
      ],
      "op": "regex",
      "value": "(?i)error"
     }
    },
    {
     "kind": "attr",
     "select": "decl_alarms",
     "cond": {
      "path": [
       "properties",
       "Metrics",
       "*",
       "MetricStat",
       "Metric",
       "MetricName"
      ],
      "op": "regex",
      "value": "(?i)error"
     }
    }
   ]
  },
  {
   "id": "alarms_publish_to_sns",
   "kind": "attr",
   "select": "decl_alarms",
   "cond": {
    "path": [
     "properties",
     "AlarmActions"
    ],
    "op": "present"
   },
   "quantifier": "all",
   "tier": "detail",
   "quote": "that can publish to an SNS topic when alerting is enabled"
  },
  {
   "id": "alarms_optional",
   "tier": "core",
   "quote": "both should be off by default and safely skippable",
   "justify": "alerting off by default means the alerting switch or topic parameter defaults to an off or blank value",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_alarms",
     "cond": {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     "quantifier": "all"
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
        "value": "(?i)alarm|alert|notif|sns|topic"
       },
       {
        "path": [
         "default"
        ],
        "op": "regex",
        "value": "(?i)^(|false|no|off|disabled|none)$"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_alarm_namespace",
   "kind": "attr",
   "select": "decl_alarms",
   "cond": {
    "path": [
     "properties",
     "Namespace"
    ],
    "op": "eq",
    "value": "AWS/DynamoDB"
   },
   "quantifier": "all",
   "tier": "extra"
  },
  {
   "id": "x_alarm_dimension_table",
   "kind": "ref",
   "from": "decl_alarms",
   "to": "table",
   "tier": "extra"
  },
  {
   "id": "x_provisioned_capacity",
   "kind": "attr",
   "select": "table",
   "cond": {
    "path": [
     "ProvisionedThroughput",
     "WriteCapacityUnits"
    ],
    "op": "gte",
    "value": 1
   },
   "tier": "extra"
  },
  {
   "id": "extra_type_aws_applicationautoscaling_scalabletarget",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::ApplicationAutoScaling::ScalableTarget"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_applicationautoscaling_scalingpolicy",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::ApplicationAutoScaling::ScalingPolicy"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_backup_backupplan",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::Backup::BackupPlan"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_backup_backupselection",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::Backup::BackupSelection"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_backup_backupvault",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::Backup::BackupVault"
    ],
    "where": []
   }
  },
  {
   "id": "extra_type_aws_iam_role",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
