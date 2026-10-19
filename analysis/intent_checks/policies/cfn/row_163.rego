package intent.cfn.row_163

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "lg": {
   "types": [
    "AWS::Logs::LogGroup"
   ],
   "where": []
  },
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "mf": {
   "types": [
    "AWS::Logs::MetricFilter"
   ],
   "where": []
  },
  "alarm": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": []
  },
  "qd": {
   "types": [
    "AWS::Logs::QueryDefinition"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "log_group",
   "kind": "exists",
   "select": "lg",
   "tier": "core",
   "quote": "create a CloudWatch Logs log group that will receive CloudTrail management events"
  },
  {
   "id": "kms_cmk",
   "kind": "exists",
   "select": "key",
   "tier": "detail",
   "quote": "a KMS customer managed key"
  },
  {
   "id": "sns_topic_encrypted_with_cmk",
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
   "to": "key",
   "tier": "core",
   "quote": "an SNS topic (encrypted with that key) to receive alarm notifications"
  },
  {
   "id": "metric_filters_on_log_group",
   "kind": "ref",
   "from": "mf",
   "to": "lg",
   "tier": "core",
   "quote": "On top of that log group, create CloudWatch Logs metric filters"
  },
  {
   "id": "fourteen_metric_filters",
   "kind": "exists",
   "select": "mf",
   "min": 14,
   "tier": "core",
   "quote": "covering each of the following conditions",
   "justify": "the prompt enumerates 14 conditions and asks for one metric filter / alarm / query definition covering each"
  },
  {
   "id": "fourteen_alarms",
   "kind": "exists",
   "select": "alarm",
   "min": 14,
   "tier": "core",
   "quote": "matching CloudWatch alarms",
   "justify": "the prompt enumerates 14 conditions and asks for one metric filter / alarm / query definition covering each"
  },
  {
   "id": "alarm_per_condition_matches_filter",
   "kind": "all_of",
   "tier": "core",
   "quote": "create CloudWatch Logs metric filters, matching CloudWatch alarms",
   "checks": [
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)(UnauthorizedOperation|AccessDenied)"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)MFAUsed"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)root"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)(put|delete|attach|detach)(role|user|group)policy"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)(StopLogging|DeleteTrail|UpdateTrail)"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)(Failed authentication|Failure)"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)(DisableKey|ScheduleKeyDeletion)"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)(PutBucketPolicy|DeleteBucketPolicy)"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)(StopConfigurationRecorder|PutConfigurationRecorder|DeleteDeliveryChannel)"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)(Authorize|Revoke)SecurityGroup(Ingress|Egress)"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)NetworkAcl"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)(Customer|Internet)Gateway"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)(CreateRoute|ReplaceRoute|DeleteRoute)"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    },
    {
     "kind": "join",
     "from": "alarm",
     "from_path": [
      "MetricName"
     ],
     "to": {
      "types": [
       "AWS::Logs::MetricFilter"
      ],
      "where": [
       {
        "path": [
         "FilterPattern"
        ],
        "op": "regex",
        "value": "(?i)(CreateVpc|DeleteVpc|ModifyVpcAttribute)"
       }
      ]
     },
     "to_path": [
      "MetricTransformations",
      "*",
      "MetricName"
     ]
    }
   ],
   "justify": "each regex keys on the CloudTrail event names that define the stated condition (console login failure = \"Failed authentication\" error or ConsoleLogin Failure response)"
  },
  {
   "id": "fourteen_query_definitions",
   "kind": "exists",
   "select": "qd",
   "min": 14,
   "tier": "detail",
   "quote": "companion Logs Insights query definitions",
   "justify": "the prompt enumerates 14 conditions and asks for one metric filter / alarm / query definition covering each"
  },
  {
   "id": "query_definitions_on_log_group",
   "kind": "ref",
   "from": "qd",
   "to": "lg",
   "tier": "detail",
   "quote": "companion Logs Insights query definitions"
  },
  {
   "id": "filter_conditions_covered",
   "kind": "all_of",
   "tier": "core",
   "quote": "unauthorized API call attempts, console sign-in without MFA, use of the root account, IAM policy changes, CloudTrail configuration changes, console login failures, disabling or scheduling deletion of customer managed KMS keys, S3 bucket policy changes, AWS Config configuration changes, security group changes, network ACL changes, network gateway changes, route table changes, and VPC changes",
   "checks": [
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)(UnauthorizedOperation|AccessDenied)"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)MFAUsed"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)root"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)(put|delete|attach|detach)(role|user|group)policy"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)(StopLogging|DeleteTrail|UpdateTrail)"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)(Failed authentication|Failure)"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)(DisableKey|ScheduleKeyDeletion)"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)(PutBucketPolicy|DeleteBucketPolicy)"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)(StopConfigurationRecorder|PutConfigurationRecorder|DeleteDeliveryChannel)"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)(Authorize|Revoke)SecurityGroup(Ingress|Egress)"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)NetworkAcl"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)(Customer|Internet)Gateway"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)(CreateRoute|ReplaceRoute|DeleteRoute)"
     }
    },
    {
     "kind": "attr",
     "select": "mf",
     "cond": {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)(CreateVpc|DeleteVpc|ModifyVpcAttribute)"
     }
    }
   ],
   "justify": "each regex keys on the CloudTrail event names that define the stated condition (console login failure = \"Failed authentication\" error or ConsoleLogin Failure response)"
  },
  {
   "id": "alarm_threshold_one",
   "kind": "attr",
   "select": "alarm",
   "quantifier": "all",
   "cond": {
    "path": [
     "Threshold"
    ],
    "op": "eq",
    "value": 1
   },
   "tier": "core",
   "quote": "a threshold of one",
   "justify": "prompt states \"a threshold of one\""
  },
  {
   "id": "alarm_reaches_or_exceeds",
   "kind": "attr",
   "select": "alarm",
   "quantifier": "all",
   "cond": {
    "path": [
     "ComparisonOperator"
    ],
    "op": "eq",
    "value": "GreaterThanOrEqualToThreshold"
   },
   "tier": "core",
   "quote": "reaches or exceeds a threshold",
   "justify": "\"reaches or exceeds\" = GreaterThanOrEqualToThreshold"
  },
  {
   "id": "alarm_five_minute_period",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "Period"
      ],
      "op": "eq",
      "value": 300
     }
    ]
   },
   "min": 13,
   "tier": "detail",
   "quote": "within a five minute period",
   "justify": "five minutes = Period 300, on the 13 alarms other than the KMS one (14 conditions)"
  },
  {
   "id": "kms_alarm_one_minute_period",
   "kind": "join",
   "tier": "detail",
   "from": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "Period"
      ],
      "op": "eq",
      "value": 60
     }
    ]
   },
   "from_path": [
    "MetricName"
   ],
   "to": {
    "types": [
     "AWS::Logs::MetricFilter"
    ],
    "where": [
     {
      "path": [
       "FilterPattern"
      ],
      "op": "regex",
      "value": "(?i)(DisableKey|ScheduleKeyDeletion)"
     }
    ]
   },
   "to_path": [
    "MetricTransformations",
    "*",
    "MetricName"
   ],
   "quote": "except the KMS key alarm, which should use a one minute period",
   "justify": "one minute = Period 60"
  },
  {
   "id": "alarm_missing_not_breaching",
   "kind": "attr",
   "select": "alarm",
   "quantifier": "all",
   "cond": {
    "path": [
     "TreatMissingData"
    ],
    "op": "eq",
    "value": "notBreaching"
   },
   "tier": "detail",
   "quote": "treat missing data as not breaching"
  },
  {
   "id": "alarm_notifies_topic",
   "kind": "ref",
   "from": "alarm",
   "to": {
    "types": [
     "AWS::SNS::Topic"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "publish its notification to the SNS topic created by the template"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
