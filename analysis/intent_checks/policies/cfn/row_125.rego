package intent.cfn.row_125

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "cpu_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "for each instance we want a CPU utilization alarm",
   "justify": "five new EC2 instances",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "CPUUtilization"
     }
    ]
   },
   "min": 5
  },
  {
   "id": "cpu_threshold",
   "kind": "attr",
   "tier": "core",
   "quote": "triggers when the average CPU exceeds 80%",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "CPUUtilization"
     }
    ]
   },
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 80
     },
     {
      "path": [
       "ComparisonOperator"
      ],
      "op": "in",
      "value": [
       "GreaterThanThreshold",
       "GreaterThanOrEqualToThreshold"
      ]
     }
    ]
   },
   "quantifier": "all",
   "justify": "threshold and comparison direction follow from the stated trigger"
  },
  {
   "id": "cpu_stat",
   "kind": "attr",
   "tier": "core",
   "quote": "triggers when the average CPU exceeds 80%",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "CPUUtilization"
     }
    ]
   },
   "cond": {
    "path": [
     "Statistic"
    ],
    "op": "eq",
    "value": "Average"
   },
   "quantifier": "all"
  },
  {
   "id": "cpu_period",
   "kind": "attr",
   "tier": "core",
   "quote": "over three consecutive 300-second periods",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "CPUUtilization"
     }
    ]
   },
   "cond": {
    "path": [
     "Period"
    ],
    "op": "eq",
    "value": 300
   },
   "quantifier": "all"
  },
  {
   "id": "cpu_periods",
   "tier": "core",
   "quote": "over three consecutive 300-second periods",
   "justify": "consecutive periods = EvaluationPeriods, with no M-of-N DatapointsToAlarm below it",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "CPUUtilization"
     }
    ]
   },
   "quantifier": "all",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "EvaluationPeriods"
      ],
      "op": "eq",
      "value": 3
     },
     {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "none_eq",
      "value": 1
     },
     {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "none_eq",
      "value": 2
     }
    ]
   }
  },
  {
   "id": "cpu_per_instance",
   "kind": "exists",
   "tier": "detail",
   "quote": "for each instance",
   "justify": "one alarm per instance, each on a different instance",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "CPUUtilization"
     }
    ]
   },
   "distinct_path": [
    "Dimensions",
    "*",
    "Value"
   ],
   "min": 5
  },
  {
   "id": "status_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "for the first three of those instances we also need a status check failed alarm",
   "justify": "the first three of those instances",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "StatusCheckFailed"
     }
    ]
   },
   "min": 3
  },
  {
   "id": "status_threshold",
   "tier": "core",
   "quote": "triggers when the maximum status check metric is 1",
   "justify": "the metric is 0 or 1, so 'is 1' means >= 1 or, equally, > 0",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "MetricName"
        ],
        "op": "eq",
        "value": "StatusCheckFailed"
       }
      ]
     },
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "MetricName"
        ],
        "op": "eq",
        "value": "StatusCheckFailed"
       }
      ]
     },
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 0
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanThreshold"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "status_stat",
   "kind": "attr",
   "tier": "core",
   "quote": "triggers when the maximum status check metric is 1",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "StatusCheckFailed"
     }
    ]
   },
   "cond": {
    "path": [
     "Statistic"
    ],
    "op": "eq",
    "value": "Maximum"
   },
   "quantifier": "all"
  },
  {
   "id": "status_period",
   "kind": "attr",
   "tier": "core",
   "quote": "for two consecutive 300-second periods",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "StatusCheckFailed"
     }
    ]
   },
   "cond": {
    "path": [
     "Period"
    ],
    "op": "eq",
    "value": 300
   },
   "quantifier": "all"
  },
  {
   "id": "status_periods",
   "tier": "core",
   "quote": "for two consecutive 300-second periods",
   "justify": "consecutive periods = EvaluationPeriods, with no M-of-N DatapointsToAlarm below it",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "StatusCheckFailed"
     }
    ]
   },
   "quantifier": "all",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "EvaluationPeriods"
      ],
      "op": "eq",
      "value": 2
     },
     {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "none_eq",
      "value": 1
     }
    ]
   }
  },
  {
   "id": "status_per_instance",
   "kind": "exists",
   "tier": "detail",
   "quote": "for the first three of those instances",
   "justify": "the first three of those instances: one alarm on each of three different instances",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "StatusCheckFailed"
     }
    ]
   },
   "distinct_path": [
    "Dimensions",
    "*",
    "Value"
   ],
   "min": 3
  },
  {
   "id": "ebs_exists",
   "kind": "exists",
   "tier": "core",
   "quote": "a more granular alarm for attached EBS volume reachability",
   "justify": "those same first three instances",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "StatusCheckFailed_AttachedEBS"
     }
    ]
   },
   "min": 3
  },
  {
   "id": "ebs_threshold",
   "tier": "core",
   "quote": "triggers when the maximum status check metric is 1",
   "justify": "the metric is 0 or 1, so 'is 1' means >= 1 or, equally, > 0",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "MetricName"
        ],
        "op": "eq",
        "value": "StatusCheckFailed_AttachedEBS"
       }
      ]
     },
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "MetricName"
        ],
        "op": "eq",
        "value": "StatusCheckFailed_AttachedEBS"
       }
      ]
     },
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 0
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanThreshold"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ebs_stat",
   "kind": "attr",
   "tier": "core",
   "quote": "triggers when the maximum status check metric is 1",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "StatusCheckFailed_AttachedEBS"
     }
    ]
   },
   "cond": {
    "path": [
     "Statistic"
    ],
    "op": "eq",
    "value": "Maximum"
   },
   "quantifier": "all"
  },
  {
   "id": "ebs_period",
   "kind": "attr",
   "tier": "core",
   "quote": "for ten consecutive 60-second periods",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "StatusCheckFailed_AttachedEBS"
     }
    ]
   },
   "cond": {
    "path": [
     "Period"
    ],
    "op": "eq",
    "value": 60
   },
   "quantifier": "all"
  },
  {
   "id": "ebs_periods",
   "tier": "core",
   "quote": "for ten consecutive 60-second periods",
   "justify": "consecutive periods = EvaluationPeriods, with no M-of-N DatapointsToAlarm below it",
   "kind": "attr",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "StatusCheckFailed_AttachedEBS"
     }
    ]
   },
   "quantifier": "all",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "EvaluationPeriods"
      ],
      "op": "eq",
      "value": 10
     },
     {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "none_eq",
      "value": 1
     },
     {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "none_eq",
      "value": 2
     },
     {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "none_eq",
      "value": 3
     },
     {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "none_eq",
      "value": 4
     },
     {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "none_eq",
      "value": 5
     },
     {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "none_eq",
      "value": 6
     },
     {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "none_eq",
      "value": 7
     },
     {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "none_eq",
      "value": 8
     },
     {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "none_eq",
      "value": 9
     }
    ]
   }
  },
  {
   "id": "ebs_per_instance",
   "kind": "exists",
   "tier": "detail",
   "quote": "for those same first three instances",
   "justify": "those same first three instances: one alarm on each of three different instances",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "StatusCheckFailed_AttachedEBS"
     }
    ]
   },
   "distinct_path": [
    "Dimensions",
    "*",
    "Value"
   ],
   "min": 3
  },
  {
   "id": "status_ebs_same_instances",
   "kind": "exists",
   "tier": "detail",
   "quote": "for those same first three instances",
   "justify": "the status and EBS alarms cover the same three instances, so together they name exactly three",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "in",
      "value": [
       "StatusCheckFailed",
       "StatusCheckFailed_AttachedEBS"
      ]
     }
    ]
   },
   "distinct_path": [
    "Dimensions",
    "*",
    "Value"
   ],
   "min": 3,
   "max": 3
  },
  {
   "id": "ec2_namespace",
   "kind": "attr",
   "tier": "detail",
   "quote": "monitoring five new EC2 instances",
   "justify": "EC2 instance metrics live in AWS/EC2",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "Namespace"
    ],
    "op": "eq",
    "value": "AWS/EC2"
   },
   "quantifier": "all"
  },
  {
   "id": "x_actions_disabled",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "ActionsEnabled"
    ],
    "op": "falsy"
   },
   "quantifier": "all"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
