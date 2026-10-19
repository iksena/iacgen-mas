package intent.cfn.row_182

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "composite": {
   "types": [
    "AWS::CloudWatch::CompositeAlarm"
   ],
   "where": []
  },
  "c_api": {
   "types": [
    "AWS::CloudWatch::CompositeAlarm"
   ],
   "where": [
    {
     "path": [
      "AlarmName"
     ],
     "op": "eq",
     "value": "API Gateway Health"
    }
   ]
  },
  "c_lambda": {
   "types": [
    "AWS::CloudWatch::CompositeAlarm"
   ],
   "where": [
    {
     "path": [
      "AlarmName"
     ],
     "op": "eq",
     "value": "Lambda Health"
    }
   ]
  },
  "c_rds": {
   "types": [
    "AWS::CloudWatch::CompositeAlarm"
   ],
   "where": [
    {
     "path": [
      "AlarmName"
     ],
     "op": "eq",
     "value": "RDS Health"
    }
   ]
  },
  "apigw": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/ApiGateway"
    }
   ]
  },
  "a_4xx": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/ApiGateway"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "4XXError"
    }
   ]
  },
  "a_5xx": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/ApiGateway"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "5XXError"
    }
   ]
  },
  "a_lat": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/ApiGateway"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)latency"
    }
   ]
  },
  "l_err": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/Lambda"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "Errors"
    }
   ]
  },
  "l_inv": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/Lambda"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "Invocations"
    }
   ]
  },
  "l_dur": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/Lambda"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "Duration"
    }
   ]
  },
  "lambda_err_inv": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/Lambda"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "in",
     "value": [
      "Errors",
      "Invocations"
     ]
    }
   ]
  },
  "rds": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/RDS"
    }
   ]
  },
  "r_CPUUtilization": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/RDS"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "CPUUtilization"
    }
   ]
  },
  "r_DatabaseConnections": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/RDS"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "DatabaseConnections"
    }
   ]
  },
  "r_Deadlocks": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/RDS"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "Deadlocks"
    }
   ]
  },
  "r_NetworkTransmitThroughput": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/RDS"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "NetworkTransmitThroughput"
    }
   ]
  },
  "r_NetworkReceiveThroughput": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/RDS"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "NetworkReceiveThroughput"
    }
   ]
  },
  "r_Queries": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/RDS"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "Queries"
    }
   ]
  },
  "r_DiskQueueDepth": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/RDS"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "DiskQueueDepth"
    }
   ]
  },
  "r_ReadLatency": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/RDS"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "ReadLatency"
    }
   ]
  },
  "r_WriteLatency": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "Namespace"
     ],
     "op": "eq",
     "value": "AWS/RDS"
    },
    {
     "path": [
      "MetricName"
     ],
     "op": "eq",
     "value": "WriteLatency"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "composite_api_gateway_health",
   "kind": "exists",
   "select": "c_api",
   "tier": "core",
   "quote": "composite alarms named API Gateway Health"
  },
  {
   "id": "composite_lambda_health",
   "kind": "exists",
   "select": "c_lambda",
   "tier": "core",
   "quote": "Lambda Health"
  },
  {
   "id": "composite_rds_health",
   "kind": "exists",
   "select": "c_rds",
   "tier": "core",
   "quote": "RDS Health"
  },
  {
   "id": "composite_or_rules",
   "kind": "attr",
   "select": "composite",
   "quantifier": "all",
   "tier": "core",
   "quote": "aggregate their underlying metric alarms with an OR-based alarm rule",
   "cond": {
    "path": [
     "AlarmRule"
    ],
    "op": "regex",
    "value": "(?is)ALARM\\(.*\\bOR\\b.*ALARM\\("
   }
  },
  {
   "id": "api_composite_three_members",
   "kind": "attr",
   "select": "c_api",
   "tier": "detail",
   "quote": "each aggregate their underlying metric alarms",
   "cond": {
    "path": [
     "AlarmRule"
    ],
    "op": "regex",
    "value": "(?is)(ALARM\\(.*){3}"
   }
  },
  {
   "id": "lambda_composite_four_members",
   "kind": "attr",
   "select": "c_lambda",
   "tier": "detail",
   "quote": "the composite rule only references the errors and duration alarms",
   "cond": {
    "path": [
     "AlarmRule"
    ],
    "op": "regex",
    "value": "(?is)(ALARM\\(.*){4}"
   }
  },
  {
   "id": "rds_composite_nine_members",
   "kind": "attr",
   "select": "c_rds",
   "tier": "detail",
   "quote": "each aggregate their underlying metric alarms",
   "cond": {
    "path": [
     "AlarmRule"
    ],
    "op": "regex",
    "value": "(?is)(ALARM\\(.*){9}"
   }
  },
  {
   "id": "apigw_alarms_exist",
   "kind": "all_of",
   "tier": "core",
   "quote": "for the API Gateway, alarm on 4XX errors",
   "checks": [
    {
     "kind": "exists",
     "select": "a_4xx"
    },
    {
     "kind": "exists",
     "select": "a_5xx"
    },
    {
     "kind": "exists",
     "select": "a_lat"
    }
   ]
  },
  {
   "id": "apigw_targets_remittance",
   "kind": "attr",
   "select": "apigw",
   "quantifier": "all",
   "tier": "detail",
   "quote": "targeting an existing Remittance API Gateway API",
   "cond": {
    "path": [
     "Dimensions",
     "*",
     "Value"
    ],
    "op": "eq",
    "value": "Remittance"
   }
  },
  {
   "id": "apigw_4xx_values",
   "kind": "attr",
   "select": "a_4xx",
   "tier": "core",
   "quote": "4XX errors averaging above 0 over a 300 second period",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "Statistic"
      ],
      "op": "eq",
      "value": "Average"
     },
     {
      "path": [
       "ComparisonOperator"
      ],
      "op": "eq",
      "value": "GreaterThanThreshold"
     },
     {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 0
     },
     {
      "path": [
       "Period"
      ],
      "op": "eq",
      "value": 300
     }
    ]
   },
   "justify": "\"above\"/\"exceed\" is GreaterThanThreshold"
  },
  {
   "id": "apigw_5xx_values",
   "kind": "attr",
   "select": "a_5xx",
   "tier": "core",
   "quote": "5XX errors averaging above 1 over a 60 second period",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "Statistic"
      ],
      "op": "eq",
      "value": "Average"
     },
     {
      "path": [
       "ComparisonOperator"
      ],
      "op": "eq",
      "value": "GreaterThanThreshold"
     },
     {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 1
     },
     {
      "path": [
       "Period"
      ],
      "op": "eq",
      "value": 60
     }
    ]
   },
   "justify": "\"above\"/\"exceed\" is GreaterThanThreshold"
  },
  {
   "id": "apigw_latency_values",
   "kind": "attr",
   "select": "a_lat",
   "tier": "core",
   "quote": "latency at or above 10000 milliseconds over a 300 second period",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "ComparisonOperator"
      ],
      "op": "eq",
      "value": "GreaterThanOrEqualToThreshold"
     },
     {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 10000
     },
     {
      "path": [
       "Period"
      ],
      "op": "eq",
      "value": 300
     }
    ]
   },
   "justify": "\"at or above\" is GreaterThanOrEqualToThreshold"
  },
  {
   "id": "apigw_eval_and_missing",
   "kind": "any_of",
   "tier": "detail",
   "quote": "each evaluated over a single evaluation period with one datapoint to alarm and TreatMissingData set to notBreaching",
   "checks": [
    {
     "select": "apigw",
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
        "value": 1
       },
       {
        "path": [
         "DatapointsToAlarm"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "TreatMissingData"
        ],
        "op": "eq",
        "value": "notBreaching"
       }
      ]
     },
     "kind": "attr"
    },
    {
     "select": "apigw",
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
        "value": 1
       },
       {
        "path": [
         "DatapointsToAlarm"
        ],
        "op": "absent"
       },
       {
        "path": [
         "TreatMissingData"
        ],
        "op": "eq",
        "value": "notBreaching"
       }
      ]
     },
     "kind": "attr"
    }
   ]
  },
  {
   "id": "lambda_alarms_exist",
   "kind": "all_of",
   "tier": "core",
   "quote": "for the Lambda functions, alarm when summed errors exceed 0",
   "checks": [
    {
     "kind": "exists",
     "select": "l_err",
     "min": 2
    },
    {
     "kind": "exists",
     "select": "l_inv",
     "min": 2
    },
    {
     "kind": "exists",
     "select": "l_dur",
     "min": 2
    }
   ]
  },
  {
   "id": "lambda_targets_get_function",
   "kind": "any_of",
   "tier": "core",
   "quote": "existing GetRemittances and CreateRemittance Lambda functions",
   "checks": [
    {
     "kind": "attr",
     "select": "l_err",
     "cond": {
      "path": [
       "Dimensions",
       "*",
       "Value"
      ],
      "op": "regex",
      "value": "(?i)get.?remittances?"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Metrics"
      ],
      "op": "regex",
      "value": "(?is)(Errors.*get.?remittances?|get.?remittances?.*Errors)"
     }
    }
   ],
   "justify": "prompt names the GetRemittances / CreateRemittance functions; any spelling/case or a ref to a function with that name counts"
  },
  {
   "id": "lambda_targets_create_function",
   "kind": "any_of",
   "tier": "core",
   "quote": "existing GetRemittances and CreateRemittance Lambda functions",
   "checks": [
    {
     "kind": "attr",
     "select": "l_err",
     "cond": {
      "path": [
       "Dimensions",
       "*",
       "Value"
      ],
      "op": "regex",
      "value": "(?i)create.?remittances?"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "Metrics"
      ],
      "op": "regex",
      "value": "(?is)(Errors.*create.?remittances?|create.?remittances?.*Errors)"
     }
    }
   ],
   "justify": "prompt names the GetRemittances / CreateRemittance functions; any spelling/case or a ref to a function with that name counts"
  },
  {
   "id": "lambda_errors_values",
   "kind": "attr",
   "select": "l_err",
   "quantifier": "all",
   "tier": "core",
   "quote": "summed errors exceed 0 over a 60 second period",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "Statistic"
      ],
      "op": "eq",
      "value": "Sum"
     },
     {
      "path": [
       "ComparisonOperator"
      ],
      "op": "eq",
      "value": "GreaterThanThreshold"
     },
     {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 0
     },
     {
      "path": [
       "Period"
      ],
      "op": "eq",
      "value": 60
     }
    ]
   },
   "justify": "\"above\"/\"exceed\" is GreaterThanThreshold"
  },
  {
   "id": "lambda_invocations_values",
   "kind": "attr",
   "select": "l_inv",
   "quantifier": "all",
   "tier": "detail",
   "quote": "summed invocations exceed 2 over a 60 second period",
   "cond": {
    "path": [],
    "op": "match",
    "value": [
     {
      "path": [
       "Statistic"
      ],
      "op": "eq",
      "value": "Sum"
     },
     {
      "path": [
       "ComparisonOperator"
      ],
      "op": "eq",
      "value": "GreaterThanThreshold"
     },
     {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 2
     },
     {
      "path": [
       "Period"
      ],
      "op": "eq",
      "value": 60
     }
    ]
   },
   "justify": "\"above\"/\"exceed\" is GreaterThanThreshold"
  },
  {
   "id": "lambda_err_inv_eval_missing",
   "kind": "any_of",
   "tier": "detail",
   "quote": "each with a single evaluation period, one datapoint to alarm, and TreatMissingData set to notBreaching",
   "checks": [
    {
     "select": "lambda_err_inv",
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
        "value": 1
       },
       {
        "path": [
         "DatapointsToAlarm"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "TreatMissingData"
        ],
        "op": "eq",
        "value": "notBreaching"
       }
      ]
     },
     "kind": "attr"
    },
    {
     "select": "lambda_err_inv",
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
        "value": 1
       },
       {
        "path": [
         "DatapointsToAlarm"
        ],
        "op": "absent"
       },
       {
        "path": [
         "TreatMissingData"
        ],
        "op": "eq",
        "value": "notBreaching"
       }
      ]
     },
     "kind": "attr"
    }
   ]
  },
  {
   "id": "lambda_duration_values",
   "kind": "any_of",
   "tier": "detail",
   "quote": "average duration at or above 10000 milliseconds over a 900 second period, single evaluation period, one datapoint to alarm",
   "justify": "\"at or above\" is GreaterThanOrEqualToThreshold",
   "checks": [
    {
     "select": "l_dur",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Average"
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 10000
       },
       {
        "path": [
         "Period"
        ],
        "op": "eq",
        "value": 900
       },
       {
        "path": [
         "EvaluationPeriods"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "DatapointsToAlarm"
        ],
        "op": "eq",
        "value": 1
       }
      ]
     },
     "kind": "attr"
    },
    {
     "select": "l_dur",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Average"
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 10000
       },
       {
        "path": [
         "Period"
        ],
        "op": "eq",
        "value": 900
       },
       {
        "path": [
         "EvaluationPeriods"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "DatapointsToAlarm"
        ],
        "op": "absent"
       }
      ]
     },
     "kind": "attr"
    }
   ]
  },
  {
   "id": "lambda_duration_missing",
   "kind": "attr",
   "select": "l_dur",
   "quantifier": "all",
   "tier": "detail",
   "quote": "have TreatMissingData set to missing",
   "cond": {
    "path": [
     "TreatMissingData"
    ],
    "op": "eq",
    "value": "missing"
   }
  },
  {
   "id": "rds_alarms_exist",
   "kind": "all_of",
   "tier": "core",
   "quote": "for the RDS instance, alarm on high CPU utilization",
   "checks": [
    {
     "kind": "exists",
     "select": "r_CPUUtilization"
    },
    {
     "kind": "exists",
     "select": "r_DatabaseConnections"
    },
    {
     "kind": "exists",
     "select": "r_Deadlocks"
    },
    {
     "kind": "exists",
     "select": "r_NetworkTransmitThroughput"
    },
    {
     "kind": "exists",
     "select": "r_NetworkReceiveThroughput"
    },
    {
     "kind": "exists",
     "select": "r_Queries"
    },
    {
     "kind": "exists",
     "select": "r_DiskQueueDepth"
    },
    {
     "kind": "exists",
     "select": "r_ReadLatency"
    },
    {
     "kind": "exists",
     "select": "r_WriteLatency"
    }
   ]
  },
  {
   "id": "rds_targets_instance",
   "kind": "attr",
   "select": "rds",
   "quantifier": "all",
   "tier": "core",
   "quote": "an existing dbcluster1-instance1 RDS instance",
   "cond": {
    "path": [
     "Dimensions",
     "*",
     "Value"
    ],
    "op": "eq",
    "value": "dbcluster1-instance1"
   }
  },
  {
   "id": "rds_thresholds",
   "kind": "all_of",
   "tier": "detail",
   "quote": "high CPU utilization averaging at or above 70 percent",
   "checks": [
    {
     "kind": "attr",
     "select": "r_CPUUtilization",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Average"
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 70
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "r_DatabaseConnections",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Average"
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 100
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "r_Deadlocks",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Average"
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 10
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "r_NetworkTransmitThroughput",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Average"
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 10485760
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "r_NetworkReceiveThroughput",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Average"
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 10485760
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "r_Queries",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Average"
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 100
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "r_DiskQueueDepth",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Average"
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 50
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "r_ReadLatency",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Average"
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 0.1
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "r_WriteLatency",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Average"
       },
       {
        "path": [
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 0.1
       }
      ]
     }
    }
   ],
   "justify": "\"at or above\" is GreaterThanOrEqualToThreshold"
  },
  {
   "id": "rds_period_eval",
   "kind": "any_of",
   "tier": "detail",
   "quote": "each evaluated over a 300 second period with a single evaluation period and one datapoint to alarm",
   "checks": [
    {
     "select": "rds",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Period"
        ],
        "op": "eq",
        "value": 300
       },
       {
        "path": [
         "EvaluationPeriods"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "DatapointsToAlarm"
        ],
        "op": "eq",
        "value": 1
       }
      ]
     },
     "kind": "attr"
    },
    {
     "select": "rds",
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "match",
      "value": [
       {
        "path": [
         "Period"
        ],
        "op": "eq",
        "value": 300
       },
       {
        "path": [
         "EvaluationPeriods"
        ],
        "op": "eq",
        "value": 1
       },
       {
        "path": [
         "DatapointsToAlarm"
        ],
        "op": "absent"
       }
      ]
     },
     "kind": "attr"
    }
   ]
  },
  {
   "id": "rds_treat_missing_default",
   "kind": "any_of",
   "tier": "detail",
   "quote": "leaving TreatMissingData unset on every RDS alarm so CloudWatch's standard default treatment applies",
   "checks": [
    {
     "kind": "attr",
     "select": "rds",
     "quantifier": "all",
     "cond": {
      "path": [
       "TreatMissingData"
      ],
      "op": "absent"
     }
    },
    {
     "kind": "attr",
     "select": "rds",
     "quantifier": "all",
     "cond": {
      "path": [
       "TreatMissingData"
      ],
      "op": "eq",
      "value": "missing"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
