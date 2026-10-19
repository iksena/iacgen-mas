package intent.cfn.row_126

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
  "alarm": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": []
  },
  "a_write_throttle": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)^Write.*Throttle"
    }
   ]
  },
  "a_throttled": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)ThrottledRequests"
    }
   ]
  },
  "a_cond_check": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)ConditionalCheck"
    }
   ]
  },
  "a_user_err": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)UserErrors"
    }
   ]
  },
  "a_sys_err": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)SystemErrors"
    }
   ]
  },
  "a_txn": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)TransactionConflict"
    }
   ]
  },
  "a_oidx": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)OnlineIndex.*Throttle"
    }
   ]
  },
  "a_latency": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)SuccessfulRequestLatency"
    }
   ]
  },
  "a_acct_read": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)Account.*Read.*Capacity"
    }
   ]
  },
  "a_acct_write": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)Account.*Write.*Capacity"
    }
   ]
  },
  "a_pending": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)PendingReplication"
    }
   ]
  },
  "a_repl_lat": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)^ReplicationLatency"
    }
   ]
  },
  "a_read_cap": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)Read.*Capacity"
    }
   ]
  },
  "a_write_cap": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)Write.*Capacity"
    }
   ]
  },
  "a_util": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": [
    {
     "path": [
      "MetricName"
     ],
     "op": "regex",
     "value": "(?i)(Read|Write).*Capacity"
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
   "quote": "creates a DynamoDB table for testing purposes"
  },
  {
   "id": "hash_key_user_id",
   "kind": "attr",
   "select": "table",
   "tier": "core",
   "quote": "a single attribute key named \"USER_ID\" as the hash key",
   "cond": {
    "path": [
     "KeySchema",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "AttributeName"
      ],
      "op": "eq",
      "value": "USER_ID"
     },
     {
      "path": [
       "KeyType"
      ],
      "op": "eq",
      "value": "HASH"
     }
    ]
   }
  },
  {
   "id": "single_key_attribute",
   "kind": "attr",
   "select": "table",
   "tier": "detail",
   "quote": "a single attribute key",
   "cond": {
    "path": [
     "KeySchema"
    ],
    "op": "len_eq",
    "value": 1
   }
  },
  {
   "id": "on_demand_billing",
   "kind": "attr",
   "select": "table",
   "tier": "core",
   "quote": "using on-demand billing",
   "cond": {
    "path": [
     "BillingMode"
    ],
    "op": "eq",
    "value": "PAY_PER_REQUEST"
   }
  },
  {
   "id": "pitr_enabled",
   "kind": "attr",
   "select": "table",
   "tier": "core",
   "quote": "point-in-time recovery enabled",
   "cond": {
    "path": [
     "PointInTimeRecoverySpecification",
     "PointInTimeRecoveryEnabled"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "alarms_monitor_table",
   "kind": "ref",
   "from": "alarm",
   "to": "table",
   "tier": "core",
   "quote": "CloudWatch alarms to monitor the table's health and performance"
  },
  {
   "id": "count_alarms_exist",
   "kind": "all_of",
   "tier": "core",
   "quote": "including alarms for write throttle events, throttled requests, conditional check failures, user and system errors, transaction conflicts",
   "checks": [
    {
     "kind": "exists",
     "select": "a_write_throttle"
    },
    {
     "kind": "exists",
     "select": "a_throttled"
    },
    {
     "kind": "exists",
     "select": "a_cond_check"
    },
    {
     "kind": "exists",
     "select": "a_user_err"
    },
    {
     "kind": "exists",
     "select": "a_sys_err"
    },
    {
     "kind": "exists",
     "select": "a_txn"
    }
   ]
  },
  {
   "id": "index_latency_alarms_exist",
   "kind": "all_of",
   "tier": "core",
   "quote": "online index throttle events, successful request latency",
   "checks": [
    {
     "kind": "exists",
     "select": "a_oidx"
    },
    {
     "kind": "exists",
     "select": "a_latency"
    }
   ]
  },
  {
   "id": "utilization_alarms_exist",
   "kind": "all_of",
   "tier": "core",
   "quote": "account-level and table-level read and write capacity utilization",
   "checks": [
    {
     "kind": "exists",
     "select": "a_acct_read"
    },
    {
     "kind": "exists",
     "select": "a_acct_write"
    },
    {
     "kind": "exists",
     "select": "a_read_cap",
     "distinct_path": [
      "MetricName"
     ],
     "min": 2
    },
    {
     "kind": "exists",
     "select": "a_write_cap",
     "distinct_path": [
      "MetricName"
     ],
     "min": 2
    }
   ],
   "justify": "\"account-level and table-level\" read (and write) capacity = two distinct read (write) capacity metrics, one of them account-level"
  },
  {
   "id": "replication_alarms_exist",
   "kind": "all_of",
   "tier": "core",
   "quote": "replication-related metrics like pending replication count and replication latency",
   "checks": [
    {
     "kind": "exists",
     "select": "a_pending"
    },
    {
     "kind": "exists",
     "select": "a_repl_lat"
    }
   ]
  },
  {
   "id": "all_alarms_period_60",
   "kind": "attr",
   "select": "alarm",
   "quantifier": "all",
   "tier": "detail",
   "quote": "all alarms configured to evaluate metrics at 60-second periods",
   "cond": {
    "path": [
     "Period"
    ],
    "op": "eq",
    "value": 60
   }
  },
  {
   "id": "count_thresholds_1",
   "kind": "all_of",
   "tier": "detail",
   "quote": "thresholds of 1 for count-based alarms",
   "checks": [
    {
     "kind": "attr",
     "select": "a_write_throttle",
     "cond": {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 1
     }
    },
    {
     "kind": "attr",
     "select": "a_throttled",
     "cond": {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 1
     }
    },
    {
     "kind": "attr",
     "select": "a_cond_check",
     "cond": {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 1
     }
    },
    {
     "kind": "attr",
     "select": "a_user_err",
     "cond": {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 1
     }
    },
    {
     "kind": "attr",
     "select": "a_sys_err",
     "cond": {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 1
     }
    },
    {
     "kind": "attr",
     "select": "a_txn",
     "cond": {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 1
     }
    }
   ]
  },
  {
   "id": "online_index_threshold_10",
   "kind": "attr",
   "select": "a_oidx",
   "tier": "detail",
   "quote": "10 for online index throttle events",
   "cond": {
    "path": [
     "Threshold"
    ],
    "op": "eq",
    "value": 10
   }
  },
  {
   "id": "latency_threshold_100",
   "kind": "attr",
   "select": "a_latency",
   "tier": "detail",
   "quote": "100 milliseconds for successful request latency",
   "cond": {
    "path": [
     "Threshold"
    ],
    "op": "eq",
    "value": 100
   }
  },
  {
   "id": "utilization_thresholds_85",
   "kind": "attr",
   "tier": "detail",
   "quote": "85 percent for utilization metrics",
   "select": "a_util",
   "quantifier": "all",
   "cond": {
    "path": [
     "Threshold"
    ],
    "op": "eq",
    "value": 85
   }
  },
  {
   "id": "pending_replication_threshold_100",
   "kind": "attr",
   "select": "a_pending",
   "tier": "detail",
   "quote": "100 for pending replication count",
   "cond": {
    "path": [
     "Threshold"
    ],
    "op": "eq",
    "value": 100
   }
  },
  {
   "id": "replication_latency_threshold_10",
   "kind": "attr",
   "select": "a_repl_lat",
   "tier": "detail",
   "quote": "10 milliseconds for replication latency",
   "cond": {
    "path": [
     "Threshold"
    ],
    "op": "eq",
    "value": 10
   }
  },
  {
   "id": "replication_eval_5_of_3",
   "kind": "all_of",
   "tier": "detail",
   "quote": "using 5 evaluation periods and 3 datapoints to trigger",
   "checks": [
    {
     "kind": "attr",
     "select": "a_pending",
     "cond": {
      "path": [
       "EvaluationPeriods"
      ],
      "op": "eq",
      "value": 5
     }
    },
    {
     "kind": "attr",
     "select": "a_pending",
     "cond": {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "eq",
      "value": 3
     }
    },
    {
     "kind": "attr",
     "select": "a_repl_lat",
     "cond": {
      "path": [
       "EvaluationPeriods"
      ],
      "op": "eq",
      "value": 5
     }
    },
    {
     "kind": "attr",
     "select": "a_repl_lat",
     "cond": {
      "path": [
       "DatapointsToAlarm"
      ],
      "op": "eq",
      "value": 3
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
