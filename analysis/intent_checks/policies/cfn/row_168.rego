package intent.cfn.row_168

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "queue": {
   "types": [
    "AWS::SQS::Queue"
   ],
   "where": []
  },
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "std_with_dlq": {
   "types": [
    "AWS::SQS::Queue"
   ],
   "where": [
    {
     "path": [
      "FifoQueue"
     ],
     "op": "none_eq",
     "value": true
    },
    {
     "path": [
      "RedrivePolicy",
      "maxReceiveCount"
     ],
     "op": "eq",
     "value": 5
    }
   ]
  },
  "std_dlq": {
   "types": [
    "AWS::SQS::Queue"
   ],
   "where": [
    {
     "path": [
      "FifoQueue"
     ],
     "op": "none_eq",
     "value": true
    },
    {
     "path": [
      "RedrivePolicy"
     ],
     "op": "absent"
    }
   ]
  },
  "fifo_with_dlq": {
   "types": [
    "AWS::SQS::Queue"
   ],
   "where": [
    {
     "path": [
      "FifoQueue"
     ],
     "op": "truthy"
    },
    {
     "path": [
      "RedrivePolicy",
      "deadLetterTargetArn"
     ],
     "op": "present"
    }
   ]
  },
  "fifo_no_redrive": {
   "types": [
    "AWS::SQS::Queue"
   ],
   "where": [
    {
     "path": [
      "FifoQueue"
     ],
     "op": "truthy"
    },
    {
     "path": [
      "RedrivePolicy"
     ],
     "op": "absent"
    }
   ]
  },
  "alarm": {
   "types": [
    "AWS::CloudWatch::Alarm"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "kms_key",
   "kind": "exists",
   "select": "key",
   "tier": "detail",
   "quote": "a KMS key to encrypt all queues"
  },
  {
   "id": "all_queues_kms_encrypted",
   "kind": "attr",
   "select": "queue",
   "quantifier": "all",
   "cond": {
    "path": [
     "KmsMasterKeyId"
    ],
    "op": "present"
   },
   "tier": "core",
   "quote": "a KMS key to encrypt all queues"
  },
  {
   "id": "queues_use_template_key",
   "kind": "ref",
   "from": "queue",
   "to": "key",
   "tier": "detail",
   "quote": "a KMS key to encrypt all queues"
  },
  {
   "id": "fifo_queues_without_redrive",
   "kind": "exists",
   "select": "fifo_no_redrive",
   "min": 2,
   "tier": "core",
   "quote": "a FIFO queue without a dead letter queue",
   "justify": "the FIFO queue without a DLQ plus the FIFO DLQ(s) (its DLQ and a separate FIFO DLQ) are all FIFO queues with no redrive policy"
  },
  {
   "id": "fifo_queue_with_fifo_dlq",
   "kind": "ref",
   "from": "fifo_with_dlq",
   "to": "fifo_no_redrive",
   "tier": "core",
   "quote": "a FIFO queue with a dead letter queue, its DLQ"
  },
  {
   "id": "standard_queue_redrive_5",
   "kind": "ref",
   "from": "std_with_dlq",
   "to": "std_dlq",
   "tier": "core",
   "quote": "a standard queue with a DLQ using a redrive policy with a maximum receive count of 5, that DLQ"
  },
  {
   "id": "alarms_actions_disabled",
   "kind": "attr",
   "select": "alarm",
   "quantifier": "all",
   "cond": {
    "path": [
     "ActionsEnabled"
    ],
    "op": "falsy"
   },
   "tier": "core",
   "quote": "with all alarms having actions disabled"
  },
  {
   "id": "std_messages_sent_sum_alarm",
   "kind": "ref",
   "tier": "core",
   "to": "std_with_dlq",
   "from": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "regex",
      "value": "(?i)NumberOfMessagesSent$"
     },
     {
      "path": [
       "Statistic"
      ],
      "op": "eq",
      "value": "Sum"
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
       "TreatMissingData"
      ],
      "op": "eq",
      "value": "breaching"
     }
    ]
   },
   "quote": "monitor the standard queue's number of messages sent as a sum with a threshold of 1 breaching on missing data"
  },
  {
   "id": "fifo_dlq_messages_sent_anomaly_band",
   "kind": "ref",
   "tier": "core",
   "to": "fifo_with_dlq",
   "from": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "Metrics",
       "*",
       "Expression"
      ],
      "op": "regex",
      "value": "(?i)ANOMALY_DETECTION_BAND"
     },
     {
      "path": [
       "Metrics",
       "*",
       "MetricStat",
       "Stat"
      ],
      "op": "eq",
      "value": "Average"
     },
     {
      "path": [
       "Metrics",
       "*",
       "MetricStat",
       "Metric",
       "MetricName"
      ],
      "op": "regex",
      "value": "(?i)NumberOfMessagesSent$"
     }
    ]
   },
   "quote": "the FIFO queue with DLQ's average number of messages sent using an anomaly detection band"
  },
  {
   "id": "sent_message_size_alarms",
   "kind": "all_of",
   "tier": "detail",
   "quote": "the maximum sent message size on both the standard and the separate FIFO queue with a threshold of 183500 bytes",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "MetricName"
        ],
        "op": "eq",
        "value": "SentMessageSize"
       },
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Maximum"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 183500
       }
      ]
     },
     "to": "std_with_dlq"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "MetricName"
        ],
        "op": "eq",
        "value": "SentMessageSize"
       },
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Maximum"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 183500
       }
      ]
     },
     "to": "fifo_no_redrive"
    }
   ]
  },
  {
   "id": "dlq_visible_messages_alarms",
   "kind": "all_of",
   "tier": "detail",
   "quote": "the sum of visible messages on both DLQs alerting when greater than zero",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "MetricName"
        ],
        "op": "eq",
        "value": "ApproximateNumberOfMessagesVisible"
       },
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Sum"
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
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanThreshold"
       }
      ]
     },
     "to": "std_dlq"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "MetricName"
        ],
        "op": "eq",
        "value": "ApproximateNumberOfMessagesVisible"
       },
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Sum"
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
         "ComparisonOperator"
        ],
        "op": "eq",
        "value": "GreaterThanThreshold"
       }
      ]
     },
     "to": "fifo_no_redrive"
    }
   ],
   "justify": "\"alerting when greater than zero\" = GreaterThanThreshold with threshold 0"
  },
  {
   "id": "oldest_message_age_alarms",
   "kind": "all_of",
   "tier": "detail",
   "quote": "the maximum age of the oldest message on the standard and separate FIFO queue with a threshold of 15 and treating missing data",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "MetricName"
        ],
        "op": "eq",
        "value": "ApproximateAgeOfOldestMessage"
       },
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Maximum"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 15
       },
       {
        "path": [
         "TreatMissingData"
        ],
        "op": "present",
        "value": null
       }
      ]
     },
     "to": "std_with_dlq"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "MetricName"
        ],
        "op": "eq",
        "value": "ApproximateAgeOfOldestMessage"
       },
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Maximum"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 15
       },
       {
        "path": [
         "TreatMissingData"
        ],
        "op": "present",
        "value": null
       }
      ]
     },
     "to": "fifo_no_redrive"
    }
   ]
  },
  {
   "id": "messages_not_visible_alarms",
   "kind": "all_of",
   "tier": "detail",
   "quote": "the maximum number of messages not visible on the standard and separate FIFO queue with respective thresholds of 108000 and 18000",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "MetricName"
        ],
        "op": "eq",
        "value": "ApproximateNumberOfMessagesNotVisible"
       },
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Maximum"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 108000
       }
      ]
     },
     "to": "std_with_dlq"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "MetricName"
        ],
        "op": "eq",
        "value": "ApproximateNumberOfMessagesNotVisible"
       },
       {
        "path": [
         "Statistic"
        ],
        "op": "eq",
        "value": "Maximum"
       },
       {
        "path": [
         "Threshold"
        ],
        "op": "eq",
        "value": 18000
       }
      ]
     },
     "to": "fifo_no_redrive"
    }
   ]
  },
  {
   "id": "std_dlq_oldest_age_alarm",
   "kind": "ref",
   "tier": "detail",
   "to": "std_dlq",
   "from": {
    "types": [
     "AWS::CloudWatch::Alarm"
    ],
    "where": [
     {
      "path": [
       "MetricName"
      ],
      "op": "eq",
      "value": "ApproximateAgeOfOldestMessage"
     },
     {
      "path": [
       "Statistic"
      ],
      "op": "eq",
      "value": "Maximum"
     },
     {
      "path": [
       "Threshold"
      ],
      "op": "eq",
      "value": 90
     }
    ]
   },
   "quote": "the maximum age of the oldest message on the standard DLQ with a threshold of 90"
  },
  {
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "TreatMissingData"
        ],
        "op": "eq",
        "value": "notBreaching"
       },
       {
        "path": [
         "Dimensions"
        ],
        "op": "absent"
       },
       {
        "path": [
         "Metrics",
         "*",
         "MetricStat"
        ],
        "op": "absent"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "TreatMissingData"
        ],
        "op": "eq",
        "value": "notBreaching"
       },
       {
        "path": [
         "AlarmName"
        ],
        "op": "regex",
        "value": "(?i)(always.?ok|synthetic)"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::CloudWatch::Alarm"
      ],
      "where": [
       {
        "path": [
         "TreatMissingData"
        ],
        "op": "eq",
        "value": "notBreaching"
       },
       {
        "path": [
         "AlarmDescription"
        ],
        "op": "regex",
        "value": "(?i)(always.?ok|synthetic)"
       }
      ]
     }
    }
   ],
   "justify": "\"always\" / \"OK\" / \"synthetic\" are the prompt's own words for this alarm; the GT metric shape is not prescribed",
   "id": "always_ok_alarm",
   "tier": "detail",
   "quote": "a synthetic always-OK alarm that evaluates to not breaching on missing data"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
