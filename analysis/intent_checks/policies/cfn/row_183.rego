# GENERATED from specs/cfn/row_183.json by intent_checks/build.py -- do not edit.
package intent.cfn.row_183

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "job": {
   "types": [
    "AWS::Glue::Job"
   ],
   "where": []
  },
  "bucket": {
   "types": [
    "AWS::S3::Bucket"
   ],
   "where": []
  },
  "stream": {
   "types": [
    "AWS::CloudWatch::MetricStream"
   ],
   "where": []
  },
  "firehose": {
   "types": [
    "AWS::KinesisFirehose::DeliveryStream"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "glue.amazonaws.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "cloudformation.amazonaws.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "firehose.amazonaws.com"
    },
    {
     "path": [
      "AssumeRolePolicyDocument"
     ],
     "op": "contains",
     "value": "streams.metrics.cloudwatch.amazonaws.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "seven_glue_jobs",
   "kind": "exists",
   "select": "job",
   "min": 7,
   "tier": "core",
   "quote": "using seven Glue jobs"
  },
  {
   "id": "job_names",
   "kind": "all_of",
   "tier": "core",
   "quote": "with each job having a specific name",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Glue::Job"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "etl_job_admin_suite_assets_access"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Glue::Job"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "etl_job_admin_suite_assets_metadata"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Glue::Job"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "etl_job_admin_suite_folder_assets"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Glue::Job"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "etl_job_admin_suite_q_metadata"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Glue::Job"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "etl_job_admin_suite_q_access"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Glue::Job"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "etl_job_admin_suite_ds_properties"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::Glue::Job"
      ],
      "where": [
       {
        "path": [
         "Name"
        ],
        "op": "eq",
        "value": "etl_job_admin_suite_datasource_properties"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "five_pythonshell_jobs",
   "kind": "exists",
   "min": 5,
   "tier": "core",
   "quote": "five Python shell jobs",
   "select": {
    "types": [
     "AWS::Glue::Job"
    ],
    "where": [
     {
      "path": [
       "Command",
       "Name"
      ],
      "op": "eq",
      "value": "pythonshell"
     },
     {
      "path": [
       "GlueVersion"
      ],
      "op": "eq",
      "value": "3.0"
     }
    ]
   },
   "justify": "Python shell jobs use Command.Name pythonshell"
  },
  {
   "id": "pythonshell_python_39",
   "kind": "attr",
   "quantifier": "all",
   "tier": "core",
   "quote": "five Python shell jobs with Python 3.9",
   "select": {
    "types": [
     "AWS::Glue::Job"
    ],
    "where": [
     {
      "path": [
       "Command",
       "Name"
      ],
      "op": "eq",
      "value": "pythonshell"
     }
    ]
   },
   "cond": {
    "path": [
     "Command",
     "PythonVersion"
    ],
    "op": "eq",
    "value": "3.9"
   },
   "justify": "Python shell jobs use Command.Name pythonshell; Python 3.9 is PythonVersion 3.9"
  },
  {
   "id": "two_etl_jobs",
   "kind": "exists",
   "min": 2,
   "tier": "core",
   "quote": "two ETL jobs with worker type G.1X and two workers using Glue version 5.0",
   "select": {
    "types": [
     "AWS::Glue::Job"
    ],
    "where": [
     {
      "path": [
       "Command",
       "Name"
      ],
      "op": "eq",
      "value": "glueetl"
     },
     {
      "path": [
       "WorkerType"
      ],
      "op": "eq",
      "value": "G.1X"
     },
     {
      "path": [
       "NumberOfWorkers"
      ],
      "op": "eq",
      "value": 2
     },
     {
      "path": [
       "GlueVersion"
      ],
      "op": "eq",
      "value": "5.0"
     }
    ]
   },
   "justify": "Glue Spark ETL jobs use Command.Name glueetl; two workers = NumberOfWorkers 2"
  },
  {
   "id": "max_concurrent_runs_1",
   "kind": "attr",
   "select": "job",
   "quantifier": "all",
   "tier": "detail",
   "quote": "MaxConcurrentRuns of 1",
   "cond": {
    "path": [
     "ExecutionProperty",
     "MaxConcurrentRuns"
    ],
    "op": "eq",
    "value": 1
   }
  },
  {
   "id": "timeout_120",
   "kind": "attr",
   "select": "job",
   "quantifier": "all",
   "tier": "detail",
   "quote": "a timeout of 120 minutes",
   "cond": {
    "path": [
     "Timeout"
    ],
    "op": "eq",
    "value": 120
   }
  },
  {
   "id": "etl_max_retries_0",
   "kind": "attr",
   "quantifier": "all",
   "tier": "detail",
   "quote": "for the ETL jobs max retries of 0",
   "select": {
    "types": [
     "AWS::Glue::Job"
    ],
    "where": [
     {
      "path": [
       "Command",
       "Name"
      ],
      "op": "eq",
      "value": "glueetl"
     }
    ]
   },
   "cond": {
    "path": [
     "MaxRetries"
    ],
    "op": "eq",
    "value": 0
   },
   "justify": "the ETL (Spark) jobs are the glueetl command type"
  },
  {
   "id": "default_args_region",
   "kind": "attr",
   "select": "job",
   "tier": "detail",
   "quote": "default arguments passing the AWS region",
   "cond": {
    "path": [
     "DefaultArguments"
    ],
    "op": "contains",
    "value": "us-east-1"
   },
   "justify": "AWS::Region resolves to us-east-1 in the normalised view"
  },
  {
   "id": "default_args_account",
   "kind": "attr",
   "select": "job",
   "tier": "detail",
   "quote": "and account ID where appropriate",
   "cond": {
    "path": [
     "DefaultArguments"
    ],
    "op": "contains",
    "value": "123456789012"
   },
   "justify": "AWS::AccountId resolves to 123456789012 in the normalised view"
  },
  {
   "id": "scripts_from_s3",
   "kind": "attr",
   "select": "job",
   "quantifier": "all",
   "tier": "detail",
   "quote": "all scripts fetched dynamically from a predefined S3 script bucket path",
   "cond": {
    "path": [
     "Command",
     "ScriptLocation"
    ],
    "op": "regex",
    "value": "(?i)^s3://"
   },
   "justify": "an S3 script path is an s3:// location"
  },
  {
   "id": "bucket_name",
   "kind": "attr",
   "select": "bucket",
   "tier": "core",
   "quote": "a newly created private S3 bucket named admin-suite-followed by the account ID",
   "cond": {
    "path": [
     "BucketName"
    ],
    "op": "regex",
    "value": "^admin-suite-?123456789012$"
   },
   "justify": "admin-suite- + AWS::AccountId (resolves to 123456789012)"
  },
  {
   "id": "bucket_public_access_blocked",
   "kind": "attr",
   "select": "bucket",
   "tier": "core",
   "quote": "with public access fully blocked",
   "cond": {
    "path": [
     "PublicAccessBlockConfiguration"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "BlockPublicAcls"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "BlockPublicPolicy"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "IgnorePublicAcls"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "RestrictPublicBuckets"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "bucket_retain",
   "kind": "attr",
   "select": "bucket",
   "tier": "core",
   "quote": "a DeletionPolicy of Retain",
   "cond": {
    "path": [
     "__resource__",
     "DeletionPolicy"
    ],
    "op": "eq",
    "value": "Retain"
   }
  },
  {
   "id": "scheduled_triggers_every_3h",
   "kind": "exists",
   "min": 7,
   "tier": "core",
   "quote": "each Glue job scheduled to run every 3 hours via its own scheduled Glue trigger",
   "select": {
    "types": [
     "AWS::Glue::Trigger"
    ],
    "where": [
     {
      "path": [
       "Type"
      ],
      "op": "eq",
      "value": "SCHEDULED"
     },
     {
      "path": [
       "Schedule"
      ],
      "op": "regex",
      "value": "(?i)^cron\\(\\s*\\S+\\s+(\\*|0)/3\\s"
     }
    ]
   },
   "justify": "seven jobs each with its own trigger; every 3 hours = hour field */3 or 0/3"
  },
  {
   "id": "triggers_reference_jobs",
   "kind": "any_of",
   "tier": "detail",
   "quote": "via its own scheduled Glue trigger",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::Glue::Trigger"
      ],
      "where": []
     },
     "to": "job"
    },
    {
     "kind": "join",
     "from": {
      "types": [
       "AWS::Glue::Trigger"
      ],
      "where": []
     },
     "from_path": [
      "Actions",
      "*",
      "JobName"
     ],
     "to": "job",
     "to_path": [
      "Name"
     ]
    }
   ]
  },
  {
   "id": "five_json_metric_streams",
   "kind": "exists",
   "min": 5,
   "tier": "core",
   "quote": "five CloudWatch metric streams using JSON output format",
   "select": {
    "types": [
     "AWS::CloudWatch::MetricStream"
    ],
    "where": [
     {
      "path": [
       "OutputFormat"
      ],
      "op": "eq",
      "value": "json"
     }
    ]
   }
  },
  {
   "id": "metric_streams_quicksight_namespace",
   "kind": "attr",
   "select": "stream",
   "tier": "detail",
   "quote": "capturing specific QuickSight metrics",
   "cond": {
    "path": [
     "IncludeFilters",
     "*",
     "Namespace"
    ],
    "op": "eq",
    "value": "AWS/QuickSight"
   },
   "justify": "QuickSight metrics live in the AWS/QuickSight namespace"
  },
  {
   "id": "stream_metrics_ingestion",
   "kind": "exists",
   "tier": "detail",
   "quote": "IngestionRowCount, IngestionLatency, IngestionInvocationCount, and IngestionErrorCount for the first stream",
   "select": {
    "types": [
     "AWS::CloudWatch::MetricStream"
    ],
    "where": [
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "IngestionRowCount"
     },
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "IngestionLatency"
     },
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "IngestionInvocationCount"
     },
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "IngestionErrorCount"
     }
    ]
   }
  },
  {
   "id": "stream_metrics_dashboard",
   "kind": "exists",
   "tier": "detail",
   "quote": "VisualLoadTime, DashboardViewLoadTime, DashboardViewCount, and VisualLoadErrorCount for the second",
   "select": {
    "types": [
     "AWS::CloudWatch::MetricStream"
    ],
    "where": [
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "VisualLoadTime"
     },
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "DashboardViewLoadTime"
     },
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "DashboardViewCount"
     },
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "VisualLoadErrorCount"
     }
    ]
   }
  },
  {
   "id": "stream_metrics_spice",
   "kind": "exists",
   "tier": "detail",
   "quote": "SPICECapacityLimitInMB and SPICECapacityConsumedInMB for the third",
   "select": {
    "types": [
     "AWS::CloudWatch::MetricStream"
    ],
    "where": [
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "SPICECapacityLimitInMB"
     },
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "SPICECapacityConsumedInMB"
     }
    ]
   }
  },
  {
   "id": "stream_metrics_quickindex",
   "kind": "exists",
   "tier": "detail",
   "quote": "QuickIndexDocumentCount and QuickIndexExtractedTextSize for the fourth",
   "select": {
    "types": [
     "AWS::CloudWatch::MetricStream"
    ],
    "where": [
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "QuickIndexDocumentCount"
     },
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "QuickIndexExtractedTextSize"
     }
    ]
   }
  },
  {
   "id": "stream_metrics_actions",
   "kind": "exists",
   "tier": "detail",
   "quote": "ActionInvocationError and ActionInvocationCount for the fifth",
   "select": {
    "types": [
     "AWS::CloudWatch::MetricStream"
    ],
    "where": [
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "ActionInvocationError"
     },
     {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "eq",
      "value": "ActionInvocationCount"
     }
    ]
   }
  },
  {
   "id": "stream_feeds_firehose",
   "kind": "ref",
   "from": "stream",
   "to": "firehose",
   "tier": "core",
   "quote": "each feeding into a dedicated DirectPut Kinesis Firehose delivery stream"
  },
  {
   "id": "five_directput_firehoses",
   "kind": "exists",
   "min": 5,
   "tier": "core",
   "quote": "a dedicated DirectPut Kinesis Firehose delivery stream",
   "select": {
    "types": [
     "AWS::KinesisFirehose::DeliveryStream"
    ],
    "where": [
     {
      "path": [
       "DeliveryStreamType"
      ],
      "op": "eq",
      "value": "DirectPut"
     }
    ]
   },
   "justify": "one dedicated delivery stream per metric stream (five)"
  },
  {
   "id": "firehose_to_bucket",
   "kind": "ref",
   "from": "firehose",
   "to": "bucket",
   "tier": "core",
   "quote": "writes to the same S3 bucket"
  },
  {
   "id": "firehose_prefixes",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with appropriate prefixes",
   "checks": [
    {
     "kind": "attr",
     "select": "firehose",
     "cond": {
      "path": [
       "S3DestinationConfiguration",
       "Prefix"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "firehose",
     "cond": {
      "path": [
       "ExtendedS3DestinationConfiguration",
       "Prefix"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "single_role_trust",
   "kind": "exists",
   "tier": "core",
   "quote": "a single IAM role assumable by glue, cloudformation, firehose, and streams.metrics.cloudwatch services",
   "select": {
    "types": [
     "AWS::IAM::Role"
    ],
    "where": [
     {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "contains",
      "value": "glue.amazonaws.com"
     },
     {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "contains",
      "value": "cloudformation.amazonaws.com"
     },
     {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "contains",
      "value": "firehose.amazonaws.com"
     },
     {
      "path": [
       "AssumeRolePolicyDocument"
      ],
      "op": "contains",
      "value": "streams.metrics.cloudwatch.amazonaws.com"
     }
    ]
   },
   "justify": "service principals are <service>.amazonaws.com"
  },
  {
   "id": "role_used_by_jobs_streams_firehose",
   "kind": "all_of",
   "tier": "detail",
   "quote": "all of this managed by a single IAM role",
   "checks": [
    {
     "kind": "ref",
     "from": "job",
     "to": "role"
    },
    {
     "kind": "ref",
     "from": "stream",
     "to": "role"
    },
    {
     "kind": "ref",
     "from": "firehose",
     "to": "role"
    }
   ]
  },
  {
   "id": "role_permissions",
   "kind": "all_of",
   "tier": "detail",
   "quote": "with permissions for QuickSight, Glue, S3, CloudWatch, Firehose, and IAM operations",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)quicksight:"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)(glue:|AWSGlue)"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)(s3:|AmazonS3)"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)cloudwatch:"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)firehose:"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)iam:"
     }
    }
   ],
   "justify": "service action prefixes (S3/Glue may come via AmazonS3*/AWSGlue* managed policies)"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
