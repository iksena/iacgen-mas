package intent.cfn.row_114

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "bucket": {
   "types": [
    "AWS::S3::Bucket"
   ],
   "where": [
    {
     "path": [
      "BucketName"
     ],
     "op": "regex",
     "value": "(?i)^admin-suite-"
    }
   ]
  },
  "jobs": {
   "types": [
    "AWS::Glue::Job"
   ],
   "where": []
  },
  "trig": {
   "types": [
    "AWS::Glue::Trigger"
   ],
   "where": []
  },
  "role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": []
  },
  "perm": {
   "types": [
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::IAM::ManagedPolicy"
   ],
   "where": []
  },
  "ms": {
   "types": [
    "AWS::CloudWatch::MetricStream"
   ],
   "where": []
  },
  "fh": {
   "types": [
    "AWS::KinesisFirehose::DeliveryStream"
   ],
   "where": []
  },
  "access": {
   "types": [
    "AWS::Glue::Job"
   ],
   "where": [
    {
     "path": [
      "WorkerType"
     ],
     "op": "eq",
     "value": "G.2X"
    },
    {
     "path": [
      "NumberOfWorkers"
     ],
     "op": "eq",
     "value": 5
    },
    {
     "path": [
      "Timeout"
     ],
     "op": "eq",
     "value": 360
    }
   ]
  },
  "others": {
   "types": [
    "AWS::Glue::Job"
   ],
   "where": [
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
      "Timeout"
     ],
     "op": "eq",
     "value": 240
    }
   ]
  },
  "p": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "default"
     ],
     "op": "eq",
     "value": "admin-console-cfn-dataprepare-code"
    }
   ]
  },
  "script_bucket": {
   "types": [
    "AWS::S3::Bucket"
   ],
   "where": [
    {
     "path": [
      "BucketName"
     ],
     "op": "contains",
     "value": "admin-console-cfn-dataprepare-code"
    }
   ]
  },
  "consolidated_role": {
   "types": [
    "AWS::IAM::Role"
   ],
   "where": [
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "regex",
     "value": "(?i)^glue\\.amazonaws\\.com$"
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "regex",
     "value": "(?i)^cloudformation\\.amazonaws\\.com$"
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "regex",
     "value": "(?i)^firehose\\.amazonaws\\.com$"
    },
    {
     "path": [
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "regex",
     "value": "(?i)metrics\\.cloudwatch\\.amazonaws\\.com|^cloudwatch\\.amazonaws\\.com$"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "admin_bucket",
   "kind": "attr",
   "tier": "core",
   "quote": "a private S3 bucket named using the pattern \"admin-suite-\" followed by the account ID",
   "select": {
    "types": [
     "AWS::S3::Bucket"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "BucketName"
    ],
    "op": "regex",
    "value": "^admin-suite-(123456789012|\\$\\{AWS::AccountId\\})$"
   },
   "justify": "account ID resolves to the pseudo-parameter value 123456789012"
  },
  {
   "id": "bucket_private",
   "kind": "any_of",
   "tier": "core",
   "quote": "a private S3 bucket",
   "checks": [
    {
     "kind": "attr",
     "select": "bucket",
     "cond": {
      "path": [
       "AccessControl"
      ],
      "op": "eq",
      "value": "Private"
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::S3::Bucket"
      ],
      "where": [
       {
        "path": [
         "BucketName"
        ],
        "op": "regex",
        "value": "(?i)^admin-suite-"
       },
       {
        "path": [
         "PublicAccessBlockConfiguration",
         "BlockPublicAcls"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "PublicAccessBlockConfiguration",
         "BlockPublicPolicy"
        ],
        "op": "truthy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "AWS::S3::Bucket"
      ],
      "where": [
       {
        "path": [
         "BucketName"
        ],
        "op": "regex",
        "value": "(?i)^admin-suite-"
       },
       {
        "path": [
         "AccessControl"
        ],
        "op": "absent"
       },
       {
        "path": [
         "PublicAccessBlockConfiguration"
        ],
        "op": "absent"
       }
      ]
     }
    }
   ],
   "justify": "a bucket with no ACL or public-access settings is private by default"
  },
  {
   "id": "script_bucket_param",
   "kind": "exists",
   "tier": "core",
   "quote": "should accept a parameter for the script bucket name which defaults to \"admin-console-cfn-dataprepare-code\"",
   "select": "p"
  },
  {
   "id": "job_scripts_in_script_bucket",
   "kind": "any_of",
   "tier": "detail",
   "quote": "upload the necessary Glue ETL scripts into it",
   "checks": [
    {
     "kind": "attr",
     "select": "jobs",
     "cond": {
      "path": [
       "Command",
       "ScriptLocation"
      ],
      "op": "contains",
      "value": "admin-console-cfn-dataprepare-code"
     },
     "quantifier": "all"
    },
    {
     "kind": "ref",
     "from": "jobs",
     "to": "script_bucket"
    }
   ]
  },
  {
   "id": "glue_jobs",
   "kind": "exists",
   "tier": "core",
   "quote": "define Glue jobs for five distinct processing pipelines",
   "select": "jobs",
   "min": 5
  },
  {
   "id": "job_pipelines",
   "kind": "all_of",
   "tier": "detail",
   "quote": "covering assets access, dataset metadata, folder assets, Q metadata, and datasource properties",
   "checks": [
    {
     "kind": "attr",
     "select": "jobs",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)assets?.?access|access.?manage|user.?access|user_info"
     }
    },
    {
     "kind": "attr",
     "select": "jobs",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)dataset"
     }
    },
    {
     "kind": "attr",
     "select": "jobs",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)folder"
     }
    },
    {
     "kind": "attr",
     "select": "jobs",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)[_/-]q[_.-]|q.?metadata"
     }
    },
    {
     "kind": "attr",
     "select": "jobs",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "(?i)data.?source"
     }
    }
   ]
  },
  {
   "id": "glue_version_5",
   "kind": "attr",
   "tier": "core",
   "quote": "each using Glue version 5.0",
   "select": "jobs",
   "cond": {
    "path": [
     "GlueVersion"
    ],
    "op": "regex",
    "value": "^5(\\.0)?$"
   },
   "quantifier": "all"
  },
  {
   "id": "access_job",
   "kind": "exists",
   "tier": "core",
   "quote": "the access management job using G.2X with 5 workers and a 360 timeout",
   "select": "access"
  },
  {
   "id": "other_jobs",
   "kind": "exists",
   "tier": "core",
   "quote": "all others use G.1X with 2 workers and a 240 timeout",
   "select": "others",
   "min": 4,
   "justify": "five jobs minus the access management job"
  },
  {
   "id": "triggers",
   "kind": "exists",
   "tier": "core",
   "quote": "all jobs must be scheduled via Glue triggers",
   "select": {
    "types": [
     "AWS::Glue::Trigger"
    ],
    "where": []
   },
   "min": 5
  },
  {
   "id": "triggers_scheduled",
   "kind": "attr",
   "tier": "core",
   "quote": "scheduled via Glue triggers to run in a staggered daily sequence",
   "select": "trig",
   "cond": {
    "path": [
     "Type"
    ],
    "op": "eq",
    "value": "SCHEDULED"
   },
   "quantifier": "all"
  },
  {
   "id": "start_2am",
   "kind": "attr",
   "tier": "core",
   "quote": "starting at 2 AM UTC",
   "select": "trig",
   "cond": {
    "path": [
     "Schedule"
    ],
    "op": "regex",
    "value": "(?i)^cron\\(\\s*0{1,2}\\s+0?2\\s+[*?]\\s+\\*\\s+[?*]"
   },
   "justify": "2 AM -> minute 0, hour 2 in a daily cron"
  },
  {
   "id": "triggers_daily",
   "kind": "attr",
   "tier": "detail",
   "quote": "staggered daily sequence",
   "select": "trig",
   "cond": {
    "path": [
     "Schedule"
    ],
    "op": "regex",
    "value": "(?i)^cron\\(\\s*\\d+\\s+\\d+\\s+[*?]\\s+\\*\\s+[?*]"
   },
   "quantifier": "all",
   "justify": "daily -> fixed minute and hour, day and month wildcards"
  },
  {
   "id": "staggered",
   "kind": "exists",
   "tier": "detail",
   "quote": "staggered daily sequence",
   "select": "trig",
   "distinct_path": [
    "Schedule"
   ],
   "min": 5,
   "justify": "five jobs staggered"
  },
  {
   "id": "triggers_to_jobs",
   "kind": "any_of",
   "tier": "detail",
   "quote": "all jobs must be scheduled via Glue triggers",
   "checks": [
    {
     "kind": "ref",
     "from": "trig",
     "to": "jobs"
    },
    {
     "kind": "join",
     "from": "trig",
     "from_path": [
      "Actions",
      "*",
      "JobName"
     ],
     "to": "jobs",
     "to_path": [
      "Name"
     ]
    }
   ]
  },
  {
   "id": "metric_streams",
   "kind": "exists",
   "tier": "core",
   "quote": "CloudWatch metric streams to capture specific QuickSight metrics across five categories",
   "select": "ms",
   "min": 5
  },
  {
   "id": "ms_namespace",
   "kind": "attr",
   "tier": "detail",
   "quote": "specific QuickSight metrics",
   "select": "ms",
   "cond": {
    "path": [
     "IncludeFilters",
     "*",
     "Namespace"
    ],
    "op": "eq",
    "value": "AWS/QuickSight"
   },
   "quantifier": "all",
   "justify": "QuickSight metrics live in AWS/QuickSight"
  },
  {
   "id": "ms_ingestion",
   "kind": "any_of",
   "tier": "detail",
   "quote": "ingestion and dataset metrics",
   "checks": [
    {
     "kind": "attr",
     "select": "ms",
     "cond": {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "regex",
      "value": "(?i)ingestion|dataset"
     }
    }
   ]
  },
  {
   "id": "ms_dashboard",
   "kind": "any_of",
   "tier": "detail",
   "quote": "dashboard and visual performance",
   "checks": [
    {
     "kind": "attr",
     "select": "ms",
     "cond": {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "regex",
      "value": "(?i)dashboard|visual"
     }
    }
   ]
  },
  {
   "id": "ms_spice",
   "kind": "any_of",
   "tier": "detail",
   "quote": "SPICE capacity usage",
   "checks": [
    {
     "kind": "attr",
     "select": "ms",
     "cond": {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "regex",
      "value": "(?i)spice"
     }
    }
   ]
  },
  {
   "id": "ms_qindex",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Q index document and text size metrics",
   "checks": [
    {
     "kind": "attr",
     "select": "ms",
     "cond": {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "regex",
      "value": "(?i)index|document|textsize"
     }
    }
   ]
  },
  {
   "id": "ms_qaction",
   "kind": "any_of",
   "tier": "detail",
   "quote": "Q action invocation count and error metrics",
   "checks": [
    {
     "kind": "attr",
     "select": "ms",
     "cond": {
      "path": [
       "IncludeFilters",
       "*",
       "MetricNames",
       "*"
      ],
      "op": "regex",
      "value": "(?i)action"
     }
    }
   ]
  },
  {
   "id": "firehoses",
   "kind": "exists",
   "tier": "core",
   "quote": "each metric stream writing to its own dedicated Kinesis Firehose delivery stream",
   "select": "fh",
   "min": 5
  },
  {
   "id": "firehose_directput",
   "kind": "attr",
   "tier": "core",
   "quote": "uses DirectPut delivery type",
   "select": "fh",
   "cond": {
    "path": [
     "DeliveryStreamType"
    ],
    "op": "eq",
    "value": "DirectPut"
   },
   "quantifier": "all"
  },
  {
   "id": "stream_to_firehose",
   "kind": "ref",
   "tier": "core",
   "quote": "each metric stream writing to its own dedicated Kinesis Firehose delivery stream",
   "from": "ms",
   "to": "fh"
  },
  {
   "id": "dedicated_firehose",
   "kind": "exists",
   "tier": "detail",
   "quote": "each metric stream writing to its own dedicated Kinesis Firehose delivery stream",
   "select": "ms",
   "distinct_path": [
    "FirehoseArn"
   ],
   "min": 5
  },
  {
   "id": "firehose_to_bucket",
   "kind": "any_of",
   "tier": "core",
   "quote": "sinks to the admin S3 bucket",
   "checks": [
    {
     "kind": "ref",
     "from": "fh",
     "to": "bucket"
    },
    {
     "kind": "attr",
     "select": "fh",
     "cond": {
      "path": [
       "S3DestinationConfiguration",
       "BucketARN"
      ],
      "op": "contains",
      "value": "admin-suite-"
     }
    },
    {
     "kind": "attr",
     "select": "fh",
     "cond": {
      "path": [
       "ExtendedS3DestinationConfiguration",
       "BucketARN"
      ],
      "op": "contains",
      "value": "admin-suite-"
     }
    }
   ]
  },
  {
   "id": "firehose_prefix",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with appropriate prefixes under the \"cloudwatch/\" path",
   "checks": [
    {
     "kind": "attr",
     "select": "fh",
     "cond": {
      "path": [
       "S3DestinationConfiguration",
       "Prefix"
      ],
      "op": "regex",
      "value": "^cloudwatch/"
     },
     "quantifier": "all"
    },
    {
     "kind": "attr",
     "select": "fh",
     "cond": {
      "path": [
       "ExtendedS3DestinationConfiguration",
       "Prefix"
      ],
      "op": "regex",
      "value": "^cloudwatch/"
     },
     "quantifier": "all"
    }
   ]
  },
  {
   "id": "role_assume",
   "kind": "exists",
   "tier": "core",
   "quote": "allows the necessary services (Glue, CloudFormation, Firehose, CloudWatch metrics) to assume it",
   "select": "consolidated_role"
  },
  {
   "id": "single_role",
   "kind": "exists",
   "tier": "core",
   "quote": "a single consolidated IAM role",
   "select": "role",
   "min": 1,
   "max": 1,
   "justify": "single means one role"
  },
  {
   "id": "role_permissions",
   "kind": "all_of",
   "tier": "core",
   "quote": "broad policy permissions covering S3, Glue, QuickSight, IAM, CloudWatch, Logs, and Firehose operations",
   "checks": [
    {
     "kind": "attr",
     "select": "perm",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "s3:[A-Z*]|AmazonS3|AdministratorAccess"
     }
    },
    {
     "kind": "attr",
     "select": "perm",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "glue:[A-Z*]|AWSGlue|AdministratorAccess"
     }
    },
    {
     "kind": "attr",
     "select": "perm",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "quicksight:[A-Z*]|policy/\\S*QuickSight|AdministratorAccess"
     }
    },
    {
     "kind": "attr",
     "select": "perm",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "iam:[A-Z*]|IAMFullAccess|IAMReadOnlyAccess|AdministratorAccess"
     }
    },
    {
     "kind": "attr",
     "select": "perm",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "cloudwatch:[A-Z*]|CloudWatchFullAccess|CloudWatchReadOnlyAccess|AdministratorAccess"
     }
    },
    {
     "kind": "attr",
     "select": "perm",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "logs:[A-Z*]|CloudWatchLogs|AdministratorAccess"
     }
    },
    {
     "kind": "attr",
     "select": "perm",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "firehose:[A-Z*]|KinesisFirehose|AdministratorAccess"
     }
    }
   ],
   "justify": "S3 operations -> s3: actions or the S3 managed policy; likewise for the other services"
  },
  {
   "id": "role_used_jobs",
   "kind": "ref",
   "tier": "detail",
   "quote": "all resources must use a single consolidated IAM role",
   "from": "jobs",
   "to": "role"
  },
  {
   "id": "role_used_fh",
   "kind": "ref",
   "tier": "detail",
   "quote": "all resources must use a single consolidated IAM role",
   "from": "fh",
   "to": "role"
  },
  {
   "id": "role_used_ms",
   "kind": "ref",
   "tier": "detail",
   "quote": "all resources must use a single consolidated IAM role",
   "from": "ms",
   "to": "role"
  },
  {
   "id": "x_jobs_etl",
   "kind": "attr",
   "tier": "extra",
   "select": "jobs",
   "cond": {
    "path": [
     "Command",
     "Name"
    ],
    "op": "eq",
    "value": "glueetl"
   },
   "quantifier": "all"
  },
  {
   "id": "x_bucket_encrypted",
   "kind": "attr",
   "tier": "extra",
   "select": "bucket",
   "cond": {
    "path": [
     "BucketEncryption"
    ],
    "op": "present"
   }
  },
  {
   "id": "x_ms_json",
   "kind": "attr",
   "tier": "extra",
   "select": "ms",
   "cond": {
    "path": [
     "OutputFormat"
    ],
    "op": "eq",
    "value": "json"
   },
   "quantifier": "all"
  },
  {
   "id": "x_trig_start",
   "kind": "attr",
   "tier": "extra",
   "select": "trig",
   "cond": {
    "path": [
     "StartOnCreation"
    ],
    "op": "truthy"
   },
   "quantifier": "all"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
