package intent.cfn.row_232

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "db": {
   "types": [
    "AWS::Glue::Database"
   ],
   "where": []
  },
  "crawler": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::Glue::Crawler"
    }
   ]
  },
  "job": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::Glue::Job"
    }
   ]
  },
  "loggroup": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::Logs::LogGroup"
    }
   ]
  },
  "role": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "AWS::IAM::Role"
    },
    {
     "path": [
      "properties",
      "AssumeRolePolicyDocument",
      "Statement",
      "*",
      "Principal",
      "Service",
      "*"
     ],
     "op": "eq",
     "value": "glue.amazonaws.com"
    }
   ]
  },
  "env_param": {
   "types": [
    "__parameter__"
   ],
   "where": [
    {
     "path": [
      "allowed_values"
     ],
     "op": "regex",
     "value": "(?i)dev"
    },
    {
     "path": [
      "allowed_values"
     ],
     "op": "regex",
     "value": "(?i)staging"
    },
    {
     "path": [
      "allowed_values"
     ],
     "op": "regex",
     "value": "(?i)prod"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "catalog_database",
   "kind": "exists",
   "select": "db",
   "tier": "core",
   "quote": "creates a Glue Data Catalog database"
  },
  {
   "id": "crawler_declared",
   "kind": "exists",
   "select": "crawler",
   "tier": "core",
   "quote": "an optional crawler",
   "justify": "optional capability, checked as declared"
  },
  {
   "id": "job_declared",
   "kind": "exists",
   "select": "job",
   "tier": "core",
   "quote": "an optional Spark ETL job",
   "justify": "optional capability, checked as declared"
  },
  {
   "id": "environment_param",
   "kind": "exists",
   "select": "env_param",
   "tier": "detail",
   "quote": "an environment (dev, staging, or prod)"
  },
  {
   "id": "naming_prefix_param",
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
      "value": "(?i)^prefix$|(name|naming|project|resource|app|stack).*prefix"
     }
    ]
   },
   "tier": "detail",
   "quote": "accept a naming prefix"
  },
  {
   "id": "names_use_environment",
   "kind": "all_of",
   "tier": "detail",
   "quote": "used to build the database, crawler, and job names",
   "justify": "the environment values are dev, staging and prod",
   "checks": [
    {
     "kind": "attr",
     "select": "db",
     "cond": {
      "path": [
       "DatabaseInput",
       "Name"
      ],
      "op": "regex",
      "value": "(?i)dev|staging|prod"
     }
    },
    {
     "kind": "attr",
     "select": "crawler",
     "cond": {
      "path": [
       "properties",
       "Name"
      ],
      "op": "regex",
      "value": "(?i)dev|staging|prod"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "properties",
       "Name"
      ],
      "op": "regex",
      "value": "(?i)dev|staging|prod"
     }
    }
   ]
  },
  {
   "id": "source_bucket_params",
   "kind": "all_of",
   "tier": "detail",
   "quote": "the ARN and prefix of an existing S3 bucket",
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
        "value": "(?i)(source|crawl|s3).*arn|^bucket_?arn$"
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
        "value": "(?i)(source|crawl|s3|data).*prefix|^bucket_?prefix$"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "crawler_to_database",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an optional crawler",
   "checks": [
    {
     "kind": "ref",
     "from": "crawler",
     "to": "db"
    },
    {
     "kind": "join",
     "from": "crawler",
     "from_path": [
      "properties",
      "DatabaseName"
     ],
     "to": "db",
     "to_path": [
      "DatabaseInput",
      "Name"
     ]
    }
   ]
  },
  {
   "id": "crawler_s3_target",
   "kind": "attr",
   "select": "crawler",
   "cond": {
    "path": [
     "properties",
     "Targets",
     "S3Targets"
    ],
    "op": "present"
   },
   "tier": "core",
   "quote": "the ARN and prefix of an existing S3 bucket that the crawler scans"
  },
  {
   "id": "crawler_daily_schedule",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a configurable cron schedule (defaulting to once daily)",
   "justify": "once daily is a cron with fixed minute and hour and wildcard day fields, or rate(1 day)",
   "checks": [
    {
     "kind": "attr",
     "select": "crawler",
     "cond": {
      "path": [
       "properties",
       "Schedule",
       "ScheduleExpression"
      ],
      "op": "regex",
      "value": "(?i)cron\\(\\s*\\d+\\s+\\d+\\s+\\*\\s+\\*\\s+\\?\\s+\\*\\s*\\)"
     }
    },
    {
     "kind": "attr",
     "select": "crawler",
     "cond": {
      "path": [
       "properties",
       "Schedule",
       "ScheduleExpression"
      ],
      "op": "regex",
      "value": "(?i)rate\\(\\s*1\\s+day\\s*\\)"
     }
    }
   ]
  },
  {
   "id": "crawler_schedule_param",
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
      "value": "(?i)schedule|cron"
     }
    ]
   },
   "tier": "detail",
   "quote": "a configurable cron schedule"
  },
  {
   "id": "crawler_log_only",
   "kind": "all_of",
   "tier": "core",
   "quote": "only log rather than automatically apply schema and partition changes it detects",
   "checks": [
    {
     "kind": "attr",
     "select": "crawler",
     "cond": {
      "path": [
       "properties",
       "SchemaChangePolicy",
       "UpdateBehavior"
      ],
      "op": "eq",
      "value": "LOG"
     }
    },
    {
     "kind": "attr",
     "select": "crawler",
     "cond": {
      "path": [
       "properties",
       "SchemaChangePolicy",
       "DeleteBehavior"
      ],
      "op": "eq",
      "value": "LOG"
     }
    }
   ]
  },
  {
   "id": "crawler_new_only",
   "kind": "attr",
   "select": "crawler",
   "cond": {
    "path": [
     "properties",
     "RecrawlPolicy",
     "RecrawlBehavior"
    ],
    "op": "eq",
    "value": "CRAWL_NEW_FOLDERS_ONLY"
   },
   "tier": "core",
   "quote": "only scan newly added data on each run",
   "justify": "scan only new data is CRAWL_NEW_FOLDERS_ONLY"
  },
  {
   "id": "crawler_toggleable",
   "kind": "attr",
   "select": "crawler",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "tier": "detail",
   "quote": "be toggleable on or off through a parameter"
  },
  {
   "id": "job_toggleable",
   "kind": "attr",
   "select": "job",
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "tier": "detail",
   "quote": "also toggleable and off by default",
   "justify": "toggle is a Condition on the job"
  },
  {
   "id": "job_off_by_default",
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
      "value": "(?i)job"
     },
     {
      "path": [
       "default"
      ],
      "op": "in",
      "value": [
       "false",
       "no",
       "disabled"
      ]
     }
    ]
   },
   "tier": "detail",
   "quote": "also toggleable and off by default",
   "justify": "off by default is a job toggle parameter defaulting to an off value"
  },
  {
   "id": "job_spark",
   "kind": "attr",
   "select": "job",
   "cond": {
    "path": [
     "properties",
     "Command",
     "Name"
    ],
    "op": "eq",
    "value": "glueetl"
   },
   "tier": "core",
   "quote": "a Glue Spark job",
   "justify": "Spark ETL job command is glueetl"
  },
  {
   "id": "job_sizing",
   "kind": "all_of",
   "tier": "detail",
   "quote": "a configurable worker type, worker count, timeout, and maximum concurrent runs",
   "checks": [
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "properties",
       "WorkerType"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "properties",
       "NumberOfWorkers"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "properties",
       "Timeout"
      ],
      "op": "present"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "properties",
       "ExecutionProperty",
       "MaxConcurrentRuns"
      ],
      "op": "present"
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
        "value": "(?i)worker.*type"
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
        "value": "(?i)(number|num|count).*worker|worker.*(count|number|num)|^workers$"
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
        "value": "(?i)timeout"
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
        "value": "(?i)concurren"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "job_script_location",
   "kind": "all_of",
   "tier": "detail",
   "quote": "reading its script from an S3 location supplied as a parameter",
   "checks": [
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "properties",
       "Command"
      ],
      "op": "regex",
      "value": "ScriptLocation"
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
        "value": "(?i)script"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "target_bucket_params",
   "kind": "all_of",
   "tier": "detail",
   "quote": "a separate target S3 bucket and prefix",
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
        "value": "(?i)(target|output|dest).*(bucket|arn)"
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
        "value": "(?i)(target|output|dest).*prefix"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "job_bookmarks",
   "kind": "attr",
   "select": "job",
   "cond": {
    "path": [
     "properties",
     "DefaultArguments",
     "--job-bookmark-option"
    ],
    "op": "eq",
    "value": "job-bookmark-enable"
   },
   "tier": "core",
   "quote": "using job bookmarks so reruns only process new data"
  },
  {
   "id": "job_continuous_logging",
   "kind": "attr",
   "select": "job",
   "cond": {
    "path": [
     "properties",
     "DefaultArguments",
     "--enable-continuous-cloudwatch-log"
    ],
    "op": "eq",
    "value": "true"
   },
   "tier": "core",
   "quote": "logging continuously to a CloudWatch log group",
   "justify": "continuous logging is the flag set to true"
  },
  {
   "id": "job_log_group",
   "kind": "any_of",
   "tier": "detail",
   "quote": "logging continuously to a CloudWatch log group",
   "checks": [
    {
     "kind": "ref",
     "from": "job",
     "to": "loggroup"
    },
    {
     "kind": "join",
     "from": "job",
     "from_path": [
      "properties",
      "DefaultArguments",
      "--continuous-log-logGroup"
     ],
     "to": "loggroup",
     "to_path": [
      "properties",
      "LogGroupName"
     ]
    }
   ]
  },
  {
   "id": "log_retention",
   "kind": "all_of",
   "tier": "detail",
   "quote": "a configurable retention period",
   "checks": [
    {
     "kind": "attr",
     "select": "loggroup",
     "cond": {
      "path": [
       "properties",
       "RetentionInDays"
      ],
      "op": "present"
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
        "value": "(?i)retention"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "service_role",
   "kind": "exists",
   "select": "role",
   "min": 1,
   "max": 1,
   "tier": "core",
   "quote": "one IAM service role",
   "justify": "Glue service role is assumed by glue.amazonaws.com; one means exactly one; the role may be gated with the crawler and job"
  },
  {
   "id": "crawler_uses_role",
   "kind": "ref",
   "from": "crawler",
   "to": "role",
   "tier": "core",
   "quote": "Both the crawler and the job should share one IAM service role"
  },
  {
   "id": "job_uses_role",
   "kind": "ref",
   "from": "job",
   "to": "role",
   "tier": "core",
   "quote": "Both the crawler and the job should share one IAM service role"
  },
  {
   "id": "role_s3_read",
   "kind": "any_of",
   "tier": "core",
   "quote": "scoped to read access on the source bucket",
   "justify": "read access is s3:GetObject; scoped rules out s3:*, * and Resource *",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "properties",
       "Policies",
       "*",
       "PolicyDocument",
       "Statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:GetObject"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "none_eq",
        "value": "s3:*"
       },
       {
        "path": [
         "Action",
         "*"
        ],
        "op": "none_eq",
        "value": "*"
       },
       {
        "path": [
         "Resource",
         "*"
        ],
        "op": "none_eq",
        "value": "*"
       }
      ]
     }
    },
    {
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
        "op": "in",
        "value": [
         "AWS::IAM::Policy",
         "AWS::IAM::ManagedPolicy"
        ]
       },
       {
        "path": [
         "properties",
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "glob_covers",
          "value": "s3:GetObject"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "none_eq",
          "value": "s3:*"
         },
         {
          "path": [
           "Action",
           "*"
          ],
          "op": "none_eq",
          "value": "*"
         },
         {
          "path": [
           "Resource",
           "*"
          ],
          "op": "none_eq",
          "value": "*"
         }
        ]
       }
      ]
     },
     "to": "role",
     "bidirectional": true
    }
   ]
  },
  {
   "id": "x_role_managed_glue",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "properties",
     "ManagedPolicyArns"
    ],
    "op": "regex",
    "value": "(?i)AWSGlueServiceRole"
   },
   "tier": "extra"
  },
  {
   "id": "x_job_glue_version",
   "kind": "attr",
   "select": "job",
   "cond": {
    "path": [
     "properties",
     "GlueVersion"
    ],
    "op": "present"
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
