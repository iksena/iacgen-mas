package intent.cfn.row_240

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
    }
   ]
  },
  "param": {
   "types": [
    "__parameter__"
   ],
   "where": []
  },
  "out": {
   "types": [
    "__output__"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "glue_job",
   "kind": "exists",
   "select": "job",
   "tier": "core",
   "quote": "creates an AWS Glue ETL job"
  },
  {
   "id": "parameters",
   "kind": "all_of",
   "tier": "detail",
   "quote": "The template must accept parameters for GlueJobName defaulting to \"map-appraiser-shapefile-to-geojson-etl\", GlueScriptLocation defaulting to \"s3://map-appraiser-glue-scripts/shapefile_to_geojson_etl.py\", and GlueServiceRoleName defaulting to \"MapAppraiserShapefileGlueServiceRole\"",
   "checks": [
    {
     "kind": "attr",
     "select": "param",
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "map-appraiser-shapefile-to-geojson-etl"
     }
    },
    {
     "kind": "attr",
     "select": "param",
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "s3://map-appraiser-glue-scripts/shapefile_to_geojson_etl.py"
     }
    },
    {
     "kind": "attr",
     "select": "param",
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "MapAppraiserShapefileGlueServiceRole"
     }
    }
   ]
  },
  {
   "id": "role_name",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "RoleName"
    ],
    "op": "eq",
    "value": "MapAppraiserShapefileGlueServiceRole"
   },
   "tier": "core",
   "quote": "provision an IAM service role using the specified role name that trusts \"glue.amazonaws.com\""
  },
  {
   "id": "role_glue_managed_policy",
   "kind": "attr",
   "select": "role",
   "cond": {
    "path": [
     "ManagedPolicyArns"
    ],
    "op": "contains",
    "value": "AWSGlueServiceRole"
   },
   "tier": "core",
   "quote": "attached to the managed policy \"AWSGlueServiceRole\""
  },
  {
   "id": "cloudwatch_logs_policy",
   "kind": "any_of",
   "tier": "detail",
   "quote": "inline policies granting full CloudWatch logging access",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "Policies"
      ],
      "op": "contains",
      "value": "logs:"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument"
        ],
        "op": "contains",
        "value": "logs:"
       }
      ]
     },
     "to": "role"
    }
   ]
  },
  {
   "id": "s3_read_raw_gis",
   "kind": "any_of",
   "tier": "detail",
   "quote": "scoped S3 read access to \"map-appraiser-data-raw-gis\"",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
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
         "Resource"
        ],
        "op": "contains",
        "value": "map-appraiser-data-raw-gis"
       },
       {
        "path": [
         "Action"
        ],
        "op": "regex",
        "value": "(?i)s3:(\\*|get|list)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "role",
     "from": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Resource"
          ],
          "op": "contains",
          "value": "map-appraiser-data-raw-gis"
         },
         {
          "path": [
           "Action"
          ],
          "op": "regex",
          "value": "(?i)s3:(\\*|get|list)"
         }
        ]
       }
      ]
     }
    }
   ],
   "justify": "read access implies s3:Get*/List*"
  },
  {
   "id": "s3_read_glue_scripts",
   "kind": "any_of",
   "tier": "detail",
   "quote": "\"map-appraiser-glue-scripts\" buckets",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
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
         "Resource"
        ],
        "op": "contains",
        "value": "map-appraiser-glue-scripts"
       },
       {
        "path": [
         "Action"
        ],
        "op": "regex",
        "value": "(?i)s3:(\\*|get|list)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "role",
     "from": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Resource"
          ],
          "op": "contains",
          "value": "map-appraiser-glue-scripts"
         },
         {
          "path": [
           "Action"
          ],
          "op": "regex",
          "value": "(?i)s3:(\\*|get|list)"
         }
        ]
       }
      ]
     }
    }
   ],
   "justify": "read access implies s3:Get*/List*"
  },
  {
   "id": "s3_rw_knowledge_base",
   "kind": "any_of",
   "tier": "detail",
   "quote": "read/write access to \"map-appraiser-data-knowledge-base\"",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
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
         "Resource"
        ],
        "op": "contains",
        "value": "map-appraiser-data-knowledge-base"
       },
       {
        "path": [
         "Action"
        ],
        "op": "regex",
        "value": "(?i)s3:(\\*|putobject)"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "role",
     "from": {
      "types": [
       "AWS::IAM::Policy"
      ],
      "where": [
       {
        "path": [
         "PolicyDocument",
         "Statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "Resource"
          ],
          "op": "contains",
          "value": "map-appraiser-data-knowledge-base"
         },
         {
          "path": [
           "Action"
          ],
          "op": "regex",
          "value": "(?i)s3:(\\*|putobject)"
         }
        ]
       }
      ]
     }
    }
   ],
   "justify": "write access implies s3:PutObject"
  },
  {
   "id": "job_glue_4_spark",
   "kind": "all_of",
   "tier": "core",
   "quote": "deploy an AWS Glue 4.0 Spark ETL job",
   "checks": [
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "GlueVersion"
      ],
      "op": "eq",
      "value": "4.0"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "Command",
       "Name"
      ],
      "op": "eq",
      "value": "glueetl"
     }
    }
   ]
  },
  {
   "id": "job_name_script",
   "kind": "all_of",
   "tier": "core",
   "quote": "utilizing the specified job name, script location, and service role",
   "checks": [
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "Name"
      ],
      "op": "eq",
      "value": "map-appraiser-shapefile-to-geojson-etl"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "Command",
       "ScriptLocation"
      ],
      "op": "eq",
      "value": "s3://map-appraiser-glue-scripts/shapefile_to_geojson_etl.py"
     }
    }
   ]
  },
  {
   "id": "job_uses_role",
   "kind": "ref",
   "from": "job",
   "to": "role",
   "tier": "core",
   "quote": "utilizing the specified job name, script location, and service role"
  },
  {
   "id": "job_workers",
   "kind": "all_of",
   "tier": "core",
   "quote": "configured with 5 \"G.2X\" workers",
   "checks": [
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "NumberOfWorkers"
      ],
      "op": "eq",
      "value": 5
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "WorkerType"
      ],
      "op": "eq",
      "value": "G.2X"
     }
    }
   ]
  },
  {
   "id": "job_limits",
   "kind": "all_of",
   "tier": "detail",
   "quote": "0 retries, a timeout of 2880 minutes, maximum concurrent runs set to 1",
   "checks": [
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "MaxRetries"
      ],
      "op": "eq",
      "value": 0
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "Timeout"
      ],
      "op": "eq",
      "value": 2880
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "ExecutionProperty",
       "MaxConcurrentRuns"
      ],
      "op": "eq",
      "value": 1
     }
    }
   ]
  },
  {
   "id": "job_default_arguments",
   "kind": "all_of",
   "tier": "detail",
   "quote": "default arguments enabling metrics, continuous CloudWatch logging, Spark UI logs at \"s3://map-appraiser-glue-scripts/spark-logs/\", job bookmarks, temporary storage at \"s3://map-appraiser-glue-scripts/temp/\"",
   "checks": [
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "DefaultArguments"
      ],
      "op": "contains",
      "value": "--enable-metrics"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "DefaultArguments"
      ],
      "op": "contains",
      "value": "--enable-continuous-cloudwatch-log"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "DefaultArguments",
       "*"
      ],
      "op": "eq",
      "value": "s3://map-appraiser-glue-scripts/spark-logs/"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "DefaultArguments"
      ],
      "op": "regex",
      "value": "(?i)job-bookmark-enable|enable-job-bookmark"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "DefaultArguments",
       "*"
      ],
      "op": "eq",
      "value": "s3://map-appraiser-glue-scripts/temp/"
     }
    }
   ]
  },
  {
   "id": "job_python_modules",
   "kind": "all_of",
   "tier": "detail",
   "quote": "additional Python modules \"geopandas0.14.1,shapely2.0.2,pyproj3.6.1,fiona1.9.5\"",
   "checks": [
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "DefaultArguments",
       "--additional-python-modules"
      ],
      "op": "regex",
      "value": "geopandas\\W*0\\.14\\.1"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "DefaultArguments",
       "--additional-python-modules"
      ],
      "op": "regex",
      "value": "shapely\\W*2\\.0\\.2"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "DefaultArguments",
       "--additional-python-modules"
      ],
      "op": "regex",
      "value": "pyproj\\W*3\\.6\\.1"
     }
    },
    {
     "kind": "attr",
     "select": "job",
     "cond": {
      "path": [
       "DefaultArguments",
       "--additional-python-modules"
      ],
      "op": "regex",
      "value": "fiona\\W*1\\.9\\.5"
     }
    }
   ]
  },
  {
   "id": "output_job_name",
   "kind": "any_of",
   "tier": "detail",
   "quote": "exporting the Glue job name, service role ARN, and S3 script upload command in the outputs",
   "checks": [
    {
     "kind": "ref",
     "from": "out",
     "to": "job"
    },
    {
     "kind": "attr",
     "select": "out",
     "cond": {
      "path": [
       "value"
      ],
      "op": "eq",
      "value": "map-appraiser-shapefile-to-geojson-etl"
     }
    }
   ]
  },
  {
   "id": "output_role_arn",
   "kind": "any_of",
   "tier": "detail",
   "quote": "exporting the Glue job name, service role ARN, and S3 script upload command in the outputs",
   "checks": [
    {
     "kind": "attr",
     "select": "out",
     "cond": {
      "path": [
       "value",
       "attr"
      ],
      "op": "eq",
      "value": "Arn"
     }
    },
    {
     "kind": "attr",
     "select": "out",
     "cond": {
      "path": [
       "value"
      ],
      "op": "regex",
      "value": "\\.Arn\\}|:role/"
     }
    }
   ]
  },
  {
   "id": "output_upload_command",
   "kind": "attr",
   "select": "out",
   "tier": "detail",
   "quote": "exporting the Glue job name, service role ARN, and S3 script upload command in the outputs",
   "cond": {
    "path": [
     "value"
    ],
    "op": "regex",
    "value": "(?i)aws s3 (cp|sync)"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
