package intent.cfn.row_265

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "key": {
   "types": [
    "AWS::KMS::Key"
   ],
   "where": []
  },
  "tables": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": []
  },
  "buckets": {
   "types": [
    "AWS::S3::Bucket"
   ],
   "where": []
  },
  "sessions": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": [
    {
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
       "op": "regex",
       "value": "(?i)session"
      }
     ]
    },
    {
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
       "value": "RANGE"
      },
      {
       "path": [
        "AttributeName"
       ],
       "op": "regex",
       "value": "(?i)type"
      }
     ]
    }
   ]
  },
  "prices": {
   "types": [
    "AWS::DynamoDB::Table"
   ],
   "where": [
    {
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
       "op": "regex",
       "value": "(?i)ingredient"
      }
     ]
    },
    {
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
       "value": "RANGE"
      },
      {
       "path": [
        "AttributeName"
       ],
       "op": "regex",
       "value": "(?i)market"
      }
     ]
    }
   ]
  }
 },
 "checks": [
  {
   "id": "kms_key",
   "tier": "core",
   "quote": "a customer managed KMS key",
   "justify": "a single key: every data store is encrypted with that key",
   "kind": "exists",
   "select": "key",
   "min": 1,
   "max": 1
  },
  {
   "id": "key_rotation",
   "kind": "attr",
   "tier": "core",
   "quote": "automatic key rotation enabled",
   "select": "key",
   "cond": {
    "path": [
     "EnableKeyRotation"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "alias",
   "tier": "core",
   "quote": "a friendly alias derived from the project and environment names",
   "kind": "ref",
   "from": {
    "types": [
     "AWS::KMS::Alias"
    ],
    "where": []
   },
   "to": "key"
  },
  {
   "id": "alias_env",
   "kind": "attr",
   "tier": "detail",
   "quote": "a friendly alias derived from the project and environment names",
   "justify": "alias derives from the environment name, which defaults to a development deployment",
   "select": {
    "types": [
     "AWS::KMS::Alias"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "AliasName"
    ],
    "op": "regex",
    "value": "(?i)dev"
   }
  },
  {
   "id": "four_tables",
   "kind": "exists",
   "tier": "core",
   "quote": "a reminders table and a rate limits table",
   "select": "tables",
   "min": 4,
   "justify": "sessions, market prices, reminders and rate limits tables"
  },
  {
   "id": "reminders_table",
   "kind": "attr",
   "tier": "detail",
   "quote": "a reminders table",
   "select": "tables",
   "cond": {
    "path": [
     "TableName"
    ],
    "op": "regex",
    "value": "(?i)reminder"
   }
  },
  {
   "id": "rate_limits_table",
   "kind": "attr",
   "tier": "detail",
   "quote": "a rate limits table",
   "select": "tables",
   "cond": {
    "path": [
     "TableName"
    ],
    "op": "regex",
    "value": "(?i)rate.?limit"
   }
  },
  {
   "id": "sessions_keys",
   "kind": "exists",
   "tier": "core",
   "quote": "a sessions table keyed on a session identifier with a data type as sort key",
   "select": "sessions",
   "justify": "keyed on means HASH; sort key means RANGE"
  },
  {
   "id": "sessions_ttl",
   "tier": "core",
   "quote": "a time-to-live attribute for expiry",
   "justify": "a time-to-live attribute for expiry means TTL is enabled on the table",
   "kind": "attr",
   "select": "sessions",
   "cond": {
    "path": [
     "TimeToLiveSpecification",
     "Enabled"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "prices_keys",
   "kind": "exists",
   "tier": "core",
   "quote": "a market prices table keyed on ingredient and market name",
   "select": "prices",
   "justify": "keyed on ingredient and market name: hash and range"
  },
  {
   "id": "prices_index",
   "tier": "core",
   "quote": "a secondary index for looking up an ingredient by last-updated time",
   "justify": "index hash on ingredient, range on last-updated",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "prices",
     "cond": {
      "path": [
       "GlobalSecondaryIndexes",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "KeySchema",
         "*",
         "AttributeName"
        ],
        "op": "regex",
        "value": "(?i)ingredient"
       },
       {
        "path": [
         "KeySchema",
         "*",
         "AttributeName"
        ],
        "op": "regex",
        "value": "(?i)update"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "prices",
     "cond": {
      "path": [
       "LocalSecondaryIndexes",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "KeySchema",
         "*",
         "AttributeName"
        ],
        "op": "regex",
        "value": "(?i)ingredient"
       },
       {
        "path": [
         "KeySchema",
         "*",
         "AttributeName"
        ],
        "op": "regex",
        "value": "(?i)update"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "on_demand",
   "kind": "attr",
   "tier": "core",
   "quote": "all on-demand billing",
   "select": "tables",
   "cond": {
    "path": [
     "BillingMode"
    ],
    "op": "eq",
    "value": "PAY_PER_REQUEST"
   },
   "quantifier": "all",
   "justify": "on-demand billing is PAY_PER_REQUEST"
  },
  {
   "id": "pitr",
   "tier": "core",
   "quote": "with point-in-time recovery turned on",
   "justify": "the prompt says all four tables; three is what prompt and ground truth both guarantee, see PROMPT_GT_MISMATCH in notes",
   "kind": "exists",
   "select": {
    "types": [
     "AWS::DynamoDB::Table"
    ],
    "where": [
     {
      "path": [
       "PointInTimeRecoverySpecification",
       "PointInTimeRecoveryEnabled"
      ],
      "op": "eq",
      "value": true
     }
    ]
   },
   "min": 3
  },
  {
   "id": "tables_encrypted",
   "tier": "core",
   "quote": "Every data store it creates should be encrypted with that key",
   "justify": "that key is a reference to the template's key or its own alias, not an AWS managed alias/aws/ key",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "tables",
     "quantifier": "all",
     "cond": {
      "path": [
       "SSESpecification",
       "SSEEnabled"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
     "select": "tables",
     "quantifier": "all",
     "cond": {
      "path": [
       "SSESpecification",
       "KMSMasterKeyId"
      ],
      "op": "regex",
      "value": "(?i)(\"ref\"|\\$\\{|alias/([^a]|a[^w]|aw[^s]|aws[^/]))"
     }
    }
   ]
  },
  {
   "id": "two_buckets",
   "kind": "exists",
   "tier": "core",
   "quote": "an image bucket and a separate bucket to receive its access logs",
   "select": "buckets",
   "min": 2,
   "justify": "an image bucket and a separate log bucket"
  },
  {
   "id": "buckets_kms",
   "tier": "core",
   "quote": "Every data store it creates should be encrypted with that key",
   "justify": "encryption with a KMS key means the aws:kms algorithm; that key is a reference to the template's key or its own alias, not an AWS managed alias/aws/ key",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "buckets",
     "quantifier": "all",
     "cond": {
      "path": [
       "BucketEncryption",
       "ServerSideEncryptionConfiguration",
       "*",
       "ServerSideEncryptionByDefault",
       "SSEAlgorithm"
      ],
      "op": "eq",
      "value": "aws:kms"
     }
    },
    {
     "kind": "attr",
     "select": "buckets",
     "quantifier": "all",
     "cond": {
      "path": [
       "BucketEncryption",
       "ServerSideEncryptionConfiguration",
       "*",
       "ServerSideEncryptionByDefault",
       "KMSMasterKeyID"
      ],
      "op": "regex",
      "value": "(?i)(\"ref\"|\\$\\{|alias/([^a]|a[^w]|aw[^s]|aws[^/]))"
     }
    }
   ]
  },
  {
   "id": "access_logging",
   "tier": "core",
   "quote": "a separate bucket to receive its access logs",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "AWS::S3::Bucket"
      ],
      "where": [
       {
        "path": [
         "LoggingConfiguration",
         "DestinationBucketName"
        ],
        "op": "present"
       }
      ]
     },
     "to": "buckets"
    },
    {
     "kind": "join",
     "from": "buckets",
     "from_path": [
      "LoggingConfiguration",
      "DestinationBucketName"
     ],
     "to": "buckets",
     "to_path": [
      "BucketName"
     ]
    }
   ]
  },
  {
   "id": "env_default",
   "tier": "detail",
   "quote": "defaulting to a development deployment",
   "justify": "a development deployment is an environment default of dev or development",
   "kind": "attr",
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
      "value": "(?i)(env|stage)"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "regex",
    "value": "(?i)^dev"
   }
  },
  {
   "id": "project_param",
   "tier": "detail",
   "quote": "The project name and environment should be parameters",
   "kind": "attr",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "regex",
    "value": "(?i)(project|app)"
   }
  },
  {
   "id": "env_param",
   "tier": "detail",
   "quote": "The project name and environment should be parameters",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)(env|stage)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "regex",
      "value": "(?i)^dev"
     }
    }
   ]
  },
  {
   "id": "naming_env",
   "tier": "detail",
   "quote": "should drive the resource naming throughout",
   "justify": "names are driven by the environment parameter, which defaults to development",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "tables",
     "quantifier": "all",
     "cond": {
      "path": [
       "TableName"
      ],
      "op": "regex",
      "value": "(?i)dev"
     }
    },
    {
     "kind": "attr",
     "select": "buckets",
     "quantifier": "all",
     "cond": {
      "path": [
       "BucketName"
      ],
      "op": "regex",
      "value": "(?i)dev"
     }
    }
   ]
  },
  {
   "id": "x_bucket_pab",
   "kind": "attr",
   "tier": "extra",
   "select": "buckets",
   "cond": {
    "path": [
     "PublicAccessBlockConfiguration",
     "BlockPublicAcls"
    ],
    "op": "eq",
    "value": true
   },
   "quantifier": "all"
  },
  {
   "id": "x_image_versioning",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "AWS::S3::Bucket"
    ],
    "where": [
     {
      "path": [
       "LoggingConfiguration",
       "DestinationBucketName"
      ],
      "op": "present"
     }
    ]
   },
   "cond": {
    "path": [
     "VersioningConfiguration",
     "Status"
    ],
    "op": "eq",
    "value": "Enabled"
   }
  },
  {
   "id": "x_key_policy_services",
   "kind": "attr",
   "tier": "extra",
   "select": "key",
   "cond": {
    "path": [
     "KeyPolicy"
    ],
    "op": "regex",
    "value": "(?i)(dynamodb|s3)\\.amazonaws\\.com"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
