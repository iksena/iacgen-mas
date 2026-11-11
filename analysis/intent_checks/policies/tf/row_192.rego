package intent.tf.row_192

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "bucket": {
   "types": [
    "aws_s3_bucket"
   ],
   "where": []
  },
  "key": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "topic": {
   "types": [
    "aws_sns_topic"
   ],
   "where": []
  },
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": []
  },
  "canary": {
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
      "aws_synthetics_canary"
     ]
    }
   ]
  }
 },
 "checks": [
  {
   "id": "role",
   "kind": "exists",
   "tier": "core",
   "quote": "provision an execution IAM role",
   "select": "role"
  },
  {
   "id": "role_lambda_trust",
   "kind": "attr",
   "tier": "core",
   "quote": "execution IAM role with a randomized two-word pet name prefix for Lambda execution",
   "select": "role",
   "cond": {
    "path": [
     "assume_role_policy"
    ],
    "op": "contains",
    "value": "lambda.amazonaws.com"
   }
  },
  {
   "id": "pet_two_words",
   "kind": "attr",
   "tier": "core",
   "quote": "a randomized two-word pet name prefix",
   "select": {
    "types": [
     "random_pet"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "length"
    ],
    "op": "eq",
    "value": 2
   },
   "justify": "two-word means length 2"
  },
  {
   "id": "role_uses_pet",
   "kind": "ref",
   "tier": "core",
   "quote": "execution IAM role with a randomized two-word pet name prefix",
   "from": "role",
   "to": {
    "types": [
     "random_pet"
    ],
    "where": []
   }
  },
  {
   "id": "perm_s3_read",
   "kind": "any_of",
   "tier": "core",
   "quote": "granting S3 object read/write and bucket listing permissions",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(GetObject|Get\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(GetObject|Get\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)s3:(GetObject|Get\\*|\\*)"
     }
    }
   ]
  },
  {
   "id": "perm_s3_write",
   "kind": "any_of",
   "tier": "core",
   "quote": "granting S3 object read/write and bucket listing permissions",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(PutObject|Put\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(PutObject|Put\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)s3:(PutObject|Put\\*|\\*)"
     }
    }
   ]
  },
  {
   "id": "perm_s3_list",
   "kind": "any_of",
   "tier": "detail",
   "quote": "bucket listing permissions",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(List|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)s3:(List|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)s3:(List|\\*)"
     }
    }
   ]
  },
  {
   "id": "perm_cw_metrics",
   "kind": "any_of",
   "tier": "core",
   "quote": "CloudWatch metric writing",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)cloudwatch:(PutMetricData|Put\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)cloudwatch:(PutMetricData|Put\\*|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)cloudwatch:(PutMetricData|Put\\*|\\*)"
     }
    }
   ]
  },
  {
   "id": "perm_logs",
   "kind": "any_of",
   "tier": "core",
   "quote": "CloudWatch logging",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)logs:(CreateLogStream|PutLogEvents|CreateLogGroup|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)logs:(CreateLogStream|PutLogEvents|CreateLogGroup|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)logs:(CreateLogStream|PutLogEvents|CreateLogGroup|\\*)"
     }
    }
   ]
  },
  {
   "id": "perm_eni",
   "kind": "any_of",
   "tier": "core",
   "quote": "EC2 ENI network interface management",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:([A-Za-z]*NetworkInterface|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_role"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "inline_policy"
      ],
      "op": "regex",
      "value": "(?i)ec2:([A-Za-z]*NetworkInterface|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)ec2:([A-Za-z]*NetworkInterface|\\*)"
     }
    }
   ]
  },
  {
   "id": "bucket",
   "kind": "exists",
   "tier": "core",
   "quote": "An S3 bucket",
   "select": "bucket"
  },
  {
   "id": "bucket_name",
   "kind": "attr",
   "tier": "core",
   "quote": "defaulting to \"benchmark-canary-bucket-tf5x\"",
   "select": "bucket",
   "cond": {
    "path": [
     "bucket"
    ],
    "op": "eq",
    "value": "benchmark-canary-bucket-tf5x"
   }
  },
  {
   "id": "bucket_force_destroy",
   "kind": "attr",
   "tier": "core",
   "quote": "with force destroy enabled",
   "select": "bucket",
   "cond": {
    "path": [
     "force_destroy"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "versioning_off",
   "kind": "any_of",
   "tier": "detail",
   "quote": "configurable versioning (defaulting to false)",
   "justify": "false means versioning not enabled",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_versioning"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "versioning_configuration",
       "*",
       "status"
      ],
      "op": "in",
      "value": [
       "Suspended",
       "Disabled"
      ]
     }
    },
    {
     "kind": "attr",
     "select": "bucket",
     "cond": {
      "path": [
       "versioning",
       "*",
       "enabled"
      ],
      "op": "eq",
      "value": false
     }
    },
    {
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
        "value": "(?i)versioning"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": false
       }
      ]
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": false
     }
    }
   ]
  },
  {
   "id": "public_access_block",
   "kind": "any_of",
   "tier": "core",
   "quote": "public access blocks",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_public_access_block"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "block_public_acls"
      ],
      "op": "eq",
      "value": true
     }
    }
   ]
  },
  {
   "id": "pab_policy",
   "kind": "attr",
   "tier": "detail",
   "quote": "public access blocks",
   "select": {
    "types": [
     "aws_s3_bucket_public_access_block"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "block_public_policy"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "pab_ignore",
   "kind": "attr",
   "tier": "detail",
   "quote": "public access blocks",
   "select": {
    "types": [
     "aws_s3_bucket_public_access_block"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "ignore_public_acls"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "pab_restrict",
   "kind": "attr",
   "tier": "detail",
   "quote": "public access blocks",
   "select": {
    "types": [
     "aws_s3_bucket_public_access_block"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "restrict_public_buckets"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "cors",
   "kind": "any_of",
   "tier": "detail",
   "quote": "default CORS rules",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_bucket_cors_configuration"
      ],
      "where": []
     }
    },
    {
     "kind": "attr",
     "select": "bucket",
     "cond": {
      "path": [
       "cors_rule"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "bucket_kms_sse",
   "kind": "any_of",
   "tier": "core",
   "quote": "KMS server-side encryption must store canary artifacts",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_server_side_encryption_configuration"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "rule",
       "*",
       "apply_server_side_encryption_by_default",
       "*",
       "sse_algorithm"
      ],
      "op": "eq",
      "value": "aws:kms"
     }
    },
    {
     "kind": "attr",
     "select": "bucket",
     "cond": {
      "path": [
       "server_side_encryption_configuration",
       "*",
       "rule",
       "*",
       "apply_server_side_encryption_by_default",
       "*",
       "sse_algorithm"
      ],
      "op": "eq",
      "value": "aws:kms"
     }
    }
   ]
  },
  {
   "id": "bucket_sse_uses_key",
   "kind": "any_of",
   "tier": "detail",
   "quote": "KMS server-side encryption",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket_server_side_encryption_configuration"
      ],
      "where": []
     },
     "to": "key"
    },
    {
     "kind": "ref",
     "from": "bucket",
     "to": "key"
    }
   ]
  },
  {
   "id": "kms_key",
   "kind": "exists",
   "tier": "core",
   "quote": "a custom KMS key",
   "select": "key"
  },
  {
   "id": "kms_rotation",
   "kind": "attr",
   "tier": "core",
   "quote": "key rotation enabled",
   "select": "key",
   "cond": {
    "path": [
     "enable_key_rotation"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "kms_deletion",
   "kind": "attr",
   "tier": "core",
   "quote": "a 10-day deletion window",
   "select": "key",
   "cond": {
    "path": [
     "deletion_window_in_days"
    ],
    "op": "eq",
    "value": 10
   }
  },
  {
   "id": "kms_alias",
   "kind": "attr",
   "tier": "core",
   "quote": "alias \"alias/benchmark-canary-key\"",
   "select": {
    "types": [
     "aws_kms_alias"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "alias/benchmark-canary-key"
   }
  },
  {
   "id": "kms_policy_cloudwatch",
   "kind": "any_of",
   "tier": "core",
   "quote": "a policy granting key access to CloudWatch and account root",
   "checks": [
    {
     "kind": "attr",
     "select": "key",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "cloudwatch.amazonaws.com"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_kms_key"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "cloudwatch.amazonaws.com"
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
        "op": "eq",
        "value": "aws_kms_key"
       }
      ]
     },
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "cloudwatch.amazonaws.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "kms_policy_root",
   "kind": "any_of",
   "tier": "core",
   "quote": "a policy granting key access to CloudWatch and account root",
   "checks": [
    {
     "kind": "attr",
     "select": "key",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i):root|[0-9]{12}|caller_identity|account_id"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_kms_key"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i):root|[0-9]{12}|caller_identity|account_id"
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
        "op": "eq",
        "value": "aws_kms_key"
       }
      ]
     },
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i):root|[0-9]{12}|caller_identity|account_id"
       }
      ]
     }
    }
   ],
   "justify": "account root is the account principal (root ARN or account id)"
  },
  {
   "id": "topic",
   "kind": "exists",
   "tier": "core",
   "quote": "An SNS topic",
   "select": "topic"
  },
  {
   "id": "topic_name",
   "kind": "attr",
   "tier": "core",
   "quote": "named \"benchmark-canary-topic\"",
   "select": "topic",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "benchmark-canary-topic"
   }
  },
  {
   "id": "topic_encrypted",
   "kind": "ref",
   "tier": "core",
   "quote": "encrypted with the KMS key",
   "from": "topic",
   "to": "key"
  },
  {
   "id": "sub_email",
   "kind": "attr",
   "tier": "core",
   "quote": "publish failure notifications to an email subscription defaulting to \"nobody@example.com\"",
   "select": {
    "types": [
     "aws_sns_topic_subscription"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "protocol"
    ],
    "op": "eq",
    "value": "email"
   }
  },
  {
   "id": "sub_endpoint",
   "kind": "attr",
   "tier": "core",
   "quote": "defaulting to \"nobody@example.com\"",
   "select": {
    "types": [
     "aws_sns_topic_subscription"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "endpoint"
    ],
    "op": "eq",
    "value": "nobody@example.com"
   }
  },
  {
   "id": "sub_topic",
   "kind": "ref",
   "tier": "detail",
   "quote": "publish failure notifications to an email subscription",
   "from": {
    "types": [
     "aws_sns_topic_subscription"
    ],
    "where": []
   },
   "to": "topic"
  },
  {
   "id": "topic_policy_publish",
   "kind": "any_of",
   "tier": "core",
   "quote": "an SNS topic policy allowing CloudWatch alarms to publish",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_sns_topic_policy",
       "aws_sns_topic"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "cloudwatch.amazonaws.com"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?i)sns:(Publish|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_sns_topic_policy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "cloudwatch.amazonaws.com"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)sns:(Publish|\\*)"
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
         "aws_sns_topic_policy",
         "aws_sns_topic"
        ]
       }
      ]
     },
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "cloudwatch.amazonaws.com"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)sns:(Publish|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "topic_policy_ref",
   "kind": "ref",
   "tier": "detail",
   "quote": "an SNS topic policy allowing CloudWatch alarms to publish",
   "from": {
    "types": [
     "aws_sns_topic_policy"
    ],
    "where": []
   },
   "to": "topic"
  },
  {
   "id": "canary",
   "kind": "exists",
   "tier": "core",
   "quote": "deploy CloudWatch Synthetics canaries",
   "select": "canary"
  },
  {
   "id": "canary_iterates",
   "kind": "attr",
   "tier": "core",
   "quote": "iterate over a map of VPC canary configurations",
   "select": "canary",
   "cond": {
    "path": [
     "properties",
     "for_each"
    ],
    "op": "present"
   },
   "justify": "iterating over a map means for_each"
  },
  {
   "id": "canary_vpc",
   "kind": "attr",
   "tier": "core",
   "quote": "inside specified subnet and security group lists",
   "select": "canary",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "vpc_config"
   }
  },
  {
   "id": "canary_subnets",
   "kind": "attr",
   "tier": "detail",
   "quote": "specified subnet and security group lists",
   "select": "canary",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "subnet_ids"
   }
  },
  {
   "id": "canary_sgs",
   "kind": "attr",
   "tier": "detail",
   "quote": "specified subnet and security group lists",
   "select": "canary",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "security_group_ids"
   }
  },
  {
   "id": "canary_zip",
   "kind": "attr",
   "tier": "detail",
   "quote": "accepting either inline zip files or S3 artifact sources",
   "select": "canary",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "zip_file"
   }
  },
  {
   "id": "canary_s3_source",
   "kind": "attr",
   "tier": "detail",
   "quote": "accepting either inline zip files or S3 artifact sources",
   "select": "canary",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "s3_key|s3_bucket"
   }
  },
  {
   "id": "canary_timeout",
   "kind": "attr",
   "tier": "core",
   "quote": "a 120-second execution timeout",
   "select": "canary",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "timeout_in_seconds\\W+120"
   }
  },
  {
   "id": "canary_schedule",
   "kind": "attr",
   "tier": "detail",
   "quote": "configurable schedule expressions",
   "select": "canary",
   "cond": {
    "path": [
     "properties"
    ],
    "op": "regex",
    "value": "expression\\W+\\$\\{"
   }
  },
  {
   "id": "canary_role",
   "kind": "any_of",
   "tier": "detail",
   "quote": "execution IAM role",
   "checks": [
    {
     "kind": "ref",
     "from": "canary",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_iam_role"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "canary",
     "to": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "data.aws_iam_role"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "canary_artifacts_bucket",
   "kind": "ref",
   "tier": "detail",
   "quote": "must store canary artifacts",
   "from": "canary",
   "to": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_s3_bucket"
     }
    ]
   }
  },
  {
   "id": "fail_alarm",
   "kind": "any_of",
   "tier": "core",
   "quote": "each canary must include a CloudWatch metric failure alarm",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_cloudwatch_metric_alarm"
       },
       {
        "path": [
         "properties",
         "metric_name"
        ],
        "op": "eq",
        "value": "Failed"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_cloudwatch_metric_alarm"
       },
       {
        "path": [
         "properties",
         "metric_name"
        ],
        "op": "eq",
        "value": "SuccessPercent"
       },
       {
        "path": [
         "properties",
         "threshold"
        ],
        "op": "eq",
        "value": 100
       },
       {
        "path": [
         "properties",
         "comparison_operator"
        ],
        "op": "eq",
        "value": "LessThanThreshold"
       }
      ]
     }
    }
   ],
   "justify": "a failure alarm is on the Synthetics Failed metric, or SuccessPercent below 100, which fires on any failure"
  },
  {
   "id": "fail_alarm_threshold",
   "kind": "any_of",
   "tier": "core",
   "quote": "triggering on 1 or more failures in a 60-second period",
   "justify": "1 or more failures: Failed >=1 or >0, or SuccessPercent below 100",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_cloudwatch_metric_alarm"
       },
       {
        "path": [
         "properties",
         "metric_name"
        ],
        "op": "eq",
        "value": "Failed"
       },
       {
        "path": [
         "properties",
         "comparison_operator"
        ],
        "op": "eq",
        "value": "GreaterThanOrEqualToThreshold"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "threshold"
      ],
      "op": "eq",
      "value": 1
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_cloudwatch_metric_alarm"
       },
       {
        "path": [
         "properties",
         "metric_name"
        ],
        "op": "eq",
        "value": "Failed"
       },
       {
        "path": [
         "properties",
         "comparison_operator"
        ],
        "op": "eq",
        "value": "GreaterThanThreshold"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "threshold"
      ],
      "op": "eq",
      "value": 0
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_cloudwatch_metric_alarm"
       },
       {
        "path": [
         "properties",
         "metric_name"
        ],
        "op": "eq",
        "value": "SuccessPercent"
       },
       {
        "path": [
         "properties",
         "threshold"
        ],
        "op": "eq",
        "value": 100
       },
       {
        "path": [
         "properties",
         "comparison_operator"
        ],
        "op": "eq",
        "value": "LessThanThreshold"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "fail_alarm_period",
   "kind": "any_of",
   "tier": "core",
   "quote": "in a 60-second period",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_cloudwatch_metric_alarm"
       },
       {
        "path": [
         "properties",
         "metric_name"
        ],
        "op": "eq",
        "value": "Failed"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "period"
      ],
      "op": "eq",
      "value": 60
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__declared__"
      ],
      "where": [
       {
        "path": [
         "type"
        ],
        "op": "eq",
        "value": "aws_cloudwatch_metric_alarm"
       },
       {
        "path": [
         "properties",
         "metric_name"
        ],
        "op": "eq",
        "value": "SuccessPercent"
       },
       {
        "path": [
         "properties",
         "threshold"
        ],
        "op": "eq",
        "value": 100
       },
       {
        "path": [
         "properties",
         "comparison_operator"
        ],
        "op": "eq",
        "value": "LessThanThreshold"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "period"
      ],
      "op": "eq",
      "value": 60
     }
    }
   ],
   "justify": "a failure alarm is on the Synthetics Failed metric, or SuccessPercent below 100, which fires on any failure"
  },
  {
   "id": "fail_alarm_topic",
   "kind": "any_of",
   "tier": "core",
   "quote": "that sends alerts to the SNS topic",
   "checks": [
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
        "op": "eq",
        "value": "aws_cloudwatch_metric_alarm"
       },
       {
        "path": [
         "properties",
         "metric_name"
        ],
        "op": "eq",
        "value": "Failed"
       },
       {
        "path": [
         "properties",
         "alarm_actions"
        ],
        "op": "present"
       }
      ]
     },
     "to": "topic"
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
        "op": "eq",
        "value": "aws_cloudwatch_metric_alarm"
       },
       {
        "path": [
         "properties",
         "metric_name"
        ],
        "op": "eq",
        "value": "SuccessPercent"
       },
       {
        "path": [
         "properties",
         "threshold"
        ],
        "op": "eq",
        "value": 100
       },
       {
        "path": [
         "properties",
         "comparison_operator"
        ],
        "op": "eq",
        "value": "LessThanThreshold"
       },
       {
        "path": [
         "properties",
         "alarm_actions"
        ],
        "op": "present"
       }
      ]
     },
     "to": "topic"
    }
   ],
   "justify": "a failure alarm is on the Synthetics Failed metric, or SuccessPercent below 100, which fires on any failure"
  },
  {
   "id": "success_alarm",
   "kind": "exists",
   "tier": "core",
   "quote": "an optional success percent metric alarm controlled by a boolean flag",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_cloudwatch_metric_alarm"
     },
     {
      "path": [
       "properties",
       "metric_name"
      ],
      "op": "eq",
      "value": "SuccessPercent"
     }
    ]
   },
   "justify": "success percent metric alarm is the SuccessPercent metric"
  },
  {
   "id": "success_alarm_gated",
   "kind": "attr",
   "tier": "detail",
   "quote": "optional success percent metric alarm controlled by a boolean flag",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_cloudwatch_metric_alarm"
     },
     {
      "path": [
       "properties",
       "metric_name"
      ],
      "op": "eq",
      "value": "SuccessPercent"
     }
    ]
   },
   "cond": {
    "path": [
     "gated"
    ],
    "op": "truthy"
   },
   "justify": "success percent metric alarm is the SuccessPercent metric"
  },
  {
   "id": "success_alarm_threshold",
   "kind": "attr",
   "tier": "core",
   "quote": "when success falls below 90 percent",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_cloudwatch_metric_alarm"
     },
     {
      "path": [
       "properties",
       "metric_name"
      ],
      "op": "eq",
      "value": "SuccessPercent"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "threshold"
    ],
    "op": "eq",
    "value": 90
   },
   "justify": "success percent metric alarm is the SuccessPercent metric"
  },
  {
   "id": "success_alarm_op",
   "kind": "attr",
   "tier": "detail",
   "quote": "falls below 90 percent",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_cloudwatch_metric_alarm"
     },
     {
      "path": [
       "properties",
       "metric_name"
      ],
      "op": "eq",
      "value": "SuccessPercent"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "comparison_operator"
    ],
    "op": "regex",
    "value": "(?i)LessThan"
   },
   "justify": "below means LessThan"
  },
  {
   "id": "success_alarm_ok_topic",
   "kind": "ref",
   "tier": "core",
   "quote": "sends OK notifications to the SNS topic",
   "from": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_cloudwatch_metric_alarm"
     },
     {
      "path": [
       "properties",
       "metric_name"
      ],
      "op": "eq",
      "value": "SuccessPercent"
     },
     {
      "path": [
       "properties",
       "ok_actions"
      ],
      "op": "present"
     }
    ]
   },
   "to": "topic",
   "justify": "success percent metric alarm is the SuccessPercent metric"
  },
  {
   "id": "x_kms_dec",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "policy"
    ],
    "op": "contains",
    "value": "kms:Decrypt"
   }
  },
  {
   "id": "x_fail_stat",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_cloudwatch_metric_alarm"
     },
     {
      "path": [
       "properties",
       "metric_name"
      ],
      "op": "eq",
      "value": "Failed"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "statistic"
    ],
    "op": "eq",
    "value": "Sum"
   }
  },
  {
   "id": "x_succ_stat",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "__declared__"
    ],
    "where": [
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "aws_cloudwatch_metric_alarm"
     },
     {
      "path": [
       "properties",
       "metric_name"
      ],
      "op": "eq",
      "value": "SuccessPercent"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "statistic"
    ],
    "op": "eq",
    "value": "Average"
   }
  },
  {
   "id": "extra_type_aws_iam_role_policy_attachment",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_iam_role_policy_attachment"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
