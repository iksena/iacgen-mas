# GENERATED from specs/tf/row_195.json by intent_checks/build.py -- do not edit.
package intent.tf.row_195

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "trail": {
   "types": [
    "aws_cloudtrail"
   ],
   "where": []
  },
  "bucket": {
   "types": [
    "aws_s3_bucket"
   ],
   "where": []
  },
  "kms": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "log_group": {
   "types": [
    "aws_cloudwatch_log_group"
   ],
   "where": []
  },
  "cw_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "contains",
     "value": "cloudtrail.amazonaws.com"
    }
   ]
  },
  "decl_trail": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_cloudtrail"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "trail_to_bucket",
   "kind": "ref",
   "tier": "core",
   "from": "trail",
   "to": "bucket",
   "quote": "provision a dedicated CloudTrail trail, an S3 log storage bucket"
  },
  {
   "id": "trail_log_file_validation",
   "kind": "attr",
   "tier": "core",
   "select": "trail",
   "cond": {
    "path": [
     "enable_log_file_validation"
    ],
    "op": "truthy"
   },
   "quote": "CloudTrail itself must enforce log file validation"
  },
  {
   "id": "trail_global_multi_region",
   "kind": "exists",
   "tier": "core",
   "quote": "include global service events (defaulting to true), multi-region trails (defaulting to true)",
   "select": {
    "types": [
     "aws_cloudtrail"
    ],
    "where": [
     {
      "path": [
       "include_global_service_events"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "is_multi_region_trail"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "trail_logging_org_defaults",
   "kind": "exists",
   "tier": "detail",
   "quote": "logging toggles (defaulting to true), organization trail toggles (defaulting to false)",
   "select": {
    "types": [
     "aws_cloudtrail"
    ],
    "where": [
     {
      "path": [
       "enable_logging"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "is_organization_trail"
      ],
      "op": "falsy"
     }
    ]
   }
  },
  {
   "id": "trail_event_selector",
   "kind": "attr",
   "tier": "core",
   "select": "trail",
   "quote": "event selectors with configurable read/write types (defaulting to \"All\"), management events (defaulting to true)",
   "cond": {
    "path": [
     "event_selector",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "read_write_type"
      ],
      "op": "eq",
      "value": "All"
     },
     {
      "path": [
       "include_management_events"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "trail_dynamic_selectors",
   "kind": "all_of",
   "tier": "detail",
   "quote": "dynamic data resource selectors, and dynamic insight selectors",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_trail",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "data_resource"
     }
    },
    {
     "kind": "attr",
     "select": "decl_trail",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "insight_selector"
     }
    }
   ]
  },
  {
   "id": "trail_kms_encrypted",
   "kind": "ref",
   "tier": "core",
   "from": "trail",
   "to": "kms",
   "quote": "CloudTrail log file encryption must use a dedicated KMS key"
  },
  {
   "id": "trail_cloudwatch_delivery",
   "kind": "all_of",
   "tier": "core",
   "quote": "a CloudWatch Log Group, an IAM role for CloudWatch Logs ingestion",
   "checks": [
    {
     "kind": "ref",
     "from": "trail",
     "to": "log_group"
    },
    {
     "kind": "ref",
     "from": "trail",
     "to": "cw_role"
    }
   ]
  },
  {
   "id": "bucket_public_access_blocked",
   "kind": "ref",
   "tier": "core",
   "to": "bucket",
   "quote": "with all public access blocked",
   "from": {
    "types": [
     "aws_s3_bucket_public_access_block"
    ],
    "where": [
     {
      "path": [
       "block_public_acls"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "block_public_policy"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "ignore_public_acls"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "restrict_public_buckets"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "bucket_sse_kms_cloudtrail_key",
   "kind": "any_of",
   "tier": "core",
   "quote": "default SSE-KMS encryption using the dedicated CloudTrail KMS key",
   "checks": [
    {
     "kind": "ref",
     "to": "kms",
     "from": {
      "types": [
       "aws_s3_bucket_server_side_encryption_configuration"
      ],
      "where": [
       {
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
      ]
     }
    },
    {
     "kind": "ref",
     "to": "kms",
     "from": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": [
       {
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
      ]
     }
    }
   ]
  },
  {
   "id": "bucket_force_destroy_default",
   "kind": "attr",
   "tier": "detail",
   "select": "bucket",
   "cond": {
    "path": [
     "force_destroy"
    ],
    "op": "truthy"
   },
   "quote": "configurable force destroy (defaulting to true)"
  },
  {
   "id": "bucket_versioning_default_off",
   "kind": "any_of",
   "tier": "detail",
   "quote": "versioning configuration (defaulting to false)",
   "justify": "versioning false -> versioning status Disabled/Suspended (or a falsy versioning variable)",
   "checks": [
    {
     "kind": "ref",
     "to": "bucket",
     "from": {
      "types": [
       "aws_s3_bucket_versioning"
      ],
      "where": [
       {
        "path": [
         "versioning_configuration",
         "*",
         "status"
        ],
        "op": "in",
        "value": [
         "Disabled",
         "Suspended"
        ]
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
        "value": "(?i)versioning"
       },
       {
        "path": [
         "default"
        ],
        "op": "falsy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bucket_name_account_region",
   "kind": "all_of",
   "tier": "detail",
   "quote": "dynamic generation incorporating account ID, region",
   "checks": [
    {
     "kind": "ref",
     "from": "bucket",
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
        "value": "data.aws_caller_identity"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "bucket",
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
        "value": "data.aws_region"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bucket_name_random_suffix",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a random 8-character lowercase suffix",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "random_string"
      ],
      "where": [
       {
        "path": [
         "length"
        ],
        "op": "eq",
        "value": 8
       },
       {
        "path": [
         "upper"
        ],
        "op": "falsy"
       },
       {
        "path": [
         "special"
        ],
        "op": "falsy"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "random_id"
      ],
      "where": [
       {
        "path": [
         "byte_length"
        ],
        "op": "eq",
        "value": 4
       }
      ]
     }
    }
   ],
   "justify": "8-character lowercase suffix -> random_string length 8 without upper/special, or random_id byte_length 4 (8 lowercase hex chars)"
  },
  {
   "id": "bucket_policy_cloudtrail",
   "kind": "any_of",
   "tier": "core",
   "quote": "an S3 bucket policy permitting CloudTrail ACL checks and put-object actions with full control",
   "justify": "ACL check -> s3:GetBucketAcl; put-object with full control -> s3:PutObject + bucket-owner-full-control",
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
        "value": "aws_s3_bucket_policy"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "s3:GetBucketAcl"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "s3:PutObject"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "bucket-owner-full-control"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "data.aws_iam_policy_document",
       "aws_s3_bucket_policy"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "s3:GetBucketAcl"
       },
       {
        "path": [],
        "op": "regex",
        "value": "s3:PutObject"
       },
       {
        "path": [],
        "op": "regex",
        "value": "bucket-owner-full-control"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "kms_key_window_rotation",
   "kind": "exists",
   "tier": "core",
   "quote": "a dedicated KMS key with a 30-day deletion window, automated annual key rotation",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": [
     {
      "path": [
       "deletion_window_in_days"
      ],
      "op": "eq",
      "value": 30
     },
     {
      "path": [
       "enable_key_rotation"
      ],
      "op": "truthy"
     }
    ]
   }
  },
  {
   "id": "kms_alias",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "aws_kms_alias"
    ],
    "where": []
   },
   "to": "kms",
   "quote": "an alias prefix"
  },
  {
   "id": "kms_policy_principals",
   "kind": "any_of",
   "tier": "core",
   "quote": "a key policy granting permissions to root IAM users, CloudTrail encryption contexts, CloudWatch Logs, S3 bucket encryption",
   "justify": "root -> :root principal; CloudTrail -> cloudtrail.amazonaws.com; CloudWatch Logs -> logs service principal; S3 -> s3 service",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_kms_key",
       "aws_kms_key_policy",
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "kms:"
       },
       {
        "path": [],
        "op": "regex",
        "value": ":root"
       },
       {
        "path": [],
        "op": "regex",
        "value": "cloudtrail\\.amazonaws\\.com"
       },
       {
        "path": [],
        "op": "regex",
        "value": "logs\\.([a-z0-9-]+\\.)?amazonaws\\.com"
       },
       {
        "path": [],
        "op": "regex",
        "value": "s3(\\.[a-z0-9-]+)?\\.amazonaws\\.com"
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
        "op": "in",
        "value": [
         "aws_kms_key",
         "aws_kms_key_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "kms:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": ":root"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "cloudtrail\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "logs\\.([a-z0-9-]+\\.)?amazonaws\\.com"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "s3(\\.[a-z0-9-]+)?\\.amazonaws\\.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "kms_policy_cloudtrail_encryption_context",
   "kind": "any_of",
   "tier": "detail",
   "quote": "CloudTrail encryption contexts",
   "justify": "'CloudTrail encryption contexts' -> kms:EncryptionContext:aws:cloudtrail:arn condition",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_kms_key",
       "aws_kms_key_policy",
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "kms:"
       },
       {
        "path": [],
        "op": "regex",
        "value": "EncryptionContext:(aws|\\$\\{[^}]*\\}):cloudtrail"
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
        "op": "in",
        "value": [
         "aws_kms_key",
         "aws_kms_key_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "kms:"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "EncryptionContext:(aws|\\$\\{[^}]*\\}):cloudtrail"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "kms_decrypt_role_input",
   "kind": "any_of",
   "tier": "detail",
   "quote": "an optional role ARN provided for log decryption",
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
        "value": "(?i)role"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": ""
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
        "value": "(?i)role"
       },
       {
        "path": [
         "default"
        ],
        "op": "absent"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "log_group_retention_90",
   "kind": "attr",
   "tier": "core",
   "select": "log_group",
   "cond": {
    "path": [
     "retention_in_days"
    ],
    "op": "eq",
    "value": 90
   },
   "quote": "retaining logs for 90 days"
  },
  {
   "id": "cw_role_policy_actions",
   "kind": "any_of",
   "tier": "core",
   "quote": "a dedicated IAM role and policy allowing CloudTrail to create log streams and put log events",
   "justify": "create log streams / put log events -> logs:CreateLogStream / logs:PutLogEvents",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "data.aws_iam_policy_document",
       "aws_iam_role_policy",
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [],
        "op": "regex",
        "value": "logs:(CreateLogStream|\\*)"
       },
       {
        "path": [],
        "op": "regex",
        "value": "logs:(PutLogEvents|\\*)"
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
        "op": "in",
        "value": [
         "aws_iam_role_policy",
         "aws_iam_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "logs:(CreateLogStream|\\*)"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "logs:(PutLogEvents|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "optional_sns_topic_with_policy",
   "kind": "all_of",
   "tier": "detail",
   "quote": "conditionally creating an SNS topic for alerts (disabled by default) with a topic policy allowing CloudTrail publishing",
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
        "value": "aws_sns_topic"
       },
       {
        "path": [
         "gated"
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
         "aws_sns_topic",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "cloudtrail\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)sns:publish"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sns_inputs_defaults",
   "kind": "all_of",
   "tier": "detail",
   "quote": "otherwise using an optional SNS topic ARN input that defaults to empty",
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
        "value": "(?i)sns"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": false
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
        "value": "(?i)sns.*arn"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": ""
       }
      ]
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
