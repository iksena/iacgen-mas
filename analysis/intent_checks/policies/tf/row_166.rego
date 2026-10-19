package intent.tf.row_166

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "bucket": {
   "types": [
    "aws_s3_bucket"
   ],
   "where": [
    {
     "path": [
      "bucket"
     ],
     "op": "eq",
     "value": "benchmark-bucket-tf5x"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "bucket_default_name",
   "kind": "exists",
   "select": "bucket",
   "tier": "core",
   "quote": "a base bucket name defaulting to \"benchmark-bucket-tf5x\""
  },
  {
   "id": "force_destroy_false",
   "kind": "attr",
   "select": "bucket",
   "tier": "detail",
   "cond": {
    "path": [
     "force_destroy"
    ],
    "op": "falsy"
   },
   "quote": "bucket force destroy defaults to false"
  },
  {
   "id": "policy_deny_insecure_transport",
   "kind": "any_of",
   "tier": "core",
   "quote": "denying s3:* actions over non-TLS transport (\"aws:SecureTransport\" equal to \"false\")",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)\"Effect\":\"Deny\""
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)\"aws:SecureTransport\":\\[?\"false\""
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)\"s3:\\*\""
       }
      ]
     },
     "to": "bucket"
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
         "data.aws_iam_policy_document",
         "aws_s3_bucket_policy",
         "aws_iam_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)deny"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "aws:SecureTransport"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3:*"
       }
      ]
     }
    }
   ],
   "justify": "planned bucket policy is often unknown at plan (built from the bucket ARN); accept the declared policy document"
  },
  {
   "id": "policy_s3_service_write",
   "kind": "any_of",
   "tier": "detail",
   "quote": "allow S3 service principals to write inventory and analytics data when bucket-owner-full-control ACL is specified",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3.amazonaws.com"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "bucket-owner-full-control"
       }
      ]
     },
     "to": "bucket"
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
         "data.aws_iam_policy_document",
         "aws_s3_bucket_policy",
         "aws_iam_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3.amazonaws.com"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "bucket-owner-full-control"
       }
      ]
     }
    }
   ],
   "justify": "'S3 service principals' -> s3.amazonaws.com; planned policy may be unknown, accept the declared document"
  },
  {
   "id": "public_access_block",
   "kind": "ref",
   "tier": "core",
   "to": "bucket",
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
     }
    ]
   },
   "quote": "Bucket access blocks must be enabled by default (controlled by enable_s3_public_access_block) to restrict public ACLs and public bucket policies"
  },
  {
   "id": "ownership_enforced",
   "kind": "ref",
   "tier": "core",
   "to": "bucket",
   "from": {
    "types": [
     "aws_s3_bucket_ownership_controls"
    ],
    "where": [
     {
      "path": [
       "rule",
       "*",
       "object_ownership"
      ],
      "op": "eq",
      "value": "BucketOwnerEnforced"
     }
    ]
   },
   "quote": "object ownership defaults to \"BucketOwnerEnforced\""
  },
  {
   "id": "sse_aes256_default",
   "kind": "any_of",
   "tier": "core",
   "quote": "Server-side encryption must default to AES256",
   "checks": [
    {
     "kind": "ref",
     "to": "bucket",
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
        "value": "AES256"
       }
      ]
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
      "value": "AES256"
     }
    }
   ]
  },
  {
   "id": "sse_kms_when_key_given",
   "kind": "exists",
   "tier": "detail",
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
      "value": "aws_s3_bucket_server_side_encryption_configuration"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "aws:kms|local\\."
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "kms_master_key_id"
     }
    ]
   },
   "quote": "unless kms_master_key_id is provided to enable \"aws:kms\" encryption",
   "justify": "aws:kms stated; the algorithm switch may be expressed through a local (unresolved)"
  },
  {
   "id": "bucket_key_disabled",
   "kind": "any_of",
   "tier": "detail",
   "quote": "bucket_key_enabled defaulting to false",
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
       "bucket_key_enabled"
      ],
      "op": "eq",
      "value": false
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
       "bucket_key_enabled"
      ],
      "op": "eq",
      "value": false
     }
    }
   ]
  },
  {
   "id": "versioning_enabled",
   "kind": "any_of",
   "tier": "core",
   "quote": "Versioning status must default to \"Enabled\"",
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
        "op": "eq",
        "value": "Enabled"
       }
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
      "op": "truthy"
     }
    }
   ]
  },
  {
   "id": "transition_min_object_size",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "aws_s3_bucket_lifecycle_configuration"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "transition_default_minimum_object_size"
    ],
    "op": "eq",
    "value": "all_storage_classes_128K"
   },
   "quote": "transition default minimum object size is set to \"all_storage_classes_128K\""
  },
  {
   "id": "abort_multipart_14d",
   "kind": "any_of",
   "tier": "core",
   "quote": "automatically abort incomplete multipart uploads after 14 days",
   "checks": [
    {
     "kind": "ref",
     "to": "bucket",
     "from": {
      "types": [
       "aws_s3_bucket_lifecycle_configuration"
      ],
      "where": [
       {
        "path": [
         "rule",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "status"
          ],
          "op": "eq",
          "value": "Enabled"
         },
         {
          "path": [
           "abort_incomplete_multipart_upload",
           "*",
           "days_after_initiation"
          ],
          "op": "eq",
          "value": 14
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "bucket",
     "cond": {
      "path": [
       "lifecycle_rule",
       "*",
       "abort_incomplete_multipart_upload_days"
      ],
      "op": "eq",
      "value": 14
     }
    }
   ]
  },
  {
   "id": "noncurrent_transition_ia_30",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_s3_bucket_lifecycle_configuration"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "rule",
     "*",
     "noncurrent_version_transition",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "noncurrent_days"
      ],
      "op": "eq",
      "value": 30
     },
     {
      "path": [
       "storage_class"
      ],
      "op": "eq",
      "value": "STANDARD_IA"
     }
    ]
   },
   "quote": "transitioning noncurrent versions to \"STANDARD_IA\" after 30 days"
  },
  {
   "id": "noncurrent_expire_365",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_s3_bucket_lifecycle_configuration"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "rule",
     "*",
     "noncurrent_version_expiration",
     "*",
     "noncurrent_days"
    ],
    "op": "eq",
    "value": 365
   },
   "quote": "expiring them after 365 days"
  },
  {
   "id": "analytics_export",
   "kind": "ref",
   "tier": "core",
   "to": "bucket",
   "from": {
    "types": [
     "aws_s3_bucket_analytics_configuration"
    ],
    "where": [
     {
      "path": [
       "storage_class_analysis",
       "*",
       "data_export",
       "*",
       "destination",
       "*",
       "s3_bucket_destination",
       "*",
       "prefix"
      ],
      "op": "regex",
      "value": "^_AWSBucketAnalytics/?$"
     }
    ]
   },
   "quote": "Storage class analytics defaulting to enabled (enable_analytics set to true) must write export data under prefix \"_AWSBucketAnalytics/\""
  },
  {
   "id": "analytics_lifecycle_30d",
   "kind": "attr",
   "tier": "detail",
   "select": {
    "types": [
     "aws_s3_bucket_lifecycle_configuration"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "rule",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "status"
      ],
      "op": "eq",
      "value": "Enabled"
     },
     {
      "path": [
       "filter",
       "*",
       "prefix"
      ],
      "op": "regex",
      "value": "^_AWSBucketAnalytics/?$"
     },
     {
      "path": [
       "expiration",
       "*",
       "days"
      ],
      "op": "eq",
      "value": 30
     }
    ]
   },
   "quote": "with a 30-day lifecycle expiration"
  },
  {
   "id": "inventory_declared",
   "kind": "exists",
   "tier": "detail",
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
      "value": "aws_s3_bucket_inventory"
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "ORC"
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "Weekly"
     },
     {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "_AWSBucketInventory"
     }
    ]
   },
   "quote": "optional bucket inventory (enable_bucket_inventory defaulting to false) writes ORC-formatted reports under prefix \"_AWSBucketInventory/\" on a \"Weekly\" schedule"
  },
  {
   "id": "inventory_not_created_by_default",
   "kind": "exists",
   "tier": "detail",
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
      "value": "aws_s3_bucket_inventory"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "enable_bucket_inventory defaulting to false"
  },
  {
   "id": "inventory_lifecycle_14d",
   "kind": "any_of",
   "tier": "detail",
   "quote": "on a \"Weekly\" schedule with a 14-day lifecycle expiration",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_lifecycle_configuration"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "rule",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "filter",
         "*",
         "prefix"
        ],
        "op": "regex",
        "value": "^_AWSBucketInventory/?$"
       },
       {
        "path": [
         "expiration",
         "*",
         "days"
        ],
        "op": "eq",
        "value": 14
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
        "value": "aws_s3_bucket_lifecycle_configuration"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?s)(_AWSBucketInventory.{0,200}?days\\W{0,6}14\\D|days\\W{0,6}14\\D.{0,200}?_AWSBucketInventory)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "logging_conditional",
   "kind": "exists",
   "tier": "detail",
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
      "value": "aws_s3_bucket_logging"
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "s3/\\$\\{[^}]+\\}/"
     }
    ]
   },
   "quote": "logging to an external target bucket is conditionally enabled when logging_bucket is specified using a target prefix of \"s3/\" followed by the bucket's id and a trailing slash"
  },
  {
   "id": "optional_features_declared",
   "kind": "all_of",
   "tier": "detail",
   "quote": "transfer acceleration status is conditionally configured when transfer_acceleration is not null, bucket ACLs are applied when s3_bucket_acl is set, and CORS rules are dynamically applied from a cors_rules list",
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
        "value": "aws_s3_bucket_accelerate_configuration"
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
        "op": "eq",
        "value": "aws_s3_bucket_acl"
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
        "op": "eq",
        "value": "aws_s3_bucket_cors_configuration"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "named_variables",
   "kind": "all_of",
   "tier": "detail",
   "quote": "when use_account_alias_prefix is enabled, or use a random suffix prefix when use_random_suffix is set to true",
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
        "op": "eq",
        "value": "use_account_alias_prefix"
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
        "op": "eq",
        "value": "use_random_suffix"
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
        "op": "eq",
        "value": "custom_bucket_policy"
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
        "op": "eq",
        "value": "enable_s3_public_access_block"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": true
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
        "op": "eq",
        "value": "kms_master_key_id"
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
        "op": "eq",
        "value": "bucket_key_enabled"
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
        "op": "eq",
        "value": "enable_analytics"
       },
       {
        "path": [
         "default"
        ],
        "op": "eq",
        "value": true
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
        "op": "eq",
        "value": "enable_bucket_inventory"
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
        "op": "eq",
        "value": "logging_bucket"
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
        "op": "eq",
        "value": "transfer_acceleration"
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
        "op": "eq",
        "value": "s3_bucket_acl"
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
        "op": "eq",
        "value": "cors_rules"
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
