# GENERATED from specs/tf/row_114.json by intent_checks/build.py -- do not edit.
package intent.tf.row_114

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
  "decl_bucket": {
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
  },
  "kms_rotating": {
   "types": [
    "aws_kms_key"
   ],
   "where": [
    {
     "path": [
      "enable_key_rotation"
     ],
     "op": "truthy"
    }
   ]
  },
  "decl_kms": {
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
  "decl_repl_role": {
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
    },
    {
     "path": [
      "properties"
     ],
     "op": "regex",
     "value": "CoreS3ReplicationRole|s3\\.amazonaws\\.com"
    }
   ]
  },
  "decl_repl_policy": {
   "types": [
    "__declared__"
   ],
   "where": [
    {
     "path": [
      "type"
     ],
     "op": "eq",
     "value": "aws_iam_policy"
    },
    {
     "path": [
      "properties"
     ],
     "op": "regex",
     "value": "CoreS3ReplicationPolicy|s3:Replicate"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "bucket_exists",
   "kind": "exists",
   "tier": "core",
   "select": "bucket",
   "quote": "creates a feature-complete Amazon S3 bucket module"
  },
  {
   "id": "sse_kms_default",
   "kind": "any_of",
   "tier": "core",
   "quote": "so encryption is always \"aws:kms\"",
   "checks": [
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
    },
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
        "value": "aws:kms"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "module_kms_key_rotating",
   "kind": "exists",
   "tier": "core",
   "select": "kms_rotating",
   "quote": "the module creates its own rotating customer-managed KMS key"
  },
  {
   "id": "module_kms_key_used_by_bucket",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with either the supplied key ARN or the module-created key",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket_server_side_encryption_configuration"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": "bucket",
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": "decl_bucket",
     "to": "decl_kms"
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
        "value": "aws_s3_bucket_server_side_encryption_configuration"
       }
      ]
     },
     "to": "decl_kms"
    }
   ]
  },
  {
   "id": "public_access_blocked",
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
   },
   "quote": "always blocking all public access on the bucket"
  },
  {
   "id": "random_hex_suffix",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a 4-byte random hexadecimal string",
   "checks": [
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
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "random_bytes"
      ],
      "where": [
       {
        "path": [
         "length"
        ],
        "op": "eq",
        "value": 4
       }
      ]
     }
    }
   ],
   "justify": "4-byte random hex string -> random_id byte_length 4 (or random_bytes length 4)"
  },
  {
   "id": "var_bucket_name",
   "kind": "exists",
   "tier": "detail",
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
      "value": "bucket_name"
     }
    ]
   },
   "quote": "an optional bucket_name variable"
  },
  {
   "id": "var_request_payer_default",
   "kind": "exists",
   "tier": "detail",
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
      "value": "request_payer"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "BucketOwner"
     }
    ]
   },
   "quote": "request_payer to \"BucketOwner\""
  },
  {
   "id": "var_encryption_defaults",
   "kind": "all_of",
   "tier": "detail",
   "quote": "encryption to true, kms_key to an empty string",
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
        "value": "encryption"
       },
       {
        "path": [
         "default"
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
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "kms_key"
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
  },
  {
   "id": "var_false_defaults",
   "kind": "all_of",
   "tier": "detail",
   "quote": "versioning, mfa_delete, force_destroy, and prefix to false",
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
        "value": "versioning"
       },
       {
        "path": [
         "default"
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
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "mfa_delete"
       },
       {
        "path": [
         "default"
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
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "force_destroy"
       },
       {
        "path": [
         "default"
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
       "__parameter__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "eq",
        "value": "prefix"
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
   "id": "website_supported",
   "kind": "any_of",
   "tier": "detail",
   "quote": "website index/error documents or redirect-all rules",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_bucket",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)website"
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
        "value": "aws_s3_bucket_website_configuration"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "cors_supported",
   "kind": "any_of",
   "tier": "detail",
   "quote": "CORS rules",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_bucket",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)cors_rule"
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
   "id": "lifecycle_supported",
   "kind": "any_of",
   "tier": "detail",
   "quote": "lifecycle rules",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_bucket",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)lifecycle_rule"
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
       }
      ]
     }
    }
   ]
  },
  {
   "id": "logging_supported",
   "kind": "any_of",
   "tier": "detail",
   "quote": "logging target bucket and prefix",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_bucket",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)target_bucket"
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
        "value": "aws_s3_bucket_logging"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "object_lock_supported",
   "kind": "any_of",
   "tier": "detail",
   "quote": "object lock configurations",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_bucket",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)object_lock"
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
        "value": "aws_s3_bucket_object_lock_configuration"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "replication_supported",
   "kind": "any_of",
   "tier": "core",
   "quote": "the module must configure cross-region replication rules",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_bucket",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)replication_configuration"
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
        "value": "aws_s3_bucket_replication_configuration"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "replication_role_named",
   "kind": "exists",
   "tier": "core",
   "select": "decl_repl_role",
   "quote": "a dedicated IAM role named \"CoreS3ReplicationRole_\" followed by the resolved bucket name",
   "justify": "role named CoreS3ReplicationRole_<bucket> (the name is often built in a local, so a role trusted by s3.amazonaws.com is also accepted)"
  },
  {
   "id": "replication_role_trust_s3",
   "kind": "any_of",
   "tier": "detail",
   "quote": "assumed by \"s3.amazonaws.com\"",
   "checks": [
    {
     "kind": "attr",
     "select": "decl_repl_role",
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "contains",
      "value": "s3.amazonaws.com"
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "s3\\.amazonaws\\.com"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "sts:AssumeRole"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "replication_policy_attached",
   "kind": "any_of",
   "tier": "core",
   "quote": "a custom policy \"CoreS3ReplicationPolicy_\" followed by the resolved bucket name permitting bucket list/replication actions and attach it directly to the role",
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
        "op": "in",
        "value": [
         "aws_iam_role_policy_attachment",
         "aws_iam_policy_attachment"
        ]
       }
      ]
     },
     "to": "decl_repl_policy"
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
        "value": "aws_iam_role_policy"
       }
      ]
     },
     "to": "decl_repl_role"
    }
   ]
  },
  {
   "id": "replication_policy_actions",
   "kind": "all_of",
   "tier": "detail",
   "quote": "permitting bucket list/replication actions",
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
        "op": "in",
        "value": [
         "data.aws_iam_policy_document",
         "aws_iam_policy",
         "aws_iam_role_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "s3:(ListBucket|List\\*|\\*)"
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
         "data.aws_iam_policy_document",
         "aws_iam_policy",
         "aws_iam_role_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "s3:(Replicate|\\*)"
       }
      ]
     }
    }
   ],
   "justify": "'bucket list/replication actions' -> s3:ListBucket and s3:Replicate* (or a covering wildcard)"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
