# GENERATED from specs/tf/row_250.json by intent_checks/build.py -- do not edit.
package intent.tf.row_250

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "primary": {
   "types": [
    "aws_s3_bucket"
   ],
   "where": []
  },
  "replica": {
   "types": [
    "aws_s3_bucket"
   ],
   "where": []
  },
  "primary_kms": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "replica_kms": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "repl_role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "assume_role_policy"
     ],
     "op": "contains",
     "value": "s3.amazonaws.com"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "primary_bucket_us_east_1",
   "kind": "any_of",
   "tier": "core",
   "quote": "utilizing an S3 backend in us-east-1",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": [
       {
        "path": [
         "region"
        ],
        "op": "eq",
        "value": "us-east-1"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": [
       {
        "path": [
         "region"
        ],
        "op": "absent"
       }
      ]
     }
    }
   ],
   "justify": "us-east-1 is stated; provider<6 plans have no per-resource region attribute, so an absent region is not penalised"
  },
  {
   "id": "primary_bucket_account_id",
   "kind": "attr",
   "tier": "detail",
   "quote": "a primary S3 bucket named dynamically with the AWS account ID",
   "select": "primary",
   "cond": {
    "path": [
     "bucket"
    ],
    "op": "regex",
    "value": "[0-9]{12}"
   }
  },
  {
   "id": "primary_versioning",
   "kind": "any_of",
   "tier": "core",
   "quote": "enforcing versioning",
   "checks": [
    {
     "kind": "attr",
     "select": "primary",
     "cond": {
      "path": [
       "versioning",
       "*",
       "enabled"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "ref",
     "to": "primary",
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
    }
   ]
  },
  {
   "id": "primary_public_access_block",
   "kind": "ref",
   "tier": "core",
   "quote": "strict public access blocks",
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
   "to": "primary"
  },
  {
   "id": "primary_deny_non_ssl",
   "kind": "any_of",
   "tier": "core",
   "quote": "a bucket policy that explicitly denies non-SSL requests",
   "checks": [
    {
     "kind": "ref",
     "to": "primary",
     "from": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Deny"
         },
         {
          "path": [
           "condition",
           "*",
           "variable"
          ],
          "op": "eq",
          "value": "aws:SecureTransport"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "primary",
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
        "value": "aws:SecureTransport"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "min": 1,
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
         "properties",
         "policy"
        ],
        "op": "contains",
        "value": "aws:SecureTransport"
       }
      ]
     }
    }
   ],
   "justify": "\"explicitly denies non-SSL requests\" -> a Deny statement on aws:SecureTransport"
  },
  {
   "id": "primary_sse_kms",
   "kind": "any_of",
   "tier": "core",
   "quote": "All objects in the primary bucket must be encrypted server-side by default using a new custom KMS key",
   "checks": [
    {
     "kind": "ref",
     "to": "primary_kms",
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
    },
    {
     "kind": "ref",
     "to": "primary_kms",
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
   "id": "primary_kms_settings",
   "kind": "all_of",
   "tier": "core",
   "quote": "configured with a 7-day deletion window and automatic key rotation",
   "checks": [
    {
     "kind": "attr",
     "select": "primary_kms",
     "cond": {
      "path": [
       "deletion_window_in_days"
      ],
      "op": "eq",
      "value": 7
     }
    },
    {
     "kind": "attr",
     "select": "primary_kms",
     "cond": {
      "path": [
       "enable_key_rotation"
      ],
      "op": "truthy"
     }
    }
   ]
  },
  {
   "id": "replica_bucket_other_region",
   "kind": "any_of",
   "tier": "core",
   "quote": "provision a replica S3 bucket in that second region",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": [
       {
        "path": [
         "region"
        ],
        "op": "present"
       },
       {
        "path": [
         "region"
        ],
        "op": "neq",
        "value": "us-east-1"
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
        "value": "aws_s3_bucket"
       },
       {
        "path": [
         "properties",
         "provider"
        ],
        "op": "present"
       }
      ]
     }
    }
   ],
   "justify": "\"second AWS region\": a bucket whose region is not us-east-1, or one declared on an aliased provider"
  },
  {
   "id": "replica_versioning",
   "kind": "any_of",
   "tier": "detail",
   "quote": "with identical versioning, SSL enforcement, and public access blocks",
   "checks": [
    {
     "kind": "attr",
     "select": "replica",
     "cond": {
      "path": [
       "versioning",
       "*",
       "enabled"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "ref",
     "to": "replica",
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
    }
   ]
  },
  {
   "id": "replica_ssl",
   "kind": "any_of",
   "tier": "detail",
   "quote": "SSL enforcement",
   "checks": [
    {
     "kind": "ref",
     "to": "replica",
     "from": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Deny"
         },
         {
          "path": [
           "condition",
           "*",
           "variable"
          ],
          "op": "eq",
          "value": "aws:SecureTransport"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "ref",
     "to": "replica",
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
        "value": "aws:SecureTransport"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "min": 2,
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
         "properties",
         "policy"
        ],
        "op": "contains",
        "value": "aws:SecureTransport"
       }
      ]
     }
    }
   ],
   "justify": "\"identical ... SSL enforcement\" -> a Deny on aws:SecureTransport; fallback = a second declared SSL bucket policy besides the primary one"
  },
  {
   "id": "replica_public_access_block",
   "kind": "ref",
   "tier": "detail",
   "quote": "public access blocks",
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
   "to": "replica"
  },
  {
   "id": "replica_kms_key",
   "kind": "all_of",
   "tier": "core",
   "quote": "secured by its own dedicated replica KMS key",
   "checks": [
    {
     "kind": "exists",
     "min": 2,
     "select": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket",
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
    }
   ],
   "justify": "\"its own dedicated replica KMS key\" alongside the primary key -> at least 2 KMS keys"
  },
  {
   "id": "replication_kms_objects",
   "kind": "any_of",
   "tier": "core",
   "quote": "Configure S3 cross-region replication on the primary bucket to automatically replicate KMS-encrypted objects",
   "checks": [
    {
     "kind": "attr",
     "select": "primary",
     "cond": {
      "path": [
       "replication_configuration",
       "*",
       "rules",
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
         "source_selection_criteria",
         "*",
         "sse_kms_encrypted_objects",
         "*",
         "enabled"
        ],
        "op": "truthy"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_replication_configuration"
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
         "source_selection_criteria",
         "*",
         "sse_kms_encrypted_objects",
         "*",
         "status"
        ],
        "op": "eq",
        "value": "Enabled"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "replication_to_replica",
   "kind": "any_of",
   "tier": "core",
   "quote": "to the replica bucket",
   "checks": [
    {
     "kind": "ref",
     "to": "replica",
     "from": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": [
       {
        "path": [
         "replication_configuration",
         "*",
         "rules",
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
     "kind": "ref",
     "to": "replica",
     "from": {
      "types": [
       "aws_s3_bucket_replication_configuration"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "replication_role",
   "kind": "any_of",
   "tier": "core",
   "quote": "attaching an IAM role",
   "checks": [
    {
     "kind": "ref",
     "to": "repl_role",
     "from": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": [
       {
        "path": [
         "replication_configuration",
         "*",
         "rules",
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
     "kind": "ref",
     "to": "repl_role",
     "from": {
      "types": [
       "aws_s3_bucket_replication_configuration"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "replication_permissions",
   "kind": "all_of",
   "tier": "detail",
   "quote": "with the precise permissions required to read the source objects, decrypt them using the primary KMS key, and encrypt them at the destination using the replica key",
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "s3:(GetObjectVersion|GetObject\\*|\\*)"
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "s3:(Replicate(Object|\\*)|\\*)"
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "kms:(Decrypt|\\*)"
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
         "aws_iam_policy",
         "aws_iam_role_policy",
         "aws_iam_role",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "kms:(Encrypt|GenerateDataKey|ReEncrypt|\\*)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "replication_policy_keys",
   "kind": "all_of",
   "tier": "detail",
   "quote": "decrypt them using the primary KMS key, and encrypt them at the destination using the replica key",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "to": "primary_kms"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy",
       "aws_iam_role_policy",
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "to": "replica_kms"
    }
   ]
  },
  {
   "id": "dynamodb_lock_tables",
   "kind": "exists",
   "tier": "core",
   "quote": "deploy individual pay-per-request DynamoDB tables keyed by \"LockID\" for each stack's state locking",
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
      "value": "aws_dynamodb_table"
     },
     {
      "path": [
       "properties",
       "billing_mode"
      ],
      "op": "contains",
      "value": "PAY_PER_REQUEST"
     },
     {
      "path": [
       "properties",
       "hash_key"
      ],
      "op": "contains",
      "value": "LockID"
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
   "id": "stack_iam_policies",
   "kind": "any_of",
   "tier": "detail",
   "quote": "dedicated IAM policies that grant stack-specific access to their respective DynamoDB table, S3 bucket prefix, and KMS key operations",
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
        "value": "aws_iam_policy"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       },
       {
        "path": [
         "properties",
         "policy"
        ],
        "op": "contains",
        "value": "dynamodb:"
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
        "value": "data.aws_iam_policy_document"
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
        "op": "contains",
        "value": "dynamodb:"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "backend_tf_files",
   "kind": "exists",
   "tier": "detail",
   "quote": "automatically generate a local \"backend.tf\" file for each stack within a relative \"eks-stacks\" directory",
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
      "value": "local_file"
     },
     {
      "path": [
       "properties",
       "filename"
      ],
      "op": "regex",
      "value": "eks-stacks[\\s\\S]*backend\\.tf"
     }
    ]
   }
  },
  {
   "id": "resources_tagged",
   "kind": "all_of",
   "tier": "detail",
   "quote": "ensuring all created resources are tagged with a standardized set of state management labels",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "tags_all"
      ],
      "op": "len_gte",
      "value": 1
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "tags_all"
      ],
      "op": "len_gte",
      "value": 1
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
