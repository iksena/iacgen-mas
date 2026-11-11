package intent.tf.row_016

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
  "kms": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "sse": {
   "types": [
    "aws_s3_bucket_server_side_encryption_configuration"
   ],
   "where": []
  },
  "pab": {
   "types": [
    "aws_s3_bucket_public_access_block"
   ],
   "where": []
  },
  "acct": {
   "types": [
    "aws_s3_account_public_access_block"
   ],
   "where": []
  },
  "kms_rot": {
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
  }
 },
 "checks": [
  {
   "id": "bucket_name",
   "kind": "attr",
   "select": "bucket",
   "tier": "core",
   "quote": "using variables to define the bucket name defaulting to \"benchmark-bucket-tf5x\"",
   "cond": {
    "path": [
     "bucket"
    ],
    "op": "eq",
    "value": "benchmark-bucket-tf5x"
   }
  },
  {
   "id": "bucket_name_variable",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "benchmark-bucket-tf5x"
     }
    ]
   },
   "tier": "detail",
   "quote": "using variables to define the bucket name defaulting to \"benchmark-bucket-tf5x\""
  },
  {
   "id": "bucket_name_tag",
   "kind": "any_of",
   "tier": "detail",
   "quote": "the Name tag defaulting to \"benchmark\"",
   "checks": [
    {
     "kind": "attr",
     "select": "bucket",
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "eq",
      "value": "benchmark"
     }
    },
    {
     "kind": "attr",
     "select": "bucket",
     "cond": {
      "path": [
       "tags_all",
       "Name"
      ],
      "op": "eq",
      "value": "benchmark"
     }
    }
   ]
  },
  {
   "id": "name_tag_variable",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "benchmark"
     }
    ]
   },
   "tier": "detail",
   "quote": "the Name tag defaulting to \"benchmark\""
  },
  {
   "id": "force_destroy",
   "kind": "attr",
   "select": "bucket",
   "cond": {
    "path": [
     "force_destroy"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "a boolean flag to enable forced destruction by default"
  },
  {
   "id": "force_destroy_variable",
   "kind": "exists",
   "select": {
    "types": [
     "__parameter__"
    ],
    "where": [
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": true
     },
     {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "(?i)(force|destr)"
     }
    ]
   },
   "tier": "detail",
   "quote": "a boolean flag to enable forced destruction by default"
  },
  {
   "id": "kms_key",
   "kind": "exists",
   "select": "kms",
   "tier": "core",
   "quote": "customer-managed KMS key"
  },
  {
   "id": "kms_rotation",
   "kind": "any_of",
   "tier": "core",
   "quote": "using a customer-managed KMS key with rotation enabled",
   "checks": [
    {
     "kind": "ref",
     "from": "sse",
     "to": "kms_rot"
    },
    {
     "kind": "ref",
     "from": "bucket",
     "to": "kms_rot"
    }
   ]
  },
  {
   "id": "sse_kms",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": "sse",
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
   ],
   "tier": "core",
   "quote": "default SSE-KMS server-side encryption"
  },
  {
   "id": "sse_uses_cmk",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "sse",
     "to": "kms"
    },
    {
     "kind": "ref",
     "from": "bucket",
     "to": "kms"
    }
   ],
   "tier": "core",
   "quote": "using a customer-managed KMS key"
  },
  {
   "id": "pab_exists",
   "kind": "exists",
   "select": "pab",
   "tier": "core",
   "quote": "have all bucket-level public access block settings enabled"
  },
  {
   "id": "pab_all_enabled",
   "kind": "all_of",
   "checks": [
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "block_public_acls"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "block_public_policy"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "ignore_public_acls"
      ],
      "op": "truthy"
     }
    },
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "restrict_public_buckets"
      ],
      "op": "truthy"
     }
    }
   ],
   "tier": "core",
   "quote": "have all bucket-level public access block settings enabled"
  },
  {
   "id": "pab_on_bucket",
   "kind": "ref",
   "from": "pab",
   "to": "bucket",
   "tier": "detail",
   "quote": "bucket-level public access block settings"
  },
  {
   "id": "account_pab",
   "kind": "exists",
   "select": "acct",
   "tier": "core",
   "quote": "the account-level S3 public access blocks"
  },
  {
   "id": "account_acls_disabled",
   "kind": "all_of",
   "tier": "core",
   "quote": "account-level S3 public access blocks for both ACLs and policies are explicitly disabled",
   "justify": "explicitly disabled means false",
   "checks": [
    {
     "kind": "attr",
     "select": "acct",
     "cond": {
      "path": [
       "block_public_acls"
      ],
      "op": "eq",
      "value": "false"
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
        "value": "aws_s3_account_public_access_block"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "block_public_acls"
      ],
      "op": "present"
     }
    }
   ]
  },
  {
   "id": "account_policy_disabled",
   "kind": "all_of",
   "tier": "core",
   "quote": "account-level S3 public access blocks for both ACLs and policies are explicitly disabled",
   "justify": "explicitly disabled means false",
   "checks": [
    {
     "kind": "attr",
     "select": "acct",
     "cond": {
      "path": [
       "block_public_policy"
      ],
      "op": "eq",
      "value": "false"
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
        "value": "aws_s3_account_public_access_block"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "block_public_policy"
      ],
      "op": "present"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
