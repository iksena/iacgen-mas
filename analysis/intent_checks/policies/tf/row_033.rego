package intent.tf.row_033

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "bucket",
   "tier": "core",
   "quote": "a KMS-encrypted, versioned S3 bucket",
   "kind": "exists",
   "select": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   }
  },
  {
   "id": "versioned",
   "tier": "core",
   "quote": "versioned S3 bucket",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": []
     },
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
      "op": "eq",
      "value": "Enabled"
     }
    }
   ]
  },
  {
   "id": "kms_encrypted",
   "tier": "core",
   "quote": "KMS-encrypted",
   "kind": "any_of",
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
      "op": "regex",
      "value": "^aws:kms"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": []
     },
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
      "op": "regex",
      "value": "^aws:kms"
     }
    }
   ]
  },
  {
   "id": "public_block",
   "tier": "core",
   "quote": "with all public access blocked",
   "kind": "all_of",
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
      "op": "truthy"
     }
    },
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
       "block_public_policy"
      ],
      "op": "truthy"
     }
    },
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
       "ignore_public_acls"
      ],
      "op": "truthy"
     }
    },
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
       "restrict_public_buckets"
      ],
      "op": "truthy"
     }
    }
   ]
  },
  {
   "id": "public_block_bucket",
   "tier": "core",
   "quote": "with all public access blocked",
   "kind": "ref",
   "from": {
    "types": [
     "aws_s3_bucket_public_access_block"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   }
  },
  {
   "id": "lock_table",
   "tier": "core",
   "quote": "a DynamoDB table with a string hash key named \"LockID\" for state locking",
   "kind": "exists",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": []
   }
  },
  {
   "id": "hash_key",
   "tier": "core",
   "quote": "a string hash key named \"LockID\"",
   "kind": "attr",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "hash_key"
    ],
    "op": "eq",
    "value": "LockID"
   }
  },
  {
   "id": "hash_key_string",
   "tier": "core",
   "quote": "a string hash key named \"LockID\"",
   "kind": "attr",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "attribute",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "LockID"
     },
     {
      "path": [
       "type"
      ],
      "op": "eq",
      "value": "S"
     }
    ]
   }
  },
  {
   "id": "x_billing_on_demand",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "billing_mode"
    ],
    "op": "eq",
    "value": "PAY_PER_REQUEST"
   }
  },
  {
   "id": "extra_type_aws_kms_key",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
