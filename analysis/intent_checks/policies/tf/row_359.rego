package intent.tf.row_359

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "bucket",
   "kind": "exists",
   "select": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   },
   "tier": "core",
   "quote": "creates a private Amazon S3 bucket"
  },
  {
   "id": "force_destroy",
   "kind": "attr",
   "select": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "force_destroy"
    ],
    "op": "truthy"
   },
   "tier": "core",
   "quote": "that can be force-destroyed"
  },
  {
   "id": "bucket_name_generated",
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
       "bucket"
      ],
      "op": "absent"
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
       "bucket_prefix"
      ],
      "op": "present"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": []
     },
     "to": {
      "types": [
       "random_id",
       "random_pet",
       "random_string",
       "random_integer",
       "random_uuid"
      ],
      "where": []
     }
    }
   ],
   "tier": "detail",
   "quote": "with an auto-generated name",
   "justify": "auto-generated name means no fixed bucket name, a prefix or a random suffix"
  },
  {
   "id": "acl_private",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_acl"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "acl"
      ],
      "op": "eq",
      "value": "private"
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
       "acl"
      ],
      "op": "eq",
      "value": "private"
     }
    }
   ],
   "tier": "core",
   "quote": "a private canned ACL applied"
  },
  {
   "id": "public_access_block",
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
   ],
   "tier": "core",
   "quote": "with all four public access block settings enabled"
  },
  {
   "id": "versioning_enabled",
   "kind": "any_of",
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
      "op": "eq",
      "value": "Enabled"
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
       "versioning",
       "*",
       "enabled"
      ],
      "op": "truthy"
     }
    }
   ],
   "tier": "core",
   "quote": "versioning enabled with MFA delete disabled"
  },
  {
   "id": "mfa_delete_disabled",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
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
     },
     "cond": {
      "path": [
       "versioning_configuration",
       "*",
       "mfa_delete"
      ],
      "op": "none_eq",
      "value": "Enabled"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": [
       {
        "path": [
         "versioning",
         "*",
         "enabled"
        ],
        "op": "truthy"
       }
      ]
     },
     "cond": {
      "path": [
       "versioning",
       "*",
       "mfa_delete"
      ],
      "op": "none_eq",
      "value": "true"
     }
    }
   ],
   "tier": "detail",
   "quote": "versioning enabled with MFA delete disabled",
   "justify": "MFA delete disabled: mfa_delete not Enabled/true (omitted means disabled)"
  },
  {
   "id": "sse_aes256",
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
      "op": "eq",
      "value": "AES256"
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
      "op": "eq",
      "value": "AES256"
     }
    }
   ],
   "tier": "core",
   "quote": "default server-side encryption using S3-managed keys (AES256)"
  },
  {
   "id": "bucket_key_enabled",
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
       "bucket_key_enabled"
      ],
      "op": "truthy"
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
       "bucket_key_enabled"
      ],
      "op": "truthy"
     }
    }
   ],
   "tier": "detail",
   "quote": "with bucket keys enabled"
  },
  {
   "id": "ownership_bucket_owner_preferred",
   "kind": "attr",
   "select": {
    "types": [
     "aws_s3_bucket_ownership_controls"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "rule",
     "*",
     "object_ownership"
    ],
    "op": "eq",
    "value": "BucketOwnerPreferred"
   },
   "tier": "core",
   "quote": "object ownership set to \"BucketOwnerPreferred\""
  },
  {
   "id": "acl_after_ownership",
   "kind": "ref",
   "from": {
    "types": [
     "aws_s3_bucket_acl"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_s3_bucket_ownership_controls"
    ],
    "where": []
   },
   "tier": "detail",
   "quote": "a private canned ACL applied after the ownership controls are in place",
   "justify": "ordering is expressed with depends_on or a reference to the ownership controls"
  },
  {
   "id": "x_ownership_bucket",
   "kind": "ref",
   "from": {
    "types": [
     "aws_s3_bucket_ownership_controls"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   },
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
