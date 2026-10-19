package intent.tf.row_363

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
  "user": {
   "types": [
    "aws_iam_user"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "endpoint-backup"
    }
   ]
  },
  "access_policy": {
   "types": [
    "aws_iam_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "endpoint-backup-bucket-read-write-access"
    }
   ]
  }
 },
 "checks": [
  {
   "id": "bucket_name_with_account_id",
   "kind": "any_of",
   "tier": "core",
   "quote": "named \"endpoint-backup\" followed by a hyphen and the current AWS account ID",
   "justify": "an AWS account ID is 12 digits; accept the resolved name or the account-id interpolation",
   "checks": [
    {
     "kind": "attr",
     "select": "bucket",
     "cond": {
      "path": [
       "bucket"
      ],
      "op": "regex",
      "value": "^endpoint-backup-[0-9]{12}$"
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
         "bucket"
        ],
        "op": "regex",
        "value": "(?i)endpoint-backup-.*account_id"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "public_access_blocked",
   "kind": "ref",
   "tier": "core",
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
   },
   "to": "bucket",
   "justify": "'all public access blocked' -> all four public-access-block flags true"
  },
  {
   "id": "transfer_acceleration_suspended",
   "kind": "any_of",
   "tier": "detail",
   "quote": "transfer acceleration suspended",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket_accelerate_configuration"
      ],
      "where": [
       {
        "path": [
         "status"
        ],
        "op": "eq",
        "value": "Suspended"
       }
      ]
     },
     "to": "bucket"
    },
    {
     "kind": "attr",
     "select": "bucket",
     "cond": {
      "path": [
       "acceleration_status"
      ],
      "op": "eq",
      "value": "Suspended"
     }
    }
   ]
  },
  {
   "id": "object_lock_disabled",
   "kind": "attr",
   "tier": "detail",
   "quote": "object lock disabled",
   "select": "bucket",
   "cond": {
    "path": [
     "object_lock_enabled"
    ],
    "op": "none_eq",
    "value": true
   }
  },
  {
   "id": "sse_aes256",
   "kind": "any_of",
   "tier": "core",
   "quote": "default server-side encryption using S3-managed keys (AES256)",
   "checks": [
    {
     "kind": "ref",
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
     },
     "to": "bucket"
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
   "id": "bucket_policy_attached",
   "kind": "ref",
   "tier": "core",
   "quote": "Attach a bucket policy",
   "from": {
    "types": [
     "aws_s3_bucket_policy"
    ],
    "where": []
   },
   "to": "bucket"
  },
  {
   "id": "deny_insecure_transport",
   "kind": "exists",
   "tier": "core",
   "quote": "denies insecure requests not made over TLS",
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
       "aws_s3_bucket_policy",
       "data.aws_iam_policy_document"
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
      "op": "regex",
      "value": "(?i)aws:SecureTransport|s3:TlsVersion"
     }
    ]
   },
   "justify": "'insecure requests not over TLS' -> a Deny conditioned on aws:SecureTransport or s3:TlsVersion"
  },
  {
   "id": "deny_tls_below_1_2",
   "kind": "exists",
   "tier": "detail",
   "quote": "not made over TLS 1.2 or higher",
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
       "aws_s3_bucket_policy",
       "data.aws_iam_policy_document"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?is)s3:TlsVersion.{0,300}?1\\.2|1\\.2.{0,300}?s3:TlsVersion"
     }
    ]
   },
   "justify": "'TLS 1.2 or higher' -> an s3:TlsVersion condition on 1.2"
  },
  {
   "id": "deny_compliance_lock_retention",
   "kind": "exists",
   "tier": "core",
   "quote": "denies uploads or retention changes that would place objects in compliance-mode lock",
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
       "aws_s3_bucket_policy",
       "data.aws_iam_policy_document"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)s3:object-lock-remaining-retention-days|s3:object-lock-retain-until-date"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)compliance"
     }
    ]
   },
   "justify": "'compliance-mode lock for more than N days' -> a deny on the object-lock retention condition keys with mode COMPLIANCE"
  },
  {
   "id": "compliance_lock_90_days",
   "kind": "any_of",
   "tier": "detail",
   "quote": "for more than 90 days",
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
         "aws_s3_bucket_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?is)(retention-days|retain-until-date).{0,300}?\\b90|\\b90.{0,300}?(retention-days|retain-until-date)"
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
         "default"
        ],
        "op": "eq",
        "value": 90
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
         "aws_s3_bucket_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?is)retention-days.{0,300}?\\$\\{(var|local)\\."
       }
      ]
     }
    }
   ]
  },
  {
   "id": "iam_user",
   "kind": "exists",
   "tier": "core",
   "quote": "create an IAM user named \"endpoint-backup\"",
   "select": "user"
  },
  {
   "id": "iam_policy_named",
   "kind": "exists",
   "tier": "core",
   "quote": "a customer-managed IAM policy named \"endpoint-backup-bucket-read-write-access\"",
   "select": "access_policy"
  },
  {
   "id": "policy_attached_to_user",
   "kind": "any_of",
   "tier": "core",
   "quote": "attached to that user",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment"
      ],
      "where": []
     },
     "to": "access_policy"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy_attachment"
      ],
      "where": [
       {
        "path": [
         "users",
         "*"
        ],
        "op": "eq",
        "value": "endpoint-backup"
       }
      ]
     },
     "to": "access_policy"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_policy_attachment"
      ],
      "where": []
     },
     "to": "access_policy"
    }
   ],
   "justify": "a user receives an attached policy directly or through a group it belongs to"
  },
  {
   "id": "attachment_targets_user",
   "kind": "any_of",
   "tier": "detail",
   "quote": "attached to that user",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user_policy_attachment"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "user"
      ],
      "op": "eq",
      "value": "endpoint-backup"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "to": "user"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_group_membership",
       "aws_iam_user_group_membership"
      ],
      "where": []
     },
     "to": "user"
    }
   ]
  },
  {
   "id": "grants_list_read_write_delete",
   "kind": "exists",
   "tier": "core",
   "quote": "granting list, read, write, delete",
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
       "data.aws_iam_policy_document"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "s3:(ListBucket|List\\*|\\*)"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "s3:(GetObject|Get\\*|\\*)"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "s3:(PutObject|Put\\*|\\*)"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "s3:(DeleteObject|Delete\\*|\\*)"
     }
    ]
   },
   "justify": "list/read/write/delete -> s3:ListBucket, GetObject, PutObject, DeleteObject (or covering wildcards)"
  },
  {
   "id": "grants_version_retention_restore",
   "kind": "exists",
   "tier": "detail",
   "quote": "version, retention, and restore access to this bucket",
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
       "data.aws_iam_policy_document"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "s3:([A-Za-z]*Version|\\*)"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "s3:([A-Za-z]*Retention|\\*)"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "s3:(RestoreObject|\\*)"
     }
    ]
   },
   "justify": "version/retention/restore -> s3:*Version*, s3:*Retention, s3:RestoreObject (or s3:*)"
  },
  {
   "id": "grants_kms_decrypt_datakey",
   "kind": "exists",
   "tier": "detail",
   "quote": "decrypt/data-key access",
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
       "data.aws_iam_policy_document"
      ]
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "kms:(Decrypt|\\*)"
     },
     {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "kms:(GenerateDataKey|\\*)"
     }
    ]
   },
   "justify": "decrypt/data-key -> kms:Decrypt and kms:GenerateDataKey*"
  },
  {
   "id": "aws_managed_s3_kms_key",
   "kind": "any_of",
   "tier": "detail",
   "quote": "on the AWS-managed S3 KMS key",
   "justify": "the AWS-managed S3 KMS key is alias/aws/s3",
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
        "value": "data.aws_kms_key"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "alias/aws/s3"
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
        "value": "data.aws_kms_alias"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "alias/aws/s3"
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
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "alias/aws/s3"
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
