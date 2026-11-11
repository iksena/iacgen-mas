package intent.tf.row_149

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "B": {
   "types": [
    "aws_s3_bucket"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "buckets_force_destroy",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": [
     {
      "path": [
       "force_destroy"
      ],
      "op": "eq",
      "value": true
     }
    ]
   },
   "quote": "The primary bucket must be constructed with force_destroy enabled",
   "min": 2,
   "justify": "primary and logging buckets both force-destroy (second bucket is the logging bucket)"
  },
  {
   "id": "main_prefix_from_name",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": "B",
     "cond": {
      "path": [
       "bucket_prefix"
      ],
      "op": "regex",
      "value": "(?i)^sadcloud"
     }
    },
    {
     "kind": "attr",
     "select": "B",
     "cond": {
      "path": [
       "bucket"
      ],
      "op": "regex",
      "value": "(?i)^sadcloud"
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
        "value": "aws_s3_bucket"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "bucket_prefix"
      ],
      "op": "regex",
      "value": "var\\.name"
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
        "value": "aws_s3_bucket"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "bucket"
      ],
      "op": "regex",
      "value": "var\\.name|sadcloud"
     }
    }
   ],
   "quote": "a prefix derived from the name variable"
  },
  {
   "id": "ownership_both",
   "kind": "exists",
   "tier": "core",
   "select": {
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
      "value": "BucketOwnerPreferred"
     }
    ]
   },
   "quote": "object ownership set to \"BucketOwnerPreferred\"",
   "min": 2,
   "justify": "primary and logging buckets both state BucketOwnerPreferred"
  },
  {
   "id": "main_acl_private",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket_acl"
      ],
      "where": [
       {
        "path": [
         "acl"
        ],
        "op": "eq",
        "value": "private"
       }
      ]
     },
     "to": "B"
    },
    {
     "kind": "attr",
     "select": "B",
     "cond": {
      "path": [
       "acl"
      ],
      "op": "eq",
      "value": "private"
     }
    }
   ],
   "quote": "a private ACL"
  },
  {
   "id": "main_versioning",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
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
     },
     "to": "B"
    },
    {
     "kind": "attr",
     "select": "B",
     "cond": {
      "path": [
       "versioning",
       "*",
       "enabled"
      ],
      "op": "eq",
      "value": true
     }
    }
   ],
   "quote": "versioning enabled by default unless a boolean variable no_versioning (defaulting to false) is set to true"
  },
  {
   "id": "versioning_toggle",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "aws_s3_bucket_versioning"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "no_versioning"
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
        "value": "aws_s3_bucket_versioning"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "no_versioning"
       }
      ]
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
        "value": "aws_s3_bucket"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "no_versioning"
     }
    }
   ],
   "quote": "unless a boolean variable no_versioning (defaulting to false) is set to true"
  },
  {
   "id": "buckets_public_blocked",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_bucket_public_access_block"
      ],
      "where": [
       {
        "path": [
         "block_public_acls"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "block_public_policy"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "ignore_public_acls"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "restrict_public_buckets"
        ],
        "op": "eq",
        "value": true
       }
      ]
     },
     "min": 2
    }
   ],
   "quote": "The main bucket must have all public access blocked",
   "justify": "primary and logging buckets both block all public access"
  },
  {
   "id": "kms_encryption_both",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
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
     },
     "min": 2
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
     },
     "min": 2
    }
   ],
   "quote": "server-side encryption using a dedicated customer-managed KMS key",
   "justify": "primary and logging buckets each encrypted with aws:kms"
  },
  {
   "id": "kms_key_rotation",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "enable_key_rotation"
        ],
        "op": "eq",
        "value": true
       }
      ]
     },
     "min": 2
    }
   ],
   "quote": "a dedicated customer-managed KMS key with automatic rotation",
   "justify": "a rotating key for the primary and one for the logging bucket"
  },
  {
   "id": "sse_uses_rotating_key",
   "kind": "any_of",
   "tier": "core",
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
        "value": "aws:kms"
       }
      ]
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "enable_key_rotation"
        ],
        "op": "eq",
        "value": true
       }
      ]
     }
    },
    {
     "kind": "ref",
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
     },
     "to": {
      "types": [
       "aws_kms_key"
      ],
      "where": [
       {
        "path": [
         "enable_key_rotation"
        ],
        "op": "eq",
        "value": true
       }
      ]
     }
    }
   ],
   "quote": "server-side encryption using a dedicated customer-managed KMS key with automatic rotation"
  },
  {
   "id": "encryption_toggle",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "aws_s3_bucket_server_side_encryption_configuration"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "no_default_encryption"
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
        "value": "aws_kms_key"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "no_default_encryption"
       }
      ]
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
        "value": "aws_s3_bucket"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "no_default_encryption"
     }
    }
   ],
   "quote": "unless a boolean variable no_default_encryption (defaulting to false) disables it"
  },
  {
   "id": "website_conditional",
   "kind": "any_of",
   "tier": "core",
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
        "value": "aws_s3_bucket_website_configuration"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "website_enabled"
       }
      ]
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
        "value": "aws_s3_bucket"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "website_enabled"
     }
    }
   ],
   "quote": "static website hosting with index document \"index.html\" must be conditionally configured based on a website_enabled boolean variable (defaulting to false)"
  },
  {
   "id": "website_index",
   "kind": "any_of",
   "tier": "core",
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
        "value": "aws_s3_bucket_website_configuration"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "index\\.html"
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
        "value": "aws_s3_bucket"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "index\\.html"
     }
    }
   ],
   "quote": "static website hosting with index document \"index.html\""
  },
  {
   "id": "logging_targets_bucket",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket_logging"
      ],
      "where": []
     },
     "to": "B"
    }
   ],
   "quote": "Logging for the main bucket must target a separate, force-destroy-enabled logging bucket"
  },
  {
   "id": "separate_logging_bucket",
   "kind": "exists",
   "tier": "core",
   "select": "B",
   "quote": "Logging for the main bucket must target a separate, force-destroy-enabled logging bucket",
   "min": 2,
   "justify": "main bucket plus a separate logging bucket"
  },
  {
   "id": "logging_bucket_name",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": "B",
     "cond": {
      "path": [
       "bucket"
      ],
      "op": "regex",
      "value": "(?i)-logging"
     }
    },
    {
     "kind": "attr",
     "select": "B",
     "cond": {
      "path": [
       "bucket_prefix"
      ],
      "op": "regex",
      "value": "(?i)-logging"
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
        "value": "aws_s3_bucket"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "bucket"
      ],
      "op": "regex",
      "value": "(?i)logging"
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
        "value": "aws_s3_bucket"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "bucket_prefix"
      ],
      "op": "regex",
      "value": "(?i)logging"
     }
    }
   ],
   "quote": "named using the name value followed by the suffix \"-logging\""
  },
  {
   "id": "logging_acl",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket_acl"
      ],
      "where": [
       {
        "path": [
         "acl"
        ],
        "op": "eq",
        "value": "log-delivery-write"
       }
      ]
     },
     "to": "B"
    },
    {
     "kind": "attr",
     "select": "B",
     "cond": {
      "path": [
       "acl"
      ],
      "op": "eq",
      "value": "log-delivery-write"
     }
    }
   ],
   "quote": "canned ACL defaulting to \"log-delivery-write\" (as defined by a bucket_acl variable)"
  },
  {
   "id": "no_logging_toggle",
   "kind": "any_of",
   "tier": "core",
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
        "value": "aws_s3_bucket"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "no_logging"
       }
      ]
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
        "value": "aws_s3_bucket"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "no_logging"
     }
    }
   ],
   "quote": "both of which are omitted if a no_logging boolean variable (defaulting to false) is set to true"
  },
  {
   "id": "cleartext_policy_conditional",
   "kind": "any_of",
   "tier": "core",
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
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "allow_cleartext"
       }
      ]
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
        "value": "aws_s3_bucket_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "allow_cleartext"
     }
    }
   ],
   "quote": "when an allow_cleartext boolean variable (defaulting to false) is true, attach an S3 bucket policy to the main bucket"
  },
  {
   "id": "cleartext_policy_deny",
   "kind": "any_of",
   "tier": "core",
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
        "value": "aws_s3_bucket_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)(Effect\\W{1,6}Deny.{0,500}SecureTransport\\W{1,8}false|SecureTransport\\W{1,8}false.{0,500}Effect\\W{1,6}Deny)"
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?is)(Effect\\W{1,6}Deny.{0,500}SecureTransport\\W{1,8}false|SecureTransport\\W{1,8}false.{0,500}Effect\\W{1,6}Deny)"
     }
    }
   ],
   "quote": "explicitly denies all s3:* actions over non-SSL transport (\"aws:SecureTransport\" equal to \"false\")"
  },
  {
   "id": "cleartext_policy_s3_all",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "aws_s3_bucket_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)s3:\\*.{0,600}SecureTransport|SecureTransport.{0,600}s3:\\*"
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?is)s3:\\*.{0,600}SecureTransport|SecureTransport.{0,600}s3:\\*"
     }
    }
   ],
   "quote": "explicitly denies all s3:* actions"
  },
  {
   "id": "cleartext_policy_on_main",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "aws_s3_bucket_policy"
       }
      ]
     },
     "to": "B"
    }
   ],
   "quote": "attach an S3 bucket policy to the main bucket"
  },
  {
   "id": "getonly_bucket",
   "kind": "any_of",
   "tier": "core",
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
        "value": "aws_s3_bucket"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "s3_getobject_only"
       }
      ]
     }
    }
   ],
   "quote": "one for public read-only access (s3_getobject_only defaulting to false) named using the name value followed by the suffix \"-getonly\""
  },
  {
   "id": "getonly_bucket_name",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "aws_s3_bucket"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "s3_getobject_only"
       },
       {
        "path": [
         "properties",
         "bucket"
        ],
        "op": "regex",
        "value": "(?i)getonly"
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
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "s3_getobject_only"
       },
       {
        "path": [
         "properties",
         "bucket_prefix"
        ],
        "op": "regex",
        "value": "(?i)getonly"
       }
      ]
     }
    }
   ],
   "quote": "named using the name value followed by the suffix \"-getonly\"",
   "justify": "suffix -getonly is stated"
  },
  {
   "id": "getonly_public_access_block_disabled",
   "kind": "any_of",
   "tier": "core",
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
        "value": "aws_s3_bucket_public_access_block"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "s3_getobject_only"
       },
       {
        "path": [
         "properties",
         "block_public_acls"
        ],
        "op": "eq",
        "value": false
       },
       {
        "path": [
         "properties",
         "block_public_policy"
        ],
        "op": "eq",
        "value": false
       },
       {
        "path": [
         "properties",
         "ignore_public_acls"
        ],
        "op": "eq",
        "value": false
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "restrict_public_buckets"
      ],
      "op": "eq",
      "value": false
     }
    }
   ],
   "quote": "optional secondary buckets with public access block restrictions completely disabled"
  },
  {
   "id": "getonly_policy",
   "kind": "any_of",
   "tier": "core",
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
        "value": "aws_s3_bucket_policy"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "s3_getobject_only"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "s3:GetObject"
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
        "value": "aws_s3_bucket_policy"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "s3_getobject_only"
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
        "value": "s3:GetObject"
       }
      ]
     }
    }
   ],
   "quote": "and an s3:GetObject policy"
  },
  {
   "id": "public_bucket",
   "kind": "any_of",
   "tier": "core",
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
        "value": "aws_s3_bucket"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "s3_public"
       }
      ]
     }
    }
   ],
   "quote": "another for full public read-write access (s3_public defaulting to false) named using the name value followed by the suffix \"-public\""
  },
  {
   "id": "public_bucket_name",
   "kind": "any_of",
   "tier": "detail",
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
        "value": "aws_s3_bucket"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "s3_public"
       },
       {
        "path": [
         "properties",
         "bucket"
        ],
        "op": "regex",
        "value": "(?i)public"
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
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "s3_public"
       },
       {
        "path": [
         "properties",
         "bucket_prefix"
        ],
        "op": "regex",
        "value": "(?i)public"
       }
      ]
     }
    }
   ],
   "quote": "named using the name value followed by the suffix \"-public\"",
   "justify": "suffix -public is stated"
  },
  {
   "id": "public_public_access_block_disabled",
   "kind": "any_of",
   "tier": "core",
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
        "value": "aws_s3_bucket_public_access_block"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "s3_public"
       },
       {
        "path": [
         "properties",
         "block_public_acls"
        ],
        "op": "eq",
        "value": false
       },
       {
        "path": [
         "properties",
         "block_public_policy"
        ],
        "op": "eq",
        "value": false
       },
       {
        "path": [
         "properties",
         "ignore_public_acls"
        ],
        "op": "eq",
        "value": false
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "restrict_public_buckets"
      ],
      "op": "eq",
      "value": false
     }
    }
   ],
   "quote": "optional secondary buckets with public access block restrictions completely disabled"
  },
  {
   "id": "public_policy",
   "kind": "any_of",
   "tier": "core",
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
        "value": "aws_s3_bucket_policy"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "s3_public"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)Allow.{0,300}s3:\\*|s3:\\*.{0,300}Allow"
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
        "value": "aws_s3_bucket_policy"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "gate"
        ],
        "op": "contains",
        "value": "s3_public"
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
        "value": "s3:\\*"
       }
      ]
     }
    }
   ],
   "quote": "and an s3:* policy"
  },
  {
   "id": "param_name",
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
      "value": "name"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "sadcloud"
     }
    ]
   },
   "quote": "a configurable name variable defaulting to \"sadcloud\""
  },
  {
   "id": "param_no_versioning",
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
      "value": "no_versioning"
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
   "quote": "a boolean variable no_versioning (defaulting to false)"
  },
  {
   "id": "param_no_default_encryption",
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
      "value": "no_default_encryption"
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
   "quote": "a boolean variable no_default_encryption (defaulting to false)"
  },
  {
   "id": "param_website_enabled",
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
      "value": "website_enabled"
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
   "quote": "a website_enabled boolean variable (defaulting to false)"
  },
  {
   "id": "param_bucket_acl",
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
      "value": "bucket_acl"
     },
     {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "log-delivery-write"
     }
    ]
   },
   "quote": "canned ACL defaulting to \"log-delivery-write\" (as defined by a bucket_acl variable)"
  },
  {
   "id": "param_no_logging",
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
      "value": "no_logging"
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
   "quote": "a no_logging boolean variable (defaulting to false)"
  },
  {
   "id": "param_allow_cleartext",
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
      "value": "allow_cleartext"
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
   "quote": "an allow_cleartext boolean variable (defaulting to false)"
  },
  {
   "id": "param_getobject",
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
      "value": "s3_getobject_only"
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
   "quote": "s3_getobject_only defaulting to false"
  },
  {
   "id": "param_public",
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
      "value": "s3_public"
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
   "quote": "s3_public defaulting to false"
  },
  {
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
   "id": "main_acl_after_ownership",
   "tier": "extra"
  },
  {
   "kind": "attr",
   "select": {
    "types": [
     "aws_s3_bucket_logging"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "target_prefix"
    ],
    "op": "present"
   },
   "id": "logging_target_prefix",
   "tier": "extra"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
