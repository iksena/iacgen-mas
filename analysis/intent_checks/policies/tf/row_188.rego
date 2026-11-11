package intent.tf.row_188

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
  "sse": {
   "types": [
    "aws_s3_bucket_server_side_encryption_configuration"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "bucket",
   "kind": "exists",
   "tier": "core",
   "quote": "creates a highly configurable S3 bucket for general-purpose use",
   "select": "bucket"
  },
  {
   "id": "pab_all",
   "kind": "any_of",
   "tier": "core",
   "quote": "always blocking all public access to the bucket",
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
   "tier": "core",
   "quote": "always blocking all public access to the bucket",
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
   "tier": "core",
   "quote": "always blocking all public access to the bucket",
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
   "tier": "core",
   "quote": "always blocking all public access to the bucket",
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
   "id": "pab_ref",
   "kind": "ref",
   "tier": "core",
   "quote": "always blocking all public access to the bucket",
   "from": {
    "types": [
     "aws_s3_bucket_public_access_block"
    ],
    "where": []
   },
   "to": "bucket"
  },
  {
   "id": "versioning_enabled",
   "kind": "any_of",
   "tier": "core",
   "quote": "enabling versioning and server-side encryption by default",
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
     "select": "bucket",
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
   ]
  },
  {
   "id": "sse_kms_default",
   "kind": "any_of",
   "tier": "core",
   "quote": "KMS encryption using a dedicated customer-managed KMS key",
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
        "value": "aws_s3_bucket_server_side_encryption_configuration"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "rule",
       "*",
       "apply_server_side_encryption_by_default",
       "*",
       "sse_algorithm"
      ],
      "op": "regex",
      "value": "aws:kms"
     }
    }
   ]
  },
  {
   "id": "kms_key",
   "kind": "exists",
   "tier": "core",
   "quote": "a dedicated customer-managed KMS key with automatic rotation created by the template",
   "select": "key"
  },
  {
   "id": "kms_rotation",
   "kind": "attr",
   "tier": "core",
   "quote": "with automatic rotation",
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
   "id": "sse_uses_key",
   "kind": "any_of",
   "tier": "core",
   "quote": "KMS encryption using a dedicated customer-managed KMS key",
   "checks": [
    {
     "kind": "ref",
     "from": "sse",
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
   "id": "kms_key_conditional",
   "kind": "attr",
   "tier": "detail",
   "quote": "created by the template unless a key ID is supplied",
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
     "gated"
    ],
    "op": "eq",
    "value": true
   }
  },
  {
   "id": "sse_aes256_fallback",
   "kind": "any_of",
   "tier": "detail",
   "quote": "or AES256 when KMS is disabled",
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
        "op": "in",
        "value": [
         "aws_s3_bucket_server_side_encryption_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "AES256"
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
        "value": "AES256"
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
        "op": "in",
        "value": [
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "contains",
      "value": "AES256"
     }
    }
   ]
  },
  {
   "id": "lifecycle",
   "kind": "any_of",
   "tier": "core",
   "quote": "lifecycle configuration rules for transitions to STANDARD_IA, GLACIER, and DEEP_ARCHIVE as well as expiration and noncurrent version handling",
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
         "aws_s3_bucket_lifecycle_configuration"
        ]
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
        "op": "in",
        "value": [
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "lifecycle_rule"
     }
    }
   ]
  },
  {
   "id": "lifecycle_standard_ia",
   "kind": "any_of",
   "tier": "detail",
   "quote": "transitions to STANDARD_IA, GLACIER, and DEEP_ARCHIVE",
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
        "op": "in",
        "value": [
         "aws_s3_bucket_lifecycle_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "STANDARD_IA"
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
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "STANDARD_IA"
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
        "op": "regex",
        "value": "STANDARD_IA"
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
        "op": "in",
        "value": [
         "aws_s3_bucket_lifecycle_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "storage_class\\W+\\$\\{(local|var|each|transition)"
     }
    }
   ]
  },
  {
   "id": "lifecycle_glacier",
   "kind": "any_of",
   "tier": "detail",
   "quote": "transitions to STANDARD_IA, GLACIER, and DEEP_ARCHIVE",
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
        "op": "in",
        "value": [
         "aws_s3_bucket_lifecycle_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "GLACIER"
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
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "GLACIER"
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
        "op": "regex",
        "value": "GLACIER"
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
        "op": "in",
        "value": [
         "aws_s3_bucket_lifecycle_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "storage_class\\W+\\$\\{(local|var|each|transition)"
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
        "value": "(?i)glacier"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "lifecycle_deep_archive",
   "kind": "any_of",
   "tier": "detail",
   "quote": "transitions to STANDARD_IA, GLACIER, and DEEP_ARCHIVE",
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
        "op": "in",
        "value": [
         "aws_s3_bucket_lifecycle_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "DEEP_ARCHIVE"
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
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "DEEP_ARCHIVE"
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
        "op": "regex",
        "value": "DEEP_ARCHIVE"
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
        "op": "in",
        "value": [
         "aws_s3_bucket_lifecycle_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "storage_class\\W+\\$\\{(local|var|each|transition)"
     }
    }
   ]
  },
  {
   "id": "lifecycle_expiration",
   "kind": "any_of",
   "tier": "detail",
   "quote": "as well as expiration and noncurrent version handling",
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
        "op": "in",
        "value": [
         "aws_s3_bucket_lifecycle_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "\"expiration\""
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
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "\"expiration\""
     }
    }
   ]
  },
  {
   "id": "lifecycle_noncurrent",
   "kind": "any_of",
   "tier": "detail",
   "quote": "as well as expiration and noncurrent version handling",
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
        "op": "in",
        "value": [
         "aws_s3_bucket_lifecycle_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)noncurrent"
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
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)noncurrent"
     }
    }
   ]
  },
  {
   "id": "logging",
   "kind": "any_of",
   "tier": "core",
   "quote": "bucket logging to a separate target bucket",
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
        "op": "in",
        "value": [
         "aws_s3_bucket_logging"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "target_bucket"
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
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "target_bucket"
     }
    }
   ]
  },
  {
   "id": "website",
   "kind": "any_of",
   "tier": "core",
   "quote": "static website hosting with index and error documents and routing rules",
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
         "aws_s3_bucket_website_configuration"
        ]
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
        "op": "in",
        "value": [
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "website"
     }
    }
   ]
  },
  {
   "id": "website_index",
   "kind": "any_of",
   "tier": "detail",
   "quote": "static website hosting with index and error documents",
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
        "op": "in",
        "value": [
         "aws_s3_bucket_website_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "index_document"
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
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "index_document"
     }
    }
   ]
  },
  {
   "id": "website_error",
   "kind": "any_of",
   "tier": "detail",
   "quote": "static website hosting with index and error documents",
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
        "op": "in",
        "value": [
         "aws_s3_bucket_website_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "error_document"
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
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "error_document"
     }
    }
   ]
  },
  {
   "id": "website_routing",
   "kind": "any_of",
   "tier": "detail",
   "quote": "and routing rules",
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
        "op": "in",
        "value": [
         "aws_s3_bucket_website_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "routing_rule"
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
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "routing_rule"
     }
    }
   ]
  },
  {
   "id": "cors",
   "kind": "any_of",
   "tier": "core",
   "quote": "CORS rules",
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
         "aws_s3_bucket_cors_configuration"
        ]
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
        "op": "in",
        "value": [
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "cors_rule"
     }
    }
   ]
  },
  {
   "id": "object_lock",
   "kind": "any_of",
   "tier": "core",
   "quote": "object lock configuration with default retention",
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
         "aws_s3_bucket_object_lock_configuration"
        ]
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
        "op": "in",
        "value": [
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "object_lock"
     }
    }
   ]
  },
  {
   "id": "object_lock_retention",
   "kind": "any_of",
   "tier": "detail",
   "quote": "object lock configuration with default retention",
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
        "op": "in",
        "value": [
         "aws_s3_bucket_object_lock_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "default_retention"
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
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "default_retention"
     }
    }
   ]
  },
  {
   "id": "bucket_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "bucket policies via an IAM policy document",
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
         "aws_s3_bucket_policy"
        ]
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_bucket_policy"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "acceleration",
   "kind": "any_of",
   "tier": "core",
   "quote": "acceleration status",
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
         "aws_s3_bucket_accelerate_configuration"
        ]
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
        "op": "in",
        "value": [
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "acceleration_status"
     }
    }
   ]
  },
  {
   "id": "requester_pays",
   "kind": "any_of",
   "tier": "core",
   "quote": "requester pays",
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
        "op": "in",
        "value": [
         "aws_s3_bucket_request_payment_configuration"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)requester"
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
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?i)requester"
     }
    }
   ]
  },
  {
   "id": "acl",
   "kind": "any_of",
   "tier": "core",
   "quote": "fine-grained ACL grants or canned ACLs",
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
         "aws_s3_bucket_acl",
         "aws_s3_bucket_grant"
        ]
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
        "op": "in",
        "value": [
         "aws_s3_bucket"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "grant|acl"
     }
    }
   ]
  },
  {
   "id": "outputs",
   "kind": "all_of",
   "tier": "detail",
   "quote": "must output the bucket ID, ARN, domain name, and tags",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)(^|_)id$"
       }
      ]
     },
     "to": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)arn"
       }
      ]
     },
     "to": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)domain"
       }
      ]
     },
     "to": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": []
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "__output__"
      ],
      "where": [
       {
        "path": [
         "name"
        ],
        "op": "regex",
        "value": "(?i)tags?$"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_kms_deletion",
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
     "deletion_window_in_days"
    ],
    "op": "gte",
    "value": 1
   }
  },
  {
   "id": "x_force_destroy",
   "kind": "attr",
   "tier": "extra",
   "select": "bucket",
   "cond": {
    "path": [
     "force_destroy"
    ],
    "op": "eq",
    "value": false
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
