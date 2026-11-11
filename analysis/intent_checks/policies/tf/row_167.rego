package intent.tf.row_167

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
  "pab": {
   "types": [
    "aws_s3_bucket_public_access_block"
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
   "id": "bucket_default_name",
   "kind": "attr",
   "tier": "core",
   "quote": "The S3 bucket name must default to \"benchmark-access-logs-bkt\"",
   "select": "bucket",
   "cond": {
    "path": [
     "bucket"
    ],
    "op": "eq",
    "value": "benchmark-access-logs-bkt"
   }
  },
  {
   "id": "tag_environment",
   "kind": "attr",
   "tier": "detail",
   "quote": "an environment variable defaulting to \"Development\"",
   "select": "bucket",
   "cond": {
    "path": [
     "tags",
     "Environment"
    ],
    "op": "eq",
    "value": "Development"
   }
  },
  {
   "id": "tag_service_provider",
   "kind": "attr",
   "tier": "detail",
   "quote": "a ServiceProvider tag set to \"Rackspace\"",
   "select": "bucket",
   "cond": {
    "path": [
     "tags",
     "ServiceProvider"
    ],
    "op": "eq",
    "value": "Rackspace"
   }
  },
  {
   "id": "sse_default_aes256",
   "kind": "any_of",
   "tier": "core",
   "quote": "Server-side encryption must default to \"AES256\"",
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
      "value": "AES256"
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
   "id": "sse_none_disables",
   "kind": "any_of",
   "tier": "core",
   "quote": "unless the algorithm variable is set to \"none\" (which disables the encryption configuration resource)",
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
        "op": "regex",
        "value": "(^|[^A-Za-z_])none([^A-Za-z_]|$)"
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
        "value": "aws_s3_bucket_server_side_encryption_configuration"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(^|[^A-Za-z_])none([^A-Za-z_]|$)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "sse_kms_options",
   "kind": "any_of",
   "tier": "detail",
   "quote": "\"aws:kms\" with a KMS key ID and bucket key setting",
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
         "properties"
        ],
        "op": "regex",
        "value": "(?s)kms_master_key_id.*bucket_key_enabled|bucket_key_enabled.*kms_master_key_id"
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
         "server_side_encryption_configuration"
        ],
        "op": "regex",
        "value": "(?s)kms_master_key_id.*bucket_key_enabled|bucket_key_enabled.*kms_master_key_id"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "pab_all_true",
   "kind": "all_of",
   "tier": "core",
   "quote": "Public access block settings must be created by default, controlled by a boolean flag defaulting to true, with all four public block rules defaulting to true",
   "checks": [
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "block_public_acls"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "block_public_policy"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "ignore_public_acls"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
     "select": "pab",
     "cond": {
      "path": [
       "restrict_public_buckets"
      ],
      "op": "eq",
      "value": true
     }
    }
   ]
  },
  {
   "id": "pab_flag_gated",
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
      "value": "aws_s3_bucket_public_access_block"
     },
     {
      "path": [
       "gated"
      ],
      "op": "eq",
      "value": true
     }
    ]
   },
   "quote": "controlled by a boolean flag defaulting to true"
  },
  {
   "id": "acl_supported",
   "kind": "any_of",
   "tier": "core",
   "quote": "Canned ACLs or JSON-encoded grants must conditionally provision access control policies",
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
        "value": "aws_s3_bucket_acl"
       },
       {
        "path": [
         "gated"
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
         "dynamic",
         "grant"
        ],
        "op": "present"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "acl_canonical_user_fallback",
   "kind": "ref",
   "tier": "detail",
   "quote": "using the caller identity canonical user ID as the fallback owner",
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
      "value": "aws_s3_bucket_acl"
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
      "value": "data.aws_canonical_user_id"
     }
    ]
   }
  },
  {
   "id": "ownership_controls",
   "kind": "any_of",
   "tier": "core",
   "quote": "bucket ownership controls are conditionally managed when control_object_ownership is true",
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
        "value": "aws_s3_bucket_ownership_controls"
       },
       {
        "path": [
         "gated"
        ],
        "op": "eq",
        "value": true
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ownership_var",
   "kind": "exists",
   "tier": "detail",
   "quote": "when control_object_ownership is true (defaulting to false)",
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
      "value": "control_object_ownership"
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
   "id": "ownership_default_writer",
   "kind": "any_of",
   "tier": "detail",
   "quote": "object ownership defaulting to \"ObjectWriter\"",
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
        "value": "aws_s3_bucket_ownership_controls"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "ObjectWriter"
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
        "value": "ObjectWriter"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "logging_supported",
   "kind": "any_of",
   "tier": "core",
   "quote": "bucket logging conditionally targets specified log bucket names and prefixes when bucket_logging is true",
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
        "value": "aws_s3_bucket_logging"
       },
       {
        "path": [
         "gated"
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
         "dynamic",
         "logging"
        ],
        "op": "present"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "logging_var",
   "kind": "exists",
   "tier": "detail",
   "quote": "when bucket_logging is true",
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
      "value": "bucket_logging"
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
   "id": "object_lock_supported",
   "kind": "any_of",
   "tier": "core",
   "quote": "S3 Object Lock configuration defaults mode to \"GOVERNANCE\" when object_lock_enabled is set to true",
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
        "value": "aws_s3_bucket_object_lock_configuration"
       },
       {
        "path": [
         "gated"
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
         "dynamic",
         "object_lock_configuration"
        ],
        "op": "present"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "object_lock_governance",
   "kind": "any_of",
   "tier": "core",
   "quote": "defaults mode to \"GOVERNANCE\"",
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
        "value": "aws_s3_bucket_object_lock_configuration"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "GOVERNANCE"
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
        "value": "GOVERNANCE"
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
         "object_lock_configuration"
        ],
        "op": "regex",
        "value": "GOVERNANCE"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "object_lock_var",
   "kind": "exists",
   "tier": "detail",
   "quote": "when object_lock_enabled is set to true",
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
      "value": "object_lock_enabled"
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
   "id": "website_supported",
   "kind": "any_of",
   "tier": "core",
   "quote": "Static website hosting configuration",
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
         "dynamic",
         "website"
        ],
        "op": "present"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "tiering_supported",
   "kind": "exists",
   "tier": "core",
   "quote": "intelligent tiering",
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
      "value": "aws_s3_bucket_intelligent_tiering_configuration"
     },
     {
      "path": [
       "gated"
      ],
      "op": "eq",
      "value": true
     }
    ]
   }
  },
  {
   "id": "metrics_supported",
   "kind": "exists",
   "tier": "core",
   "quote": "CloudWatch metrics",
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
      "value": "aws_s3_bucket_metric"
     },
     {
      "path": [
       "gated"
      ],
      "op": "eq",
      "value": true
     }
    ]
   }
  },
  {
   "id": "cors_supported",
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
        "op": "eq",
        "value": "aws_s3_bucket_cors_configuration"
       },
       {
        "path": [
         "gated"
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
         "dynamic",
         "cors_rule"
        ],
        "op": "present"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "lifecycle_supported",
   "kind": "any_of",
   "tier": "core",
   "quote": "lifecycle configuration rules",
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
        "value": "aws_s3_bucket_lifecycle_configuration"
       },
       {
        "path": [
         "gated"
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
         "dynamic",
         "lifecycle_rule"
        ],
        "op": "present"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "lifecycle_abort_multipart",
   "kind": "any_of",
   "tier": "detail",
   "quote": "supporting incomplete multipart upload aborts",
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
        "value": "aws_s3_bucket_lifecycle_configuration"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "abort_incomplete_multipart_upload"
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
         "lifecycle_rule"
        ],
        "op": "regex",
        "value": "abort_incomplete_multipart_upload"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "lifecycle_expiration",
   "kind": "any_of",
   "tier": "detail",
   "quote": "expiration dates/days",
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
        "value": "aws_s3_bucket_lifecycle_configuration"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "expiration"
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
         "lifecycle_rule"
        ],
        "op": "regex",
        "value": "expiration"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "lifecycle_transition",
   "kind": "any_of",
   "tier": "detail",
   "quote": "version transitions",
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
        "value": "aws_s3_bucket_lifecycle_configuration"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "transition"
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
         "lifecycle_rule"
        ],
        "op": "regex",
        "value": "transition"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "x_force_destroy_off",
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
  },
  {
   "id": "x_bucket_key_off",
   "kind": "attr",
   "tier": "extra",
   "select": "sse",
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
   "id": "x_object_lock_off",
   "kind": "attr",
   "tier": "extra",
   "select": "bucket",
   "cond": {
    "path": [
     "object_lock_enabled"
    ],
    "op": "eq",
    "value": false
   }
  },
  {
   "id": "extra_type_aws_s3_bucket_versioning",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_s3_bucket_versioning"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
