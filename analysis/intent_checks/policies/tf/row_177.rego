package intent.tf.row_177

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
  }
 },
 "checks": [
  {
   "id": "bucket",
   "kind": "exists",
   "tier": "core",
   "quote": "provisions a single bucket",
   "select": "bucket",
   "max": 1,
   "justify": "'a single bucket' means exactly one"
  },
  {
   "id": "auto_generated_name",
   "kind": "attr",
   "tier": "core",
   "quote": "with an automatically generated name",
   "select": "bucket",
   "cond": {
    "path": [
     "bucket"
    ],
    "op": "absent"
   }
  },
  {
   "id": "kms_key",
   "kind": "exists",
   "tier": "core",
   "quote": "using a new customer-managed KMS key",
   "select": "kms"
  },
  {
   "id": "kms_rotation",
   "kind": "attr",
   "tier": "core",
   "quote": "key rotation enabled",
   "select": "kms",
   "cond": {
    "path": [
     "enable_key_rotation"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "kms_deletion_window",
   "kind": "attr",
   "tier": "core",
   "quote": "a 7-day deletion window",
   "justify": "7-day stated",
   "select": "kms",
   "cond": {
    "path": [
     "deletion_window_in_days"
    ],
    "op": "eq",
    "value": 7
   }
  },
  {
   "id": "sse_kms",
   "tier": "core",
   "quote": "encrypts it by default with SSE-KMS",
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
   ]
  },
  {
   "id": "sse_uses_key",
   "tier": "core",
   "quote": "encrypts it by default with SSE-KMS using a new customer-managed KMS key",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": "sse",
     "to": "kms"
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
        "value": "aws_kms_key"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": "bucket",
     "to": "kms"
    }
   ]
  },
  {
   "id": "pab_block_public_acls",
   "kind": "attr",
   "tier": "core",
   "quote": "blocks public ACLs",
   "select": "pab",
   "cond": {
    "path": [
     "block_public_acls"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "pab_block_public_policy",
   "kind": "attr",
   "tier": "core",
   "quote": "and policies",
   "select": "pab",
   "cond": {
    "path": [
     "block_public_policy"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "pab_ignore_public_acls",
   "kind": "attr",
   "tier": "core",
   "quote": "ignores public ACLs",
   "select": "pab",
   "cond": {
    "path": [
     "ignore_public_acls"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "pab_restrict_public_buckets",
   "kind": "attr",
   "tier": "core",
   "quote": "restricts public buckets",
   "select": "pab",
   "cond": {
    "path": [
     "restrict_public_buckets"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "two_toggles_default_true",
   "tier": "detail",
   "quote": "two boolean toggles that both default to true",
   "kind": "all_of",
   "justify": "two toggles both defaulting to true",
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
        "value": true
       }
      ]
     },
     "min": 2
    }
   ]
  },
  {
   "id": "opt_object_lock",
   "kind": "exists",
   "tier": "detail",
   "quote": "object lock with default retention",
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
      "value": "(?i)default_retention"
     }
    ]
   }
  },
  {
   "id": "opt_acl",
   "kind": "exists",
   "tier": "detail",
   "quote": "a canned ACL or explicit ACL grants",
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
     }
    ]
   }
  },
  {
   "id": "opt_website",
   "kind": "exists",
   "tier": "detail",
   "quote": "static website hosting",
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
  },
  {
   "id": "opt_cors",
   "kind": "exists",
   "tier": "detail",
   "quote": "CORS rules",
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
  },
  {
   "id": "opt_versioning",
   "kind": "exists",
   "tier": "detail",
   "quote": "versioning",
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
   }
  },
  {
   "id": "opt_logging",
   "kind": "exists",
   "tier": "detail",
   "quote": "access logging to a target bucket",
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
  },
  {
   "id": "opt_accel",
   "kind": "exists",
   "tier": "detail",
   "quote": "transfer acceleration",
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
     }
    ]
   }
  },
  {
   "id": "opt_payer",
   "kind": "exists",
   "tier": "detail",
   "quote": "requester-pays configuration",
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
      "value": "aws_s3_bucket_request_payment_configuration"
     }
    ]
   }
  },
  {
   "id": "opt_lifecycle",
   "kind": "exists",
   "tier": "detail",
   "quote": "lifecycle rules",
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
  },
  {
   "id": "opt_replication",
   "kind": "exists",
   "tier": "detail",
   "quote": "cross-region replication",
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
  },
  {
   "id": "opt_tiering",
   "kind": "exists",
   "tier": "detail",
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
     }
    ]
   }
  },
  {
   "id": "opt_ownership",
   "kind": "exists",
   "tier": "detail",
   "quote": "object ownership controls defaulting to \"ObjectWriter\" when enabled",
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
     }
    ]
   }
  },
  {
   "id": "ownership_objectwriter",
   "tier": "detail",
   "quote": "defaulting to \"ObjectWriter\" when enabled",
   "kind": "any_of",
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
        "value": "aws_s3_bucket_ownership_controls"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "rule",
       "*",
       "object_ownership"
      ],
      "op": "eq",
      "value": "ObjectWriter"
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
   "id": "opt_custom_sse",
   "kind": "any_of",
   "tier": "detail",
   "quote": "a caller-supplied encryption configuration that replaces the default KMS encryption",
   "justify": "replacing the default means a second declared SSE configuration or a dynamic one",
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
        "value": "(?i)dynamic"
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
        "value": "(?i)var\\.[a-z_]*(encrypt|sse)"
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
       }
      ]
     },
     "min": 2
    }
   ]
  },
  {
   "id": "opt_force_destroy",
   "tier": "detail",
   "quote": "force destroy",
   "kind": "any_of",
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
        "op": "regex",
        "value": "(?i)force_destroy"
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
       "properties",
       "force_destroy"
      ],
      "op": "regex",
      "value": "\\$\\{"
     }
    }
   ]
  },
  {
   "id": "opt_bucket_name_prefix",
   "tier": "detail",
   "quote": "an explicit bucket name or name prefix",
   "kind": "any_of",
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
      "value": "var\\."
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
      "value": "var\\."
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
        "value": "(?i)^bucket(_name|_prefix)?$"
       }
      ]
     }
    }
   ],
   "justify": "an optional input means the name or prefix comes from a variable"
  },
  {
   "id": "bucket_policy",
   "kind": "exists",
   "tier": "core",
   "quote": "the module must build a combined bucket policy",
   "justify": "combined bucket policy",
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
   }
  },
  {
   "id": "policy_elb_logs",
   "tier": "core",
   "quote": "grant classic ELB and ALB/NLB access log delivery",
   "kind": "any_of",
   "justify": "classic ELB log delivery uses the ELB service account; ALB/NLB uses delivery.logs",
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
         "aws_s3_bucket_policy",
         "aws_iam_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(delivery\\.logs|elb_service_account|elasticloadbalancing)"
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
        "value": "data.aws_elb_service_account"
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
        "op": "regex",
        "value": "(?i)(^|_)(elb|alb|nlb|lb)_.*log"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_classic_elb",
   "tier": "detail",
   "quote": "classic ELB",
   "kind": "any_of",
   "justify": "classic ELB log delivery is granted to the regional ELB account",
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
        "value": "data.aws_elb_service_account"
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
         "aws_s3_bucket_policy",
         "aws_iam_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(elb_service_account|elasticloadbalancing\\.amazonaws|arn:aws[a-z-]*:iam::\\d+:root)"
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
        "op": "regex",
        "value": "(?i)(^|_)elb_.*log"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_alb_nlb",
   "tier": "detail",
   "quote": "ALB/NLB access log delivery",
   "kind": "any_of",
   "justify": "ALB/NLB log delivery principal is delivery.logs.amazonaws.com",
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
         "aws_s3_bucket_policy",
         "aws_iam_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(delivery\\.logs\\.amazonaws\\.com|logdelivery\\.elasticloadbalancing)"
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
        "op": "regex",
        "value": "(?i)(^|_)(alb|nlb|lb)_.*log"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_secure_transport",
   "tier": "detail",
   "quote": "deny any request made without secure transport",
   "kind": "any_of",
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
         "aws_s3_bucket_policy",
         "aws_iam_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "aws:SecureTransport"
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
        "op": "regex",
        "value": "(?i)(secure_?transport|insecure|https_only|ssl)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_tls12",
   "tier": "detail",
   "quote": "deny requests using TLS versions older than 1.2",
   "kind": "any_of",
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
         "aws_s3_bucket_policy",
         "aws_iam_policy"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "s3:TlsVersion"
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
        "op": "regex",
        "value": "(?i)tls"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_user_json",
   "tier": "core",
   "quote": "merge a user-supplied JSON policy",
   "kind": "any_of",
   "justify": "a user-supplied JSON policy arrives through a variable",
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
        "value": "data.aws_iam_policy_document"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)(source_policy_documents|override_policy_documents|source_json|override_json)"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "(?i)var\\.(policy|[a-z_]*(json|custom|user)[a-z_]*)\\b"
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
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)var\\.(policy|[a-z_]*(json|custom|user)[a-z_]*)\\b"
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
        "value": "(?i)(^policy$|policy_?json|json_?policy|custom_[a-z_]*policy|user_[a-z_]*policy)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "pab_after_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "applying the public access block and ownership controls only after the bucket policy",
   "justify": "ordering after the policy",
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
        "value": "aws_s3_bucket_public_access_block"
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
        "value": "aws_s3_bucket_policy"
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
        "value": "aws_s3_bucket_public_access_block"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "aws_s3_bucket_policy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "ownership_after_policy",
   "kind": "any_of",
   "tier": "core",
   "quote": "applying the public access block and ownership controls only after the bucket policy",
   "justify": "ordering after the policy",
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
        "value": "aws_s3_bucket_ownership_controls"
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
        "value": "aws_s3_bucket_policy"
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
        "value": "aws_s3_bucket_ownership_controls"
       },
       {
        "path": [
         "properties"
        ],
        "op": "regex",
        "value": "aws_s3_bucket_policy"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "force_destroy_off",
   "kind": "attr",
   "tier": "detail",
   "quote": "all disabled or empty by default",
   "select": "bucket",
   "cond": {
    "path": [
     "force_destroy"
    ],
    "op": "none_eq",
    "value": true
   }
  },
  {
   "id": "object_lock_off",
   "kind": "attr",
   "tier": "detail",
   "quote": "all disabled or empty by default",
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
   "id": "x_pab_bucket",
   "kind": "ref",
   "tier": "extra",
   "from": "pab",
   "to": "bucket"
  },
  {
   "id": "x_sse_bucket",
   "kind": "ref",
   "tier": "extra",
   "from": "sse",
   "to": "bucket"
  },
  {
   "id": "x_ownership_pab",
   "kind": "ref",
   "tier": "extra",
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
      "value": "aws_s3_bucket_ownership_controls"
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
      "value": "aws_s3_bucket_public_access_block"
     }
    ]
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
