package intent.tf.row_060

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "bucket",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   },
   "quote": "creates a customizable S3 bucket"
  },
  {
   "id": "bucket_name_param",
   "kind": "any_of",
   "tier": "detail",
   "quote": "standard parameters for the bucket name",
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
      "value": "var\\.|local\\."
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
      "value": "var\\.|local\\."
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
        "value": "(?i)bucket_?name|^bucket$"
       }
      ]
     }
    }
   ],
   "justify": "'accept standard parameters' means the setting comes from an input (var/local reference) or a variable named for it"
  },
  {
   "id": "object_lock_param",
   "kind": "any_of",
   "tier": "detail",
   "quote": "object lock status",
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
       "object_lock_enabled"
      ],
      "op": "regex",
      "value": "var\\.|local\\."
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
        "value": "(?i)object_?lock"
       }
      ]
     }
    }
   ],
   "justify": "'accept standard parameters' means the setting comes from an input (var/local reference) or a variable named for it"
  },
  {
   "id": "tags_param",
   "kind": "any_of",
   "tier": "detail",
   "quote": "resource tags",
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
       "tags"
      ],
      "op": "regex",
      "value": "var\\.|local\\."
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
        "value": "(?i)tags"
       }
      ]
     }
    }
   ],
   "justify": "'accept standard parameters' means the setting comes from an input (var/local reference) or a variable named for it"
  },
  {
   "id": "force_destroy_default",
   "kind": "all_of",
   "tier": "core",
   "quote": "a force destroy option that defaults to false to prevent accidental deletion of non-empty buckets",
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
        "value": "(?i)force"
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
      "value": "^false$|var\\.|local\\."
     }
    }
   ]
  },
  {
   "id": "block_public_access",
   "kind": "all_of",
   "tier": "core",
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
   "quote": "the bucket must block all public access"
  },
  {
   "id": "pab_on_bucket",
   "kind": "ref",
   "tier": "core",
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
   },
   "quote": "the bucket must block all public access"
  },
  {
   "id": "kms_key",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "quote": "a dedicated customer-managed KMS key"
  },
  {
   "id": "default_encryption_kms",
   "kind": "any_of",
   "tier": "core",
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
       "properties"
      ],
      "op": "regex",
      "value": "aws:kms"
     }
    }
   ],
   "quote": "use default encryption with a dedicated customer-managed KMS key"
  },
  {
   "id": "encryption_uses_cmk",
   "kind": "any_of",
   "tier": "core",
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
     "from": {
      "types": [
       "aws_s3_bucket"
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
   "quote": "use default encryption with a dedicated customer-managed KMS key"
  },
  {
   "id": "encryption_on_bucket",
   "kind": "ref",
   "tier": "core",
   "from": {
    "types": [
     "aws_s3_bucket_server_side_encryption_configuration"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   },
   "quote": "use default encryption"
  },
  {
   "id": "bucket_policy_declared",
   "kind": "exists",
   "tier": "core",
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
   "quote": "dynamically creating and attaching bucket policy documents"
  },
  {
   "id": "policy_document",
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
      "value": "data.aws_iam_policy_document"
     }
    ]
   },
   "quote": "dynamically creating and attaching bucket policy documents"
  },
  {
   "id": "policy_conditional",
   "kind": "any_of",
   "tier": "core",
   "quote": "only when policies are provided",
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
       "count"
      ],
      "op": "present"
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
       "for_each"
      ],
      "op": "present"
     }
    }
   ],
   "justify": "created only when provided means a count/for_each-gated bucket policy"
  },
  {
   "id": "policy_on_bucket",
   "kind": "ref",
   "tier": "core",
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
   "to": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   },
   "quote": "attaching bucket policy documents"
  },
  {
   "id": "policy_uses_document",
   "kind": "any_of",
   "tier": "detail",
   "quote": "dynamically creating and attaching bucket policy documents",
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
      "value": "jsonencode"
     }
    }
   ],
   "justify": "a policy document built in-template: an aws_iam_policy_document reference or an inline jsonencode() document"
  },
  {
   "id": "stmt_sid",
   "kind": "any_of",
   "tier": "detail",
   "quote": "defined SID",
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
        "value": "\"sid\""
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
      "value": "jsonencode(?s).*\\bSid\\b"
     }
    }
   ]
  },
  {
   "id": "stmt_actions",
   "kind": "any_of",
   "tier": "detail",
   "quote": "actions",
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
        "value": "\"actions\""
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
      "value": "jsonencode(?s).*\\bAction\\b"
     }
    }
   ]
  },
  {
   "id": "stmt_effect",
   "kind": "any_of",
   "tier": "detail",
   "quote": "effect",
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
        "value": "\"effect\""
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
      "value": "jsonencode(?s).*\\bEffect\\b"
     }
    }
   ]
  },
  {
   "id": "stmt_resources",
   "kind": "any_of",
   "tier": "detail",
   "quote": "resources",
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
        "value": "\"resources\""
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
      "value": "jsonencode(?s).*\\bResource\\b"
     }
    }
   ]
  },
  {
   "id": "stmt_principals",
   "kind": "any_of",
   "tier": "detail",
   "quote": "principals",
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
        "value": "\"principals\""
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
      "value": "jsonencode(?s).*\\bPrincipal\\b"
     }
    }
   ]
  },
  {
   "id": "policy_id_version",
   "kind": "any_of",
   "tier": "detail",
   "quote": "policy identifiers, versions",
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
        "value": "(?s)\"policy_id\".*\"version\""
       }
      ]
     }
    }
   ]
  },
  {
   "id": "kms_rotation",
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
     "enable_key_rotation"
    ],
    "op": "truthy"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
