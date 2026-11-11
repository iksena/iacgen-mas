package intent.tf.row_031

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "bucket",
   "tier": "core",
   "quote": "creates an Amazon S3 bucket for storing document I/O files",
   "kind": "exists",
   "select": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   }
  },
  {
   "id": "random_int",
   "tier": "core",
   "quote": "prefixing a random integer between 1 and 50000",
   "kind": "exists",
   "select": {
    "types": [
     "random_integer"
    ],
    "where": [
     {
      "path": [
       "min"
      ],
      "op": "eq",
      "value": 1
     },
     {
      "path": [
       "max"
      ],
      "op": "eq",
      "value": 50000
     }
    ]
   }
  },
  {
   "id": "bucket_uses_random",
   "tier": "core",
   "quote": "prefixing a random integer between 1 and 50000 to a base bucket name variable",
   "kind": "ref",
   "from": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   },
   "to": {
    "types": [
     "random_integer"
    ],
    "where": []
   }
  },
  {
   "id": "base_name_var",
   "tier": "detail",
   "quote": "a base bucket name variable that defaults to \"doc-io-files\"",
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
      "value": "doc-io-files"
     }
    ]
   }
  },
  {
   "id": "force_destroy",
   "tier": "core",
   "quote": "a boolean variable defaulting to true to control force destruction of the bucket",
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
   }
  },
  {
   "id": "force_destroy_var",
   "tier": "detail",
   "quote": "a boolean variable defaulting to true to control force destruction of the bucket",
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
      "value": "(?i)destr"
     }
    ]
   },
   "justify": "\"control force destruction\" names the variable's purpose"
  },
  {
   "id": "public_block",
   "tier": "core",
   "quote": "block all public access",
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
   "quote": "block all public access",
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
   "id": "sse_kms",
   "tier": "core",
   "quote": "enable default SSE-KMS encryption",
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
   "id": "cmk",
   "tier": "core",
   "quote": "with a customer-managed KMS key",
   "kind": "exists",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   }
  },
  {
   "id": "sse_uses_cmk",
   "tier": "core",
   "quote": "with a customer-managed KMS key",
   "kind": "any_of",
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
    },
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
       "aws_kms_alias"
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
       "aws_kms_alias"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "bucket_policy",
   "tier": "core",
   "quote": "attach a bucket policy",
   "kind": "exists",
   "select": {
    "types": [
     "aws_s3_bucket_policy"
    ],
    "where": []
   }
  },
  {
   "id": "bucket_policy_bucket",
   "tier": "core",
   "quote": "attach a bucket policy",
   "kind": "ref",
   "from": {
    "types": [
     "aws_s3_bucket_policy"
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
   "id": "policy_s3_all",
   "tier": "core",
   "quote": "grants full S3 access (\"s3:*\") to a specified AWS account ID",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "eq",
        "value": "s3:*"
       },
       {
        "path": [
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "regex",
        "value": "566373416292"
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
        "value": "data.aws_iam_policy_document"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "statement",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "actions",
         "*"
        ],
        "op": "eq",
        "value": "s3:*"
       },
       {
        "path": [
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "regex",
        "value": "566373416292|\\$\\{var\\."
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "contains",
        "value": "s3:*"
       },
       {
        "path": [],
        "op": "regex",
        "value": "566373416292"
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
      "op": "match",
      "value": [
       {
        "path": [],
        "op": "contains",
        "value": "s3:*"
       },
       {
        "path": [],
        "op": "regex",
        "value": "566373416292|\\$\\{var\\."
       }
      ]
     }
    }
   ]
  },
  {
   "id": "policy_account",
   "tier": "detail",
   "quote": "to a specified AWS account ID, which should default to \"566373416292\"",
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
         "default"
        ],
        "op": "eq",
        "value": "566373416292"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "566373416292"
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
      "op": "contains",
      "value": "566373416292"
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
      "op": "contains",
      "value": "566373416292"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement"
      ],
      "op": "contains",
      "value": "566373416292"
     }
    }
   ]
  },
  {
   "id": "policy_bucket_and_objects",
   "tier": "detail",
   "quote": "covering both the bucket itself and all objects contained within it",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "/*"
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
      "op": "contains",
      "value": "/*"
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
      "op": "contains",
      "value": "/*"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "statement"
      ],
      "op": "contains",
      "value": "/*"
     }
    }
   ]
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
