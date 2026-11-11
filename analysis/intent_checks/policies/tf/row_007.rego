package intent.tf.row_007

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "buckets_seven",
   "tier": "core",
   "quote": "one standalone bucket with the suffix \"bucket2\", two count-based buckets",
   "kind": "exists",
   "select": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   },
   "min": 7,
   "justify": "1 + 2 + 4 buckets are enumerated"
  },
  {
   "id": "bucket2_name",
   "tier": "core",
   "quote": "one standalone bucket with the suffix \"bucket2\"",
   "kind": "attr",
   "select": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   },
   "cond": {
    "path": [],
    "op": "regex",
    "value": "(?i)\"bucket(_prefix)?\":\\s*\"[^\"]*bucket2(-[^\"]*)?\""
   }
  },
  {
   "id": "count_bucket_names",
   "tier": "core",
   "quote": "two count-based buckets with the suffixes \"bucket3\" and \"bucket4\"",
   "kind": "all_of",
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
      "path": [],
      "op": "regex",
      "value": "(?i)\"bucket(_prefix)?\":\\s*\"[^\"]*bucket3(-[^\"]*)?\""
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
      "path": [],
      "op": "regex",
      "value": "(?i)\"bucket(_prefix)?\":\\s*\"[^\"]*bucket4(-[^\"]*)?\""
     }
    }
   ]
  },
  {
   "id": "collection_bucket_names",
   "tier": "core",
   "quote": "four additional buckets defined via local map and list collections using the suffixes \"bucket101\", \"bucket102\", \"bucket103\", and \"bucket104\"",
   "kind": "all_of",
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
      "path": [],
      "op": "regex",
      "value": "(?i)\"bucket(_prefix)?\":\\s*\"[^\"]*bucket101(-[^\"]*)?\""
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
      "path": [],
      "op": "regex",
      "value": "(?i)\"bucket(_prefix)?\":\\s*\"[^\"]*bucket102(-[^\"]*)?\""
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
      "path": [],
      "op": "regex",
      "value": "(?i)\"bucket(_prefix)?\":\\s*\"[^\"]*bucket103(-[^\"]*)?\""
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
      "path": [],
      "op": "regex",
      "value": "(?i)\"bucket(_prefix)?\":\\s*\"[^\"]*bucket104(-[^\"]*)?\""
     }
    }
   ]
  },
  {
   "id": "account_prefix",
   "tier": "core",
   "quote": "every bucket name is dynamically prefixed with the current AWS account ID",
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
     "quantifier": "all",
     "cond": {
      "path": [],
      "op": "regex",
      "value": "\"bucket(_prefix)?\":\\s*\"000000000000"
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
     "quantifier": "all",
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "\"bucket(_prefix)?\":\\s*\"\\$\\{(data\\.aws_caller_identity\\.[A-Za-z0-9_-]+\\.account_id|local\\.[A-Za-z0-9_]*account[A-Za-z0-9_]*)\\}"
     }
    }
   ],
   "justify": "the prompt asks for the current AWS account ID; 000000000000 is the plan's caller-identity account"
  },
  {
   "id": "count_based_buckets",
   "tier": "detail",
   "quote": "two count-based buckets",
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
       "count"
      ],
      "op": "present"
     }
    ]
   }
  },
  {
   "id": "collection_buckets",
   "tier": "detail",
   "quote": "four additional buckets defined via local map and list collections",
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
       "for_each"
      ],
      "op": "regex",
      "value": "local\\."
     }
    ]
   }
  },
  {
   "id": "pab_per_bucket",
   "tier": "core",
   "quote": "Every bucket must block all public access",
   "kind": "any_of",
   "justify": "one block per bucket, seven buckets",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_bucket_public_access_block"
      ],
      "where": []
     },
     "min": 7
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_account_public_access_block"
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
     }
    }
   ]
  },
  {
   "id": "pab_all_true",
   "tier": "core",
   "quote": "Every bucket must block all public access",
   "kind": "any_of",
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
      "path": [],
      "op": "match",
      "value": [
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
     "quantifier": "all"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_account_public_access_block"
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
     }
    }
   ]
  },
  {
   "id": "sse_kms_all",
   "tier": "core",
   "quote": "use default SSE-KMS encryption",
   "kind": "any_of",
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
     "min": 7
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
     "min": 7
    }
   ],
   "justify": "seven buckets"
  },
  {
   "id": "single_cmk",
   "tier": "core",
   "quote": "a single shared customer-managed KMS key created by the template",
   "kind": "exists",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "min": 1,
   "max": 1,
   "justify": "single shared key means exactly one"
  },
  {
   "id": "sse_uses_key",
   "tier": "core",
   "quote": "use default SSE-KMS encryption with a single shared customer-managed KMS key created by the template",
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
        "value": "aws_s3_bucket_server_side_encryption_configuration"
       }
      ]
     },
     "quantifier": "all",
     "cond": {
      "path": [
       "properties",
       "rule",
       "*",
       "apply_server_side_encryption_by_default",
       "*",
       "kms_master_key_id"
      ],
      "op": "regex",
      "value": "\\$\\{(aws_kms_key|aws_kms_alias|local)\\."
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
     "quantifier": "all",
     "cond": {
      "path": [
       "properties",
       "server_side_encryption_configuration",
       "*",
       "rule",
       "*",
       "apply_server_side_encryption_by_default",
       "*",
       "kms_master_key_id"
      ],
      "op": "regex",
      "value": "\\$\\{(aws_kms_key|aws_kms_alias|local)\\."
     }
    }
   ]
  },
  {
   "id": "key_rotation",
   "tier": "extra",
   "kind": "attr",
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
    "op": "eq",
    "value": true
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
