package intent.tf.row_323

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "fe_bucket": {
   "types": [
    "aws_s3_bucket"
   ],
   "where": [
    {
     "path": [
      "bucket"
     ],
     "op": "regex",
     "value": "^s3-frontend-nft-maker-v2"
    }
   ]
  },
  "state_bucket": {
   "types": [
    "aws_s3_bucket"
   ],
   "where": [
    {
     "path": [
      "bucket"
     ],
     "op": "regex",
     "value": "^near-frontend-"
    }
   ]
  },
  "kms_rot": {
   "types": [
    "aws_kms_key"
   ],
   "where": [
    {
     "path": [
      "enable_key_rotation"
     ],
     "op": "truthy"
    }
   ]
  },
  "oai": {
   "types": [
    "aws_cloudfront_origin_access_identity"
   ],
   "where": []
  },
  "dist": {
   "types": [
    "aws_cloudfront_distribution"
   ],
   "where": []
  },
  "pab_all": {
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
  "sse_kms": {
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
  }
 },
 "checks": [
  {
   "id": "fe_bucket",
   "kind": "any_of",
   "tier": "core",
   "quote": "a private S3 bucket named \"s3-frontend-nft-maker-v2\" suffixed with the account ID",
   "justify": "suffixed with the account ID: a 12-digit account ID or an account_id interpolation after the stated name",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": [
       {
        "path": [
         "bucket"
        ],
        "op": "regex",
        "value": "^s3-frontend-nft-maker-v2.*[0-9]{12}$"
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
         "bucket"
        ],
        "op": "regex",
        "value": "^s3-frontend-nft-maker-v2.*account_id"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "state_bucket",
   "kind": "any_of",
   "tier": "core",
   "quote": "whose name starts with \"near-frontend-\", includes a configurable environment name, and ends with \"terraform-state\" and the account ID",
   "justify": "ends with terraform-state and the account ID: a 12-digit account ID or an account_id interpolation",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": [
       {
        "path": [
         "bucket"
        ],
        "op": "regex",
        "value": "^near-frontend-.*terraform-state.*[0-9]{12}$"
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
         "bucket"
        ],
        "op": "regex",
        "value": "^near-frontend-.*terraform-state.*account_id"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "state_bucket_env_name",
   "tier": "detail",
   "quote": "includes a configurable environment name",
   "kind": "all_of",
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
        "value": "(?i)env"
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
         "bucket"
        ],
        "op": "regex",
        "value": "^(near-frontend-\\$\\{.*(var|local)\\.|\\$\\{local\\.[A-Za-z0-9_]*state)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "fe_pab",
   "kind": "ref",
   "tier": "core",
   "from": "pab_all",
   "to": "fe_bucket",
   "quote": "blocking all public access"
  },
  {
   "id": "state_pab",
   "kind": "ref",
   "tier": "core",
   "from": "pab_all",
   "to": "state_bucket",
   "quote": "with all public access blocked"
  },
  {
   "id": "fe_sse_kms",
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
     "to": "fe_bucket"
    },
    {
     "kind": "attr",
     "select": "fe_bucket",
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
   ],
   "quote": "encrypted with SSE-KMS",
   "justify": "SSE-KMS is sse_algorithm aws:kms"
  },
  {
   "id": "state_sse_kms",
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
     "to": "state_bucket"
    },
    {
     "kind": "attr",
     "select": "state_bucket",
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
   ],
   "quote": "SSE-KMS encryption using its own customer-managed KMS key",
   "justify": "SSE-KMS is sse_algorithm aws:kms"
  },
  {
   "id": "two_kms_keys",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "min": 2,
   "quote": "using a dedicated customer-managed KMS key",
   "justify": "a dedicated key for the frontend bucket and its own key for the state bucket"
  },
  {
   "id": "fe_kms_rotation",
   "kind": "exists",
   "tier": "core",
   "select": "kms_rot",
   "quote": "with automatic rotation"
  },
  {
   "id": "fe_sse_uses_rotating_key",
   "kind": "ref",
   "tier": "detail",
   "from": "sse_kms",
   "to": "kms_rot",
   "quote": "encrypted with SSE-KMS using a dedicated customer-managed KMS key with automatic rotation"
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
       "aws_s3_bucket_website_configuration"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "index_document",
       "*",
       "suffix"
      ],
      "op": "eq",
      "value": "index.html"
     }
    },
    {
     "kind": "attr",
     "select": "fe_bucket",
     "cond": {
      "path": [
       "website",
       "*",
       "index_document"
      ],
      "op": "eq",
      "value": "index.html"
     }
    }
   ],
   "quote": "configured for website hosting with \"index.html\" as both the index and error document"
  },
  {
   "id": "website_error",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_website_configuration"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "error_document",
       "*",
       "key"
      ],
      "op": "eq",
      "value": "index.html"
     }
    },
    {
     "kind": "attr",
     "select": "fe_bucket",
     "cond": {
      "path": [
       "website",
       "*",
       "error_document"
      ],
      "op": "eq",
      "value": "index.html"
     }
    }
   ],
   "quote": "with \"index.html\" as both the index and error document"
  },
  {
   "id": "cors_exists",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_cors_configuration",
       "aws_s3_bucket"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "cors_rule",
       "*",
       "allowed_origins",
       "*"
      ],
      "op": "eq",
      "value": "*"
     }
    }
   ],
   "quote": "a CORS rule allowing GET, PUT, POST, and DELETE from any origin",
   "justify": "any origin is the * wildcard"
  },
  {
   "id": "cors_get",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_cors_configuration",
       "aws_s3_bucket"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "cors_rule",
       "*",
       "allowed_methods",
       "*"
      ],
      "op": "eq",
      "value": "GET"
     }
    }
   ],
   "quote": "a CORS rule allowing GET, PUT, POST, and DELETE from any origin"
  },
  {
   "id": "cors_put",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_cors_configuration",
       "aws_s3_bucket"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "cors_rule",
       "*",
       "allowed_methods",
       "*"
      ],
      "op": "eq",
      "value": "PUT"
     }
    }
   ],
   "quote": "a CORS rule allowing GET, PUT, POST, and DELETE from any origin"
  },
  {
   "id": "cors_post",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_cors_configuration",
       "aws_s3_bucket"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "cors_rule",
       "*",
       "allowed_methods",
       "*"
      ],
      "op": "eq",
      "value": "POST"
     }
    }
   ],
   "quote": "a CORS rule allowing GET, PUT, POST, and DELETE from any origin"
  },
  {
   "id": "cors_delete",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_s3_bucket_cors_configuration",
       "aws_s3_bucket"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "cors_rule",
       "*",
       "allowed_methods",
       "*"
      ],
      "op": "eq",
      "value": "DELETE"
     }
    }
   ],
   "quote": "a CORS rule allowing GET, PUT, POST, and DELETE from any origin"
  },
  {
   "id": "distribution",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_cloudfront_distribution"
    ],
    "where": []
   },
   "quote": "Serve it through a CloudFront distribution"
  },
  {
   "id": "dist_oai",
   "kind": "ref",
   "tier": "core",
   "from": "dist",
   "to": "oai",
   "quote": "reads the bucket via an origin access identity"
  },
  {
   "id": "dist_bucket",
   "kind": "ref",
   "tier": "detail",
   "from": "dist",
   "to": "fe_bucket",
   "quote": "reads the bucket via an origin access identity"
  },
  {
   "id": "bucket_policy_bucket",
   "kind": "ref",
   "tier": "detail",
   "from": {
    "types": [
     "aws_s3_bucket_policy"
    ],
    "where": []
   },
   "to": "fe_bucket",
   "quote": "granted read and list access in the bucket policy"
  },
  {
   "id": "policy_oai",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": []
     },
     "to": "oai"
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket_policy"
      ],
      "where": []
     },
     "to": "oai"
    }
   ],
   "quote": "granted read and list access in the bucket policy"
  },
  {
   "id": "policy_read",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:GetObject"
       }
      ]
     },
     "to": "oai"
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
        "value": "(?i)s3:(getobject|get\\*|\\*)"
       }
      ]
     },
     "to": "oai"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_bucket_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)s3:(getobject|get\\*|\\*)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)CloudFront Origin Access Identity"
       }
      ]
     }
    }
   ],
   "quote": "granted read and list access in the bucket policy"
  },
  {
   "id": "policy_list",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "s3:ListBucket"
       }
      ]
     },
     "to": "oai"
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
        "value": "(?i)s3:(listbucket|list\\*|\\*)"
       }
      ]
     },
     "to": "oai"
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_s3_bucket_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)s3:(listbucket|list\\*|\\*)"
       },
       {
        "path": [
         "policy"
        ],
        "op": "regex",
        "value": "(?i)CloudFront Origin Access Identity"
       }
      ]
     }
    }
   ],
   "quote": "granted read and list access in the bucket policy"
  },
  {
   "id": "https_redirect",
   "kind": "attr",
   "tier": "core",
   "select": "dist",
   "cond": {
    "path": [
     "default_cache_behavior",
     "*",
     "viewer_protocol_policy"
    ],
    "op": "eq",
    "value": "redirect-to-https"
   },
   "quote": "redirects viewers to HTTPS",
   "justify": "redirecting viewers to HTTPS is viewer_protocol_policy redirect-to-https"
  },
  {
   "id": "ipv6",
   "kind": "attr",
   "tier": "core",
   "select": "dist",
   "cond": {
    "path": [
     "is_ipv6_enabled"
    ],
    "op": "truthy"
   },
   "quote": "enables IPv6"
  },
  {
   "id": "root_object",
   "kind": "attr",
   "tier": "core",
   "select": "dist",
   "cond": {
    "path": [
     "default_root_object"
    ],
    "op": "eq",
    "value": "index.html"
   },
   "quote": "uses \"index.html\" as the default root object"
  },
  {
   "id": "behavior_immutable",
   "kind": "attr",
   "tier": "core",
   "select": "dist",
   "cond": {
    "path": [
     "ordered_cache_behavior",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "path_pattern"
      ],
      "op": "eq",
      "value": "/content/immutable/*"
     },
     {
      "path": [
       "compress"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "adds longer-lived compressed cache behaviors for the \"/content/immutable/*\" and \"/content/*\" paths",
   "justify": "compressed cache behavior for the stated path"
  },
  {
   "id": "behavior_content",
   "kind": "attr",
   "tier": "core",
   "select": "dist",
   "cond": {
    "path": [
     "ordered_cache_behavior",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "path_pattern"
      ],
      "op": "eq",
      "value": "/content/*"
     },
     {
      "path": [
       "compress"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "adds longer-lived compressed cache behaviors for the \"/content/immutable/*\" and \"/content/*\" paths",
   "justify": "compressed cache behavior for the stated path"
  },
  {
   "id": "price_class",
   "kind": "attr",
   "tier": "core",
   "select": "dist",
   "cond": {
    "path": [
     "price_class"
    ],
    "op": "eq",
    "value": "PriceClass_200"
   },
   "quote": "uses price class 200",
   "justify": "price class 200 is PriceClass_200"
  },
  {
   "id": "default_cert",
   "kind": "attr",
   "tier": "core",
   "select": "dist",
   "cond": {
    "path": [
     "viewer_certificate",
     "*",
     "cloudfront_default_certificate"
    ],
    "op": "truthy"
   },
   "quote": "with the default CloudFront certificate"
  },
  {
   "id": "waf_scope",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_wafv2_web_acl"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "scope"
    ],
    "op": "eq",
    "value": "CLOUDFRONT"
   },
   "quote": "a CloudFront-scoped WAFv2 web ACL",
   "justify": "CloudFront-scoped means scope CLOUDFRONT"
  },
  {
   "id": "dist_waf",
   "kind": "ref",
   "tier": "core",
   "from": "dist",
   "to": {
    "types": [
     "aws_wafv2_web_acl"
    ],
    "where": []
   },
   "quote": "protected by a CloudFront-scoped WAFv2 web ACL"
  },
  {
   "id": "waf_default_allow",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_wafv2_web_acl"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default_action",
     "*",
     "allow"
    ],
    "op": "len_gte",
    "value": 1
   },
   "quote": "that allows traffic by default"
  },
  {
   "id": "waf_common_rules",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_wafv2_web_acl"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "rule",
     "*",
     "statement",
     "*",
     "managed_rule_group_statement",
     "*",
     "name"
    ],
    "op": "eq",
    "value": "AWSManagedRulesCommonRuleSet"
   },
   "quote": "applies the AWS managed common rule set",
   "justify": "the AWS managed common rule set is AWSManagedRulesCommonRuleSet"
  },
  {
   "id": "state_versioning",
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
     "to": "state_bucket"
    },
    {
     "kind": "attr",
     "select": "state_bucket",
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
   "quote": "a versioned, private S3 bucket",
   "justify": "versioned means status Enabled"
  },
  {
   "id": "lock_table",
   "kind": "exists",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": [
     {
      "path": [
       "name"
      ],
      "op": "eq",
      "value": "near-frontend-terraform-state"
     }
    ]
   },
   "quote": "a DynamoDB table named \"near-frontend-terraform-state\""
  },
  {
   "id": "lock_hash",
   "kind": "attr",
   "tier": "core",
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
   },
   "quote": "with a string \"LockID\" hash key"
  },
  {
   "id": "lock_hash_type",
   "kind": "attr",
   "tier": "detail",
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
   },
   "quote": "with a string \"LockID\" hash key",
   "justify": "a string attribute has type S"
  },
  {
   "id": "lock_read",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "read_capacity"
    ],
    "op": "eq",
    "value": 5
   },
   "quote": "provisioned capacity of 5 read and 5 write units"
  },
  {
   "id": "lock_write",
   "kind": "attr",
   "tier": "core",
   "select": {
    "types": [
     "aws_dynamodb_table"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "write_capacity"
    ],
    "op": "eq",
    "value": 5
   },
   "quote": "provisioned capacity of 5 read and 5 write units"
  },
  {
   "id": "x_cors_headers",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_s3_bucket_cors_configuration"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "cors_rule",
     "*",
     "allowed_headers",
     "*"
    ],
    "op": "eq",
    "value": "*"
   }
  },
  {
   "id": "x_state_acl",
   "kind": "attr",
   "tier": "extra",
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
   "id": "x_waf_metrics",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_wafv2_web_acl"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "visibility_config",
     "*",
     "cloudwatch_metrics_enabled"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_immutable_ttl",
   "kind": "attr",
   "tier": "extra",
   "select": {
    "types": [
     "aws_cloudfront_distribution"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "ordered_cache_behavior",
     "*"
    ],
    "op": "match",
    "value": [
     {
      "path": [
       "path_pattern"
      ],
      "op": "eq",
      "value": "/content/immutable/*"
     },
     {
      "path": [
       "max_ttl"
      ],
      "op": "gte",
      "value": 31536000
     }
    ]
   }
  },
  {
   "id": "extra_type_aws_s3_bucket_ownership_controls",
   "kind": "exists",
   "tier": "extra",
   "select": {
    "types": [
     "aws_s3_bucket_ownership_controls"
    ],
    "where": []
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
