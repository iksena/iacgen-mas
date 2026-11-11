package intent.tf.row_199

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "bucket",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   },
   "quote": "a private S3 bucket"
  },
  {
   "id": "pab_block_public_acls",
   "tier": "core",
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
     "cond": {
      "path": [
       "properties",
       "block_public_acls"
      ],
      "op": "truthy"
     }
    }
   ],
   "quote": "all public access blocked"
  },
  {
   "id": "pab_block_public_policy",
   "tier": "core",
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
     "cond": {
      "path": [
       "properties",
       "block_public_policy"
      ],
      "op": "truthy"
     }
    }
   ],
   "quote": "all public access blocked"
  },
  {
   "id": "pab_ignore_public_acls",
   "tier": "core",
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
     "cond": {
      "path": [
       "properties",
       "ignore_public_acls"
      ],
      "op": "truthy"
     }
    }
   ],
   "quote": "all public access blocked"
  },
  {
   "id": "pab_restrict_public_buckets",
   "tier": "core",
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
      "path": [
       "restrict_public_buckets"
      ],
      "op": "truthy"
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
        "value": "aws_s3_bucket_public_access_block"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "restrict_public_buckets"
      ],
      "op": "truthy"
     }
    }
   ],
   "quote": "all public access blocked"
  },
  {
   "id": "sse_kms",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_s3_bucket_server_side_encryption_configuration",
     "aws_s3_bucket"
    ],
    "where": []
   },
   "cond": {
    "path": [],
    "op": "regex",
    "value": "aws:kms"
   },
   "quote": "default SSE-KMS encryption"
  },
  {
   "id": "sse_cmk",
   "tier": "core",
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
    }
   ],
   "quote": "default SSE-KMS encryption with a customer-managed key"
  },
  {
   "id": "kms_key",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_kms_key"
    ],
    "where": []
   },
   "quote": "a customer-managed key"
  },
  {
   "id": "kms_cf_decrypt",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "(?is)cloudfront\\.amazonaws\\.com.{0,400}kms:(decrypt|\\*)|kms:(decrypt|\\*).{0,400}cloudfront\\.amazonaws\\.com"
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
        "value": "aws_kms_key"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)cloudfront\\.amazonaws\\.com.{0,400}kms:(decrypt|\\*)|kms:(decrypt|\\*).{0,400}cloudfront\\.amazonaws\\.com"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     },
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*",
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "cloudfront.amazonaws.com"
       },
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "kms:Decrypt"
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
        "value": "aws_kms_key_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?is)cloudfront\\.amazonaws\\.com.{0,400}kms:(decrypt|\\*)|kms:(decrypt|\\*).{0,400}cloudfront\\.amazonaws\\.com"
     }
    }
   ],
   "quote": "whose policy lets CloudFront decrypt objects for this distribution"
  },
  {
   "id": "kms_distribution",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_cloudfront_distribution"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_kms_key"
      ],
      "where": []
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
        "value": "aws_cloudfront_distribution"
       }
      ]
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
        "value": "aws_kms_key"
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
        "value": "aws_cloudfront_distribution"
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
        "value": "aws_kms_key"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "(?i)sourcearn"
     }
    },
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
         "principals",
         "*",
         "identifiers",
         "*"
        ],
        "op": "eq",
        "value": "cloudfront.amazonaws.com"
       },
       {
        "path": [
         "statement",
         "*",
         "actions",
         "*"
        ],
        "op": "glob_covers",
        "value": "kms:Decrypt"
       },
       {
        "path": [
         "statement",
         "*",
         "condition",
         "*",
         "variable"
        ],
        "op": "regex",
        "value": "(?i)sourcearn"
       }
      ]
     },
     "to": {
      "types": [
       "aws_cloudfront_distribution"
      ],
      "where": []
     }
    }
   ],
   "quote": "lets CloudFront decrypt objects for this distribution"
  },
  {
   "id": "random_id",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "random_id"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "byte_length"
      ],
      "op": "eq",
      "value": 8
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "random_string"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "length"
      ],
      "op": "eq",
      "value": 16
     }
    }
   ],
   "quote": "an 8-byte hexadecimal random ID",
   "justify": "8 bytes is 16 hex characters"
  },
  {
   "id": "random_in_bucket",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
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
       "random_id"
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
       "random_string"
      ],
      "where": []
     }
    }
   ],
   "quote": "an automated fallback name prefixed with \"webapp-template-\" appended with an 8-byte hexadecimal random ID"
  },
  {
   "id": "versioning",
   "tier": "detail",
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
        "op": "eq",
        "value": "aws_s3_bucket_versioning"
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
       }
      ]
     }
    },
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
      "op": "in",
      "value": [
       "Suspended",
       "Disabled"
      ]
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
      "op": "falsy"
     }
    }
   ],
   "quote": "optional bucket versioning defaulting to false",
   "justify": "'defaulting to false' means versioning is off unless switched on"
  },
  {
   "id": "oac",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_cloudfront_origin_access_control"
    ],
    "where": []
   },
   "quote": "Origin Access Control"
  },
  {
   "id": "oac_type",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudfront_origin_access_control"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "origin_access_control_origin_type"
    ],
    "op": "eq",
    "value": "s3"
   },
   "quote": "CloudFront access to the bucket must be enforced using Origin Access Control",
   "justify": "bucket origin implies s3 origin type"
  },
  {
   "id": "oac_sigv4",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudfront_origin_access_control"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "signing_protocol"
    ],
    "op": "eq",
    "value": "sigv4"
   },
   "quote": "an origin signing protocol of SigV4"
  },
  {
   "id": "dist_uses_oac",
   "tier": "core",
   "kind": "ref",
   "from": {
    "types": [
     "aws_cloudfront_distribution"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_cloudfront_origin_access_control"
    ],
    "where": []
   },
   "quote": "CloudFront access to the bucket must be enforced using Origin Access Control"
  },
  {
   "id": "dist_origin_bucket",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_cloudfront_distribution"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   },
   "quote": "CloudFront access to the bucket"
  },
  {
   "id": "bucket_policy",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_s3_bucket_policy"
    ],
    "where": []
   },
   "quote": "an S3 bucket policy"
  },
  {
   "id": "bucket_policy_bucket",
   "tier": "detail",
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
   },
   "quote": "an S3 bucket policy"
  },
  {
   "id": "policy_getobject",
   "tier": "core",
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
      "op": "regex",
      "value": "(?i)s3:(getobject|\\*|get\\*)"
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket_policy"
      ],
      "where": []
     },
     "to": {
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
      "value": "(?i)s3:(getobject|\\*|get\\*)"
     }
    }
   ],
   "quote": "allowing s3:GetObject"
  },
  {
   "id": "policy_source_arn",
   "tier": "core",
   "kind": "any_of",
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
       },
       {
        "path": [
         "statement",
         "*",
         "condition",
         "*",
         "variable"
        ],
        "op": "regex",
        "value": "(?i)sourcearn"
       }
      ]
     },
     "to": {
      "types": [
       "aws_cloudfront_distribution"
      ],
      "where": []
     }
    },
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
       },
       {
        "path": [
         "statement",
         "*",
         "condition",
         "*",
         "variable"
        ],
        "op": "regex",
        "value": "(?i)sourcearn"
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
        "value": "aws_cloudfront_distribution"
       }
      ]
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket_policy"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_cloudfront_distribution"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_s3_bucket_policy"
      ],
      "where": []
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
        "value": "aws_cloudfront_distribution"
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
      "op": "regex",
      "value": "(?i)sourcearn"
     }
    }
   ],
   "quote": "strictly when the source ARN matches the CloudFront distribution ARN"
  },
  {
   "id": "policy_source_arn_cond",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
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
     "cond": {
      "path": [
       "statement",
       "*",
       "condition",
       "*",
       "variable"
      ],
      "op": "regex",
      "value": "(?i)sourcearn"
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
      "op": "regex",
      "value": "(?i)sourcearn"
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
      "value": "(?i)sourcearn"
     }
    }
   ],
   "quote": "allowing s3:GetObject strictly when the source ARN matches"
  },
  {
   "id": "waf",
   "tier": "core",
   "kind": "attr",
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
   "quote": "a CloudFront-scoped WAFv2 web ACL"
  },
  {
   "id": "waf_allow",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
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
        "value": "aws_wafv2_web_acl"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "default_action"
      ],
      "op": "regex",
      "value": "(?i)allow"
     }
    }
   ],
   "quote": "default action allow"
  },
  {
   "id": "waf_metrics",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
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
        "value": "aws_wafv2_web_acl"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "visibility_config"
      ],
      "op": "regex",
      "value": "(?i)cloudwatch_metrics_enabled[^a-z]{1,6}true"
     }
    }
   ],
   "quote": "metrics enabled"
  },
  {
   "id": "dist_waf",
   "tier": "core",
   "kind": "ref",
   "from": {
    "types": [
     "aws_cloudfront_distribution"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_wafv2_web_acl"
    ],
    "where": []
   },
   "quote": "must be protected by a CloudFront-scoped WAFv2 web ACL"
  },
  {
   "id": "dist_price",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudfront_distribution"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "price_class"
    ],
    "op": "eq",
    "value": "PriceClass_100"
   },
   "quote": "default to PriceClass_100"
  },
  {
   "id": "dist_ipv6",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudfront_distribution"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "is_ipv6_enabled"
    ],
    "op": "truthy"
   },
   "quote": "IPv6 enabled"
  },
  {
   "id": "dist_root",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudfront_distribution"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default_root_object"
    ],
    "op": "eq",
    "value": "index.html"
   },
   "quote": "index.html as the default root object"
  },
  {
   "id": "https_default",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudfront_distribution"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default_cache_behavior",
     "*",
     "viewer_protocol_policy"
    ],
    "op": "eq",
    "value": "redirect-to-https",
    "every": true
   },
   "quote": "HTTPS redirection across all behaviors"
  },
  {
   "id": "https_ordered",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudfront_distribution"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "ordered_cache_behavior",
     "*",
     "viewer_protocol_policy"
    ],
    "op": "eq",
    "value": "redirect-to-https",
    "every": true
   },
   "quote": "HTTPS redirection across all behaviors"
  },
  {
   "id": "cache_optimized",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_cloudfront_distribution"
      ],
      "where": []
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
        "value": "data.aws_cloudfront_cache_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "Managed-CachingOptimized"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudfront_distribution"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "default_cache_behavior",
       "*",
       "cache_policy_id"
      ],
      "op": "eq",
      "value": "658327ea-f89d-4fab-a63d-7e88639e58f6"
     }
    }
   ],
   "quote": "the AWS-managed Managed-CachingOptimized cache policy by default",
   "justify": "managed policy id of Managed-CachingOptimized"
  },
  {
   "id": "cache_disabled",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_cloudfront_distribution"
      ],
      "where": []
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
        "value": "data.aws_cloudfront_cache_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "Managed-CachingDisabled"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudfront_distribution"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "ordered_cache_behavior",
       "*",
       "cache_policy_id"
      ],
      "op": "eq",
      "value": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
     }
    }
   ],
   "quote": "Managed-CachingDisabled specifically for the /index.html path",
   "justify": "managed policy id of Managed-CachingDisabled"
  },
  {
   "id": "ordered_index",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudfront_distribution"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "ordered_cache_behavior",
     "*",
     "path_pattern"
    ],
    "op": "regex",
    "value": "^/?index\\.html$"
   },
   "quote": "an ordered cache behavior with Managed-CachingDisabled specifically for the /index.html path"
  },
  {
   "id": "err403",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudfront_distribution"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "custom_error_response",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "error_code"
        ],
        "op": "eq",
        "value": 403
       },
       {
        "path": [
         "response_code"
        ],
        "op": "eq",
        "value": 404
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
        "value": "aws_cloudfront_distribution"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?is)error_code[^0-9]{1,8}403[^0-9].{0,200}response_code[^0-9]{1,8}404"
     }
    }
   ],
   "quote": "mapping HTTP 403 and 404 error codes to a 404 response code"
  },
  {
   "id": "err404",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudfront_distribution"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "custom_error_response",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "error_code"
        ],
        "op": "eq",
        "value": 404
       },
       {
        "path": [
         "response_code"
        ],
        "op": "eq",
        "value": 404
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
        "value": "aws_cloudfront_distribution"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?is)error_code[^0-9]{1,8}404[^0-9].{0,200}response_code[^0-9]{1,8}404"
     }
    }
   ],
   "quote": "mapping HTTP 403 and 404 error codes to a 404 response code"
  },
  {
   "id": "err_ttl",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudfront_distribution"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "custom_error_response",
       "*",
       "error_caching_min_ttl"
      ],
      "op": "eq",
      "value": 10,
      "every": true
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
        "value": "aws_cloudfront_distribution"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?is)error_caching_min_ttl[^0-9]{1,8}10([^0-9]|$)"
     }
    }
   ],
   "quote": "a 10-second minimum TTL"
  },
  {
   "id": "err_page",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_cloudfront_distribution"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "custom_error_response",
       "*",
       "response_page_path"
      ],
      "op": "eq",
      "value": "/index.html",
      "every": true
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
        "value": "aws_cloudfront_distribution"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "(?is)response_page_path[^/]{1,8}/index\\.html"
     }
    }
   ],
   "quote": "returning /index.html"
  },
  {
   "id": "acm",
   "tier": "core",
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
      "value": "aws_acm_certificate"
     }
    ]
   },
   "quote": "automatically creating an ACM certificate in us-east-1 with DNS validation"
  },
  {
   "id": "acm_dns",
   "tier": "core",
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
      "value": "aws_acm_certificate"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "validation_method"
    ],
    "op": "eq",
    "value": "DNS"
   },
   "quote": "with DNS validation"
  },
  {
   "id": "acm_validation",
   "tier": "core",
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
      "value": "aws_acm_certificate_validation"
     }
    ]
   },
   "quote": "certificate validation"
  },
  {
   "id": "validation_records",
   "tier": "core",
   "kind": "any_of",
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
        "value": "aws_route53_record"
       },
       {
        "path": [
         "properties",
         "zone_id"
        ],
        "op": "present"
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
        "value": "aws_acm_certificate"
       }
      ]
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
        "value": "aws_route53_record"
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
        "value": "aws_acm_certificate"
       }
      ]
     }
    }
   ],
   "quote": "Route 53 DNS validation records"
  },
  {
   "id": "alias_record",
   "tier": "core",
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
      "value": "aws_route53_record"
     },
     {
      "path": [
       "properties",
       "type"
      ],
      "op": "eq",
      "value": "A"
     },
     {
      "path": [
       "properties",
       "alias"
      ],
      "op": "present"
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
      "value": "aws_cloudfront_distribution"
     }
    ]
   },
   "quote": "Route 53 alias A records targeting the distribution"
  },
  {
   "id": "sni_only",
   "tier": "core",
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
      "value": "aws_cloudfront_distribution"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "viewer_certificate"
    ],
    "op": "contains",
    "value": "sni-only"
   },
   "quote": "SNI-only SSL support"
  },
  {
   "id": "tls_min",
   "tier": "core",
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
        "value": "aws_cloudfront_distribution"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "viewer_certificate"
      ],
      "op": "contains",
      "value": "TLSv1.2_2021"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "__parameter__"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "default"
      ],
      "op": "eq",
      "value": "TLSv1.2_2021"
     }
    }
   ],
   "quote": "a default minimum TLS version of TLSv1.2_2021"
  },
  {
   "id": "dist_aliases",
   "tier": "core",
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
      "value": "aws_cloudfront_distribution"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "aliases"
    ],
    "op": "present"
   },
   "quote": "optional www. domain aliases"
  },
  {
   "id": "www_flag",
   "tier": "detail",
   "kind": "attr",
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
      "value": "(?i)www"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": false
   },
   "quote": "optional www. domain aliases with wildcard subject alternative names controlled by a boolean flag defaulting to false"
  },
  {
   "id": "cert_sans",
   "tier": "detail",
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
      "value": "aws_acm_certificate"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "subject_alternative_names"
    ],
    "op": "present"
   },
   "quote": "wildcard subject alternative names"
  },
  {
   "id": "x_oac_always",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudfront_origin_access_control"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "signing_behavior"
    ],
    "op": "eq",
    "value": "always"
   }
  },
  {
   "id": "x_key_rotation",
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
    "op": "truthy"
   }
  },
  {
   "id": "x_compress",
   "tier": "extra",
   "kind": "attr",
   "select": {
    "types": [
     "aws_cloudfront_distribution"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "default_cache_behavior",
     "*",
     "compress"
    ],
    "op": "truthy"
   }
  },
  {
   "id": "x_acm_cbd",
   "tier": "extra",
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
      "value": "aws_acm_certificate"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "lifecycle"
    ],
    "op": "contains",
    "value": "create_before_destroy"
   }
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
