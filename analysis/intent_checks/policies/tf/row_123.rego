package intent.tf.row_123

import rego.v1

import data.intent.lib

spec := {
 "selectors": {
  "trail": {
   "types": [
    "aws_cloudtrail"
   ],
   "where": []
  },
  "bucket": {
   "types": [
    "aws_s3_bucket"
   ],
   "where": []
  },
  "rand": {
   "types": [
    "random_string"
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
  },
  "bpolicy": {
   "types": [
    "aws_s3_bucket_policy"
   ],
   "where": []
  },
  "lg": {
   "types": [
    "aws_cloudwatch_log_group"
   ],
   "where": []
  },
  "role": {
   "types": [
    "aws_iam_role"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "CloudTrailRoleForCloudWatchLogs"
    }
   ]
  },
  "rolepol": {
   "types": [
    "aws_iam_role_policy"
   ],
   "where": [
    {
     "path": [
      "name"
     ],
     "op": "eq",
     "value": "allow-access-to-cw-logs"
    }
   ]
  },
  "kms": {
   "types": [
    "aws_kms_key"
   ],
   "where": []
  },
  "alias": {
   "types": [
    "aws_kms_alias"
   ],
   "where": []
  },
  "rand_any": {
   "types": [
    "random_string",
    "random_integer"
   ],
   "where": []
  },
  "d_bpol_res": {
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
  "d_kms_res": {
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
      "aws_kms_key",
      "aws_kms_key_policy"
     ]
    }
   ]
  },
  "kmspol": {
   "types": [
    "aws_kms_key_policy"
   ],
   "where": []
  }
 },
 "checks": [
  {
   "id": "trail_exists",
   "kind": "exists",
   "tier": "core",
   "select": "trail",
   "quote": "AWS CloudTrail instance"
  },
  {
   "id": "trail_name",
   "kind": "attr",
   "tier": "core",
   "select": "trail",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "management_trail"
   },
   "quote": "variable defaulting to \"management_trail\""
  },
  {
   "id": "trail_multi_region",
   "kind": "attr",
   "tier": "core",
   "select": "trail",
   "cond": {
    "path": [
     "is_multi_region_trail"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "multi-region trail"
  },
  {
   "id": "trail_validation",
   "kind": "attr",
   "tier": "core",
   "select": "trail",
   "cond": {
    "path": [
     "enable_log_file_validation"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "log file validation"
  },
  {
   "id": "trail_global_events",
   "kind": "attr",
   "tier": "core",
   "select": "trail",
   "cond": {
    "path": [
     "include_global_service_events"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "global service event tracking"
  },
  {
   "id": "trail_mgmt_all",
   "kind": "any_of",
   "tier": "core",
   "quote": "management event filtering covering all read/write types",
   "checks": [
    {
     "kind": "attr",
     "select": "trail",
     "cond": {
      "path": [
       "event_selector",
       "*"
      ],
      "op": "match",
      "value": [
       {
        "path": [
         "include_management_events"
        ],
        "op": "eq",
        "value": true
       },
       {
        "path": [
         "read_write_type"
        ],
        "op": "eq",
        "value": "All"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_cloudtrail"
      ],
      "where": [
       {
        "path": [
         "advanced_event_selector",
         "*",
         "field_selector",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "field"
          ],
          "op": "eq",
          "value": "eventCategory"
         },
         {
          "path": [
           "equals",
           "*"
          ],
          "op": "eq",
          "value": "Management"
         }
        ]
       },
       {
        "path": [
         "advanced_event_selector",
         "*",
         "field_selector",
         "*",
         "field"
        ],
        "op": "none_eq",
        "value": "readOnly"
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_cloudtrail"
      ],
      "where": [
       {
        "path": [
         "event_selector",
         "*"
        ],
        "op": "absent"
       },
       {
        "path": [
         "advanced_event_selector",
         "*"
        ],
        "op": "absent"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "trail_org_default",
   "kind": "all_of",
   "tier": "detail",
   "quote": "optional organization trail behavior toggled via a boolean variable defaulting to false",
   "checks": [
    {
     "kind": "attr",
     "select": "trail",
     "cond": {
      "path": [
       "is_organization_trail"
      ],
      "op": "eq",
      "value": false
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
        "value": "aws_cloudtrail"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "is_organization_trail"
      ],
      "op": "present"
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
        "value": "(?i)org"
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
    }
   ],
   "justify": "a boolean variable defaulting to false for the organization-trail toggle"
  },
  {
   "id": "bucket_exists",
   "kind": "exists",
   "tier": "core",
   "select": "bucket",
   "quote": "newly provisioned S3 bucket"
  },
  {
   "id": "trail_to_bucket",
   "kind": "ref",
   "tier": "core",
   "from": "trail",
   "to": "bucket",
   "quote": "CloudTrail logs must deliver to a newly provisioned S3 bucket"
  },
  {
   "id": "bucket_prefix_name",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "bucket",
     "cond": {
      "path": [
       "bucket"
      ],
      "op": "regex",
      "value": "^cloudtrail-bucket-"
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
       "properties",
       "bucket"
      ],
      "op": "regex",
      "value": "cloudtrail-bucket-"
     }
    }
   ],
   "quote": "appends a 12-digit numeric random string to \"cloudtrail-bucket-\""
  },
  {
   "id": "rand_len",
   "kind": "any_of",
   "tier": "core",
   "quote": "12-digit numeric random string",
   "justify": "12-digit means length 12 (or an integer between 10^11 and 10^12-1)",
   "checks": [
    {
     "kind": "attr",
     "select": "rand",
     "cond": {
      "path": [
       "length"
      ],
      "op": "eq",
      "value": 12
     }
    },
    {
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
        "op": "gte",
        "value": 100000000000
       },
       {
        "path": [
         "max"
        ],
        "op": "lte",
        "value": 999999999999
       }
      ]
     }
    }
   ]
  },
  {
   "id": "rand_numeric",
   "kind": "any_of",
   "tier": "detail",
   "checks": [
    {
     "kind": "attr",
     "select": "rand",
     "cond": {
      "path": [
       "numeric"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "attr",
     "select": "rand",
     "cond": {
      "path": [
       "number"
      ],
      "op": "eq",
      "value": true
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "random_integer"
      ],
      "where": []
     }
    }
   ],
   "quote": "12-digit numeric random string"
  },
  {
   "id": "rand_no_letters",
   "kind": "any_of",
   "tier": "detail",
   "quote": "12-digit numeric random string",
   "justify": "numeric-only means no letters or specials",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "random_string"
      ],
      "where": [
       {
        "path": [
         "upper"
        ],
        "op": "eq",
        "value": false
       },
       {
        "path": [
         "lower"
        ],
        "op": "eq",
        "value": false
       },
       {
        "path": [
         "special"
        ],
        "op": "eq",
        "value": false
       }
      ]
     }
    },
    {
     "kind": "exists",
     "select": {
      "types": [
       "random_integer"
      ],
      "where": []
     }
    }
   ]
  },
  {
   "id": "bucket_uses_rand",
   "kind": "ref",
   "tier": "detail",
   "from": "bucket",
   "to": "rand_any",
   "quote": "appends a 12-digit numeric random string"
  },
  {
   "id": "sse_kms",
   "kind": "any_of",
   "tier": "core",
   "quote": "encrypted by default with SSE-KMS",
   "justify": "SSE-KMS means aws:kms",
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
   "id": "sse_key",
   "kind": "any_of",
   "tier": "core",
   "quote": "using the customer managed CloudTrail KMS key",
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
     "to": "kms"
    }
   ]
  },
  {
   "id": "pab_all",
   "kind": "all_of",
   "tier": "core",
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
   ],
   "quote": "blocked from all public access"
  },
  {
   "id": "bucket_policy",
   "kind": "exists",
   "tier": "core",
   "select": "bpolicy",
   "quote": "attached to a bucket policy permitting CloudTrail"
  },
  {
   "id": "bp_getbucketacl",
   "kind": "any_of",
   "tier": "core",
   "quote": "permitting CloudTrail to perform GetBucketAcl and PutObject",
   "checks": [
    {
     "kind": "ref",
     "from": "bpolicy",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
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
          "op": "glob_covers",
          "value": "s3:GetBucketAcl"
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "eq",
          "value": "cloudtrail.amazonaws.com"
         },
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "bpolicy",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "s3:GetBucketAcl"
     }
    },
    {
     "kind": "attr",
     "select": "d_bpol_res",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "s3:GetBucketAcl"
     }
    },
    {
     "kind": "ref",
     "from": "d_bpol_res",
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
        "value": "s3:GetBucketAcl"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bp_putobject",
   "kind": "any_of",
   "tier": "core",
   "quote": "permitting CloudTrail to perform GetBucketAcl and PutObject",
   "checks": [
    {
     "kind": "ref",
     "from": "bpolicy",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
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
          "op": "glob_covers",
          "value": "s3:PutObject"
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "eq",
          "value": "cloudtrail.amazonaws.com"
         },
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "bpolicy",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "s3:PutObject([^A-Za-z]|$)"
     }
    },
    {
     "kind": "attr",
     "select": "d_bpol_res",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "s3:PutObject([^A-Za-z]|$)"
     }
    },
    {
     "kind": "ref",
     "from": "d_bpol_res",
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
        "value": "s3:PutObject([^A-Za-z]|$)"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bp_cloudtrail_principal",
   "kind": "any_of",
   "tier": "detail",
   "quote": "permitting CloudTrail to perform GetBucketAcl and PutObject",
   "checks": [
    {
     "kind": "ref",
     "from": "bpolicy",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "eq",
          "value": "cloudtrail.amazonaws.com"
         },
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "bpolicy",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "cloudtrail\\.amazonaws\\.com"
     }
    },
    {
     "kind": "attr",
     "select": "d_bpol_res",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "cloudtrail\\.amazonaws\\.com"
     }
    },
    {
     "kind": "ref",
     "from": "d_bpol_res",
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
        "value": "cloudtrail\\.amazonaws\\.com"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "bp_owner_full_control",
   "kind": "any_of",
   "tier": "detail",
   "quote": "bucket-owner-full-control checks",
   "checks": [
    {
     "kind": "ref",
     "from": "bpolicy",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
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
          "op": "glob_covers",
          "value": "s3:PutObject"
         },
         {
          "path": [
           "condition",
           "*",
           "values",
           "*"
          ],
          "op": "eq",
          "value": "bucket-owner-full-control"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "bpolicy",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "bucket-owner-full-control"
     }
    },
    {
     "kind": "attr",
     "select": "d_bpol_res",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "bucket-owner-full-control"
     }
    },
    {
     "kind": "ref",
     "from": "d_bpol_res",
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
        "value": "bucket-owner-full-control"
       }
      ]
     }
    }
   ]
  },
  {
   "id": "loggroup_name",
   "kind": "attr",
   "tier": "core",
   "select": "lg",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "cloudtrail_logs"
   },
   "quote": "CloudWatch Log Group named via a variable defaulting to \"cloudtrail_logs\""
  },
  {
   "id": "loggroup_retention",
   "kind": "any_of",
   "tier": "core",
   "checks": [
    {
     "kind": "attr",
     "select": "lg",
     "cond": {
      "path": [
       "retention_in_days"
      ],
      "op": "eq",
      "value": 0
     }
    },
    {
     "kind": "attr",
     "select": "lg",
     "cond": {
      "path": [
       "retention_in_days"
      ],
      "op": "absent"
     }
    }
   ],
   "quote": "retention set to never expire (0 days)",
   "justify": "never expire = 0 days or retention omitted"
  },
  {
   "id": "trail_to_loggroup",
   "kind": "ref",
   "tier": "core",
   "from": "trail",
   "to": "lg",
   "quote": "streams must be forwarded to a dedicated CloudWatch Log Group"
  },
  {
   "id": "role_named",
   "kind": "exists",
   "tier": "core",
   "select": "role",
   "quote": "IAM role named \"CloudTrailRoleForCloudWatchLogs\""
  },
  {
   "id": "role_trust",
   "kind": "any_of",
   "tier": "detail",
   "quote": "integrated using an IAM role",
   "checks": [
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "cloudtrail\\.amazonaws\\.com"
     }
    },
    {
     "kind": "ref",
     "from": "role",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
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
          "op": "glob_covers",
          "value": "sts:AssumeRole"
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "eq",
          "value": "cloudtrail.amazonaws.com"
         }
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
        "op": "eq",
        "value": "aws_iam_role"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "CloudTrailRoleForCloudWatchLogs"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "assume_role_policy"
      ],
      "op": "regex",
      "value": "cloudtrail\\.amazonaws\\.com"
     }
    }
   ],
   "justify": "a role CloudTrail uses must let CloudTrail assume it (sts:AssumeRole)"
  },
  {
   "id": "trail_uses_role",
   "kind": "ref",
   "tier": "detail",
   "from": "trail",
   "to": "role",
   "quote": "integrated using an IAM role"
  },
  {
   "id": "rolepol_named",
   "kind": "any_of",
   "tier": "core",
   "quote": "inline policy named \"allow-access-to-cw-logs\"",
   "checks": [
    {
     "kind": "exists",
     "select": "rolepol"
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "allow-access-to-cw-logs"
     }
    }
   ]
  },
  {
   "id": "rolepol_on_role",
   "kind": "any_of",
   "tier": "detail",
   "quote": "IAM role named \"CloudTrailRoleForCloudWatchLogs\" with an inline policy named \"allow-access-to-cw-logs\"",
   "checks": [
    {
     "kind": "ref",
     "from": "rolepol",
     "to": "role"
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "name"
      ],
      "op": "eq",
      "value": "allow-access-to-cw-logs"
     }
    }
   ]
  },
  {
   "id": "rolepol_logstream",
   "kind": "any_of",
   "tier": "detail",
   "quote": "permitting CloudTrail to create log streams and put log events",
   "checks": [
    {
     "kind": "attr",
     "select": "rolepol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "logs:(CreateLogStream|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "rolepol",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
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
          "op": "glob_covers",
          "value": "logs:CreateLogStream"
         },
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         }
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
        "op": "eq",
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "allow-access-to-cw-logs"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "logs:(CreateLogStream|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "regex",
      "value": "logs:(CreateLogStream|\\*)"
     }
    }
   ]
  },
  {
   "id": "rolepol_putevents",
   "kind": "any_of",
   "tier": "detail",
   "quote": "permitting CloudTrail to create log streams and put log events",
   "checks": [
    {
     "kind": "attr",
     "select": "rolepol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "logs:(PutLogEvents|\\*)"
     }
    },
    {
     "kind": "ref",
     "from": "rolepol",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
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
          "op": "glob_covers",
          "value": "logs:PutLogEvents"
         },
         {
          "path": [
           "effect"
          ],
          "op": "eq",
          "value": "Allow"
         }
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
        "op": "eq",
        "value": "aws_iam_role_policy"
       },
       {
        "path": [
         "properties",
         "name"
        ],
        "op": "eq",
        "value": "allow-access-to-cw-logs"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "logs:(PutLogEvents|\\*)"
     }
    },
    {
     "kind": "attr",
     "select": "role",
     "cond": {
      "path": [
       "inline_policy",
       "*",
       "policy"
      ],
      "op": "regex",
      "value": "logs:(PutLogEvents|\\*)"
     }
    }
   ]
  },
  {
   "id": "kms_exists",
   "kind": "exists",
   "tier": "core",
   "select": "kms",
   "quote": "provisions a customer managed KMS key"
  },
  {
   "id": "kms_toggle",
   "kind": "exists",
   "tier": "detail",
   "quote": "KMS encryption is governed by a boolean variable defaulting to true",
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
     }
    ]
   }
  },
  {
   "id": "kms_alias",
   "kind": "attr",
   "tier": "core",
   "select": "alias",
   "cond": {
    "path": [
     "name"
    ],
    "op": "eq",
    "value": "alias/cloudtrail_key"
   },
   "quote": "key alias defaulting to \"alias/cloudtrail_key\""
  },
  {
   "id": "trail_uses_kms",
   "kind": "ref",
   "tier": "core",
   "from": "trail",
   "to": "kms",
   "quote": "used for both the trail and the log bucket"
  },
  {
   "id": "kp_generatedatakey",
   "kind": "any_of",
   "tier": "detail",
   "quote": "CloudTrail data key generation",
   "checks": [
    {
     "kind": "attr",
     "select": "kms",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "kms:GenerateDataKey"
     }
    },
    {
     "kind": "ref",
     "from": "kms",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
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
          "op": "glob_covers",
          "value": "kms:GenerateDataKey"
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "eq",
          "value": "cloudtrail.amazonaws.com"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "d_kms_res",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "kms:GenerateDataKey"
     }
    },
    {
     "kind": "ref",
     "from": "d_kms_res",
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
        "value": "kms:GenerateDataKey"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "kmspol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "kms:GenerateDataKey"
     }
    }
   ]
  },
  {
   "id": "kp_describekey",
   "kind": "any_of",
   "tier": "detail",
   "quote": "key description",
   "checks": [
    {
     "kind": "attr",
     "select": "kms",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "kms:DescribeKey"
     }
    },
    {
     "kind": "ref",
     "from": "kms",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
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
          "op": "glob_covers",
          "value": "kms:DescribeKey"
         },
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "eq",
          "value": "cloudtrail.amazonaws.com"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "d_kms_res",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "kms:DescribeKey"
     }
    },
    {
     "kind": "ref",
     "from": "d_kms_res",
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
        "value": "kms:DescribeKey"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "kmspol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "kms:DescribeKey"
     }
    }
   ]
  },
  {
   "id": "kp_s3",
   "kind": "any_of",
   "tier": "detail",
   "quote": "S3 use of the key for bucket encryption",
   "checks": [
    {
     "kind": "attr",
     "select": "kms",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "s3\\.amazonaws\\.com"
     }
    },
    {
     "kind": "ref",
     "from": "kms",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "eq",
          "value": "s3.amazonaws.com"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "d_kms_res",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "s3\\.amazonaws\\.com"
     }
    },
    {
     "kind": "ref",
     "from": "d_kms_res",
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
        "value": "s3\\.amazonaws\\.com"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "kmspol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "s3\\.amazonaws\\.com"
     }
    }
   ]
  },
  {
   "id": "kp_decrypt",
   "kind": "any_of",
   "tier": "detail",
   "quote": "account-wide log decryption rights",
   "checks": [
    {
     "kind": "attr",
     "select": "kms",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "kms:Decrypt"
     }
    },
    {
     "kind": "ref",
     "from": "kms",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
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
          "op": "glob_covers",
          "value": "kms:Decrypt"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "d_kms_res",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": "kms:Decrypt"
     }
    },
    {
     "kind": "ref",
     "from": "d_kms_res",
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
        "value": "kms:Decrypt"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "kmspol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "kms:Decrypt"
     }
    }
   ]
  },
  {
   "id": "kp_root",
   "kind": "any_of",
   "tier": "detail",
   "quote": "key policy allowing account root and caller identity administration",
   "checks": [
    {
     "kind": "attr",
     "select": "kms",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": ":root"
     }
    },
    {
     "kind": "ref",
     "from": "kms",
     "to": {
      "types": [
       "data.aws_iam_policy_document"
      ],
      "where": [
       {
        "path": [
         "statement",
         "*"
        ],
        "op": "match",
        "value": [
         {
          "path": [
           "principals",
           "*",
           "identifiers",
           "*"
          ],
          "op": "regex",
          "value": ":root$"
         }
        ]
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "d_kms_res",
     "cond": {
      "path": [
       "properties",
       "policy"
      ],
      "op": "regex",
      "value": ":root"
     }
    },
    {
     "kind": "ref",
     "from": "d_kms_res",
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
        "value": ":root"
       }
      ]
     }
    },
    {
     "kind": "attr",
     "select": "kmspol",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": ":root"
     }
    }
   ]
  },
  {
   "id": "x_trail_after_policy",
   "kind": "ref",
   "tier": "extra",
   "from": "trail",
   "to": "bpolicy"
  },
  {
   "id": "x_kms_context",
   "kind": "any_of",
   "tier": "extra",
   "checks": [
    {
     "kind": "attr",
     "select": "kms",
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "EncryptionContext"
     }
    },
    {
     "kind": "ref",
     "from": "kms",
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
        "value": "EncryptionContext"
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
