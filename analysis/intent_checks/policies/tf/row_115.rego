package intent.tf.row_115

import rego.v1

import data.intent.lib

spec := {
 "selectors": {},
 "checks": [
  {
   "id": "random_string",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "random_string"
    ],
    "where": []
   },
   "quote": "optional random suffix generation using a lowercase alphanumeric string"
  },
  {
   "id": "random_length",
   "tier": "detail",
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
    "value": 4
   },
   "quote": "length defaulting to 4"
  },
  {
   "id": "random_no_special",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "random_string"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "special"
    ],
    "op": "falsy"
   },
   "quote": "special characters disabled"
  },
  {
   "id": "random_lower_alnum",
   "tier": "detail",
   "kind": "all_of",
   "checks": [
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
       "upper"
      ],
      "op": "falsy"
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
       "lower"
      ],
      "op": "truthy"
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
       "numeric"
      ],
      "op": "truthy"
     }
    }
   ],
   "quote": "lowercase alphanumeric string"
  },
  {
   "id": "random_suffix_param",
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
      "op": "eq",
      "value": "random_suffix"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "controlled by a random_suffix boolean defaulting to true"
  },
  {
   "id": "bucket_name_default",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
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
      "value": "zedcloud"
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
       "bucket"
      ],
      "op": "regex",
      "value": "^zedcloud"
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
      "op": "contains",
      "value": "zedcloud"
     }
    }
   ],
   "quote": "the S3 bucket name (defaulting to \"zedcloud\")"
  },
  {
   "id": "user_name_default",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
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
      "value": "zedcloud-s3-user"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_user"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^zedcloud-s3-user"
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
        "value": "aws_iam_user"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "name"
      ],
      "op": "contains",
      "value": "zedcloud-s3-user"
     }
    }
   ],
   "quote": "IAM username (defaulting to \"zedcloud-s3-user\")"
  },
  {
   "id": "policy_name_default",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
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
      "value": "zedcloud-s3-policy"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "name"
      ],
      "op": "regex",
      "value": "^zedcloud-s3-policy"
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
        "value": "aws_iam_policy"
       }
      ]
     },
     "cond": {
      "path": [
       "properties",
       "name"
      ],
      "op": "contains",
      "value": "zedcloud-s3-policy"
     }
    }
   ],
   "quote": "IAM policy name (defaulting to \"zedcloud-s3-policy\")"
  },
  {
   "id": "suffix_appended",
   "tier": "detail",
   "kind": "all_of",
   "quote": "to append to the S3 bucket name (defaulting to \"zedcloud\"), IAM username (defaulting to \"zedcloud-s3-user\"), and IAM policy name",
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
       "random_string"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user"
      ],
      "where": []
     },
     "to": {
      "types": [
       "random_string"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
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
   ]
  },
  {
   "id": "bucket_exists",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_s3_bucket"
    ],
    "where": []
   },
   "quote": "The S3 bucket must be created"
  },
  {
   "id": "bucket_force_destroy",
   "tier": "core",
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
   },
   "quote": "created with force_destroy enabled"
  },
  {
   "id": "bucket_tagged",
   "tier": "detail",
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
     "cond": {
      "path": [
       "tags",
       "Name"
      ],
      "op": "regex",
      "value": "^zedcloud"
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
       "tags",
       "Name"
      ],
      "op": "regex",
      "value": "(?i)(bucket|zedcloud)"
     }
    }
   ],
   "quote": "tagged with its resolved name"
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
   "quote": "a customer-managed KMS key with rotation enabled"
  },
  {
   "id": "kms_rotation",
   "tier": "core",
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
   },
   "quote": "a customer-managed KMS key with rotation enabled"
  },
  {
   "id": "sse_kms",
   "tier": "core",
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
      "op": "eq",
      "value": "aws:kms"
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
      "op": "eq",
      "value": "aws:kms"
     }
    }
   ],
   "quote": "encrypted by default with SSE-KMS"
  },
  {
   "id": "sse_uses_cmk",
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
       "aws_kms_key"
      ],
      "where": []
     }
    }
   ],
   "quote": "encrypted by default with SSE-KMS using a customer-managed KMS key"
  },
  {
   "id": "pab_exists",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_s3_bucket_public_access_block"
    ],
    "where": []
   },
   "quote": "restricted using an S3 public access block"
  },
  {
   "id": "pab_block_public_acls",
   "tier": "core",
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
   },
   "quote": "block_public_acls"
  },
  {
   "id": "pab_ignore_public_acls",
   "tier": "core",
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
   },
   "quote": "ignore_public_acls"
  },
  {
   "id": "pab_block_public_policy",
   "tier": "core",
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
   },
   "quote": "block_public_policy"
  },
  {
   "id": "pab_restrict_public_buckets",
   "tier": "core",
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
   },
   "quote": "restrict_public_buckets"
  },
  {
   "id": "pab_bucket",
   "tier": "detail",
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
   },
   "quote": "restricted using an S3 public access block"
  },
  {
   "id": "upload_object",
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
      "op": "in",
      "value": [
       "aws_s3_object",
       "aws_s3_bucket_object"
      ]
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "quote": "An image upload resource must be conditionally created based on an upload_image boolean",
   "justify": "conditionally created means the object is count/for_each gated"
  },
  {
   "id": "upload_param",
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
      "op": "eq",
      "value": "upload_image"
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
   "quote": "an upload_image boolean (defaulting to false)"
  },
  {
   "id": "upload_source",
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
      "op": "in",
      "value": [
       "aws_s3_object",
       "aws_s3_bucket_object"
      ]
     },
     {
      "path": [
       "gated"
      ],
      "op": "truthy"
     }
    ]
   },
   "cond": {
    "path": [
     "properties",
     "source"
    ],
    "op": "regex",
    "value": "image_filename|my-file\\.qcow2|local\\.[A-Za-z0-9_]*(image|file)"
   },
   "quote": "referencing a local image source file specified by image_filename"
  },
  {
   "id": "image_filename_param",
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
      "op": "eq",
      "value": "image_filename"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "my-file.qcow2"
   },
   "quote": "image_filename (defaulting to \"my-file.qcow2\")"
  },
  {
   "id": "s3_folder_param",
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
      "op": "eq",
      "value": "s3_folder"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": "my-folder"
   },
   "quote": "s3_folder (defaulting to \"my-folder\")"
  },
  {
   "id": "create_folder_param",
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
      "op": "eq",
      "value": "create_folder"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "if create_folder (defaulting to true) is set"
  },
  {
   "id": "upload_bucket",
   "tier": "detail",
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
        "op": "in",
        "value": [
         "aws_s3_object",
         "aws_s3_bucket_object"
        ]
       },
       {
        "path": [
         "gated"
        ],
        "op": "truthy"
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
       "aws_s3_object",
       "aws_s3_bucket_object"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": []
     }
    }
   ],
   "quote": "uploading it to an S3 key path"
  },
  {
   "id": "iam_user",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "quote": "provisioning an IAM user with force_destroy set to true"
  },
  {
   "id": "iam_user_force_destroy",
   "tier": "core",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "force_destroy"
    ],
    "op": "truthy"
   },
   "quote": "an IAM user with force_destroy set to true"
  },
  {
   "id": "iam_user_path",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "path"
    ],
    "op": "eq",
    "value": "/"
   },
   "quote": "under path \"/\""
  },
  {
   "id": "iam_user_toggle",
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
      "op": "eq",
      "value": "create_iam_user"
     }
    ]
   },
   "cond": {
    "path": [
     "default"
    ],
    "op": "eq",
    "value": true
   },
   "quote": "IAM user creation must be toggled via create_iam_user (defaulting to true)"
  },
  {
   "id": "access_key",
   "tier": "core",
   "kind": "exists",
   "select": {
    "types": [
     "aws_iam_access_key"
    ],
    "where": []
   },
   "quote": "an active IAM access key"
  },
  {
   "id": "access_key_active",
   "tier": "detail",
   "kind": "attr",
   "select": {
    "types": [
     "aws_iam_access_key"
    ],
    "where": []
   },
   "cond": {
    "path": [
     "status"
    ],
    "op": "eq",
    "value": "Active"
   },
   "quote": "an active IAM access key"
  },
  {
   "id": "access_key_user",
   "tier": "detail",
   "kind": "ref",
   "from": {
    "types": [
     "aws_iam_access_key"
    ],
    "where": []
   },
   "to": {
    "types": [
     "aws_iam_user"
    ],
    "where": []
   },
   "quote": "an active IAM access key"
  },
  {
   "id": "policy_actions",
   "tier": "core",
   "kind": "any_of",
   "checks": [
    {
     "kind": "exists",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:GetObject"
       },
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:ListBucket"
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
         "aws_iam_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3:GetObject"
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3:ListBucket"
       }
      ]
     }
    }
   ],
   "quote": "an IAM policy granting s3:GetObject on bucket objects and s3:ListBucket on the bucket ARN"
  },
  {
   "id": "policy_on_bucket",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_policy"
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
        "value": "aws_iam_policy"
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
     "to": {
      "types": [
       "aws_s3_bucket"
      ],
      "where": []
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
         "aws_iam_policy",
         "data.aws_iam_policy_document"
        ]
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "arn:aws:s3:::(\\$\\{|zedcloud)"
     }
    },
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "contains",
      "value": "arn:aws:s3:::zedcloud"
     }
    }
   ],
   "quote": "s3:GetObject on bucket objects and s3:ListBucket on the bucket ARN",
   "justify": "an S3 bucket ARN is arn:aws:s3::: plus the stated bucket name \"zedcloud\""
  },
  {
   "id": "attachment_links",
   "tier": "core",
   "kind": "all_of",
   "checks": [
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_policy"
      ],
      "where": []
     }
    },
    {
     "kind": "ref",
     "from": {
      "types": [
       "aws_iam_user_policy_attachment",
       "aws_iam_policy_attachment"
      ],
      "where": []
     },
     "to": {
      "types": [
       "aws_iam_user"
      ],
      "where": []
     }
    }
   ],
   "quote": "an IAM user policy attachment linking the policy to the user"
  },
  {
   "id": "sse_on_bucket",
   "tier": "detail",
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
       "aws_s3_bucket"
      ],
      "where": []
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
        "value": "aws_s3_bucket_server_side_encryption_configuration"
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
   "quote": "The S3 bucket must be created with force_destroy enabled, tagged with its resolved name, and encrypted by default"
  },
  {
   "id": "policy_get_on_objects",
   "tier": "detail",
   "kind": "any_of",
   "checks": [
    {
     "kind": "attr",
     "select": {
      "types": [
       "aws_iam_policy"
      ],
      "where": [
       {
        "path": [
         "policy"
        ],
        "op": "contains",
        "value": "s3:GetObject"
       }
      ]
     },
     "cond": {
      "path": [
       "policy"
      ],
      "op": "regex",
      "value": "/\\*"
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
         "aws_iam_policy",
         "data.aws_iam_policy_document"
        ]
       },
       {
        "path": [
         "properties"
        ],
        "op": "contains",
        "value": "s3:GetObject"
       }
      ]
     },
     "cond": {
      "path": [
       "properties"
      ],
      "op": "regex",
      "value": "/\\*"
     }
    }
   ],
   "quote": "s3:GetObject on bucket objects"
  }
 ]
}

results := lib.evaluate(spec)

targets := lib.targets(spec)
